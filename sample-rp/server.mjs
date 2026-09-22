// A minimal OpenID Connect relying party (RP) for trying the IdP in a browser.
//
// It is deliberately independent of the Rails code: it knows only the IdP's
// public URLs and its own client credentials, and it does the PKCE hashing and
// the RS256 signature check with Node's built-in `crypto`. If this agrees with
// the IdP, the two implementations agree with each other and with the specs.
//
//   node sample-rp/server.mjs      then open http://localhost:4000
//
// Zero dependencies. Not production code: sessions live in memory, and the
// client secret has a public default that matches `bin/rails db:seed`.

import { createServer } from 'node:http'
import { createHash, createPublicKey, randomBytes, timingSafeEqual, verify } from 'node:crypto'

const ISSUER = process.env.ISSUER ?? 'http://localhost:3000'
const CLIENT_ID = process.env.CLIENT_ID ?? 'sample-rp'
const CLIENT_SECRET = process.env.CLIENT_SECRET ?? 'sample-rp-secret'
const PORT = Number(process.env.PORT ?? 4000)
const REDIRECT_URI = process.env.REDIRECT_URI ?? `http://localhost:${PORT}/callback`
const SCOPE = 'openid profile email'
const FLOW_TTL_MS = 10 * 60 * 1000

const sha256 = (input) => createHash('sha256').update(input).digest()
const base64url = (buffer) => buffer.toString('base64url')
const randomToken = (bytes) => base64url(randomBytes(bytes))

const safeEqual = (a, b) => {
  const [x, y] = [Buffer.from(String(a)), Buffer.from(String(b))]
  return x.length === y.length && timingSafeEqual(x, y)
}

// Login attempts in flight, keyed by the id in the `rp_sid` cookie. Each holds
// the secrets that must survive the round trip through the IdP.
const pending = new Map()

async function getJson(url, init) {
  const response = await fetch(url, init)
  return { response, body: await response.json() }
}

// OIDC Discovery: everything else is looked up from the issuer URL.
let metadata
async function discover() {
  if (metadata) return metadata
  const { body } = await getJson(`${ISSUER}/.well-known/openid-configuration`)
  // Discovery §4.3: the issuer in the document must be the one we asked.
  if (body.issuer !== ISSUER) {
    throw new Error(`Discovery issuer mismatch: expected ${ISSUER}, got ${body.issuer}`)
  }
  return (metadata = body)
}

// --- Step 1: send the user to the IdP ---------------------------------------

async function startLogin(res) {
  const { authorization_endpoint } = await discover()

  for (const [id, flow] of pending) {
    if (Date.now() - flow.createdAt > FLOW_TTL_MS) pending.delete(id)
  }

  const flow = {
    state: randomToken(16), // ties the callback to this browser (CSRF protection)
    nonce: randomToken(16), // ties the ID token to this login (replay protection)
    verifier: randomToken(32), // PKCE secret; only its hash goes to the IdP now
    createdAt: Date.now(),
  }
  const sid = randomToken(16)
  pending.set(sid, flow)

  const url = new URL(authorization_endpoint)
  url.search = new URLSearchParams({
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: SCOPE,
    state: flow.state,
    nonce: flow.nonce,
    code_challenge: base64url(sha256(flow.verifier)),
    code_challenge_method: 'S256',
  }).toString()

  res.writeHead(302, {
    Location: url.toString(),
    'Set-Cookie': `rp_sid=${sid}; HttpOnly; SameSite=Lax; Path=/`,
  })
  res.end()
}

// --- Step 2: the IdP sends the user back with a code ------------------------

async function handleCallback(req, res, query) {
  const sid = parseCookies(req).rp_sid
  const flow = pending.get(sid)
  pending.delete(sid) // one attempt per login, whatever happens next
  if (!flow || Date.now() - flow.createdAt > FLOW_TTL_MS) {
    return sendPage(res, 400, 'No login in progress', '<p>Start again from the <a href="/">home page</a>.</p>')
  }
  if (!safeEqual(query.get('state') ?? '', flow.state)) {
    return sendPage(res, 400, 'State mismatch', '<p>The <code>state</code> did not match, so this response is rejected.</p>')
  }
  if (query.has('error')) {
    return sendPage(res, 400, 'The IdP returned an error', `<pre>${escapeHtml(JSON.stringify(Object.fromEntries(query), null, 2))}</pre>`)
  }
  const code = query.get('code')
  if (!code) return sendPage(res, 400, 'Missing code', '<p>The callback had no <code>code</code>.</p>')

  const { token_endpoint, jwks_uri, userinfo_endpoint } = await discover()

  // Step 3: redeem the code. This is a back-channel call, so the client secret
  // and the PKCE verifier never pass through the browser.
  const basic = Buffer.from(`${encodeURIComponent(CLIENT_ID)}:${encodeURIComponent(CLIENT_SECRET)}`).toString('base64')
  const { response, body: tokens } = await getJson(token_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: `Basic ${basic}` },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: flow.verifier,
    }),
  })
  if (!response.ok) {
    return sendPage(res, 502, 'Token request failed', `<pre>${escapeHtml(JSON.stringify(tokens, null, 2))}</pre>`)
  }

  // Step 4: never trust an ID token until it has been verified.
  const { body: jwks } = await getJson(jwks_uri)
  const result = verifyIdToken(tokens.id_token, { jwks, nonce: flow.nonce, accessToken: tokens.access_token })

  // Step 5: fetch the user's profile claims with the access token. This is where
  // the profile and email scopes pay off; the ID token itself stays minimal.
  const { response: userinfoResponse, body: userinfo } = await getJson(userinfo_endpoint, {
    headers: { Authorization: `Bearer ${tokens.access_token}` },
  })
  if (!userinfoResponse.ok) {
    return sendPage(res, 502, 'UserInfo request failed', `<pre>${escapeHtml(JSON.stringify(userinfo, null, 2))}</pre>`)
  }
  // Core §5.3.2: if the sub differs from the ID token's, the response must not be used.
  if (userinfo.sub !== result.claims.sub) {
    throw new Error(`UserInfo sub (${userinfo.sub}) does not match the ID token sub (${result.claims.sub})`)
  }
  result.checks.push({ name: 'UserInfo sub matches the ID token sub', ok: true, detail: `sub = ${userinfo.sub}` })

  sendPage(res, 200, 'Signed in', renderSuccess(tokens, result, userinfo))
}

// OIDC Core §3.1.3.7. Each check is recorded so the page can show what passed;
// the first failure throws, which the caller turns into an error page.
function verifyIdToken(idToken, { jwks, nonce, accessToken }) {
  const parts = String(idToken).split('.')
  if (parts.length !== 3) throw new Error('The ID token is not a well-formed JWT')
  const [encodedHeader, encodedClaims, encodedSignature] = parts
  const header = JSON.parse(Buffer.from(encodedHeader, 'base64url'))
  const claims = JSON.parse(Buffer.from(encodedClaims, 'base64url'))

  const checks = []
  const check = (name, ok, detail) => {
    checks.push({ name, ok, detail })
    if (!ok) throw new Error(`ID token check failed: ${name} (${detail})`)
  }

  // Pick the algorithm ourselves. Trusting the header's `alg` is how "none" and
  // HS256-with-the-public-key attacks work.
  check('alg is RS256', header.alg === 'RS256', `header.alg = ${header.alg}`)
  const jwk = jwks.keys.find((key) => key.kty === 'RSA' && key.kid === header.kid)
  check('signing key found in JWKS', Boolean(jwk), `kid = ${header.kid}`)
  const signatureValid = verify(
    'RSA-SHA256',
    Buffer.from(`${encodedHeader}.${encodedClaims}`),
    createPublicKey({ key: jwk, format: 'jwk' }),
    Buffer.from(encodedSignature, 'base64url'),
  )
  check('signature is valid', signatureValid, 'RSASSA-PKCS1-v1_5 with SHA-256')
  check('iss is the issuer', claims.iss === ISSUER, `iss = ${claims.iss}`)
  check('aud contains our client_id', [claims.aud].flat().includes(CLIENT_ID), `aud = ${claims.aud}`)
  check('exp is in the future', claims.exp > Math.floor(Date.now() / 1000), `exp = ${claims.exp}`)
  check('nonce matches the one we sent', claims.nonce === nonce, `nonce = ${claims.nonce}`)
  const atHash = base64url(sha256(accessToken).subarray(0, 16))
  check('at_hash matches the access token', claims.at_hash === atHash, `at_hash = ${claims.at_hash}`)

  return { header, claims, checks }
}

// --- Pages ------------------------------------------------------------------

function renderSuccess(tokens, { header, claims, checks }, userinfo) {
  const accessTokenClaims = JSON.parse(Buffer.from(tokens.access_token.split('.')[1], 'base64url'))
  const checkItems = checks.map((c) => `<li>✅ ${escapeHtml(c.name)} <small>${escapeHtml(c.detail)}</small></li>`).join('')
  const json = (value) => `<pre>${escapeHtml(JSON.stringify(value, null, 2))}</pre>`
  const authTime = claims.auth_time ? new Date(claims.auth_time * 1000).toLocaleString() : 'unknown'

  return `
    <p>Logged in as <strong>${escapeHtml(userinfo.name ?? userinfo.email ?? 'an unnamed user')}</strong> (user <code>${escapeHtml(claims.sub)}</code>), who authenticated at ${escapeHtml(authTime)}.</p>
    <h2>ID token checks</h2><ul>${checkItems}</ul>
    <h2>UserInfo response</h2>${json(userinfo)}
    <h2>ID token header</h2>${json(header)}
    <h2>ID token claims</h2>${json(claims)}
    <h2>Token response</h2>${json({ token_type: tokens.token_type, expires_in: tokens.expires_in, scope: tokens.scope })}
    <h2>Access token claims</h2>
    <p><small>Decoded for display only. A relying party should treat the access token as opaque and just present it as a bearer token; verifying it is the API's job.</small></p>
    ${json(accessTokenClaims)}
    <p><a href="/login">Log in again</a></p>`
}

function sendPage(res, status, title, body) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8' })
  res.end(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>${escapeHtml(title)}</title>
<style>
  body { font: 16px/1.5 system-ui, sans-serif; max-width: 760px; margin: 40px auto; padding: 0 16px; }
  pre { background: #f4f3ec; color: #111; padding: 12px; border-radius: 8px; overflow-x: auto; }
  code { background: #f4f3ec; color: #111; padding: 2px 6px; border-radius: 4px; }
  li { margin: 4px 0; } small { color: #6b6375; }
  @media (prefers-color-scheme: dark) { body { background: #16171d; color: #d1d5db; } a { color: #c084fc; } }
</style></head>
<body><h1>${escapeHtml(title)}</h1>${body}</body></html>`)
}

const HTML_ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }
const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (char) => HTML_ESCAPES[char])

function parseCookies(req) {
  return Object.fromEntries(
    (req.headers.cookie ?? '').split(';').map((pair) => pair.trim().split(/=(.*)/s).slice(0, 2)).filter(([name]) => name),
  )
}

// --- Server -----------------------------------------------------------------

createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`)
  try {
    if (req.method === 'GET' && url.pathname === '/') {
      sendPage(res, 200, 'Sample relying party', `<p>Uses the IdP at <code>${escapeHtml(ISSUER)}</code> as <code>${escapeHtml(CLIENT_ID)}</code>.</p><p><a href="/login">Log in</a></p>`)
    } else if (req.method === 'GET' && url.pathname === '/login') {
      await startLogin(res)
    } else if (req.method === 'GET' && url.pathname === '/callback') {
      await handleCallback(req, res, url.searchParams)
    } else {
      sendPage(res, 404, 'Not found', '<p><a href="/">Home</a></p>')
    }
  } catch (error) {
    console.error(error)
    sendPage(res, 500, 'Something went wrong', `<pre>${escapeHtml(error.message)}</pre>`)
  }
}).listen(PORT, () => {
  console.log(`Sample RP on http://localhost:${PORT}  (issuer ${ISSUER}, client ${CLIENT_ID})`)
})
