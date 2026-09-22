# Sample relying party

A tiny OpenID Connect client for trying the IdP in a browser. It uses only Node's
standard library (Node 22+), so there is nothing to install.

```sh
# 1. backend (seeds a user and the `sample-rp` client)
cd backend && bin/rails db:seed && bin/rails server

# 2. frontend (the IdP's login page)
cd frontend && npm run dev

# 3. this app
node sample-rp/server.mjs
```

Open <http://localhost:4000> and click **Log in**. You'll be sent to the IdP, sign in
as `dev@example.com` / `password123`, and come back to a page showing the verified
ID token.

It walks the authorization code flow with PKCE (S256) and, on the callback, checks
the `state`, redeems the code, then verifies the ID token's signature against the
JWKS and its `iss`, `aud`, `exp`, `nonce` and `at_hash` claims. It then calls
`/userinfo` with the access token and checks that its `sub` matches the ID token's. It is written
independently of the Rails code on purpose, so the two act as a check on each other.

Configuration (all optional): `ISSUER`, `CLIENT_ID`, `CLIENT_SECRET`, `PORT`,
`REDIRECT_URI`.
