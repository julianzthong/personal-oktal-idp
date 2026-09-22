import { API_URL } from './config.ts'

// Errors are a list so that a signup can report every problem at once.
export type AuthResult =
  | { ok: true; email: string }
  | { ok: false; errors: string[] }

const failure = (...errors: string[]): AuthResult => ({ ok: false, errors })

const NETWORK_ERROR = "Couldn't reach the server. Is the backend running?"
const GENERIC_ERROR = 'Something went wrong. Please try again.'

// The session lives in a cookie set by the backend, so every call needs
// `credentials: 'include'` for the browser to store and send it cross-origin.
// Returns null when the server can't be reached at all.
async function postJson(path: string, payload: object): Promise<Response | null> {
  try {
    return await fetch(`${API_URL}${path}`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })
  } catch {
    return null
  }
}

// Rate limited. The backend says how long to wait in Retry-After (it's exposed
// through CORS for exactly this reason).
function tooManyRequests(response: Response): AuthResult {
  const seconds = Number(response.headers.get('Retry-After'))
  if (!(seconds > 0)) return failure('Too many attempts. Please try again later.')
  const wait = seconds < 90 ? `${seconds} seconds` : `${Math.ceil(seconds / 60)} minutes`
  return failure(`Too many attempts. Try again in ${wait}.`)
}

export async function login(email: string, password: string): Promise<AuthResult> {
  const response = await postJson('/login', { email, password })
  if (!response) return failure(NETWORK_ERROR)

  if (response.ok) {
    const user: { email: string } = await response.json()
    return { ok: true, email: user.email }
  }
  if (response.status === 401) return failure('Incorrect email or password.')
  if (response.status === 429) return tooManyRequests(response)
  return failure(GENERIC_ERROR)
}

export async function signup(
  name: string,
  email: string,
  password: string,
  passwordConfirmation: string,
): Promise<AuthResult> {
  const response = await postJson('/signup', {
    name,
    email,
    password,
    password_confirmation: passwordConfirmation,
  })
  if (!response) return failure(NETWORK_ERROR)

  if (response.ok) {
    const user: { email: string } = await response.json()
    return { ok: true, email: user.email }
  }
  if (response.status === 422) {
    // Full sentences from the model validations, e.g. "Email has already been taken".
    const body: { errors: string[] } = await response.json()
    return { ok: false, errors: body.errors }
  }
  if (response.status === 429) return tooManyRequests(response)
  return failure(GENERIC_ERROR)
}

export async function logout(): Promise<void> {
  await fetch(`${API_URL}/logout`, { method: 'DELETE', credentials: 'include' })
}
