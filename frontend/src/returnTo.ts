import { API_URL } from './config.ts'

// /authorize sends anonymous users here with a `return_to` URL that resumes
// their authorization request. The backend builds it from its own issuer, but
// the query string is attacker-influenced, so before navigating anywhere we
// insist it points at the backend's /authorize endpoint and nothing else.
// Otherwise this page would be an open redirector.
export function safeReturnTo(value: string | null): string | null {
  if (!value) return null
  try {
    const url = new URL(value)
    const backend = new URL(API_URL)
    return url.origin === backend.origin && url.pathname === '/authorize' ? url.toString() : null
  } catch {
    return null
  }
}
