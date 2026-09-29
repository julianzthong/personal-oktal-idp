import { API_URL } from './config.ts'

// The backend sends anonymous or not-yet-consented users here with a
// `return_to` URL that resumes their in-progress /authorize request. The
// backend builds it from its own issuer, but the query string is
// attacker-influenced, so before navigating anywhere we insist it points at
// one specific backend endpoint and nothing else. Otherwise this page would
// be an open redirector.
export function safeReturnTo(value: string | null, allowedPath: string): string | null {
  if (!value) return null
  try {
    const url = new URL(value)
    const backend = new URL(API_URL)
    return url.origin === backend.origin && url.pathname === allowedPath ? url.toString() : null
  } catch {
    return null
  }
}
