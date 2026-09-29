import { useSearchParams } from 'react-router'
import { safeReturnTo } from '../returnTo.ts'
import './auth.css'

const SCOPE_DESCRIPTIONS: Record<string, string> = {
  openid: 'Confirm your identity',
  profile: 'Access your name',
  email: 'Access your email address',
  offline_access: "Keep you signed in, even when you're not using the app",
}

// /authorize sends a logged-in user here when they haven't yet approved a
// client for the scopes it's asking for. The decision itself is made by
// navigating to return_to with &allow=true or &allow=false appended — a real
// top-level GET, not a fetch, because the backend's response to that is
// another redirect, this time to the relying party's own callback URL. That
// has to happen as a real page navigation for the relying party to receive it.
export default function ConsentPage() {
  const [searchParams] = useSearchParams()
  const returnTo = safeReturnTo(searchParams.get('return_to'), '/consent')
  const clientName = searchParams.get('client_name')
  const scopes = (searchParams.get('scope') ?? '').split(' ').filter(Boolean)

  if (!returnTo || !clientName || scopes.length === 0) {
    return (
      <main className="auth">
        <h1>Nothing to approve</h1>
        <p>This page is reached from an app's sign-in flow, not visited directly.</p>
      </main>
    )
  }

  const decide = (allow: boolean) => window.location.assign(`${returnTo}&allow=${allow}`)

  return (
    <main className="auth">
      <h1>Allow access?</h1>
      <p>
        <strong>{clientName}</strong> would like to:
      </p>

      <ul className="scopes">
        {scopes.map((scope) => (
          <li key={scope}>{SCOPE_DESCRIPTIONS[scope] ?? scope}</li>
        ))}
      </ul>

      <div className="actions">
        <button type="button" onClick={() => decide(true)}>
          Allow
        </button>
        <button type="button" className="secondary" onClick={() => decide(false)}>
          Deny
        </button>
      </div>
    </main>
  )
}
