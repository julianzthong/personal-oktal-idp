import { logout } from '../api.ts'
import './auth.css'

// Shown after signing in or up when there is no return_to to continue to, i.e.
// the user came straight to this app instead of from a relying party.
export default function SignedIn({ email, onSignedOut }: { email: string; onSignedOut: () => void }) {
  async function handleSignOut() {
    await logout()
    onSignedOut()
  }

  return (
    <main className="auth">
      <h1>You're signed in</h1>
      <p>
        Signed in as <strong>{email}</strong>. To sign in to an app, start from that app.
      </p>
      <button type="button" className="secondary" onClick={handleSignOut}>
        Sign out
      </button>
    </main>
  )
}
