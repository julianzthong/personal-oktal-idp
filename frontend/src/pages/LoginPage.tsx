import { useState, type SubmitEvent } from 'react'
import { Link, useLocation, useSearchParams } from 'react-router'
import { login } from '../api.ts'
import { safeReturnTo } from '../returnTo.ts'
import ErrorList from './ErrorList.tsx'
import SignedIn from './SignedIn.tsx'
import './auth.css'

export default function LoginPage() {
  const [searchParams] = useSearchParams()
  const { search } = useLocation() // carried over to the signup link so return_to survives
  const returnTo = safeReturnTo(searchParams.get('return_to'))

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [errors, setErrors] = useState<string[]>([])
  const [submitting, setSubmitting] = useState(false)
  const [signedInAs, setSignedInAs] = useState<string | null>(null)

  async function handleSubmit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault()
    setErrors([])
    setSubmitting(true)

    const result = await login(email, password)
    if (!result.ok) {
      setErrors(result.errors)
      setSubmitting(false)
      return
    }

    setPassword('')
    if (returnTo) {
      // A full navigation, not a router one: /authorize is served by the backend.
      window.location.assign(returnTo)
    } else {
      setSignedInAs(result.email)
      setSubmitting(false)
    }
  }

  if (signedInAs) return <SignedIn email={signedInAs} onSignedOut={() => setSignedInAs(null)} />

  return (
    <main className="auth">
      <h1>Sign in</h1>
      {returnTo && <p className="hint">Sign in to continue.</p>}

      <form onSubmit={handleSubmit}>
        <label>
          Email
          <input
            type="email"
            name="email"
            autoComplete="username"
            required
            autoFocus
            value={email}
            onChange={(event) => setEmail(event.target.value)}
          />
        </label>
        <label>
          Password
          <input
            type="password"
            name="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(event) => setPassword(event.target.value)}
          />
        </label>

        <ErrorList errors={errors} />

        <button type="submit" disabled={submitting}>
          {submitting ? 'Signing in…' : 'Sign in'}
        </button>
      </form>

      <p className="switch">
        New here? <Link to={{ pathname: '/signup', search }}>Create an account</Link>
      </p>
    </main>
  )
}
