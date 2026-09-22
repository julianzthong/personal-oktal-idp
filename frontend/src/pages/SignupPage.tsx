import { useState, type SubmitEvent } from 'react'
import { Link, useLocation, useSearchParams } from 'react-router'
import { signup } from '../api.ts'
import { safeReturnTo } from '../returnTo.ts'
import ErrorList from './ErrorList.tsx'
import SignedIn from './SignedIn.tsx'
import './auth.css'

export default function SignupPage() {
  const [searchParams] = useSearchParams()
  const { search } = useLocation() // carried over to the login link so return_to survives
  const returnTo = safeReturnTo(searchParams.get('return_to'))

  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [passwordConfirmation, setPasswordConfirmation] = useState('')
  const [errors, setErrors] = useState<string[]>([])
  const [submitting, setSubmitting] = useState(false)
  const [signedInAs, setSignedInAs] = useState<string | null>(null)

  async function handleSubmit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault()
    setErrors([])
    setSubmitting(true)

    const result = await signup(name, email, password, passwordConfirmation)
    if (!result.ok) {
      setErrors(result.errors)
      setSubmitting(false)
      return
    }

    // The backend logged the new user in, so this continues exactly like a login.
    setPassword('')
    setPasswordConfirmation('')
    if (returnTo) {
      window.location.assign(returnTo)
    } else {
      setSignedInAs(result.email)
      setSubmitting(false)
    }
  }

  if (signedInAs) return <SignedIn email={signedInAs} onSignedOut={() => setSignedInAs(null)} />

  return (
    <main className="auth">
      <h1>Create an account</h1>
      {returnTo && <p className="hint">Then you'll continue where you left off.</p>}

      <form onSubmit={handleSubmit}>
        <label>
          Name <span className="optional">(optional)</span>
          <input
            type="text"
            name="name"
            autoComplete="name"
            autoFocus
            maxLength={100}
            value={name}
            onChange={(event) => setName(event.target.value)}
          />
        </label>
        <label>
          Email
          <input
            type="email"
            name="email"
            autoComplete="username"
            required
            value={email}
            onChange={(event) => setEmail(event.target.value)}
          />
        </label>
        <label>
          Password
          <input
            type="password"
            name="password"
            autoComplete="new-password"
            required
            minLength={8}
            value={password}
            onChange={(event) => setPassword(event.target.value)}
          />
        </label>
        <label>
          Confirm password
          <input
            type="password"
            name="password_confirmation"
            autoComplete="new-password"
            required
            value={passwordConfirmation}
            onChange={(event) => setPasswordConfirmation(event.target.value)}
          />
        </label>

        <ErrorList errors={errors} />

        <button type="submit" disabled={submitting}>
          {submitting ? 'Creating account…' : 'Create account'}
        </button>
      </form>

      <p className="switch">
        Already have an account? <Link to={{ pathname: '/login', search }}>Sign in</Link>
      </p>
    </main>
  )
}
