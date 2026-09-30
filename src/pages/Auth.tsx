import { FormEvent, useEffect, useLayoutEffect, useState } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Eye, EyeOff, LockKeyhole, Wifi } from 'lucide-react'
import { APIError, activate, login, platformSetup, setCSRF, setup, setupStatus } from '../api'
import { usernameProblem } from './Users'

function sentence(message: string) {
  const trimmed = message.trim()
  if (!trimmed) return 'Sign-in failed.'
  const normalized = `${trimmed[0].toLocaleUpperCase()}${trimmed.slice(1)}`
  return /[.!?]$/.test(normalized) ? normalized : `${normalized}.`
}

function retryWait(seconds?: number) {
  if (seconds === undefined || !Number.isFinite(seconds) || seconds <= 0) return 'a short while'
  if (seconds < 60) {
    const rounded = Math.ceil(seconds)
    return `${rounded} second${rounded === 1 ? '' : 's'}`
  }
  const minutes = Math.ceil(seconds / 60)
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? '' : 's'}`
  const hours = Math.ceil(seconds / 3600)
  if (hours < 24) return `${hours} hour${hours === 1 ? '' : 's'}`
  const days = Math.ceil(seconds / 86400)
  return `${days} day${days === 1 ? '' : 's'}`
}

function signInErrorMessage(error: unknown) {
  if (error instanceof APIError) {
    if (error.code === 'rate_limited') return `Too many sign-in attempts. Try again in about ${retryWait(error.retryAfterSeconds)}.`
    if (error.code === 'login_failed') return 'The username, password, or authenticator code is incorrect.'
    return sentence(error.message)
  }
  return error instanceof Error ? sentence(error.message) : 'Unable to sign in.'
}

function PasswordField({ id, label, value, onChange, autoComplete, minLength, helpText }: {
  id: string
  label: string
  value: string
  onChange: (value: string) => void
  autoComplete: string
  minLength?: number
  helpText?: string
}) {
  const [visible, setVisible] = useState(false)
  const fieldName = label === 'Confirm password' ? 'confirmation password' : 'password'
  return <label>{label}<div className="input-with-action"><input id={id} type={visible ? 'text' : 'password'} value={value} onChange={event => onChange(event.target.value)} autoComplete={autoComplete} minLength={minLength} required /><button type="button" aria-label={`${visible ? 'Hide' : 'Show'} ${fieldName}`} aria-controls={id} onClick={() => setVisible(show => !show)}>{visible ? <EyeOff size={17} /> : <Eye size={17} />}</button></div>{helpText && <small>{helpText}</small>}</label>
}

/**
 * The one-time token of an activation or password-reset link: from the URL
 * fragment, or from the query string of a link issued before tokens moved to
 * the fragment. It is empty when the address holds none.
 */
export function activationTokenFromLocation(search: string, hash: string) {
  const fragment = new URLSearchParams(hash.startsWith('#') ? hash.slice(1) : hash)
  return fragment.get('token') ?? new URLSearchParams(search).get('token') ?? ''
}

function activationLocationWithoutToken(pathname: string, search: string, hash: string) {
  const query = new URLSearchParams(search)
  const fragment = new URLSearchParams(hash.startsWith('#') ? hash.slice(1) : hash)
  if (!query.has('token') && !fragment.has('token')) return null
  query.delete('token')
  fragment.delete('token')
  const cleanSearch = query.toString()
  const cleanHash = fragment.toString()
  return `${pathname}${cleanSearch ? `?${cleanSearch}` : ''}${cleanHash ? `#${cleanHash}` : ''}`
}

/**
 * The page that sent a signed-out visitor to the sign-in page, as its path
 * and search string, which the console records in the sign-in page's
 * location state. Only a path within the console is returned.
 */
export function signInReturnPath(state: unknown) {
  const from = (state as { from?: { pathname?: unknown; search?: unknown } } | null)?.from
  if (typeof from?.pathname !== 'string' || !from.pathname.startsWith('/') || from.pathname.startsWith('//')) return null
  return `${from.pathname}${typeof from.search === 'string' ? from.search : ''}`
}

export function Login() {
  const navigate = useNavigate(); const location = useLocation(); const queryClient = useQueryClient(); const publicStatus = useQuery({ queryKey: ['setup-status'], queryFn: setupStatus, staleTime: 30_000 }); const [username, setUsername] = useState('admin'); const [password, setPassword] = useState(''); const [otp, setOtp] = useState(''); const [recovery, setRecovery] = useState(''); const [showRecovery, setShowRecovery] = useState(false); const [error, setError] = useState(''); const [busy, setBusy] = useState(false); const [notice, setNotice] = useState(() => (location.state as { message?: string } | null)?.message ?? '')
  async function submit(event: FormEvent) { event.preventDefault(); setError(''); setNotice(''); setBusy(true); try { const value = await login(password, otp, showRecovery ? recovery : undefined, username); setCSRF(value.csrf_token); await queryClient.invalidateQueries({ queryKey: ['session'] }); await queryClient.invalidateQueries({ queryKey: ['setup-status'] }); window.dispatchEvent(new Event('edgewatch:authenticated')); const destination = signInReturnPath(location.state) ?? (value.totp_enrollment_required ? '/security' : value.role === 'viewer' ? '/jobs' : '/'); navigate(destination, { replace: true }) } catch (err) { setError(signInErrorMessage(err)) } finally { setBusy(false) } }
  function toggleRecovery() { setShowRecovery(value => !value); setError('') }
  return <AuthFrame eyebrow="Welcome back" title="Sign in to EdgeWatch" subtitle="Review your network surface and respond to changes."><form onSubmit={submit} className="auth-form">{notice && <div className="success-banner" role="status">{notice}</div>}{publicStatus.data?.platform_setup_available && <div className="notice warning" role="status"><LockKeyhole size={14} /><span>A platform setup token from the EdgeWatch host is waiting to be used. <Link to="/setup">Create the platform administrator</Link>.</span></div>}<label>Username<input autoFocus value={username} onChange={e => setUsername(e.target.value)} autoComplete="username" required /></label><label>Password<input type="password" value={password} onChange={e => setPassword(e.target.value)} autoComplete="current-password" required /></label><label>{showRecovery ? 'Recovery code' : 'Authenticator code'}<input inputMode={showRecovery ? 'text' : 'numeric'} value={showRecovery ? recovery : otp} onChange={e => showRecovery ? setRecovery(e.target.value) : setOtp(e.target.value)} placeholder={showRecovery ? 'AB12CD34EF' : '123456'} autoComplete="one-time-code" /></label>{error && <div className="form-error" role="alert">{error}</div>}<button disabled={busy} className="button primary wide" type="submit">{busy ? 'Signing in…' : 'Sign in'}</button><button type="button" className="link-button" onClick={toggleRecovery}>{showRecovery ? 'Use authenticator code' : 'Use a recovery code'}</button><Link className="link-button" to="/activate">Activate an account</Link>{publicStatus.data?.public_dashboard_enabled && <a className="link-button" href="/public">View read-only highlights</a>}</form></AuthFrame>
}

export function Setup() {
  // An installation without an administrator gets the first-run setup. Once
  // it is set up, this page offers the platform setup while the token that
  // `edgewatch admin platform-setup-token` printed on the host is valid, and
  // otherwise says that setup is complete and leads to sign-in.
  const status = useQuery({ queryKey: ['setup-status'], queryFn: setupStatus, staleTime: 30_000 })
  const platformSetupAvailable = !!status.data?.configured && !!status.data.platform_setup_available
  // A token that expires, or that another operator uses, while the platform
  // setup is open keeps the form and what was typed in it. The form says
  // that the token lapsed and takes a new one from the host.
  const [platformSetupOpened, setPlatformSetupOpened] = useState(false)
  if (platformSetupAvailable && !platformSetupOpened) setPlatformSetupOpened(true)
  if (!status.data) return status.isError ? <AuthFrame eyebrow="Setup" title="EdgeWatch is unavailable" subtitle="The setup status could not be read. Reload this page when the service is available."><Link className="link-button" to="/login">Go to sign in</Link></AuthFrame> : <div className="loading"><span className="spinner" />Loading EdgeWatch…</div>
  if (!status.data.configured) return <InitialSetup />
  if (platformSetupAvailable || platformSetupOpened) return <PlatformSetup minimumLength={status.data.password_requirements?.minimum_length ?? 12} tokenLapsed={!platformSetupAvailable} />
  return <SetupComplete />
}

function SetupComplete() {
  return <AuthFrame eyebrow="Setup" title="EdgeWatch is already set up" subtitle="The first administrator exists, and no valid platform setup token is waiting to create the first platform administrator."><div className="auth-form"><div className="notice"><LockKeyhole size={14} /><span>To create the first platform administrator, print a platform setup token on the EdgeWatch host with <code>edgewatch admin platform-setup-token</code> and reload this page within 15 minutes. Otherwise, sign in with your account.</span></div><Link className="button primary wide" to="/login">Go to sign in</Link></div></AuthFrame>
}

function PlatformSetup({ minimumLength, tokenLapsed }: { minimumLength: number; tokenLapsed: boolean }) {
  const navigate = useNavigate(); const queryClient = useQueryClient(); const [token, setToken] = useState(''); const [username, setUsername] = useState(''); const [password, setPassword] = useState(''); const [confirm, setConfirm] = useState(''); const [error, setError] = useState(''); const [busy, setBusy] = useState(false)
  useEffect(() => { if (tokenLapsed) setError('') }, [tokenLapsed])
  async function submit(event: FormEvent) {
    event.preventDefault()
    setError('')
    if (!username.trim()) { setError('Choose a username for the platform administrator.'); return }
    const problem = usernameProblem(username)
    if (problem) { setError(problem); return }
    if (password.length < minimumLength) { setError(`Use at least ${minimumLength} characters for the password.`); return }
    if (password !== confirm) { setError('Passwords do not match.'); return }
    setBusy(true)
    try {
      await platformSetup(token.trim(), username.trim(), password)
      await queryClient.invalidateQueries({ queryKey: ['setup-status'] })
      navigate('/login', { replace: true, state: { message: 'Platform administrator created. Sign in with the new account.' } })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Setup failed')
    } finally {
      setBusy(false)
    }
  }
  return <AuthFrame eyebrow="Business units" title="Create the platform administrator" subtitle="Platform administrators create business units and manage their administrators, but never see a unit’s scan data. Existing accounts keep working in the default unit."><form onSubmit={submit} className="auth-form"><div className="notice"><LockKeyhole size={14} /><span>Use the token that <code>edgewatch admin platform-setup-token</code> printed on the EdgeWatch host. It expires 15 minutes after it was printed.</span></div>{tokenLapsed && !busy && <div className="notice warning" role="status"><LockKeyhole size={14} /><span>The platform setup token has expired or was already used. Print a new one on the EdgeWatch host with <code>edgewatch admin platform-setup-token</code> and paste it below; what you typed is kept. Once a platform administrator exists, sign in instead.</span></div>}<label>Platform setup token<input autoFocus value={token} onChange={e => setToken(e.target.value)} autoComplete="one-time-code" placeholder="Paste the token from the host" required /></label><label>Username<input value={username} onChange={e => setUsername(e.target.value)} autoComplete="username" required maxLength={80} /><small>Usernames are unique across the deployment, including every unit.</small></label><PasswordField id="platform-password" label="Password" value={password} onChange={setPassword} autoComplete="new-password" minLength={minimumLength} helpText={`At least ${minimumLength} characters. Set up TOTP after signing in; it is required once more than one unit exists.`} /><PasswordField id="platform-password-confirm" label="Confirm password" value={confirm} onChange={setConfirm} autoComplete="new-password" />{error && <div className="form-error" role="alert">{error}</div>}<button disabled={busy} className="button primary wide" type="submit">{busy ? 'Creating account…' : 'Create platform administrator'}</button><Link className="link-button" to="/login">Back to sign in</Link></form></AuthFrame>
}

function InitialSetup() {
  const navigate = useNavigate(); const queryClient = useQueryClient(); const [token, setToken] = useState(''); const [password, setPassword] = useState(''); const [confirm, setConfirm] = useState(''); const [error, setError] = useState(''); const [busy, setBusy] = useState(false)
  async function submit(event: FormEvent) { event.preventDefault(); setError(''); if (password.length < 12) { setError('Use at least 12 characters for the administrator password.'); return } if (password !== confirm) { setError('Passwords do not match.'); return }; setBusy(true); try { await setup(token.trim(), password); await queryClient.invalidateQueries({ queryKey: ['setup-status'] }); await queryClient.invalidateQueries({ queryKey: ['session'] }); navigate('/login') } catch (err) { setError(err instanceof Error ? err.message : 'Setup failed') } finally { setBusy(false) } }
  return <AuthFrame eyebrow="First-run setup" title="Create your administrator" subtitle="The setup token is printed once in the EdgeWatch container logs and expires after 15 minutes."><form onSubmit={submit} className="auth-form"><label>Setup token<input autoFocus value={token} onChange={e => setToken(e.target.value)} autoComplete="one-time-code" placeholder="Paste the token from the logs" required /></label><PasswordField id="initial-password" label="Password" value={password} onChange={setPassword} autoComplete="new-password" minLength={12} helpText="At least 12 characters. You can enable TOTP after signing in." /><PasswordField id="initial-password-confirm" label="Confirm password" value={confirm} onChange={setConfirm} autoComplete="new-password" />{error && <div className="form-error" role="alert">{error}</div>}<button disabled={busy} className="button primary wide" type="submit">{busy ? 'Creating account…' : 'Create administrator'}</button></form></AuthFrame>
}

export function Activate() {
  const navigate = useNavigate(); const location = useLocation(); const [token, setToken] = useState(() => activationTokenFromLocation(location.search, location.hash)); const [password, setPassword] = useState(''); const [confirm, setConfirm] = useState(''); const [error, setError] = useState(''); const [busy, setBusy] = useState(false)
  useLayoutEffect(() => {
    const cleanLocation = activationLocationWithoutToken(location.pathname, location.search, location.hash)
    if (cleanLocation !== null) navigate(cleanLocation, { replace: true, state: location.state })
  }, [location.hash, location.pathname, location.search, location.state, navigate])
  async function submit(event: FormEvent) { event.preventDefault(); setError(''); if (password !== confirm) { setError('Passwords do not match.'); return }; setBusy(true); try { await activate(token.trim(), password); navigate('/login', { replace: true, state: { message: 'Account activated. Sign in with your new password.' } }) } catch (err) { setError(err instanceof Error ? err.message : 'Activation failed') } finally { setBusy(false) } }
  return <AuthFrame eyebrow="Activate account" title="Choose your password" subtitle="This activation link is single-use and expires shortly."><form onSubmit={submit} className="auth-form"><label>Activation token<input autoFocus value={token} onChange={e => setToken(e.target.value)} autoComplete="one-time-code" required /></label><PasswordField id="activation-password" label="Password" value={password} onChange={setPassword} autoComplete="new-password" minLength={12} helpText="At least 12 characters." /><PasswordField id="activation-password-confirm" label="Confirm password" value={confirm} onChange={setConfirm} autoComplete="new-password" />{error && <div className="form-error" role="alert">{error}</div>}<button disabled={busy} className="button primary wide" type="submit">{busy ? 'Activating…' : 'Activate account'}</button></form></AuthFrame>
}

/**
 * An activation or password-reset link opened in a browser that holds a
 * session. The link sets the password of the account that it was issued
 * for, which need not be the signed-in account, so the console neither uses
 * it with this session nor drops it: the token stays in the address until
 * the visitor signs out, and the activation page then opens with it. The
 * visitor may also return to the console, which leaves the link unused.
 */
export function SignedInActivation({ displayName, username, onSignOut }: { displayName?: string; username: string; onSignOut: () => Promise<void> }) {
  const navigate = useNavigate(); const [busy, setBusy] = useState(false)
  const account = displayName && displayName !== username ? `${displayName} (${username})` : username
  return <AuthFrame eyebrow="Account link" title="You are already signed in" subtitle="This activation or password-reset link sets the password of the account it was issued for. Sign out to use it."><div className="auth-form"><div className="notice"><LockKeyhole size={14} /><span>Signed in as <strong>{account}</strong>. The link is not used with this session: it opens once you have signed out, and stays valid until it expires.</span></div><button type="button" className="button primary wide" disabled={busy} onClick={() => { setBusy(true); void onSignOut() }}>{busy ? 'Signing out…' : 'Sign out and continue'}</button><button type="button" className="link-button" onClick={() => navigate('/', { replace: true })}>Return to the console</button></div></AuthFrame>
}

function AuthFrame({ eyebrow, title, subtitle, children }: { eyebrow: string; title: string; subtitle: string; children: React.ReactNode }) { return <div className="auth-layout"><div className="auth-art"><div className="brand light"><span className="brand-mark"><Wifi size={19} /></span><span>EdgeWatch</span></div><div className="art-copy"><div className="signal"><i /><i /><i /><i /><i /></div><h2>Know what changed.</h2><p>Simple, scheduled network visibility for the systems you own.</p></div><span className="art-footer">Local-first · Privacy-minded · Built for operators</span></div><div className="auth-side"><div className="auth-card"><div className="auth-mobile-brand"><Wifi size={18} /> EdgeWatch</div><div className="auth-heading"><div className="auth-icon"><LockKeyhole size={20} /></div><p className="eyebrow">{eyebrow}</p><h1>{title}</h1><p className="muted">{subtitle}</p></div>{children}</div></div></div> }
