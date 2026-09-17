import { FormEvent, useEffect, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Check, Copy, KeyRound, LogOut, ShieldCheck, UserRound } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { api, getSession, logout, logoutAllSessions, setCSRF, updateDisplayName } from '../api'
import { ActionDialog } from '../components/ActionDialog'

export function Security() {
  const client = useQueryClient()
  const navigate = useNavigate()
  const session = useQuery({ queryKey: ['session'], queryFn: async () => { const value = await getSession(); setCSRF(value.csrf_token); return value } })
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const [totp, setTotp] = useState<{ secret: string; otpauth: string } | null>(null)
  const [code, setCode] = useState('')
  const [currentFactor, setCurrentFactor] = useState('')
  const [recovery, setRecovery] = useState<string[]>([])
  const [recoveryAcknowledged, setRecoveryAcknowledged] = useState(false)
  const [disablePrompt, setDisablePrompt] = useState(false)
  const [recoveryPrompt, setRecoveryPrompt] = useState(false)
  const [revokePrompt, setRevokePrompt] = useState(false)
  const [recoveryBusy, setRecoveryBusy] = useState(false)
  const [displayName, setDisplayName] = useState('')
  const [displayNameBusy, setDisplayNameBusy] = useState(false)
  const displayNameInitialized = useRef(false)

  useEffect(() => {
    if (displayNameInitialized.current || !session.data) return
    setDisplayName(session.data.display_name ?? session.data.username ?? 'admin')
    displayNameInitialized.current = true
  }, [session.data])

  async function saveDisplayName(event: FormEvent) {
    event.preventDefault()
    setMessage('')
    setError('')
    setDisplayNameBusy(true)
    try {
      const value = await updateDisplayName(displayName)
      setDisplayName(value.display_name)
      setMessage('Display name updated.')
      await Promise.all([
        client.invalidateQueries({ queryKey: ['session'] }),
        client.invalidateQueries({ queryKey: ['admin-status'] }),
      ])
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Display name update failed')
    } finally {
      setDisplayNameBusy(false)
    }
  }

  async function change(event: FormEvent) {
    event.preventDefault()
    setMessage('')
    setError('')
    try {
      await api('/auth/password', { method: 'PUT', body: JSON.stringify({ current_password: current, new_password: next }) })
      setCSRF('')
      client.clear()
      navigate('/login')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Password update failed')
    }
  }

  async function revokeSessions() {
    setMessage('')
    setError('')
    try {
      await logoutAllSessions()
      setCSRF('')
      client.clear()
      setRevokePrompt(false)
      navigate('/login')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not revoke sessions')
    }
  }

  async function beginTotp() {
    setError('')
    try {
      const factor = currentFactor.trim()
      const value = await api<{ secret: string; otpauth: string }>('/auth/totp/setup', { method: 'POST', body: JSON.stringify({ password: current, ...(session.data?.totp_enabled ? { code: /^\d{6}$/.test(factor) ? factor : '', recovery_code: /^\d{6}$/.test(factor) ? '' : factor } : {}) }) })
      setTotp(value)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not start TOTP setup')
    }
  }

  async function enableTotp() {
    setError('')
    try {
      const value = await api<{ recovery_codes: string[] }>('/auth/totp/enable', { method: 'POST', body: JSON.stringify({ code }) })
      setRecovery(value.recovery_codes)
      setRecoveryAcknowledged(false)
      setTotp(null)
      setCode('')
      setCurrentFactor('')
      // The acting session is intentionally preserved by the server while
      // these one-time codes are displayed. Keep its CSRF token and cookie
      // usable so background refetches and the acknowledgement logout cannot
      // turn the recovery panel into an unauthenticated error state.
      setMessage('TOTP enabled. Save the recovery codes below, then sign in again.')
      await client.invalidateQueries({ queryKey: ['session'] })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'TOTP setup failed')
    }
  }

  async function finishTotpSetup() {
    if (!recoveryAcknowledged) {
      setError('Confirm that you saved the recovery codes before continuing.')
      return
    }
    setError('')
    setRecoveryBusy(true)
    try {
      // Enabling TOTP keeps only this browser session alive so the recovery
      // codes can be copied. Acknowledging the codes ends that session before
      // navigating to login, guaranteeing that a reload requires the normal
      // password + TOTP (or recovery-code) flow.
      await logout()
      setCSRF('')
      client.clear()
      client.setQueryData(['session'], null)
      navigate('/login', { replace: true })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not finish TOTP setup')
    } finally {
      setRecoveryBusy(false)
    }
  }

  function factorPayload(factor: string) {
    const value = factor.trim()
    return { code: /^\d{6}$/.test(value) ? value : '', recovery_code: /^\d{6}$/.test(value) ? '' : value }
  }

  async function disableTotp(password: string, factor = '') {
    setError('')
    try {
      await api('/auth/totp', { method: 'DELETE', body: JSON.stringify({ password, ...factorPayload(factor) }) })
      // TOTP changes revoke every existing session. Return to sign-in rather
      // than leaving the page in a state whose cookie is no longer valid.
      setDisablePrompt(false)
      setCSRF('')
      client.clear()
      navigate('/login')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not disable TOTP')
    }
  }

  async function regenerateRecoveryCodes(password: string, factor = '') {
    setError('')
    try {
      const value = await api<{ recovery_codes: string[] }>('/auth/totp/recovery-codes', { method: 'POST', body: JSON.stringify({ password, ...factorPayload(factor) }) })
      setRecovery(value.recovery_codes)
      setRecoveryAcknowledged(false)
      setRecoveryPrompt(false)
      setMessage('Recovery codes regenerated. Save the new codes before leaving this page.')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not regenerate recovery codes')
    }
  }

  const accountLabel = session.data?.role === 'administrator' ? 'Administrator' : session.data?.role === 'operator' ? 'Operator' : 'Viewer'
  return <section className="page narrow">
    <div className="page-heading"><div><p className="eyebrow">{accountLabel} account</p><h1>Security</h1><p className="muted">Protect the local console and keep recovery under your control.</p></div></div>
    {message && <div className="success-banner"><Check size={17} />{message}</div>}
    {error && <div className="form-error banner" role="alert">{error}</div>}
    <div className="settings-grid">
      <div className="panel">
        <div className="panel-heading"><div><h2>Profile</h2><p className="muted">Choose the name shown throughout the console.</p></div><UserRound className="muted-icon" size={19} /></div>
        <form className="settings-form" onSubmit={saveDisplayName}>
          <label>Display name<input type="text" value={displayName} onChange={(event) => setDisplayName(event.target.value)} maxLength={80} autoComplete="nickname" required /><small>Shown in the sidebar and dashboard. Your sign-in remains unchanged.</small></label>
          <button className="button primary" type="submit" disabled={displayNameBusy || !displayName.trim()}>{displayNameBusy ? 'Saving…' : 'Save display name'}</button>
        </form>
      </div>
      <div className="panel">
        <div className="panel-heading"><div><h2>Password</h2><p className="muted">Your password is protected with Argon2id.</p></div><KeyRound className="muted-icon" size={19} /></div>
        <form className="settings-form" onSubmit={change}>
          <label>Current password<input type="password" value={current} onChange={(event) => setCurrent(event.target.value)} autoComplete="current-password" required /></label>
          <label>New password<input type="password" value={next} onChange={(event) => setNext(event.target.value)} minLength={12} autoComplete="new-password" required /><small>At least 12 characters.</small></label>
          <button className="button primary" type="submit">Update password</button>
        </form>
        <button className="button secondary" type="button" onClick={() => { setError(''); setRevokePrompt(true) }}><LogOut size={16} /> Log out all sessions</button>
      </div>
      <div className="panel">
        <div className="panel-heading"><div><h2>Authenticator app</h2><p className="muted">{session.data?.totp_enabled ? 'TOTP is protecting your sign-in.' : 'Optional extra protection for sign-in.'}</p></div><ShieldCheck className={session.data?.totp_enabled ? 'green-icon' : 'muted-icon'} size={20} /></div>
        {session.data?.totp_enabled ? <div className="settings-form"><div className="status-line"><span className="pill green">Enabled</span><span className="muted">Recovery codes are single-use.</span></div><div className="heading-actions"><button className="button secondary" type="button" onClick={() => { setError(''); setRecoveryPrompt(true) }}>Regenerate recovery codes</button><button className="button secondary" type="button" onClick={() => { setError(''); setDisablePrompt(true) }}>Disable TOTP</button></div></div> : totp ? <div className="settings-form"><p>Scan this secret in your authenticator app, then enter the six-digit code.</p><code className="secret">{totp.secret}</code>{session.data?.totp_enabled && <label>Current authenticator code or recovery code<input value={currentFactor} onChange={(event) => setCurrentFactor(event.target.value)} autoComplete="one-time-code" /></label>}<label>Verification code<input inputMode="numeric" value={code} onChange={(event) => setCode(event.target.value)} placeholder="123456" /></label><button className="button primary" type="button" onClick={enableTotp}>Enable TOTP</button></div> : <div className="settings-form"><p>Enter your current password, then set up an authenticator app.</p>{session.data?.totp_enabled && <label>Current authenticator code or recovery code<input value={currentFactor} onChange={(event) => setCurrentFactor(event.target.value)} autoComplete="one-time-code" /></label>}<button className="button secondary" type="button" onClick={beginTotp}>Set up authenticator</button></div>}
      </div>
    </div>
    {recovery.length > 0 && <div className="panel recovery"><h2>Save your recovery codes</h2><p className="muted">These are shown once. Store them somewhere offline before leaving this page.</p><div className="code-grid">{recovery.map((value) => <code key={value}>{value}</code>)}</div><label className="checkbox-row"><input type="checkbox" checked={recoveryAcknowledged} onChange={(event) => setRecoveryAcknowledged(event.target.checked)} /> I saved these recovery codes in a secure place.</label><div className="heading-actions"><button className="button secondary" type="button" onClick={() => navigator.clipboard?.writeText(recovery.join('\n'))}><Copy size={16} /> Copy codes</button><button className="button primary" type="button" onClick={finishTotpSetup} disabled={recoveryBusy || !recoveryAcknowledged}>{recoveryBusy ? 'Signing out…' : 'Continue to sign in'}</button></div></div>}
    {disablePrompt && <ActionDialog title="Disable authenticator protection?" description="Enter your account password and current authenticator code (or a recovery code) to disable TOTP. Existing browser sessions will be signed out." confirmLabel="Disable TOTP" destructive valueLabel="Account password" valueType="password" valueRequired autoComplete="current-password" secondaryValueLabel="Current authenticator code or recovery code" secondaryValueRequired secondaryAutoComplete="one-time-code" onConfirm={(password, factor) => disableTotp(password, factor)} onCancel={() => setDisablePrompt(false)} error={error} />}
    {recoveryPrompt && <ActionDialog title="Regenerate recovery codes?" description="Enter your account password and current authenticator code (or a recovery code). Existing recovery codes will stop working immediately." confirmLabel="Regenerate codes" destructive valueLabel="Account password" valueType="password" valueRequired autoComplete="current-password" secondaryValueLabel="Current authenticator code or recovery code" secondaryValueRequired secondaryAutoComplete="one-time-code" onConfirm={(password, factor) => regenerateRecoveryCodes(password, factor)} onCancel={() => setRecoveryPrompt(false)} error={error} />}
    {revokePrompt && <ActionDialog title="Log out all sessions?" description="Every EdgeWatch browser session, including this one, will be signed out." confirmLabel="Log out all sessions" destructive onConfirm={() => revokeSessions()} onCancel={() => setRevokePrompt(false)} error={error} />}
  </section>
}
