import { FormEvent, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Check, Copy, KeyRound, LogOut, ShieldCheck } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { api, getSession, logoutAllSessions, setCSRF } from '../api'

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
  const [recovery, setRecovery] = useState<string[]>([])

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
    if (!window.confirm('Sign out EdgeWatch on every browser, including this one?')) return
    setMessage('')
    setError('')
    try {
      await logoutAllSessions()
      setCSRF('')
      client.clear()
      navigate('/login')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not revoke sessions')
    }
  }

  async function beginTotp() {
    setError('')
    try {
      const value = await api<{ secret: string; otpauth: string }>('/auth/totp/setup', { method: 'POST', body: JSON.stringify({ password: current }) })
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
      setTotp(null)
      setCode('')
      await client.invalidateQueries({ queryKey: ['session'] })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'TOTP setup failed')
    }
  }

  async function disableTotp() {
    const password = window.prompt('Enter your administrator password to disable TOTP')
    if (!password) return
    try {
      await api('/auth/totp', { method: 'DELETE', body: JSON.stringify({ password }) })
      await client.invalidateQueries({ queryKey: ['session'] })
      setMessage('TOTP disabled.')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not disable TOTP')
    }
  }

  return <section className="page narrow">
    <div className="page-heading"><div><p className="eyebrow">Administrator</p><h1>Security</h1><p className="muted">Protect the local console and keep recovery under your control.</p></div></div>
    {message && <div className="success-banner"><Check size={17} />{message}</div>}
    {error && <div className="form-error banner" role="alert">{error}</div>}
    <div className="settings-grid">
      <div className="panel">
        <div className="panel-heading"><div><h2>Password</h2><p className="muted">Argon2id-protected administrator credentials.</p></div><KeyRound className="muted-icon" size={19} /></div>
        <form className="settings-form" onSubmit={change}>
          <label>Current password<input type="password" value={current} onChange={(event) => setCurrent(event.target.value)} autoComplete="current-password" required /></label>
          <label>New password<input type="password" value={next} onChange={(event) => setNext(event.target.value)} minLength={12} autoComplete="new-password" required /><small>At least 12 characters.</small></label>
          <button className="button primary" type="submit">Update password</button>
        </form>
        <button className="button secondary" type="button" onClick={revokeSessions}><LogOut size={16} /> Log out all sessions</button>
      </div>
      <div className="panel">
        <div className="panel-heading"><div><h2>Authenticator app</h2><p className="muted">{session.data?.totp_enabled ? 'TOTP is protecting administrator sign-in.' : 'Optional extra protection for sign-in.'}</p></div><ShieldCheck className={session.data?.totp_enabled ? 'green-icon' : 'muted-icon'} size={20} /></div>
        {session.data?.totp_enabled ? <div className="settings-form"><div className="status-line"><span className="pill green">Enabled</span><span className="muted">Recovery codes are single-use.</span></div><button className="button secondary" type="button" onClick={disableTotp}>Disable TOTP</button></div> : totp ? <div className="settings-form"><p>Scan this secret in your authenticator app, then enter the six-digit code.</p><code className="secret">{totp.secret}</code><label>Verification code<input inputMode="numeric" value={code} onChange={(event) => setCode(event.target.value)} placeholder="123456" /></label><button className="button primary" type="button" onClick={enableTotp}>Enable TOTP</button></div> : <div className="settings-form"><p>Enter your current password, then set up an authenticator app.</p><button className="button secondary" type="button" onClick={beginTotp}>Set up authenticator</button></div>}
      </div>
    </div>
    {recovery.length > 0 && <div className="panel recovery"><h2>Save your recovery codes</h2><p className="muted">These are shown once. Store them somewhere offline before leaving this page.</p><div className="code-grid">{recovery.map((value) => <code key={value}>{value}</code>)}</div><button className="button secondary" type="button" onClick={() => navigator.clipboard?.writeText(recovery.join('\n'))}><Copy size={16} /> Copy codes</button></div>}
  </section>
}
