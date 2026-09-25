import { FormEvent, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { ShieldCheck, UserPlus, UsersRound } from 'lucide-react'
import { getSession, invitePlatformAdmin, listPlatformAdmins } from '../../api'
import { formatDateTime } from '../../format'
import { usernameProblem } from '../Users'
import { errorMessage, Loading, OneTimeLink } from './common'

/** Main administrators: platform accounts with no unit and no access to scan data. */
export function PlatformAdmins() {
  const client = useQueryClient()
  const admins = useQuery({ queryKey: ['platform-admins'], queryFn: listPlatformAdmins })
  const session = useQuery({ queryKey: ['session'], queryFn: getSession })
  const [username, setUsername] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [link, setLink] = useState<{ title: string; path: string } | null>(null)
  async function invite(event: FormEvent) {
    event.preventDefault()
    setError('')
    const problem = usernameProblem(username)
    if (problem) { setError(problem); return }
    setBusy(true)
    try {
      const value = await invitePlatformAdmin({ username: username.trim(), display_name: displayName.trim(), password })
      setUsername('')
      setDisplayName('')
      setPassword('')
      setLink({ title: `Activation link for ${value.user.username}`, path: value.activation_path })
      await client.invalidateQueries({ queryKey: ['platform-admins'] })
    } catch (err) {
      setError(errorMessage(err, 'The main administrator could not be invited.'))
    } finally {
      setBusy(false)
    }
  }
  return <section className="page">
    <div className="page-heading"><div><p className="eyebrow">Platform</p><h1>Platform admins</h1><p className="muted">Main administrators create business units and manage their accounts. They never see jobs, scans, hosts, or incidents.</p></div><UsersRound className="muted-icon" size={24} /></div>
    {link && <OneTimeLink title={link.title} path={link.path} note="Shown once; it expires in 30 minutes. Send it to the new main administrator directly." onDismiss={() => setLink(null)} />}
    <div className="settings-grid">
      <div className="panel"><div className="panel-heading"><div><h2>Invite a main administrator</h2><p className="muted">They choose their own password. Ask them to enable TOTP right away: it protects the reset route into every unit.</p></div><UserPlus className="muted-icon" size={20} /></div>
        {error && <div className="form-error" role="alert">{error}</div>}
        <form className="settings-form" onSubmit={invite}>
          <label>Username<input value={username} onChange={event => setUsername(event.target.value)} autoComplete="off" required maxLength={80} /></label>
          <label>Display name<input value={displayName} onChange={event => setDisplayName(event.target.value)} autoComplete="off" required maxLength={80} /></label>
          <label>Your password<input type="password" value={password} onChange={event => setPassword(event.target.value)} autoComplete="current-password" required /></label>
          <button className="button primary" type="submit" disabled={busy}>{busy ? 'Creating…' : 'Create activation link'}</button>
        </form>
      </div>
      <div className="panel"><div className="panel-heading"><div><h2>Main administrators</h2><p className="muted">At least one enabled main administrator is always kept.</p></div><ShieldCheck className="muted-icon" size={20} /></div>
        {admins.isLoading ? <Loading label="Loading main administrators…" /> : !admins.data ? <div className="error-card" role="alert">Could not load main administrators.</div> : <div className="user-list">{admins.data.admins.map(admin => <div className="user-row" key={admin.id}>
          <div><strong>{admin.display_name}{admin.id === session.data?.user_id ? ' (you)' : ''}</strong><span>{admin.username}{admin.last_login_at ? ` · last sign-in ${formatDateTime(admin.last_login_at)}` : ''}</span></div>
          <span className={admin.pending ? 'pill amber' : admin.enabled ? 'pill green' : 'pill gray'}>{admin.pending ? 'Pending activation' : admin.enabled ? 'Enabled' : 'Disabled'}</span>
          <span className={admin.totp_enabled ? 'pill green' : 'pill amber'}>{admin.totp_enabled ? 'TOTP on' : 'No TOTP'}</span>
        </div>)}</div>}
      </div>
    </div>
  </section>
}
