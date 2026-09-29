import { FormEvent, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { ShieldCheck, UserPlus, UsersRound } from 'lucide-react'
import { getSession, invitePlatformAdmin, listPlatformAdmins, revokePlatformAdminInvitation, setPlatformAdminEnabled } from '../../api'
import type { UserSummary } from '../../api'
import { ActionDialog } from '../../components/ActionDialog'
import { usernameProblem } from '../Users'
import { errorMessage, isConflict, lastSignIn, Loading, OneTimeLink } from './common'

/**
 * The platform administrators: accounts without a unit that manage the units
 * and their administrators, and never see a unit's jobs, scans, hosts, or
 * incidents. An administrator invites, enables, and disables the others, and
 * revokes the invitation of one that has not redeemed it yet; its own account
 * is changed from Security.
 */
export function PlatformAdmins() {
  const client = useQueryClient()
  const admins = useQuery({ queryKey: ['platform-admins'], queryFn: listPlatformAdmins })
  const session = useQuery({ queryKey: ['session'], queryFn: getSession })
  const [username, setUsername] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const [link, setLink] = useState<{ title: string; path: string; account: string } | null>(null)
  const [toggle, setToggle] = useState<UserSummary | null>(null)
  const [toggleError, setToggleError] = useState('')
  const [revoke, setRevoke] = useState<UserSummary | null>(null)
  const [revokeError, setRevokeError] = useState('')
  async function invite(event: FormEvent) {
    event.preventDefault()
    setError('')
    setMessage('')
    const problem = usernameProblem(username)
    if (problem) { setError(problem); return }
    setBusy(true)
    try {
      const value = await invitePlatformAdmin({ username: username.trim(), display_name: displayName.trim(), password })
      setUsername('')
      setDisplayName('')
      setPassword('')
      setLink({ title: `Activation link for ${value.user.username}`, path: value.activation_path, account: value.user.id })
      await client.invalidateQueries({ queryKey: ['platform-admins'] })
    } catch (err) {
      setError(errorMessage(err, 'The platform administrator could not be invited.'))
    } finally {
      setBusy(false)
    }
  }
  async function confirmToggle(secret: string) {
    if (!toggle) return
    setToggleError('')
    try {
      const value = await setPlatformAdminEnabled(toggle.id, !toggle.enabled, toggle.revision, secret)
      setMessage(`${value.username} ${value.enabled ? 'enabled' : 'disabled and signed out'}.`)
      await client.invalidateQueries({ queryKey: ['platform-admins'] })
      setToggle(null)
    } catch (err) {
      if (!isConflict(err)) {
        setToggleError(errorMessage(err, 'The platform administrator could not be changed.'))
        return
      }
      // The account changed elsewhere, so its revision is stale: reload the
      // list, and confirm again with the current row while the change still
      // applies.
      await client.invalidateQueries({ queryKey: ['platform-admins'] })
      const current = client.getQueryData<{ admins: UserSummary[] }>(['platform-admins'])?.admins.find(admin => admin.id === toggle.id)
      if (current && !current.pending && current.enabled === toggle.enabled) {
        setToggle(current)
        setToggleError(`${toggle.username} changed elsewhere. The latest state is loaded; confirm again to ${toggle.enabled ? 'disable' : 'enable'} it.`)
        return
      }
      setToggle(null)
      setMessage(`${toggle.username} changed elsewhere. The latest state is loaded.`)
    }
  }
  async function confirmRevoke(secret: string) {
    if (!revoke) return
    setRevokeError('')
    try {
      await revokePlatformAdminInvitation(revoke.id, secret)
      setMessage(`The invitation of ${revoke.username} was revoked; its activation link no longer works.`)
      // A link still on the page for this account no longer works either.
      setLink(current => current?.account === revoke.id ? null : current)
      await client.invalidateQueries({ queryKey: ['platform-admins'] })
      setRevoke(null)
    } catch (err) {
      setRevokeError(errorMessage(err, 'The invitation could not be revoked.'))
    }
  }
  return <section className="page">
    <div className="page-heading"><div><p className="eyebrow">Platform</p><h1>Platform admins</h1><p className="muted">Platform administrators create business units and manage their administrators. They never see a unit’s jobs, scans, hosts, or incidents.</p></div><UsersRound className="muted-icon" size={24} /></div>
    {message && <div className="success-banner" role="status">{message}</div>}
    {link && <OneTimeLink title={link.title} path={link.path} note="Shown once; it expires in 30 minutes. Send it to the new platform administrator directly." onDismiss={() => setLink(null)} />}
    <div className="settings-grid">
      <div className="panel"><div className="panel-heading"><div><h2>Invite a platform administrator</h2><p className="muted">They choose their own password, and must set up TOTP once more than one unit exists: it protects the password resets of every unit’s administrators.</p></div><UserPlus className="muted-icon" size={20} /></div>
        {error && <div className="form-error" role="alert">{error}</div>}
        <form className="settings-form" onSubmit={invite}>
          <label>Username<input value={username} onChange={event => setUsername(event.target.value)} autoComplete="off" required maxLength={80} /><small>Usernames are unique across all units and the platform.</small></label>
          <label>Display name<input value={displayName} onChange={event => setDisplayName(event.target.value)} autoComplete="off" maxLength={80} /></label>
          <label>Your password<input type="password" value={password} onChange={event => setPassword(event.target.value)} autoComplete="current-password" required /></label>
          <button className="button primary" type="submit" disabled={busy}>{busy ? 'Creating…' : 'Create activation link'}</button>
        </form>
      </div>
      <div className="panel"><div className="panel-heading"><div><h2>Platform administrators</h2><p className="muted">At least one enabled platform administrator is always kept. Disabling one ends its sessions. A pending one has not redeemed its invitation yet; revoking the invitation stops its link.</p></div><ShieldCheck className="muted-icon" size={20} /></div>
        {admins.isLoading ? <Loading label="Loading platform administrators…" /> : !admins.data ? <div className="error-card" role="alert">Could not load the platform administrators.</div> : <div className="user-list">{admins.data.admins.map(admin => {
          const self = admin.id === session.data?.user_id
          return <div className="user-row account-row" key={admin.id} data-testid={`admin-${admin.username}`}>
            <div><strong>{admin.display_name}{self ? ' (you)' : ''}</strong><span>{admin.username}{lastSignIn(admin.last_login_at)}</span></div>
            <span className="account-badges"><span className={admin.pending ? 'pill amber' : admin.enabled ? 'pill green' : 'pill gray'}>{admin.pending ? 'Pending activation' : admin.enabled ? 'Enabled' : 'Disabled'}</span><span className={admin.totp_enabled ? 'pill green' : 'pill amber'}>{admin.totp_enabled ? 'TOTP on' : 'No TOTP'}</span></span>
            {!self && <div className="user-row-actions">{admin.pending
              ? <button type="button" className="button ghost" onClick={() => { setMessage(''); setRevokeError(''); setRevoke(admin) }}>Revoke invitation</button>
              : <button type="button" className="button ghost" onClick={() => { setMessage(''); setToggleError(''); setToggle(admin) }}>{admin.enabled ? 'Disable' : 'Enable'}</button>}</div>}
          </div>
        })}</div>}
      </div>
    </div>
    {toggle && <ActionDialog title={`${toggle.enabled ? 'Disable' : 'Enable'} ${toggle.username}?`} description={toggle.enabled ? 'The platform administrator is signed out everywhere and cannot sign in until enabled again. Confirm with your password.' : 'The platform administrator can sign in again with its password and authenticator. Confirm with your password.'} confirmLabel={toggle.enabled ? 'Disable' : 'Enable'} destructive={toggle.enabled} valueLabel="Your password" valueType="password" valueRequired autoComplete="current-password" onConfirm={confirmToggle} onCancel={() => { setToggle(null); setToggleError('') }} error={toggleError} />}
    {revoke && <ActionDialog title={`Revoke the invitation of ${revoke.username}?`} description="Its one-time activation link stops working at once, so nobody can use it to become a platform administrator. The account stays pending. Confirm with your password." confirmLabel="Revoke invitation" destructive valueLabel="Your password" valueType="password" valueRequired autoComplete="current-password" onConfirm={confirmRevoke} onCancel={() => { setRevoke(null); setRevokeError('') }} error={revokeError} />}
  </section>
}
