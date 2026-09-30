import { FormEvent, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { ShieldCheck, UserPlus, UsersRound } from 'lucide-react'
import { APIError, deletePendingPlatformAdmin, getSession, invitePlatformAdmin, listPlatformAdmins, renewPlatformAdminInvitation, revokePlatformAdminInvitation, setPlatformAdminEnabled } from '../../api'
import type { UserSummary } from '../../api'
import { ActionDialog } from '../../components/ActionDialog'
import { ErrorNotice } from '../../components/ErrorNotice'
import { usernameProblem } from '../Users'
import { errorMessage, isChangedElsewhere, isConflict, lastSignIn, Loading, OneTimeLink } from './common'

/** The actions on a pending administrator, which has not redeemed its invitation. */
type PendingAction = 'renew' | 'revoke' | 'remove'

const pendingActions: Record<PendingAction, { button: string; title: (username: string) => string; description: string; destructive: boolean; failure: string }> = {
  renew: { button: 'Renew invitation', title: username => `Renew the invitation of ${username}?`, description: 'A new one-time activation link is created and shown once, and any earlier link stops working. The account stays pending until the link is redeemed. Confirm with your password.', destructive: false, failure: 'The invitation could not be renewed.' },
  revoke: { button: 'Revoke invitation', title: username => `Revoke the invitation of ${username}?`, description: 'Its one-time activation link stops working at once, so nobody can use it to become a platform administrator. The account stays pending. Confirm with your password.', destructive: true, failure: 'The invitation could not be revoked.' },
  remove: { button: 'Remove', title: username => `Remove ${username}?`, description: 'The pending platform administrator is removed and its activation link stops working, so its username can be invited again. Confirm with your password.', destructive: true, failure: 'The platform administrator could not be removed.' },
}

/**
 * The platform administrators: accounts without a unit that manage the units
 * and their administrators, and never see a unit's jobs, scans, hosts, or
 * incidents. An administrator invites, enables, and disables the others. For
 * one that has not redeemed its invitation yet, it renews the invitation
 * with a new link, revokes it, or removes the account; its own account is
 * changed from Security.
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
  const [pending, setPending] = useState<{ action: PendingAction; admin: UserSummary } | null>(null)
  const [pendingError, setPendingError] = useState('')
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
  async function confirmPending(secret: string) {
    if (!pending) return
    const { action, admin } = pending
    setPendingError('')
    try {
      if (action === 'renew') {
        const value = await renewPlatformAdminInvitation(admin.id, secret)
        setLink({ title: `Activation link for ${admin.username}`, path: value.activation_path, account: admin.id })
        setMessage(`A new activation link for ${admin.username} was created; any earlier link no longer works.`)
      } else {
        if (action === 'revoke') {
          await revokePlatformAdminInvitation(admin.id, secret)
          setMessage(`The invitation of ${admin.username} was revoked; its activation link no longer works.`)
        } else {
          await deletePendingPlatformAdmin(admin.id, secret)
          setMessage(`${admin.username} was removed; its username can be invited again.`)
        }
        // A link still on the page for this account no longer works either.
        setLink(current => current?.account === admin.id ? null : current)
      }
      await client.invalidateQueries({ queryKey: ['platform-admins'] })
      setPending(null)
    } catch (err) {
      if (isChangedElsewhere(err)) {
        // The account may have redeemed its link, or been removed, elsewhere:
        // reload the list, and ask again only while the account is still
        // pending.
        await client.invalidateQueries({ queryKey: ['platform-admins'] })
        const current = client.getQueryData<{ admins: UserSummary[] }>(['platform-admins'])?.admins.find(item => item.id === admin.id)
        if (!current?.pending) {
          setPending(null)
          setPendingError('')
          setMessage(`${admin.username} changed elsewhere. The latest state is loaded.`)
          return
        }
      }
      // An invitation that expired or was revoked has no link left to stop:
      // point to the actions that recover the account.
      setPendingError(err instanceof APIError && err.code === 'no_active_activation'
        ? `${admin.username} has no usable activation link left. Renew the invitation to create a new link, or remove the account.`
        : errorMessage(err, pendingActions[action].failure))
    }
  }
  return <section className="page">
    <div className="page-heading"><div><p className="eyebrow">Platform</p><h1>Platform admins</h1><p className="muted">Platform administrators create business units and manage their administrators. They never see a unit’s jobs, scans, hosts, or incidents.</p></div><UsersRound className="muted-icon" size={24} /></div>
    {message && <div className="success-banner" role="status">{message}</div>}
    {link && <OneTimeLink key={link.path} title={link.title} path={link.path} note="Shown once; it expires in 30 minutes. Send it to the new platform administrator directly." onDismiss={() => setLink(null)} />}
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
      <div className="panel"><div className="panel-heading"><div><h2>Platform administrators</h2><p className="muted">At least one enabled platform administrator is always kept. Disabling one ends its sessions. A pending one has not redeemed its invitation yet: renew the invitation for a new link, revoke it to stop the link, or remove the account to free its username.</p></div><ShieldCheck className="muted-icon" size={20} /></div>
        {admins.isLoading ? <Loading label="Loading platform administrators…" /> : admins.error || !admins.data ? <ErrorNotice message="Could not load the platform administrators." onRetry={() => admins.refetch()} /> : <div className="user-list">{admins.data.admins.map(admin => {
          const self = admin.id === session.data?.user_id
          return <div className="user-row account-row" key={admin.id} data-testid={`admin-${admin.username}`}>
            <div><strong>{admin.display_name}{self ? ' (you)' : ''}</strong><span>{admin.username}{lastSignIn(admin.last_login_at)}</span></div>
            <span className="account-badges"><span className={admin.pending ? 'pill amber' : admin.enabled ? 'pill green' : 'pill gray'}>{admin.pending ? 'Pending activation' : admin.enabled ? 'Enabled' : 'Disabled'}</span><span className={admin.totp_enabled ? 'pill green' : 'pill amber'}>{admin.totp_enabled ? 'TOTP on' : 'No TOTP'}</span></span>
            {!self && <div className="user-row-actions">{admin.pending
              ? (Object.keys(pendingActions) as PendingAction[]).map(action => <button key={action} type="button" className="button ghost" onClick={() => { setMessage(''); setPendingError(''); setPending({ action, admin }) }}>{pendingActions[action].button}</button>)
              : <button type="button" className="button ghost" onClick={() => { setMessage(''); setToggleError(''); setToggle(admin) }}>{admin.enabled ? 'Disable' : 'Enable'}</button>}</div>}
          </div>
        })}</div>}
      </div>
    </div>
    {toggle && <ActionDialog title={`${toggle.enabled ? 'Disable' : 'Enable'} ${toggle.username}?`} description={toggle.enabled ? 'The platform administrator is signed out everywhere and cannot sign in until enabled again. Confirm with your password.' : 'The platform administrator can sign in again with its password and authenticator. Confirm with your password.'} confirmLabel={toggle.enabled ? 'Disable' : 'Enable'} destructive={toggle.enabled} valueLabel="Your password" valueType="password" valueRequired autoComplete="current-password" onConfirm={confirmToggle} onCancel={() => { setToggle(null); setToggleError('') }} error={toggleError} />}
    {pending && <ActionDialog title={pendingActions[pending.action].title(pending.admin.username)} description={pendingActions[pending.action].description} confirmLabel={pendingActions[pending.action].button} destructive={pendingActions[pending.action].destructive} valueLabel="Your password" valueType="password" valueRequired autoComplete="current-password" onConfirm={confirmPending} onCancel={() => { setPending(null); setPendingError('') }} error={pendingError} />}
  </section>
}
