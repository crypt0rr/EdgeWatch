import { FormEvent, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { KeyRound, LogOut, ShieldCheck, UserPlus, Users as UsersIcon } from 'lucide-react'
import { APIError, createUser, getSession, issueUserActivation, issueUserPasswordReset, listUsers, revokeUserActivation, revokeUserSessions, Role, updateUser } from '../api'
import type { UserSummary } from '../api'
import { ActionDialog } from '../components/ActionDialog'
import { ErrorNotice } from '../components/ErrorNotice'
import { OneTimeLink } from '../components/OneTimeLink'
import { useServerDraft, type ServerDraftSnapshot } from '../hooks/useServerDraft'

const USERNAME_MAX_BYTES = 80
type UserEditFields = { displayName: string; role: Role }
type UserEditTarget = { userID: string; username: string; pending: boolean }

// Mirrors the server's username rule so an invalid name is explained before
// the request. The limit counts UTF-8 bytes, so the input's maxLength (which
// counts UTF-16 code units) alone cannot enforce it.
export function usernameProblem(value: string) {
  const username = value.trim()
  if (new TextEncoder().encode(username).length > USERNAME_MAX_BYTES) return `Usernames can use at most ${USERNAME_MAX_BYTES} bytes; accented and non-Latin characters use 2 to 4 bytes each.`
  if (/[\p{Cc}/\\:]/u.test(username)) return 'Usernames cannot contain control characters, "/", "\\", or ":".'
  return ''
}

/**
 * The actions that an account row offers, which are those the server allows.
 * An administrator cannot disable its own account, and while the signed-in
 * account is not known yet no account is offered for disabling. A disabled
 * account receives no activation or password-reset link until it is enabled
 * again, and disabling it revoked its links, so it has none to revoke. Any
 * other account can get a new link, which replaces its older ones, and have
 * an active link revoked when one is reported by the server. Another enabled
 * account that has signed up can have its sessions revoked; a pending or
 * disabled account has none, and the administrator ends its own from the
 * Security page.
 */
function userActions(user: UserSummary, sessionUserID: string | undefined) {
  const linkable = user.pending || user.enabled
  const other = sessionUserID !== undefined && user.id !== sessionUserID
  return {
    toggle: !user.pending && (!user.enabled || other),
    revokeSessions: !user.pending && user.enabled && other,
    issueLink: linkable,
    revokeLink: linkable && user.has_active_link === true,
  }
}

export function Users() {
  type Prompt = { action: 'toggle' | 'renew' | 'revoke' | 'sessions' | 'edit'; userID: string; username: string; label: string; targetEnabled?: boolean; revision?: number; linkKind?: 'activation' | 'password-reset' }
  const client = useQueryClient(); const users = useQuery({ queryKey: ['users'], queryFn: listUsers }); const session = useQuery({ queryKey: ['session'], queryFn: getSession }); const [username, setUsername] = useState(''); const [displayName, setDisplayName] = useState(''); const [role, setRole] = useState<Role>('viewer'); const [password, setPassword] = useState(''); const [message, setMessage] = useState(''); const [error, setError] = useState(''); const [issued, setIssued] = useState<{ path: string; username: string; userID: string; kind: 'activation' | 'password-reset' } | null>(null); const [prompt, setPrompt] = useState<Prompt | null>(null); const [editTarget, setEditTarget] = useState<UserEditTarget | null>(null); const [editSnapshot, setEditSnapshot] = useState<ServerDraftSnapshot<UserEditFields, number> | null>(null)
  const editingUser = editTarget ? users.data?.users.find(value => value.id === editTarget.userID) : undefined
  const editServer: UserEditFields = { displayName: editingUser?.display_name ?? editSnapshot?.value.displayName ?? '', role: editingUser?.role ?? editSnapshot?.value.role ?? 'viewer' }
  const editRevision = editingUser?.revision ?? editSnapshot?.baseRevision ?? 0
  const editState = useServerDraft<UserEditFields, UserEditFields, number>(editServer, editRevision, {
    controlled: { snapshot: editSnapshot, onChange: setEditSnapshot },
  })
  const editRemoved = !!editTarget && !!users.data && !users.data.users.some(value => value.id === editTarget.userID)
  const editDraft = editTarget ? {
    ...editTarget,
    ...editState.draft,
    originalDisplayName: editServer.displayName,
    originalRole: editServer.role,
    revision: editState.baseRevision,
  } : null
  const create = useMutation({ mutationFn: () => createUser(username, displayName, role, password), onSuccess: value => { setUsername(''); setDisplayName(''); setPassword(''); setIssued({ path: value.activation_path, username: value.user.username, userID: value.user.id, kind: 'activation' }); setMessage(`Created ${value.user.username}. Share the one-time activation link before leaving this page.`); void client.invalidateQueries({ queryKey: ['users'] }) }, onError: err => setError(err instanceof Error ? err.message : 'Could not create user') })
  async function submit(event: FormEvent) { event.preventDefault(); setMessage(''); setError(''); const problem = usernameProblem(username); if (problem) { setError(problem); return } create.mutate() }
  type Account = Awaited<ReturnType<typeof listUsers>>['users'][number]
  function openPrompt(action: 'toggle' | 'renew' | 'revoke' | 'sessions' | 'edit', user: Account, label: string) { setError(''); setMessage(''); setPrompt({ action, userID: user.id, username: user.username, label }) }
  function toggle(user: Account) {
    setError('')
    setMessage('')
    setPrompt({ action: 'toggle', userID: user.id, username: user.username, label: `${user.enabled ? 'Disable' : 'Enable'} ${user.username}`, targetEnabled: !user.enabled, revision: user.revision })
  }
  function renew(user: Account) {
    setError('')
    setMessage('')
    setPrompt({ action: 'renew', userID: user.id, username: user.username, label: user.pending ? `Renew activation link for ${user.username}` : `Create password reset link for ${user.username}`, linkKind: user.pending ? 'activation' : 'password-reset' })
  }
  function revoke(user: Account) { openPrompt('revoke', user, `Revoke ${user.pending ? 'activation' : 'password reset'} link for ${user.username}`) }
  function revokeSessions(user: Account) { openPrompt('sessions', user, `Revoke all sessions of ${user.username}?`) }
  function edit(user: Account) {
    setError('')
    setMessage('')
    setEditTarget({ userID: user.id, username: user.username, pending: user.pending })
    setEditSnapshot({ value: { displayName: user.display_name, role: user.role }, baseRevision: user.revision })
    openPrompt('edit', user, `Edit account for ${user.username}`)
  }
  // Revocation, disablement, and role changes invalidate outstanding
  // one-time links, so the page stops offering the affected link for copying.
  function dropToken(userID: string) { setIssued(current => current?.userID === userID ? null : current) }
  function discardRemovedEditDraft() {
    setPrompt(null)
    setEditTarget(null)
    setEditSnapshot(null)
    setError('')
    setMessage('Removed account draft discarded.')
  }
  function reviewRemovedEditDraft() {
    if (!editTarget) return
    setError('')
    setPrompt({ action: 'edit', userID: editTarget.userID, username: editTarget.username, label: `Edit account for ${editTarget.username}` })
  }
  async function confirmAction(secret: string) {
    if (!prompt) return
    if (prompt.action === 'edit' && editRemoved) {
      discardRemovedEditDraft()
      return
    }
    setMessage('')
    setError('')
    try {
      if (prompt.action === 'toggle') {
        const targetEnabled = prompt.targetEnabled
        const user = users.data?.users.find(value => value.id === prompt.userID)
        if (targetEnabled === undefined || prompt.revision === undefined) return
        if (!user) {
          setPrompt(null)
          setMessage(`${prompt.username} was removed elsewhere. The latest account list is loaded.`)
          return
        }
        if (user.enabled === targetEnabled) {
          if (!targetEnabled) dropToken(user.id)
          setPrompt(null)
          setMessage(`${prompt.username} was already ${targetEnabled ? 'enabled' : 'disabled'} elsewhere. The latest state is loaded.`)
          return
        }
        await updateUser(user.id, { enabled: targetEnabled, revision: prompt.revision, password: secret })
        if (!targetEnabled) dropToken(user.id)
        setMessage(`${prompt.username} ${targetEnabled ? 'enabled' : 'disabled'}.`)
      } else if (prompt.action === 'renew') {
        const value = prompt.linkKind === 'password-reset'
          ? await issueUserPasswordReset(prompt.userID, secret)
          : await issueUserActivation(prompt.userID, secret)
        setIssued({ path: value.activation_path, username: prompt.username, userID: prompt.userID, kind: prompt.linkKind ?? 'activation' })
        setMessage(`New link generated for ${prompt.username}. It expires in 30 minutes.`)
      } else if (prompt.action === 'revoke') {
        await revokeUserActivation(prompt.userID, secret)
        dropToken(prompt.userID)
        setMessage(`The link for ${prompt.username} was revoked.`)
      } else if (prompt.action === 'sessions') {
        await revokeUserSessions(prompt.userID, secret)
        setMessage(`${prompt.username} was signed out of every session.`)
      } else {
        const draft = editDraft
        if (!draft || draft.userID !== prompt.userID) return
        if (draft.displayName.trim() === draft.originalDisplayName && draft.role === draft.originalRole) {
          setMessage(`${draft.username} has no changes.`)
        } else {
          await updateUser(draft.userID, { display_name: draft.displayName, role: draft.role, revision: draft.revision, password: secret })
          if (draft.role !== draft.originalRole) {
            dropToken(draft.userID)
            const linkType = draft.pending ? 'activation' : 'password reset'
            setMessage(`Updated ${draft.username}. Any outstanding ${linkType} link is now invalid${draft.pending ? '; renew it to issue another' : ''}.`)
          } else {
            setMessage(`Updated ${draft.username}.`)
          }
        }
        setEditTarget(null)
        setEditSnapshot(null)
      }
      setPrompt(null)
      await client.invalidateQueries({ queryKey: ['users'] })
    } catch (err) {
      if (err instanceof APIError && err.code === 'conflict') {
        if (prompt.action === 'edit') {
          try {
            const refreshed = await listUsers()
            client.setQueryData(['users'], refreshed)
            if (!refreshed.users.some(value => value.id === prompt.userID)) {
              setError('This account was removed elsewhere. Your draft is still here, but it cannot be saved. Choose Discard draft to remove it.')
            } else {
              setError('This account changed in another session. Your edits are kept on their original revision; keep your edits or load the latest account.')
            }
          } catch {
            setError('This account changed in another session, and the latest details could not be loaded. Refresh before saving again.')
          }
        } else if (prompt.action === 'toggle') {
          try {
            const refreshed = await listUsers()
            client.setQueryData(['users'], refreshed)
            const latest = refreshed.users.find(value => value.id === prompt.userID)
            setPrompt(null)
            if (!latest) {
              setMessage(`${prompt.username} was removed elsewhere. The latest account list is loaded.`)
            } else if (latest.enabled === prompt.targetEnabled) {
              if (!latest.enabled) dropToken(latest.id)
              setMessage(`${prompt.username} was already ${latest.enabled ? 'enabled' : 'disabled'} elsewhere. The latest state is loaded.`)
            } else {
              setError(`This account changed in another session. The latest state is loaded; review it and reopen ${prompt.targetEnabled ? 'Enable' : 'Disable'} ${prompt.username}.`)
            }
          } catch {
            setPrompt(null)
            setError(`This account changed in another session, and its latest state could not be loaded. Refresh before reopening ${prompt.targetEnabled ? 'Enable' : 'Disable'} ${prompt.username}.`)
          }
        } else {
          await client.invalidateQueries({ queryKey: ['users'] })
          setError('This account changed in another session. The latest revision is loaded; try again if needed.')
        }
      } else if (err instanceof APIError && err.code === 'no_active_activation' && prompt.action === 'revoke') {
        setPrompt(null)
        dropToken(prompt.userID)
        await client.invalidateQueries({ queryKey: ['users'] })
        setMessage(`There was no outstanding link for ${prompt.username}.`)
      } else {
        setError(err instanceof Error ? err.message : 'The user action could not be completed.')
      }
    }
  }
  const roleChangeNeedsPassword = prompt?.action === 'edit' && editDraft?.role !== editServer.role
  const promptDescription = prompt?.action === 'edit'
    ? editRemoved
      ? `This account was removed elsewhere. Your draft is retained here, but it can no longer be saved. Choose Discard draft to remove it.`
      : `Review the display name and role for ${prompt.username}. Changing this account’s role requires your administrator password.${roleChangeNeedsPassword ? ` It also revokes any outstanding ${editDraft?.pending ? 'activation' : 'password reset'} link.` : ''}`
    : prompt?.action === 'toggle'
      ? `Confirm the account change for ${prompt.username}. Enter your administrator password to authorize it.`
      : prompt?.action === 'renew'
        ? `Generate a one-time activation or password reset link for ${prompt.username}. The link expires in 30 minutes.`
        : prompt?.action === 'sessions'
          ? `${prompt.username} is signed out on every device. Its password, authenticator, and links do not change. Enter your administrator password to authorize it.`
          : `Revoke the outstanding activation or password reset link for ${prompt?.username ?? 'this account'}. Enter your administrator password to authorize the change.`
  function cancelPrompt() {
    const keepingRemovedDraft = editRemoved && prompt?.action === 'edit'
    setPrompt(null)
    setError('')
    if (!keepingRemovedDraft) {
      setEditTarget(null)
      setEditSnapshot(null)
    }
  }
  return <section className="page">
    <div className="page-heading"><div><p className="eyebrow">Administration</p><h1>Users</h1><p className="muted">Invite operators and viewers without sharing passwords.</p></div><UsersIcon className="muted-icon" size={24} /></div>
    {message && <div className="success-banner" role="status">{message}</div>}
    {error && <div className="form-error banner" role="alert">{error}</div>}
    {editRemoved && !prompt && <div className="notice warning" role="status"><span>This account was removed elsewhere. Your draft is kept on this page, but it cannot be saved. Review it or choose Discard draft to remove it.</span><button type="button" className="text-button" onClick={reviewRemovedEditDraft}>Review draft</button><button type="button" className="text-button" onClick={discardRemovedEditDraft}>Discard draft</button></div>}
    <div className="settings-grid">
      <div className="panel">
        <div className="panel-heading"><div><h2>Invite user</h2><p className="muted">The user chooses their own Argon2id password.</p></div><UserPlus className="muted-icon" size={20} /></div>
        <form className="settings-form" onSubmit={submit}>
          <label>Username<input value={username} onChange={event => setUsername(event.target.value)} autoComplete="off" required maxLength={80} /></label>
          <label>Display name<input value={displayName} onChange={event => setDisplayName(event.target.value)} autoComplete="off" required maxLength={80} /></label>
          <label>Role<select value={role} onChange={event => setRole(event.target.value as Role)}><option value="viewer">Viewer · read only</option><option value="operator">Operator · manage scans</option><option value="administrator">Administrator · full access</option></select></label>
          <label>Administrator password<input type="password" value={password} onChange={event => setPassword(event.target.value)} autoComplete="current-password" required /><small>Confirm your password before creating the account.</small></label>
          <button className="button primary" disabled={create.isPending} type="submit">{create.isPending ? 'Creating…' : 'Create activation link'}</button>
        </form>
      </div>
      <div className="panel">
        <div className="panel-heading"><div><h2>Configured accounts</h2><p className="muted">Disabled users cannot sign in and lose active sessions.</p></div><ShieldCheck className="muted-icon" size={20} /></div>
        {users.isLoading ? <div className="loading"><span className="spinner" />Loading users…</div> : users.error || !users.data ? <ErrorNotice message="Could not load users." onRetry={() => users.refetch()} /> : users.data.users.length ? <div className="user-list">{users.data.users.map(user => {
          const offered = userActions(user, session.data?.user_id)
          const userLink = issued?.userID === user.id ? issued : null
          return <div className="user-row" key={user.id}>
            <div><strong>{user.display_name}</strong><span>{user.username} · {user.role}</span></div>
            <span className={user.pending ? 'pill amber' : user.enabled ? 'pill green' : 'pill gray'}>{user.pending ? 'Pending activation' : user.enabled ? 'Enabled' : 'Disabled'}</span>
            <div className="user-row-actions">
              {offered.toggle && <button type="button" className={`button ghost${user.enabled ? ' danger-text' : ''}`} onClick={() => toggle(user)}>{user.enabled ? 'Disable' : 'Enable'}</button>}
              {offered.revokeSessions && <button type="button" className="button ghost danger-text" onClick={() => revokeSessions(user)}><LogOut size={14} /> Revoke sessions</button>}
              {offered.issueLink && <button type="button" className="button ghost" onClick={() => renew(user)}><KeyRound size={14} /> {user.pending ? 'Renew activation link' : 'Create password reset link'}</button>}
              {offered.revokeLink && <button type="button" className="button ghost danger-text" onClick={() => revoke(user)}>{user.pending ? 'Revoke activation link' : 'Revoke password reset link'}</button>}
              <button type="button" className="button ghost" onClick={() => edit(user)}>Edit account</button>
            </div>
            {userLink && <OneTimeLink key={userLink.path} title={userLink.kind === 'activation' ? `Activation link for ${userLink.username}` : `Password reset link for ${userLink.username}`} path={userLink.path} note="This one-time link expires in 30 minutes. Send it to the user; they choose their own password." focusOnMount onDismiss={() => setIssued(null)} />}
            {!userLink && (user.pending || user.enabled) && !user.has_active_link && <small className="user-link-status">No outstanding activation or password reset link.</small>}
          </div>
        })}</div> : <div className="inline-empty">No users have been configured yet.</div>}
      </div>
    </div>
    {prompt && <ActionDialog title={prompt.label} description={promptDescription} confirmLabel={prompt.action === 'edit' ? editRemoved ? 'Discard draft' : 'Save changes' : prompt.action === 'sessions' ? 'Revoke sessions' : 'Confirm'} valueLabel={prompt.action === 'edit' ? !editRemoved && roleChangeNeedsPassword ? 'Administrator password' : undefined : 'Administrator password'} valueType="password" valueRequired={prompt.action !== 'edit' || (!editRemoved && !!roleChangeNeedsPassword)} autoComplete="current-password" destructive={editRemoved || prompt.action === 'revoke' || prompt.action === 'sessions' || prompt.label.startsWith('Disable ')} restoreFocus={prompt.action !== 'renew'} onConfirm={confirmAction} onCancel={cancelPrompt} error={error}>{prompt.action === 'edit' && editDraft && <><label>Display name<input value={editDraft.displayName} maxLength={80} disabled={editRemoved} onChange={event => editState.setDraft(value => ({ ...value, displayName: event.target.value }))} /></label><label>Role<select value={editDraft.role} disabled={editRemoved} onChange={event => editState.setDraft(value => ({ ...value, role: event.target.value as Role }))}><option value="viewer" disabled={editDraft.userID === session.data?.user_id}>Viewer · read only</option><option value="operator" disabled={editDraft.userID === session.data?.user_id}>Operator · manage scans</option><option value="administrator">Administrator · full access</option></select>{editDraft.userID === session.data?.user_id && <small>You cannot change your own administrator role.</small>}</label>{editState.remoteChanged && !editRemoved && <div className="notice warning" role="status"><span>This account changed elsewhere. Your edits still use revision {editState.baseRevision}; the latest account is revision {editRevision}.</span><button type="button" className="text-button" onClick={() => { editState.rebase(editRevision); setError('Your account edits now use the latest revision. Review the values and save again.') }}>Keep my edits</button><button type="button" className="text-button" onClick={() => { editState.adopt(); setError('Latest account loaded.') }}>Load theirs</button></div>}</>}</ActionDialog>}
  </section>
}
