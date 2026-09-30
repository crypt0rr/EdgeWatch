import { FormEvent, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Copy, KeyRound, ShieldCheck, UserPlus, Users as UsersIcon } from 'lucide-react'
import { APIError, createUser, getSession, issueUserActivation, listUsers, revokeUserActivation, Role, updateUser } from '../api'
import type { UserSummary } from '../api'
import { ActionDialog } from '../components/ActionDialog'
import { ErrorNotice } from '../components/ErrorNotice'

const USERNAME_MAX_BYTES = 80

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
 * its outstanding link revoked.
 */
function userActions(user: UserSummary, sessionUserID: string | undefined) {
  const linkable = user.pending || user.enabled
  return {
    toggle: !user.pending && (!user.enabled || (sessionUserID !== undefined && user.id !== sessionUserID)),
    issueLink: linkable,
    revokeLink: linkable,
  }
}

export function Users() {
  const client = useQueryClient(); const users = useQuery({ queryKey: ['users'], queryFn: listUsers }); const session = useQuery({ queryKey: ['session'], queryFn: getSession }); const [username, setUsername] = useState(''); const [displayName, setDisplayName] = useState(''); const [role, setRole] = useState<Role>('viewer'); const [password, setPassword] = useState(''); const [message, setMessage] = useState(''); const [error, setError] = useState(''); const [issued, setIssued] = useState<{ token: string; username: string; userID: string } | null>(null); const [prompt, setPrompt] = useState<{ action: 'toggle' | 'renew' | 'revoke'; userID: string; label: string } | null>(null)
  const create = useMutation({ mutationFn: () => createUser(username, displayName, role, password), onSuccess: value => { setUsername(''); setDisplayName(''); setPassword(''); setIssued({ token: value.activation_token, username: value.user.username, userID: value.user.id }); setMessage(`Created ${value.user.username}. Copy the activation token before leaving this page.`); void client.invalidateQueries({ queryKey: ['users'] }) }, onError: err => setError(err instanceof Error ? err.message : 'Could not create user') })
  async function submit(event: FormEvent) { event.preventDefault(); setMessage(''); setError(''); const problem = usernameProblem(username); if (problem) { setError(problem); return } create.mutate() }
  async function toggle(user: Awaited<ReturnType<typeof listUsers>>['users'][number]) { setPrompt({ action: 'toggle', userID: user.id, label: `${user.enabled ? 'Disable' : 'Enable'} ${user.username}` }) }
  async function renew(userID: string) { setPrompt({ action: 'renew', userID, label: 'Issue activation link' }) }
  async function revoke(userID: string) { setPrompt({ action: 'revoke', userID, label: 'Revoke activation link' }) }
  // A revoked link, and every link of a disabled account, stops working, so
  // the page stops offering the token of that account for copying.
  function dropToken(userID: string) { setIssued(current => current?.userID === userID ? null : current) }
  async function confirmAction(secret: string) { if (!prompt) return; setMessage(''); setError(''); try { if (prompt.action === 'toggle') { const user = users.data?.users.find(value => value.id === prompt.userID); if (!user) return; await updateUser(user.id, { enabled: !user.enabled, revision: user.revision, password: secret }); if (user.enabled) dropToken(user.id); setMessage(`${user.username} ${user.enabled ? 'disabled' : 'enabled'}.`) } else if (prompt.action === 'renew') { const value = await issueUserActivation(prompt.userID, secret); const user = users.data?.users.find(item => item.id === prompt.userID); setIssued({ token: value.activation_token, username: user?.username ?? 'the selected account', userID: prompt.userID }); setMessage(`New activation token generated for ${user?.username ?? 'the selected account'}. It expires in 30 minutes.`) } else { await revokeUserActivation(prompt.userID, secret); dropToken(prompt.userID); setMessage('The outstanding activation link was revoked.') } await client.invalidateQueries({ queryKey: ['users'] }); setPrompt(null) } catch (err) { if (err instanceof APIError && err.code === 'conflict') { await client.invalidateQueries({ queryKey: ['users'] }); setError('This account changed in another session. The latest revision is loaded; try again if needed.') } else setError(err instanceof Error ? err.message : 'The user action could not be completed.') } }
  return <section className="page"><div className="page-heading"><div><p className="eyebrow">Administration</p><h1>Users</h1><p className="muted">Invite operators and viewers without sharing passwords.</p></div><UsersIcon className="muted-icon" size={24} /></div>{message && <div className="success-banner" role="status">{message}</div>}{error && <div className="form-error banner" role="alert">{error}</div>}{issued && <div className="panel activation-token"><div><strong>Activation token for {issued.username}</strong><p className="muted">Confirm the username before copying this one-time token. It expires shortly and can be revoked from the account row.</p></div><code aria-label={`Activation token for ${issued.username}`}>{issued.token}</code><button type="button" className="button secondary" onClick={() => navigator.clipboard?.writeText(issued.token)}><Copy size={16} /> Copy token</button></div>}<div className="settings-grid"><div className="panel"><div className="panel-heading"><div><h2>Invite user</h2><p className="muted">The user chooses their own Argon2id password.</p></div><UserPlus className="muted-icon" size={20} /></div><form className="settings-form" onSubmit={submit}><label>Username<input value={username} onChange={event => setUsername(event.target.value)} autoComplete="off" required maxLength={80} /></label><label>Display name<input value={displayName} onChange={event => setDisplayName(event.target.value)} autoComplete="off" required maxLength={80} /></label><label>Role<select value={role} onChange={event => setRole(event.target.value as Role)}><option value="viewer">Viewer · read only</option><option value="operator">Operator · manage scans</option><option value="administrator">Administrator · full access</option></select></label><label>Administrator password<input type="password" value={password} onChange={event => setPassword(event.target.value)} autoComplete="current-password" required /><small>Confirm your password before creating the account.</small></label><button className="button primary" disabled={create.isPending} type="submit">{create.isPending ? 'Creating…' : 'Create activation link'}</button></form></div><div className="panel"><div className="panel-heading"><div><h2>Configured accounts</h2><p className="muted">Disabled users cannot sign in and lose active sessions.</p></div><ShieldCheck className="muted-icon" size={20} /></div>{users.isLoading ? <div className="loading"><span className="spinner" />Loading users…</div> : users.error || !users.data ? <ErrorNotice message="Could not load users." onRetry={() => users.refetch()} /> : users.data.users.length ? <div className="user-list">{users.data.users.map(user => { const offered = userActions(user, session.data?.user_id); return <div className="user-row" key={user.id}><div><strong>{user.display_name}</strong><span>{user.username} · {user.role}</span></div><span className={user.pending ? 'pill amber' : user.enabled ? 'pill green' : 'pill gray'}>{user.pending ? 'Pending activation' : user.enabled ? 'Enabled' : 'Disabled'}</span><div className="user-row-actions">{offered.toggle && <button type="button" className="button ghost" onClick={() => toggle(user)}>{user.enabled ? 'Disable' : 'Enable'}</button>}{offered.issueLink && <button type="button" className="button ghost" onClick={() => renew(user.id)}><KeyRound size={14} /> {user.pending ? 'Renew activation' : 'Reset activation'}</button>}{offered.revokeLink && <button type="button" className="button ghost" onClick={() => revoke(user.id)}>Revoke link</button>}</div></div> })}</div> : <div className="inline-empty">No users have been configured yet.</div>}</div></div>{prompt && <ActionDialog title={prompt.label} description="Confirm the target account before issuing or revoking an activation token. Enter your administrator password to authorize this account change." confirmLabel="Confirm" valueLabel="Administrator password" valueType="password" valueRequired autoComplete="current-password" onConfirm={confirmAction} onCancel={() => setPrompt(null)} error={error} />}</section>
}
