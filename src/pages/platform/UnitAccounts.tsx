import { FormEvent, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, KeyRound, ShieldCheck, UserPlus } from 'lucide-react'
import { inviteUnitAccount, listUnitAccounts, resetUnitAccountPassword, revokeUnitAccountSessions, updateUnitAccount } from '../../api'
import type { BusinessUnitDetail, UnitAccount, UnitRole } from '../../api'
import { ActionDialog } from '../../components/ActionDialog'
import { formatDateTime } from '../../format'
import { usernameProblem } from '../Users'
import { errorMessage, isConflict, Loading, OneTimeLink, unitRoleLabels } from './common'

type Prompt =
  | { kind: 'role'; account: UnitAccount; role: UnitRole }
  | { kind: 'toggle' | 'sessions' | 'reset'; account: UnitAccount }

type LinkNotice = { title: string; path: string; note: string; warning?: string }

export const IMPERSONATION_WARNING = 'You will be able to sign in as this user with this link.'

/**
 * Account management for one unit, as seen by a main administrator. Password
 * resets are offered only on unit administrator rows: the platform can recover
 * a locked-out unit, while operators and viewers are reset inside their unit.
 */
export function UnitAccounts({ unit }: { unit: BusinessUnitDetail }) {
  const client = useQueryClient()
  const accounts = useQuery({ queryKey: ['platform-unit-accounts', unit.id], queryFn: () => listUnitAccounts(unit.id) })
  const [username, setUsername] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [role, setRole] = useState<UnitRole>('administrator')
  const [password, setPassword] = useState('')
  const [inviteBusy, setInviteBusy] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const [link, setLink] = useState<LinkNotice | null>(null)
  const [prompt, setPrompt] = useState<Prompt | null>(null)
  const [promptError, setPromptError] = useState('')
  const active = unit.status === 'active'

  async function refresh() {
    await client.invalidateQueries({ queryKey: ['platform-unit-accounts', unit.id] })
    await client.invalidateQueries({ queryKey: ['platform-unit', unit.id] })
    await client.invalidateQueries({ queryKey: ['platform-units'] })
  }

  async function invite(event: FormEvent) {
    event.preventDefault()
    setMessage('')
    setError('')
    const problem = usernameProblem(username)
    if (problem) { setError(problem); return }
    setInviteBusy(true)
    try {
      const value = await inviteUnitAccount(unit.id, { username: username.trim(), display_name: displayName.trim(), role, password })
      setUsername('')
      setDisplayName('')
      setPassword('')
      setLink({ title: `Activation link for ${value.user.username}`, path: value.activation_path, note: `Shown once; it expires in 30 minutes. Send it to the person directly. Whoever opens it chooses the password, so this invitation is recorded in ${unit.name}’s audit log.` })
      await refresh()
    } catch (err) {
      setError(errorMessage(err, 'The account could not be invited.'))
    } finally {
      setInviteBusy(false)
    }
  }

  function ask(next: Prompt) {
    setPromptError('')
    setMessage('')
    setPrompt(next)
  }

  async function confirm(secret: string) {
    if (!prompt) return
    setPromptError('')
    const { account } = prompt
    try {
      if (prompt.kind === 'role') {
        await updateUnitAccount(unit.id, account.id, { role: prompt.role, revision: account.revision, password: secret })
        setMessage(`${account.username} is now ${unitRoleLabels[prompt.role].toLowerCase()}.`)
      } else if (prompt.kind === 'toggle') {
        await updateUnitAccount(unit.id, account.id, { enabled: !account.enabled, revision: account.revision, password: secret })
        setMessage(`${account.username} ${account.enabled ? 'disabled and signed out' : 'enabled'}.`)
      } else if (prompt.kind === 'sessions') {
        await revokeUnitAccountSessions(unit.id, account.id, secret)
        setMessage(`${account.username} was signed out of every session.`)
      } else {
        const value = await resetUnitAccountPassword(unit.id, account.id, secret)
        setLink({
          title: `Password reset link for ${account.username}`,
          path: value.activation_path,
          note: `Shown once; it expires ${formatDateTime(value.expires_at)}. The reset is recorded in ${unit.name}’s audit log, which its administrators can read.`,
          warning: value.target_totp_enabled ? undefined : IMPERSONATION_WARNING,
        })
      }
      await refresh()
      setPrompt(null)
    } catch (err) {
      if (isConflict(err)) await refresh()
      setPromptError(isConflict(err) ? 'This account changed in another session. The latest version is loaded; try again if needed.' : errorMessage(err, 'The account change could not be completed.'))
    }
  }

  return <div className="unit-accounts">
    {message && <div className="success-banner" role="status">{message}</div>}
    {link && <OneTimeLink {...link} onDismiss={() => setLink(null)} />}
    <div className="settings-grid">
      <div className="panel"><div className="panel-heading"><div><h2>Invite an account</h2><p className="muted">The person chooses their own password from a one-time activation link.</p></div><UserPlus className="muted-icon" size={20} /></div>
        {error && <div className="form-error" role="alert">{error}</div>}
        {!active && <p className="notice">Enable the unit before inviting accounts.</p>}
        <form className="settings-form" onSubmit={invite}>
          <label>Username<input value={username} onChange={event => setUsername(event.target.value)} autoComplete="off" required maxLength={80} disabled={!active} /><small>Usernames are unique across all units.</small></label>
          <label>Display name<input value={displayName} onChange={event => setDisplayName(event.target.value)} autoComplete="off" required maxLength={80} disabled={!active} /></label>
          <label>Role<select value={role} onChange={event => setRole(event.target.value as UnitRole)} disabled={!active}><option value="administrator">Administrator · manages the unit</option><option value="operator">Operator · manages scans</option><option value="viewer">Viewer · read only</option></select></label>
          <label>Your password<input type="password" value={password} onChange={event => setPassword(event.target.value)} autoComplete="current-password" required disabled={!active} /></label>
          <button className="button primary" type="submit" disabled={!active || inviteBusy}>{inviteBusy ? 'Creating…' : 'Create activation link'}</button>
        </form>
      </div>
      <div className="panel"><div className="panel-heading"><div><h2>Accounts in {unit.name}</h2><p className="muted">You can reset passwords only for unit administrators, to recover a unit that is locked out. The unit’s administrators reset operators and viewers.</p></div><ShieldCheck className="muted-icon" size={20} /></div>
        {accounts.isLoading ? <Loading label="Loading accounts…" /> : !accounts.data ? <div className="error-card" role="alert">Could not load accounts.</div> : accounts.data.accounts.length ? <div className="user-list">{accounts.data.accounts.map(account => <AccountRow key={account.id} account={account} onAction={ask} />)}</div> : <div className="inline-empty">No accounts yet. Invite the unit’s first administrator.</div>}
      </div>
    </div>
    {prompt && <AccountDialog prompt={prompt} unitName={unit.name} error={promptError} onConfirm={confirm} onCancel={() => { setPrompt(null); setPromptError('') }} />}
  </div>
}

function AccountRow({ account, onAction }: { account: UnitAccount; onAction: (prompt: Prompt) => void }) {
  const status = account.pending ? ['Pending activation', 'amber'] : account.enabled ? ['Enabled', 'green'] : ['Disabled', 'gray']
  return <div className="user-row account-row" data-testid={`account-${account.username}`}>
    <div><strong>{account.display_name}</strong><span>{account.username} · {unitRoleLabels[account.role]}{account.last_login_at ? ` · last sign-in ${formatDateTime(account.last_login_at)}` : ''}</span></div>
    <span className="account-badges"><span className={`pill ${status[1]}`}>{status[0]}</span><span className={account.totp_enabled ? 'pill green' : 'pill amber'}>{account.totp_enabled ? 'TOTP on' : 'No TOTP'}</span></span>
    <div className="user-row-actions">
      <label className="role-picker"><span className="sr-only">Role for {account.username}</span><select value={account.role} disabled={account.pending} onChange={event => onAction({ kind: 'role', account, role: event.target.value as UnitRole })}><option value="administrator">Administrator</option><option value="operator">Operator</option><option value="viewer">Viewer</option></select></label>
      {!account.pending && <button type="button" className="button ghost" onClick={() => onAction({ kind: 'toggle', account })}>{account.enabled ? 'Disable' : 'Enable'}</button>}
      {!account.pending && <button type="button" className="button ghost" onClick={() => onAction({ kind: 'sessions', account })}>Revoke sessions</button>}
      {account.role === 'administrator' && !account.pending && <button type="button" className="button ghost" onClick={() => onAction({ kind: 'reset', account })}><KeyRound size={14} /> Reset password</button>}
    </div>
  </div>
}

function AccountDialog({ prompt, unitName, error, onConfirm, onCancel }: { prompt: Prompt; unitName: string; error: string; onConfirm: (password: string) => Promise<void>; onCancel: () => void }) {
  const { account } = prompt
  const common = { valueLabel: 'Your password', valueType: 'password' as const, valueRequired: true, autoComplete: 'current-password', onConfirm, onCancel, error }
  if (prompt.kind === 'role') return <ActionDialog {...common} title={`Change ${account.username} to ${unitRoleLabels[prompt.role].toLowerCase()}?`} description="The new role applies from the account’s next request. A unit always keeps at least one enabled administrator." confirmLabel="Change role" />
  if (prompt.kind === 'toggle') return <ActionDialog {...common} title={`${account.enabled ? 'Disable' : 'Enable'} ${account.username}?`} description={account.enabled ? 'The account is signed out everywhere and cannot sign in until it is enabled again.' : 'The account can sign in again with its existing password and TOTP.'} confirmLabel={account.enabled ? 'Disable account' : 'Enable account'} destructive={account.enabled} />
  if (prompt.kind === 'sessions') return <ActionDialog {...common} title={`Revoke all sessions for ${account.username}?`} description="The account is signed out on every device. Its password and TOTP do not change." confirmLabel="Revoke sessions" destructive />
  return <ActionDialog {...common} title={`Reset password for ${account.username}?`} description={`EdgeWatch creates a one-time link that lets its holder choose a new password for this ${unitName} administrator. You see it once, it expires in 30 minutes, and ${unitName}’s administrators see the reset in their audit log.`} confirmLabel="Create reset link" destructive={!account.totp_enabled}>
    {account.totp_enabled
      ? <div className="notice"><ShieldCheck size={14} /><span>{account.username} has TOTP. The link alone does not sign anyone in; the person also needs their authenticator.</span></div>
      : <div className="notice warning" role="alert"><AlertTriangle size={14} /><span><strong>{IMPERSONATION_WARNING}</strong> {account.username} has no TOTP, so whoever holds the link controls the account and can see {unitName}’s data.</span></div>}
  </ActionDialog>
}
