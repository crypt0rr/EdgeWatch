import { FormEvent, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, KeyRound, LogOut, ShieldCheck, UserPlus } from 'lucide-react'
import { APIError, inviteUnitAdmin, listUnitAccounts, resetUnitAdminPassword, revokeUnitAccountSessions } from '../../api'
import type { BusinessUnit, UnitAccount } from '../../api'
import { ActionDialog } from '../../components/ActionDialog'
import { ErrorNotice } from '../../components/ErrorNotice'
import { formatDateTime } from '../../format'
import { usernameProblem } from '../Users'
import { errorMessage, isChangedElsewhere, lastSignIn, Loading, OneTimeLink, unitRoleLabels } from './common'

type Prompt = { kind: 'sessions' | 'reset'; account: UnitAccount }

type LinkNotice = { title: string; path: string; note: string; warning?: string }

/** The warning for a reset link of an account without an authenticator. */
export const IMPERSONATION_WARNING = 'You will be able to sign in as this user with this link.'

/**
 * The accounts of one unit, as a platform administrator sees them: summaries
 * without credentials. The platform invites only the unit's administrators,
 * and resets only their passwords, to recover a unit that is locked out; the
 * unit's administrators invite and reset its operators and viewers.
 */
export function UnitAccounts({ unit }: { unit: BusinessUnit }) {
  const client = useQueryClient()
  const accounts = useQuery({ queryKey: ['platform-unit-accounts', unit.id], queryFn: () => listUnitAccounts(unit.id) })
  const [username, setUsername] = useState('')
  const [displayName, setDisplayName] = useState('')
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
      const value = await inviteUnitAdmin(unit.id, { username: username.trim(), display_name: displayName.trim(), password })
      setUsername('')
      setDisplayName('')
      setPassword('')
      setLink({ title: `Activation link for ${value.user.username}`, path: value.activation_path, note: `Shown once; it expires in 30 minutes. Send it to the new administrator directly: whoever opens it chooses the password. ${unit.name}’s administrators see the invitation in their audit.` })
      await refresh()
    } catch (err) {
      setError(errorMessage(err, 'The administrator could not be invited.'))
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
      if (prompt.kind === 'sessions') {
        await revokeUnitAccountSessions(unit.id, account.id, secret)
        setMessage(`${account.username} was signed out of every session.`)
      } else {
        const value = await resetUnitAdminPassword(unit.id, account.id, secret)
        setLink({
          title: `Password reset link for ${account.username}`,
          path: value.activation_path,
          note: `Shown once; it expires ${formatDateTime(value.expires_at)}. ${unit.name}’s administrators see the reset in their audit.`,
          warning: value.totp_enrolled ? undefined : IMPERSONATION_WARNING,
        })
      }
      await refresh()
      setPrompt(null)
    } catch (err) {
      // Only the unit's administrators enable an account, so the server's
      // advice to enable it is replaced with who disabled it.
      const disabledByUnit = err instanceof APIError && err.code === 'user_disabled'
      if (isChangedElsewhere(err)) {
        // The account or the unit changed elsewhere: reload them, and ask
        // again only while the reloaded account still offers the action.
        await refresh()
        const current = client.getQueryData<{ accounts: UnitAccount[] }>(['platform-unit-accounts', unit.id])?.accounts.find(item => item.id === account.id)
        const unitNow = client.getQueryData<BusinessUnit>(['platform-unit', unit.id]) ?? unit
        if (!current || !accountActions(current, unitNow.status === 'active')[prompt.kind]) {
          const changed = current && unitNow.status !== unit.status ? unit.name : account.username
          setPrompt(null)
          setPromptError('')
          setMessage(disabledByUnit ? `${account.username} was disabled by ${unit.name}’s administrators. The latest state is loaded.` : `${changed} changed elsewhere. The latest state is loaded.`)
          return
        }
      }
      setPromptError(disabledByUnit ? `${account.username} was disabled by ${unit.name}’s administrators.` : errorMessage(err, 'The account change could not be completed.'))
    }
  }

  return <div className="unit-accounts">
    {message && <div className="success-banner" role="status">{message}</div>}
    {link && <OneTimeLink key={link.path} {...link} onDismiss={() => setLink(null)} />}
    <div className="settings-grid">
      <div className="panel"><div className="panel-heading"><div><h2>Invite an administrator</h2><p className="muted">You invite the unit’s administrators; they invite its operators and viewers. The person chooses their own password from a one-time link.</p></div><UserPlus className="muted-icon" size={20} /></div>
        {error && <div className="form-error" role="alert">{error}</div>}
        {!active && <p className="notice">Enable the unit before inviting administrators.</p>}
        <form className="settings-form" onSubmit={invite}>
          <label>Username<input value={username} onChange={event => setUsername(event.target.value)} autoComplete="off" required maxLength={80} disabled={!active} /><small>Usernames are unique across all units and the platform.</small></label>
          <label>Display name<input value={displayName} onChange={event => setDisplayName(event.target.value)} autoComplete="off" maxLength={80} disabled={!active} /></label>
          <div className="fixed-role"><span>Role</span><strong>Administrator</strong><small>Manages the unit, its jobs, and its accounts.</small></div>
          <label>Your password<input type="password" value={password} onChange={event => setPassword(event.target.value)} autoComplete="current-password" required disabled={!active} /></label>
          <button className="button primary" type="submit" disabled={!active || inviteBusy}>{inviteBusy ? 'Creating…' : 'Create activation link'}</button>
        </form>
      </div>
      <div className="panel"><div className="panel-heading"><div><h2>Accounts in {unit.name}</h2><p className="muted">You can reset the password only of an administrator, to recover a unit that is locked out. The unit’s administrators reset operators and viewers.</p></div><ShieldCheck className="muted-icon" size={20} /></div>
        {!active && <p className="notice">Enable the unit before resetting passwords or renewing activation links. The accounts of a disabled unit cannot sign in or redeem a link.</p>}
        {accounts.isLoading ? <Loading label="Loading accounts…" /> : accounts.error || !accounts.data ? <ErrorNotice message="Could not load the unit’s accounts." onRetry={() => accounts.refetch()} /> : accounts.data.accounts.length ? <div className="user-list">{accounts.data.accounts.map(account => <AccountRow key={account.id} account={account} unitActive={active} onAction={ask} />)}</div> : <div className="inline-empty">No accounts yet. Invite the unit’s first administrator.</div>}
      </div>
    </div>
    {prompt && <AccountDialog prompt={prompt} unitName={unit.name} error={promptError} onConfirm={confirm} onCancel={() => { setPrompt(null); setPromptError('') }} />}
  </div>
}

/**
 * The actions that an account row offers. The server resets an
 * administrator that is enabled or still pending, which renews its
 * activation link, and only while the unit is active. Revoking sessions
 * stays available in a disabled unit, for any account that has signed up.
 */
function accountActions(account: UnitAccount, unitActive: boolean): Record<Prompt['kind'], boolean> {
  return {
    sessions: !account.pending,
    reset: unitActive && account.role === 'administrator' && (account.enabled || account.pending),
  }
}

function AccountRow({ account, unitActive, onAction }: { account: UnitAccount; unitActive: boolean; onAction: (prompt: Prompt) => void }) {
  const status = account.pending ? ['Pending activation', 'amber'] : account.enabled ? ['Enabled', 'green'] : ['Disabled', 'gray']
  const offered = accountActions(account, unitActive)
  return <div className="user-row account-row" data-testid={`account-${account.username}`}>
    <div><strong>{account.display_name}</strong><span>{account.username} · {unitRoleLabels[account.role] ?? account.role}{lastSignIn(account.last_login_at)}</span></div>
    <span className="account-badges"><span className={`pill ${status[1]}`}>{status[0]}</span><span className={account.totp_enabled ? 'pill green' : 'pill amber'}>{account.totp_enabled ? 'TOTP on' : 'No TOTP'}</span></span>
    {(offered.sessions || offered.reset) && <div className="user-row-actions">
      {offered.sessions && <button type="button" className="button ghost" onClick={() => onAction({ kind: 'sessions', account })}><LogOut size={14} /> Revoke sessions</button>}
      {offered.reset && <button type="button" className="button ghost" onClick={() => onAction({ kind: 'reset', account })}><KeyRound size={14} /> {account.pending ? 'New activation link' : 'Reset password'}</button>}
    </div>}
  </div>
}

function AccountDialog({ prompt, unitName, error, onConfirm, onCancel }: { prompt: Prompt; unitName: string; error: string; onConfirm: (password: string) => Promise<void>; onCancel: () => void }) {
  const { account } = prompt
  const common = { valueLabel: 'Your password', valueType: 'password' as const, valueRequired: true, autoComplete: 'current-password', onConfirm, onCancel, error }
  if (prompt.kind === 'sessions') return <ActionDialog {...common} title={`Revoke all sessions of ${account.username}?`} description="The account is signed out on every device. Its password and authenticator do not change. Confirm with your password." confirmLabel="Revoke sessions" destructive />
  return <ActionDialog {...common} title={`Reset the password of ${account.username}?`} description={`EdgeWatch creates a one-time link that lets its holder choose a new password for this ${unitName} administrator. You see it once, it expires in 30 minutes, and ${unitName}’s administrators see the reset in their audit.`} confirmLabel="Create reset link" destructive={!account.totp_enabled}>
    {account.totp_enabled
      ? <div className="notice"><ShieldCheck size={14} /><span>{account.username} uses TOTP. The link alone signs no one in; the person also needs their authenticator.</span></div>
      : <div className="notice warning" role="alert"><AlertTriangle size={14} /><span><strong>{IMPERSONATION_WARNING}</strong> {account.username} has no TOTP, so whoever holds the link controls the account and can see {unitName}’s data.</span></div>}
  </ActionDialog>
}
