/** @vitest-environment jsdom */

import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { APIError, createUser, getSession, issueUserActivation, issueUserPasswordReset, listUsers, revokeUserActivation, updateUser } from '../api'
import type { SessionUser } from '../api'
import { defaultUnitScope, renderWithProviders } from '../test/test-utils'
import { Users } from './Users'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return { ...actual, createUser: vi.fn(), getSession: vi.fn(), issueUserActivation: vi.fn(), issueUserPasswordReset: vi.fn(), listUsers: vi.fn(), revokeUserActivation: vi.fn(), updateUser: vi.fn() }
})

const user = { id: 'user-2', username: 'operator', display_name: 'Operator', role: 'operator' as const, enabled: true, pending: false, totp_enabled: false, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z', revision: 4 }
const pending = { ...user, id: 'user-3', username: 'new-user', display_name: 'New User', pending: true, enabled: false, revision: 1 }
// The signed-in administrator, and an account an administrator disabled.
const self = { ...user, id: 'user-1', username: 'site-admin', display_name: 'Site Admin', role: 'administrator' as const, revision: 2 }
const disabled = { ...user, id: 'user-4', username: 'former', display_name: 'Former Viewer', role: 'viewer' as const, enabled: false, revision: 6 }
const session: SessionUser = { user_id: self.id, username: self.username, display_name: self.display_name, role: 'administrator', permissions: ['users.manage'], csrf_token: 'csrf', totp_enabled: true, password_requirements: { minimum_length: 12 }, ...defaultUnitScope }

/** The account row that shows the display name. */
function row(displayName: string) {
  return screen.getByText(displayName).closest('.user-row') as HTMLElement
}

/** The names of the actions that the account row offers. */
function actions(displayName: string) {
  return within(row(displayName)).queryAllByRole('button').map(button => button.textContent?.trim())
}

describe('user administration', () => {
  beforeEach(() => {
    vi.mocked(getSession).mockResolvedValue(session)
    vi.mocked(listUsers).mockResolvedValue({ users: [user, pending] })
    vi.mocked(createUser).mockResolvedValue({ user, activation_token: 'token-123', activation_path: '/activate#token=token-123' })
    vi.mocked(issueUserActivation).mockResolvedValue({ activation_token: 'renewed-token', activation_path: '/activate#token=renewed-token', expires_at: '2026-01-01T01:00:00Z' })
    vi.mocked(issueUserPasswordReset).mockResolvedValue({ activation_token: 'reset-token', activation_path: '/activate#token=reset-token', expires_at: '2026-01-01T01:00:00Z' })
    vi.mocked(revokeUserActivation).mockResolvedValue(undefined)
    vi.mocked(updateUser).mockResolvedValue({ ...user, enabled: false, revision: 5 })
  })
  afterEach(() => vi.resetAllMocks())

  it('creates an invitation, exposes the token once, and clears the form', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } })
    renderWithProviders(<Users />)
    await waitFor(() => expect(screen.getByText('Operator')).toBeInTheDocument())
    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'operator' } })
    fireEvent.change(screen.getByLabelText('Display name'), { target: { value: 'Operator' } })
    fireEvent.change(screen.getByLabelText('Role'), { target: { value: 'operator' } })
    fireEvent.change(screen.getByLabelText(/^Administrator password/), { target: { value: 'administrator-password' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create activation link' }))
    await waitFor(() => expect(createUser).toHaveBeenCalledWith('operator', 'Operator', 'operator', 'administrator-password'))
    expect(screen.getByLabelText('Activation link for operator')).toHaveTextContent('/activate#token=token-123')
    expect(screen.getByText(/Created operator/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Copy link' }))
    await waitFor(() => expect(screen.getByRole('button', { name: 'Copied' })).toBeInTheDocument())
    expect(writeText).toHaveBeenCalledWith(`${window.location.origin}/activate#token=token-123`)
    fireEvent.click(screen.getByRole('button', { name: 'Done' }))
    expect(screen.queryByLabelText('Activation link for operator')).not.toBeInTheDocument()
  })

  it('applies the server username rule before sending an invitation', async () => {
    renderWithProviders(<Users />)
    await waitFor(() => expect(screen.getByText('Operator')).toBeInTheDocument())
    fireEvent.change(screen.getByLabelText('Display name'), { target: { value: 'Alice' } })
    fireEvent.change(screen.getByLabelText(/^Administrator password/), { target: { value: 'administrator-password' } })
    for (const [username, problem] of [['corp\\alice', 'cannot contain'], ['ops:alice', 'cannot contain'], ['a/b', 'cannot contain'], ['ali\tce', 'cannot contain'], ['é'.repeat(41), 'at most 80 bytes']]) {
      fireEvent.change(screen.getByLabelText('Username'), { target: { value: username } })
      fireEvent.click(screen.getByRole('button', { name: 'Create activation link' }))
      await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(problem))
    }
    expect(createUser).not.toHaveBeenCalled()

    // 40 two-byte characters are exactly 80 bytes.
    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'é'.repeat(40) } })
    fireEvent.click(screen.getByRole('button', { name: 'Create activation link' }))
    await waitFor(() => expect(createUser).toHaveBeenCalledWith('é'.repeat(40), 'Alice', 'viewer', 'administrator-password'))
  })

  it('surfaces invitation creation failures', async () => {
    vi.mocked(createUser).mockRejectedValueOnce(new Error('creation failed'))
    renderWithProviders(<Users />)
    await waitFor(() => expect(screen.getByText('Operator')).toBeInTheDocument())
    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'operator' } })
    fireEvent.change(screen.getByLabelText('Display name'), { target: { value: 'Operator' } })
    fireEvent.change(screen.getByLabelText(/^Administrator password/), { target: { value: 'administrator-password' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create activation link' }))
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('creation failed'))
  })

  it('toggles enabled users and handles optimistic-concurrency conflicts', async () => {
    renderWithProviders(<Users />)
    await waitFor(() => expect(screen.getByText('Operator')).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: 'Disable' }))
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Disable' }))
    fireEvent.change(screen.getByLabelText('Administrator password'), { target: { value: 'administrator-password' } })
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }))
    await waitFor(() => expect(updateUser).toHaveBeenCalledWith('user-2', { enabled: false, revision: 4, password: 'administrator-password' }))
    expect(screen.getByText('operator disabled.')).toBeInTheDocument()

    vi.mocked(updateUser).mockRejectedValueOnce(new APIError('stale', 'conflict', { current: { ...user, revision: 5 } }))
    fireEvent.click(screen.getByRole('button', { name: 'Disable' }))
    fireEvent.change(screen.getByLabelText('Administrator password'), { target: { value: 'administrator-password' } })
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }))
    await waitFor(() => expect(within(screen.getByRole('dialog')).getByRole('alert')).toHaveTextContent('changed in another session'))
  })

  it('renews and revokes pending activation links', async () => {
    renderWithProviders(<Users />)
    await waitFor(() => expect(screen.getByRole('button', { name: 'Renew activation link' })).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: 'Renew activation link' }))
    fireEvent.change(screen.getByLabelText('Administrator password'), { target: { value: 'administrator-password' } })
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }))
    await waitFor(() => expect(issueUserActivation).toHaveBeenCalledWith('user-3', 'administrator-password'))
    expect(screen.getByLabelText('Activation link for new-user')).toHaveTextContent('/activate#token=renewed-token')
    fireEvent.click(within(row('New User')).getByRole('button', { name: 'Revoke activation link' }))
    fireEvent.change(screen.getByLabelText('Administrator password'), { target: { value: 'administrator-password' } })
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }))
    await waitFor(() => expect(revokeUserActivation).toHaveBeenCalledWith('user-3', 'administrator-password'))
    expect(screen.getByText('The link for new-user was revoked.')).toBeInTheDocument()
  })

  it('offers each account only the actions the server allows', async () => {
    vi.mocked(listUsers).mockResolvedValue({ users: [self, user, disabled, pending] })
    renderWithProviders(<Users />)
    await waitFor(() => expect(screen.getByText('Former Viewer')).toBeInTheDocument())
    // An administrator cannot disable its own account, and a disabled
    // account receives no link until it is enabled again, so it has none to
    // revoke either.
    await waitFor(() => expect(actions('Site Admin')).toEqual(['Create password reset link', 'Revoke password reset link', 'Edit account']))
    expect(actions('Operator')).toEqual(['Disable', 'Create password reset link', 'Revoke password reset link', 'Edit account'])
    expect(actions('Former Viewer')).toEqual(['Enable', 'Edit account'])
    expect(actions('New User')).toEqual(['Renew activation link', 'Revoke activation link', 'Edit account'])
  })

  it('does not offer to disable an account before it knows which account is signed in', async () => {
    vi.mocked(getSession).mockReturnValue(new Promise(() => {}))
    vi.mocked(listUsers).mockResolvedValue({ users: [self, disabled] })
    renderWithProviders(<Users />)
    await waitFor(() => expect(screen.getByText('Former Viewer')).toBeInTheDocument())
    expect(actions('Site Admin')).toEqual(['Create password reset link', 'Revoke password reset link', 'Edit account'])
    expect(actions('Former Viewer')).toEqual(['Enable', 'Edit account'])
  })

  it('revokes a password-reset link from the account row that the notice points to', async () => {
    renderWithProviders(<Users />)
    await waitFor(() => expect(screen.getByText('Operator')).toBeInTheDocument())
    fireEvent.click(within(row('Operator')).getByRole('button', { name: 'Create password reset link' }))
    fireEvent.change(screen.getByLabelText('Administrator password'), { target: { value: 'administrator-password' } })
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }))
    await waitFor(() => expect(issueUserPasswordReset).toHaveBeenCalledWith('user-2', 'administrator-password'))
    expect(screen.getByLabelText('Password reset link for operator')).toHaveTextContent('/activate#token=reset-token')
    expect(screen.getByText(/You can revoke it from this account row/)).toBeInTheDocument()
    fireEvent.click(within(row('Operator')).getByRole('button', { name: 'Revoke password reset link' }))
    fireEvent.change(screen.getByLabelText('Administrator password'), { target: { value: 'administrator-password' } })
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }))
    await waitFor(() => expect(revokeUserActivation).toHaveBeenCalledWith('user-2', 'administrator-password'))
    expect(screen.getByText('The link for operator was revoked.')).toBeInTheDocument()
  })

  it('stops showing a token once its link is revoked or its account is disabled, and keeps it for another account', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } })
    vi.mocked(createUser).mockResolvedValue({ user: pending, activation_token: 'invite-token', activation_path: '/activate#token=invite-token' })
    async function confirm() {
      fireEvent.change(screen.getByLabelText('Administrator password'), { target: { value: 'administrator-password' } })
      fireEvent.click(screen.getByRole('button', { name: 'Confirm' }))
      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    }
    renderWithProviders(<Users />)
    await waitFor(() => expect(screen.getByText('Operator')).toBeInTheDocument())

    // An invitation's token goes when its link is revoked.
    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'new-user' } })
    fireEvent.change(screen.getByLabelText('Display name'), { target: { value: 'New User' } })
    fireEvent.change(screen.getByLabelText(/^Administrator password/), { target: { value: 'administrator-password' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create activation link' }))
    expect(await screen.findByLabelText('Activation link for new-user')).toHaveTextContent('/activate#token=invite-token')
    fireEvent.click(within(row('New User')).getByRole('button', { name: 'Revoke activation link' }))
    await confirm()
    expect(revokeUserActivation).toHaveBeenCalledWith('user-3', 'administrator-password')
    expect(screen.getByText('The link for new-user was revoked.')).toBeInTheDocument()
    expect(screen.queryByLabelText('Activation link for new-user')).not.toBeInTheDocument()
    expect(screen.queryByText('/activate#token=invite-token')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Copy link' })).not.toBeInTheDocument()

    // Revoking another account's link keeps the token on the page.
    fireEvent.click(within(row('Operator')).getByRole('button', { name: 'Create password reset link' }))
    await confirm()
    expect(screen.getByLabelText('Password reset link for operator')).toHaveTextContent('/activate#token=reset-token')
    fireEvent.click(within(row('New User')).getByRole('button', { name: 'Revoke activation link' }))
    await confirm()
    await waitFor(() => expect(revokeUserActivation).toHaveBeenCalledTimes(2))
    expect(screen.getByLabelText('Password reset link for operator')).toHaveTextContent('/activate#token=reset-token')
    expect(screen.getByRole('button', { name: 'Copy link' })).toBeInTheDocument()

    // Disabling the account revokes its links, so its token goes too.
    fireEvent.click(within(row('Operator')).getByRole('button', { name: 'Disable' }))
    await confirm()
    expect(updateUser).toHaveBeenCalledWith('user-2', { enabled: false, revision: 4, password: 'administrator-password' })
    expect(screen.getByText('operator disabled.')).toBeInTheDocument()
    expect(screen.queryByLabelText('Password reset link for operator')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Copy link' })).not.toBeInTheDocument()
  })

  it('keeps a token when another account is disabled or enabled', async () => {
    vi.mocked(listUsers).mockResolvedValue({ users: [user, disabled, pending] })
    vi.mocked(updateUser).mockResolvedValue({ ...disabled, enabled: true, revision: 7 })
    renderWithProviders(<Users />)
    await waitFor(() => expect(screen.getByText('Former Viewer')).toBeInTheDocument())
    fireEvent.click(within(row('Operator')).getByRole('button', { name: 'Create password reset link' }))
    fireEvent.change(screen.getByLabelText('Administrator password'), { target: { value: 'administrator-password' } })
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }))
    expect(await screen.findByLabelText('Password reset link for operator')).toHaveTextContent('/activate#token=reset-token')
    fireEvent.click(within(row('Former Viewer')).getByRole('button', { name: 'Enable' }))
    fireEvent.change(screen.getByLabelText('Administrator password'), { target: { value: 'administrator-password' } })
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }))
    await waitFor(() => expect(updateUser).toHaveBeenCalledWith('user-4', { enabled: true, revision: 6, password: 'administrator-password' }))
    expect(await screen.findByText('former enabled.')).toBeInTheDocument()
    expect(screen.getByLabelText('Password reset link for operator')).toHaveTextContent('/activate#token=reset-token')
  })

  it('edits a display name without asking for a password and uses the captured revision', async () => {
    vi.mocked(updateUser).mockResolvedValue({ ...user, display_name: 'Operations Lead', revision: 5 })
    renderWithProviders(<Users />)
    await waitFor(() => expect(screen.getByText('Operator')).toBeInTheDocument())

    fireEvent.click(within(row('Operator')).getByRole('button', { name: 'Edit account' }))
    const dialog = screen.getByRole('dialog')
    expect(dialog).toHaveTextContent('Edit account for operator')
    expect(dialog).toHaveTextContent('Review the display name and role for operator.')
    fireEvent.change(within(dialog).getByLabelText('Display name'), { target: { value: 'Operations Lead' } })
    expect(within(dialog).queryByLabelText('Administrator password')).not.toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save changes' }))

    await waitFor(() => expect(updateUser).toHaveBeenCalledWith('user-2', { display_name: 'Operations Lead', role: 'operator', revision: 4, password: '' }))
    expect(await screen.findByText('Updated operator.')).toBeInTheDocument()
  })

  it('requires administrator confirmation when changing a role', async () => {
    vi.mocked(updateUser).mockResolvedValue({ ...user, role: 'viewer', revision: 5 })
    renderWithProviders(<Users />)
    await waitFor(() => expect(screen.getByText('Operator')).toBeInTheDocument())

    fireEvent.click(within(row('Operator')).getByRole('button', { name: 'Edit account' }))
    const dialog = screen.getByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText('Role'), { target: { value: 'viewer' } })
    const password = within(dialog).getByLabelText('Administrator password')
    expect(password).toBeRequired()
    fireEvent.change(password, { target: { value: 'administrator-password' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save changes' }))

    await waitFor(() => expect(updateUser).toHaveBeenCalledWith('user-2', { display_name: 'Operator', role: 'viewer', revision: 4, password: 'administrator-password' }))
    expect(await screen.findByText('Updated operator.')).toBeInTheDocument()
  })

  it('closes a stale role editor and requires review of the refreshed account', async () => {
    vi.mocked(listUsers)
      .mockResolvedValueOnce({ users: [user, pending] })
      .mockResolvedValue({ users: [{ ...user, display_name: 'Operations Lead', revision: 5 }, pending] })
    vi.mocked(updateUser).mockRejectedValueOnce(new APIError('stale', 'conflict', { current: { ...user, revision: 5 } }))
    renderWithProviders(<Users />)
    await waitFor(() => expect(screen.getByText('Operator')).toBeInTheDocument())

    fireEvent.click(within(row('Operator')).getByRole('button', { name: 'Edit account' }))
    const dialog = screen.getByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText('Role'), { target: { value: 'viewer' } })
    fireEvent.change(within(dialog).getByLabelText('Administrator password'), { target: { value: 'administrator-password' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save changes' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('latest details are loaded; review them and reopen Edit account')
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    await waitFor(() => expect(screen.getByText('Operations Lead')).toBeInTheDocument())
    fireEvent.click(within(row('Operations Lead')).getByRole('button', { name: 'Edit account' }))
    expect(within(screen.getByRole('dialog')).getByLabelText('Display name')).toHaveValue('Operations Lead')
  })

  it('clears an old action error when the dialog is cancelled and another account is opened', async () => {
    vi.mocked(updateUser).mockRejectedValueOnce(new Error('Incorrect administrator password.'))
    renderWithProviders(<Users />)
    await waitFor(() => expect(screen.getByText('Operator')).toBeInTheDocument())

    fireEvent.click(within(row('Operator')).getByRole('button', { name: 'Disable' }))
    const firstDialog = screen.getByRole('dialog')
    fireEvent.change(within(firstDialog).getByLabelText('Administrator password'), { target: { value: 'wrong-password' } })
    fireEvent.click(within(firstDialog).getByRole('button', { name: 'Confirm' }))
    expect(await within(firstDialog).findByRole('alert')).toHaveTextContent('Incorrect administrator password.')
    fireEvent.click(within(firstDialog).getByRole('button', { name: 'Cancel' }))

    fireEvent.click(within(row('New User')).getByRole('button', { name: 'Renew activation link' }))
    const nextDialog = screen.getByRole('dialog')
    expect(nextDialog).toHaveTextContent('Renew activation link for new-user')
    expect(within(nextDialog).queryByRole('alert')).not.toBeInTheDocument()
  })

  it('prevents an administrator from selecting a lower role for their own account', async () => {
    vi.mocked(listUsers).mockResolvedValue({ users: [self, user] })
    renderWithProviders(<Users />)
    await waitFor(() => expect(screen.getByText('Site Admin')).toBeInTheDocument())

    fireEvent.click(within(row('Site Admin')).getByRole('button', { name: 'Edit account' }))
    const dialog = screen.getByRole('dialog')
    expect(within(dialog).getByRole('option', { name: 'Viewer · read only' })).toBeDisabled()
    expect(within(dialog).getByRole('option', { name: 'Operator · manage scans' })).toBeDisabled()
    expect(within(dialog).getByRole('option', { name: 'Administrator · full access' })).toBeEnabled()
  })

  it('renders API failures without hiding the account list', async () => {
    vi.mocked(listUsers).mockRejectedValue(new Error('database unavailable'))
    renderWithProviders(<Users />)
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Could not load users.'))
    expect(screen.getByRole('heading', { name: 'Users' })).toBeInTheDocument()
  })
})
