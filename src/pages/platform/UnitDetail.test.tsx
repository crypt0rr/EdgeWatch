/** @vitest-environment jsdom */

import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { APIError, deleteUnit, disableUnit, enableUnit, getUnit, getUnitNotifications, inviteUnitAccount, listUnitAccounts, resetUnitAccountPassword, revokeUnitAccountSessions, setUnitNotifications, updateUnit, updateUnitAccount } from '../../api'
import type { BusinessUnitDetail, UnitAccount } from '../../api'
import { renderWithProviders } from '../../test/test-utils'
import { capacityProblems, UnitDetail } from './UnitDetail'
import { IMPERSONATION_WARNING } from './UnitAccounts'

vi.mock('../../api', async () => {
  const actual = await vi.importActual<typeof import('../../api')>('../../api')
  return { ...actual, deleteUnit: vi.fn(), disableUnit: vi.fn(), enableUnit: vi.fn(), getUnit: vi.fn(), getUnitNotifications: vi.fn(), inviteUnitAccount: vi.fn(), listUnitAccounts: vi.fn(), resetUnitAccountPassword: vi.fn(), revokeUnitAccountSessions: vi.fn(), setUnitNotifications: vi.fn(), updateUnit: vi.fn(), updateUnitAccount: vi.fn() }
})

const limits = { max_concurrent_scans: 4, max_probe_count: 5_000_000, max_naabu_probe_count: 20_000_000, max_probe_count_limit: 100_000_000 }
const allPermissions = ['units.manage', 'unit_accounts.manage', 'platform_notifications.manage']

function unit(overrides: Partial<BusinessUnitDetail> = {}): BusinessUnitDetail {
  return {
    id: 'unit-retail', name: 'Retail', slug: 'retail', status: 'active', is_default: false, revision: 3, created_at: '2026-08-01T00:00:00Z', updated_at: '2026-09-01T00:00:00Z',
    accounts: 5, administrators: 2, pending_invitations: 1, public_enabled: true,
    capacity: { slot_cap: 1, slots_in_use: 1, queued: 2, max_probe_count: 2_000_000, max_naabu_probe_count: 10_000_000 },
    limits, erase_categories: [{ key: 'jobs', label: 'Jobs and schedules', detail: 'Every job and schedule.' }, { key: 'accounts', label: 'Accounts, sessions, and invitations', detail: 'Every account.' }],
    ...overrides,
  }
}

function account(overrides: Partial<UnitAccount> & Pick<UnitAccount, 'id' | 'username' | 'role'>): UnitAccount {
  return { display_name: overrides.username, enabled: true, pending: false, totp_enabled: false, created_at: '2026-08-01T00:00:00Z', updated_at: '2026-08-01T00:00:00Z', revision: 1, ...overrides }
}

const accounts = [
  account({ id: 'a-riley', username: 'riley', display_name: 'Riley Novak', role: 'administrator', last_login_at: '2026-09-24T08:00:00Z' }),
  account({ id: 'a-jordan', username: 'jordan', display_name: 'Jordan Ellis', role: 'administrator', totp_enabled: true, revision: 2 }),
  account({ id: 'a-casey', username: 'casey', display_name: 'Casey Lindqvist', role: 'operator' }),
  account({ id: 'a-taylor', username: 'taylor', display_name: 'Taylor Brandt', role: 'viewer', enabled: false }),
  account({ id: 'a-pat', username: 'pat', display_name: 'Pat Osei', role: 'viewer', pending: true, enabled: false }),
]

function renderUnit(tab = 'overview', permissions = allPermissions) {
  return renderWithProviders(<Routes><Route path="/platform/units/:id" element={<UnitDetail permissions={permissions} />} /><Route path="/platform/units/:id/:tab" element={<UnitDetail permissions={permissions} />} /></Routes>, { route: [`/platform/units/unit-retail/${tab}`] })
}

async function confirmWithPassword(password = 'my-password') {
  const dialog = await screen.findByRole('dialog')
  fireEvent.change(within(dialog).getByLabelText('Your password'), { target: { value: password } })
  fireEvent.submit(within(dialog).getByLabelText('Your password').closest('form')!)
  return dialog
}

function row(username: string) {
  return screen.getByTestId(`account-${username}`)
}

describe('business unit detail', () => {
  beforeEach(() => {
    vi.mocked(getUnit).mockResolvedValue(unit())
    vi.mocked(listUnitAccounts).mockResolvedValue({ accounts })
    vi.mocked(updateUnit).mockResolvedValue(unit({ revision: 4 }))
    vi.mocked(updateUnitAccount).mockResolvedValue(accounts[2])
    vi.mocked(revokeUnitAccountSessions).mockResolvedValue(undefined)
    vi.mocked(resetUnitAccountPassword).mockResolvedValue({ activation_token: 'reset-token', activation_path: '/activate#token=reset-token', expires_at: '2026-09-25T12:30:00Z', target_totp_enabled: false })
    vi.mocked(inviteUnitAccount).mockResolvedValue({ user: account({ id: 'a-new', username: 'morgan.retail', role: 'viewer', pending: true }), activation_token: 'invite-token', activation_path: '/activate#token=invite-token' })
    vi.mocked(disableUnit).mockResolvedValue(unit({ status: 'disabled' }))
    vi.mocked(enableUnit).mockResolvedValue(unit())
    vi.mocked(deleteUnit).mockResolvedValue(unit({ status: 'deleting', delete_progress: 0 }))
    vi.mocked(getUnitNotifications).mockResolvedValue({ revision: 1, destinations: [{ id: 'deploy-ops-slack', name: 'Ops Slack', provider: 'slack', enabled: true, assigned: true }, { id: 'deploy-security-mail', name: 'Security mail', provider: 'smtp', enabled: false, assigned: false }] })
    vi.mocked(setUnitNotifications).mockResolvedValue({ revision: 2, destinations: [] })
  })
  afterEach(() => vi.clearAllMocks())

  it('offers a password reset only on active administrator rows', async () => {
    renderUnit('accounts')
    await screen.findByText('Riley Novak')
    expect(within(row('riley')).getByRole('button', { name: /Reset password/ })).toBeInTheDocument()
    expect(within(row('jordan')).getByRole('button', { name: /Reset password/ })).toBeInTheDocument()
    expect(within(row('casey')).queryByRole('button', { name: /Reset password/ })).not.toBeInTheDocument()
    expect(within(row('taylor')).queryByRole('button', { name: /Reset password/ })).not.toBeInTheDocument()
    expect(within(row('pat')).queryByRole('button', { name: /Reset password/ })).not.toBeInTheDocument()
    expect(within(row('pat')).getByText('Pending activation')).toBeInTheDocument()
    expect(within(row('riley')).getByText('No TOTP')).toBeInTheDocument()
    expect(within(row('jordan')).getByText('TOTP on')).toBeInTheDocument()
  })

  it('warns that a reset link for an administrator without TOTP allows signing in as them, and shows the link once', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } })
    renderUnit('accounts')
    await screen.findByText('Riley Novak')
    fireEvent.click(within(row('riley')).getByRole('button', { name: /Reset password/ }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByRole('alert')).toHaveTextContent(IMPERSONATION_WARNING)
    await confirmWithPassword()
    await waitFor(() => expect(resetUnitAccountPassword).toHaveBeenCalledWith('unit-retail', 'a-riley', 'my-password'))
    const link = await screen.findByLabelText('Password reset link for riley')
    expect(link).toHaveTextContent('/activate#token=reset-token')
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(screen.getByRole('alert')).toHaveTextContent(IMPERSONATION_WARNING)
    fireEvent.click(screen.getByRole('button', { name: /Copy link/ }))
    await waitFor(() => expect(writeText).toHaveBeenCalledWith(`${window.location.origin}/activate#token=reset-token`))
    expect(await screen.findByRole('button', { name: /Copied/ })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Done' }))
    expect(screen.queryByLabelText('Password reset link for riley')).not.toBeInTheDocument()
  })

  it('does not warn about impersonation when the administrator has TOTP', async () => {
    vi.mocked(resetUnitAccountPassword).mockResolvedValue({ activation_token: 'reset-2', activation_path: '/activate#token=reset-2', expires_at: '2026-09-25T12:30:00Z', target_totp_enabled: true })
    const writeText = vi.fn().mockRejectedValue(new Error('denied'))
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } })
    renderUnit('accounts')
    await screen.findByText('Jordan Ellis')
    fireEvent.click(within(row('jordan')).getByRole('button', { name: /Reset password/ }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText(/jordan has TOTP/)).toBeInTheDocument()
    expect(within(dialog).queryByText(IMPERSONATION_WARNING)).not.toBeInTheDocument()
    await confirmWithPassword()
    await screen.findByLabelText('Password reset link for jordan')
    expect(screen.queryByText(IMPERSONATION_WARNING)).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /Copy link/ }))
    await waitFor(() => expect(writeText).toHaveBeenCalled())
    expect(screen.getByRole('button', { name: /Copy link/ })).toBeInTheDocument()
  })

  it('reports a refused reset inside the dialog', async () => {
    vi.mocked(resetUnitAccountPassword).mockRejectedValueOnce(new APIError('Main administrators can reset only unit administrators.', 'reset_not_allowed'))
    renderUnit('accounts')
    await screen.findByText('Riley Novak')
    fireEvent.click(within(row('riley')).getByRole('button', { name: /Reset password/ }))
    const dialog = await confirmWithPassword()
    await waitFor(() => expect(within(dialog).getByText('Main administrators can reset only unit administrators.')).toBeInTheDocument())
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('invites accounts with a unit role and validates the username first', async () => {
    renderUnit('accounts')
    await screen.findByText('Riley Novak')
    const role = screen.getByLabelText('Role') as HTMLSelectElement
    expect(Array.from(role.options).map(option => option.value)).toEqual(['administrator', 'operator', 'viewer'])
    fireEvent.change(screen.getByLabelText(/^Username/), { target: { value: 'a/b' } })
    fireEvent.change(screen.getByLabelText('Display name'), { target: { value: 'New Person' } })
    fireEvent.change(role, { target: { value: 'viewer' } })
    const invitePassword = screen.getAllByLabelText('Your password')[0]
    fireEvent.change(invitePassword, { target: { value: 'my-password' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create activation link' }))
    expect(await screen.findByText(/cannot contain/)).toBeInTheDocument()
    expect(inviteUnitAccount).not.toHaveBeenCalled()
    fireEvent.change(screen.getByLabelText(/^Username/), { target: { value: 'morgan.retail' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create activation link' }))
    await waitFor(() => expect(inviteUnitAccount).toHaveBeenCalledWith('unit-retail', { username: 'morgan.retail', display_name: 'New Person', role: 'viewer', password: 'my-password' }))
    expect(await screen.findByLabelText('Activation link for morgan.retail')).toHaveTextContent('/activate#token=invite-token')

    vi.mocked(inviteUnitAccount).mockRejectedValueOnce(new APIError('That username is already in use.', 'username_taken'))
    expect(screen.getByLabelText(/^Username/)).toHaveValue('')
    fireEvent.change(screen.getByLabelText(/^Username/), { target: { value: 'riley' } })
    fireEvent.change(screen.getByLabelText('Display name'), { target: { value: 'Riley again' } })
    fireEvent.change(screen.getAllByLabelText('Your password')[0], { target: { value: 'my-password' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create activation link' }))
    expect(await screen.findByText('That username is already in use.')).toBeInTheDocument()
  })

  it('changes roles, toggles accounts, and revokes sessions after password confirmation', async () => {
    renderUnit('accounts')
    await screen.findByText('Casey Lindqvist')
    fireEvent.change(within(row('casey')).getByLabelText('Role for casey'), { target: { value: 'administrator' } })
    expect(await screen.findByRole('heading', { name: 'Change casey to administrator?' })).toBeInTheDocument()
    await confirmWithPassword()
    await waitFor(() => expect(updateUnitAccount).toHaveBeenCalledWith('unit-retail', 'a-casey', { role: 'administrator', revision: 1, password: 'my-password' }))
    expect(await screen.findByText('casey is now administrator.')).toBeInTheDocument()

    fireEvent.click(within(row('taylor')).getByRole('button', { name: 'Enable' }))
    await confirmWithPassword()
    await waitFor(() => expect(updateUnitAccount).toHaveBeenCalledWith('unit-retail', 'a-taylor', { enabled: true, revision: 1, password: 'my-password' }))
    expect(await screen.findByText('taylor enabled.')).toBeInTheDocument()

    fireEvent.click(within(row('riley')).getByRole('button', { name: 'Disable' }))
    expect(await screen.findByRole('heading', { name: 'Disable riley?' })).toBeInTheDocument()
    await confirmWithPassword()
    await waitFor(() => expect(updateUnitAccount).toHaveBeenCalledWith('unit-retail', 'a-riley', { enabled: false, revision: 1, password: 'my-password' }))
    expect(await screen.findByText('riley disabled and signed out.')).toBeInTheDocument()

    fireEvent.click(within(row('jordan')).getByRole('button', { name: 'Revoke sessions' }))
    await confirmWithPassword()
    await waitFor(() => expect(revokeUnitAccountSessions).toHaveBeenCalledWith('unit-retail', 'a-jordan', 'my-password'))
    expect(await screen.findByText('jordan was signed out of every session.')).toBeInTheDocument()
  })

  it('keeps the dialog open with the server explanation for the last administrator and for conflicts', async () => {
    vi.mocked(updateUnitAccount).mockRejectedValueOnce(new APIError('Retail must keep at least one enabled administrator.', 'last_administrator'))
    renderUnit('accounts')
    await screen.findByText('Riley Novak')
    fireEvent.change(within(row('riley')).getByLabelText('Role for riley'), { target: { value: 'viewer' } })
    const dialog = await confirmWithPassword()
    await waitFor(() => expect(within(dialog).getByText('Retail must keep at least one enabled administrator.')).toBeInTheDocument())
    vi.mocked(updateUnitAccount).mockRejectedValueOnce(new APIError('stale', 'conflict'))
    fireEvent.submit(within(dialog).getByLabelText('Your password').closest('form')!)
    await waitFor(() => expect(within(dialog).getByText(/changed in another session/)).toBeInTheDocument())
    expect(listUnitAccounts).toHaveBeenCalledTimes(2)
  })

  it('blocks invitations while the unit is disabled', async () => {
    vi.mocked(getUnit).mockResolvedValue(unit({ status: 'disabled', disabled_at: '2026-09-20T00:00:00Z' }))
    renderUnit('accounts')
    expect(await screen.findByText('Enable the unit before inviting accounts.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Create activation link' })).toBeDisabled()
    expect(screen.getByText(/This unit is disabled\./)).toBeInTheDocument()
  })

  it('keeps delete disabled until the unit is disabled and disables it after password confirmation', async () => {
    renderUnit('danger')
    const remove = await screen.findByRole('button', { name: 'Delete unit…' })
    expect(remove).toBeDisabled()
    expect(screen.getByText('Disable the unit first. Only a disabled unit can be deleted.')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Disable unit' }))
    expect(await screen.findByRole('heading', { name: 'Disable Retail?' })).toBeInTheDocument()
    vi.mocked(disableUnit).mockRejectedValueOnce(new APIError('password confirmation failed', 'invalid_password'))
    const dialog = await confirmWithPassword('wrong')
    await waitFor(() => expect(within(dialog).getByText('password confirmation failed')).toBeInTheDocument())
    vi.mocked(getUnit).mockResolvedValue(unit({ status: 'disabled' }))
    fireEvent.submit(within(dialog).getByLabelText('Your password').closest('form')!)
    await waitFor(() => expect(disableUnit).toHaveBeenLastCalledWith('unit-retail', 'wrong'))
    await waitFor(() => expect(screen.getByRole('button', { name: 'Delete unit…' })).toBeEnabled())
    fireEvent.click(screen.getByRole('button', { name: 'Enable unit' }))
    await confirmWithPassword()
    await waitFor(() => expect(enableUnit).toHaveBeenCalledWith('unit-retail', 'my-password'))
  })

  it('explains that the default unit cannot be deleted', async () => {
    vi.mocked(getUnit).mockResolvedValue(unit({ id: 'default', name: 'Default', slug: 'default', is_default: true, status: 'disabled' }))
    renderUnit('danger')
    expect(await screen.findByRole('button', { name: 'Delete unit…' })).toBeDisabled()
    expect(screen.getByText(/The default unit cannot be deleted/)).toBeInTheDocument()
  })

  it('lists what will be erased and requires the typed unit name and a password before showing progress', async () => {
    vi.mocked(getUnit).mockResolvedValue(unit({ status: 'disabled' }))
    renderUnit('danger')
    fireEvent.click(await screen.findByRole('button', { name: 'Delete unit…' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByRole('list', { name: 'Data that will be erased' })).toHaveTextContent('Jobs and schedules')
    expect(within(dialog).getByText('Accounts, sessions, and invitations')).toBeInTheDocument()
    const confirm = within(dialog).getByRole('button', { name: 'Delete unit' })
    expect(confirm).toBeDisabled()
    fireEvent.change(within(dialog).getByLabelText('Type “Retail” to confirm'), { target: { value: 'retail' } })
    fireEvent.change(within(dialog).getByLabelText('Your password'), { target: { value: 'my-password' } })
    fireEvent.click(confirm)
    expect(await within(dialog).findByText('The confirmation text does not match.')).toBeInTheDocument()
    expect(deleteUnit).not.toHaveBeenCalled()

    vi.mocked(getUnit).mockResolvedValue(unit({ status: 'deleting', delete_progress: 42 }))
    fireEvent.change(within(dialog).getByLabelText('Type “Retail” to confirm'), { target: { value: 'Retail' } })
    fireEvent.click(confirm)
    await waitFor(() => expect(deleteUnit).toHaveBeenCalledWith('unit-retail', 'Retail', 'my-password'))
    expect(await screen.findByRole('heading', { name: 'Deleting… 42%' })).toBeInTheDocument()
    expect(screen.getByRole('progressbar', { name: 'Deleting Retail' })).toHaveAttribute('value', '42')
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('reports delete failures and shows the tombstone once deletion finishes', async () => {
    vi.mocked(getUnit).mockResolvedValue(unit({ status: 'disabled' }))
    vi.mocked(deleteUnit).mockRejectedValueOnce(new APIError('Disable the unit before deleting it.', 'unit_not_disabled'))
    const view = renderUnit('danger')
    fireEvent.click(await screen.findByRole('button', { name: 'Delete unit…' }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText('Type “Retail” to confirm'), { target: { value: 'Retail' } })
    fireEvent.change(within(dialog).getByLabelText('Your password'), { target: { value: 'my-password' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete unit' }))
    expect(await within(dialog).findByText('Disable the unit before deleting it.')).toBeInTheDocument()
    view.unmount()

    vi.mocked(getUnit).mockResolvedValue(unit({ status: 'deleted', delete_progress: 100 }))
    renderUnit('danger')
    expect(await screen.findByRole('heading', { name: 'Retail was deleted' })).toBeInTheDocument()
    expect(screen.queryByRole('navigation', { name: 'Retail sections' })).not.toBeInTheDocument()
  })

  it('renames the unit and warns that changing the slug moves its public link', async () => {
    renderUnit('overview')
    expect(await screen.findByText('Changing the slug changes public links. Anyone who uses the current link would get “not found”.')).toBeInTheDocument()
    const save = screen.getByRole('button', { name: 'Save changes' })
    expect(save).toBeDisabled()
    fireEvent.change(screen.getByLabelText(/^Slug/), { target: { value: 'Shops' } })
    expect(screen.getByText(/public\/retail will stop working/)).toBeInTheDocument()
    fireEvent.click(save)
    await waitFor(() => expect(updateUnit).toHaveBeenCalledWith('unit-retail', { revision: 3, name: 'Retail', slug: 'shops' }))
    expect(await screen.findByText('Saved. The public page is now at /public/shops.')).toBeInTheDocument()

    fireEvent.change(screen.getByLabelText(/^Slug/), { target: { value: 'bad slug' } })
    fireEvent.click(save)
    expect(await screen.findByText(/Use 1 to 40 lowercase letters/)).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText(/^Slug/), { target: { value: 'retail' } })
    fireEvent.change(screen.getByLabelText('Unit name'), { target: { value: '   ' } })
    fireEvent.click(save)
    expect(await screen.findByText('Enter a unit name.')).toBeInTheDocument()

    vi.mocked(updateUnit).mockRejectedValueOnce(new APIError('stale', 'conflict'))
    fireEvent.change(screen.getByLabelText('Unit name'), { target: { value: 'Retail stores' } })
    fireEvent.click(save)
    expect(await screen.findByText(/Another main administrator changed this unit/)).toBeInTheDocument()
    vi.mocked(updateUnit).mockRejectedValueOnce(new APIError('Another unit already uses this name.', 'name_taken'))
    fireEvent.click(save)
    expect(await screen.findByText('Another unit already uses this name.')).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Unit name'), { target: { value: 'Retail' } })
  })

  it('shows the legacy public URL and disabled time for the default unit', async () => {
    vi.mocked(getUnit).mockResolvedValue(unit({ id: 'default', name: 'Default', slug: 'default', is_default: true, public_enabled: false, disabled_at: '2026-09-20T00:00:00Z' }))
    renderUnit('overview')
    expect(await screen.findByText(/public also serves this unit/)).toBeInTheDocument()
    expect(screen.getByText('The default unit holds everything that existed before business units were enabled.')).toBeInTheDocument()
    expect(screen.getByText('No')).toBeInTheDocument()
    expect(screen.getByText('Disabled')).toBeInTheDocument()
  })

  it('validates capacity against the read-only deployment limits', async () => {
    renderUnit('capacity')
    expect(await screen.findByText('Now 1 in use and 2 queued.')).toBeInTheDocument()
    expect(screen.getByText('100,000,000')).toBeInTheDocument()
    const save = screen.getByRole('button', { name: 'Save capacity' })
    fireEvent.change(screen.getByLabelText(/^Scan slot cap/), { target: { value: '5' } })
    expect(screen.getByText(/Use a whole number from 1 to 4/)).toBeInTheDocument()
    expect(screen.getByLabelText(/^Scan slot cap/)).toHaveAttribute('aria-invalid', 'true')
    expect(save).toBeDisabled()
    fireEvent.submit(save.closest('form')!)
    expect(updateUnit).not.toHaveBeenCalled()
    fireEvent.change(screen.getByLabelText(/^Scan slot cap/), { target: { value: '2' } })
    fireEvent.click(save)
    await waitFor(() => expect(updateUnit).toHaveBeenCalledWith('unit-retail', { revision: 3, capacity: { slot_cap: 2, max_probe_count: 2_000_000, max_naabu_probe_count: 10_000_000 } }))
    expect(await screen.findByText(/Capacity saved/)).toBeInTheDocument()
    vi.mocked(updateUnit).mockRejectedValueOnce(new Error('Capacity must stay within the deployment limits.'))
    fireEvent.click(save)
    expect(await screen.findByText('Capacity must stay within the deployment limits.')).toBeInTheDocument()
  })

  it('reports every capacity field outside the deployment limits', () => {
    expect(capacityProblems({ slot_cap: 0, max_probe_count: 6_000_000, max_naabu_probe_count: 1.5 }, limits)).toEqual({
      slot_cap: expect.stringContaining('1 to 4'),
      max_probe_count: expect.stringContaining('Nmap'),
      max_naabu_probe_count: expect.stringContaining('Naabu'),
    })
    expect(capacityProblems({ slot_cap: 4, max_probe_count: 1, max_naabu_probe_count: 20_000_000 }, limits)).toEqual({})
  })

  it('assigns deployment destinations by name without exposing URLs', async () => {
    const { container } = renderUnit('notifications')
    const slack = await screen.findByLabelText(/Ops Slack/)
    expect(slack).toBeChecked()
    expect(screen.getByText('smtp · disabled in config.yaml')).toBeInTheDocument()
    expect(container.textContent).not.toContain('://')
    const save = screen.getByRole('button', { name: 'Save assignment' })
    expect(save).toBeDisabled()
    fireEvent.click(screen.getByLabelText(/Security mail/))
    expect(save).toBeEnabled()
    fireEvent.click(screen.getByLabelText(/Security mail/))
    expect(save).toBeDisabled()
    fireEvent.click(screen.getByLabelText(/Security mail/))
    fireEvent.click(slack)
    fireEvent.click(save)
    await waitFor(() => expect(setUnitNotifications).toHaveBeenCalledWith('unit-retail', ['deploy-security-mail'], 1))
    expect(await screen.findByText(/Retail can now route alerts to 1 deployment destination/)).toBeInTheDocument()
    vi.mocked(setUnitNotifications).mockRejectedValueOnce(new Error('assignment failed'))
    fireEvent.click(screen.getByLabelText(/Security mail/))
    fireEvent.click(screen.getByRole('button', { name: 'Save assignment' }))
    expect(await screen.findByText('assignment failed')).toBeInTheDocument()
  })

  it('handles empty and failed destination lists', async () => {
    vi.mocked(getUnitNotifications).mockResolvedValueOnce({ revision: 1, destinations: [] })
    const view = renderUnit('notifications')
    expect(await screen.findByText('config.yaml defines no deployment destinations.')).toBeInTheDocument()
    view.unmount()
    vi.mocked(getUnitNotifications).mockRejectedValueOnce(new Error('offline'))
    renderUnit('notifications')
    expect(await screen.findByText('Could not load deployment destinations.')).toBeInTheDocument()
  })

  it('hides tabs the caller cannot use and falls back to the overview', async () => {
    renderUnit('accounts', ['units.manage'])
    const tabs = await screen.findByRole('navigation', { name: 'Retail sections' })
    expect(within(tabs).queryByRole('link', { name: 'Accounts' })).not.toBeInTheDocument()
    expect(within(tabs).queryByRole('link', { name: 'Notifications' })).not.toBeInTheDocument()
    expect(within(tabs).getByRole('link', { name: 'Overview' })).toHaveAttribute('aria-current', 'page')
    expect(screen.getByRole('heading', { name: 'Name and public link' })).toBeInTheDocument()
    expect(listUnitAccounts).not.toHaveBeenCalled()
  })

  it('reports units that cannot be loaded and accounts that cannot be listed', async () => {
    vi.mocked(getUnit).mockRejectedValueOnce(new Error('not found'))
    const view = renderUnit('overview')
    expect(await screen.findByText('This business unit could not be loaded.')).toBeInTheDocument()
    view.unmount()
    vi.mocked(listUnitAccounts).mockRejectedValueOnce(new Error('offline'))
    renderUnit('accounts')
    expect(await screen.findByText('Could not load accounts.')).toBeInTheDocument()
  })

  it('shows an empty account list for a new unit', async () => {
    vi.mocked(listUnitAccounts).mockResolvedValueOnce({ accounts: [] })
    renderUnit('accounts')
    expect(await screen.findByText('No accounts yet. Invite the unit’s first administrator.')).toBeInTheDocument()
  })
})
