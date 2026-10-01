/** @vitest-environment jsdom */

import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { APIError, deleteUnit, disableUnit, enableUnit, getUnit, getUnitCapacity, inviteUnitAdmin, listUnitAccounts, renameUnit, resetUnitAdminPassword, revokeUnitAccountSessions, updateUnitCapacity } from '../../api'
import type { BusinessUnit, UnitCapacitySettings } from '../../api'
import { formatDateTime } from '../../format'
import { businessUnit, platformPermissions, unitAccount, unitCapacity } from '../../test/platform-fixtures'
import { renderWithProviders } from '../../test/test-utils'
import { IMPERSONATION_WARNING } from './UnitAccounts'
import { UnitDetail } from './UnitDetail'

vi.mock('../../api', async () => {
  const actual = await vi.importActual<typeof import('../../api')>('../../api')
  return { ...actual, deleteUnit: vi.fn(), disableUnit: vi.fn(), enableUnit: vi.fn(), getUnit: vi.fn(), getUnitCapacity: vi.fn(), inviteUnitAdmin: vi.fn(), listUnitAccounts: vi.fn(), renameUnit: vi.fn(), resetUnitAdminPassword: vi.fn(), revokeUnitAccountSessions: vi.fn(), updateUnitCapacity: vi.fn() }
})

const accounts = [
  unitAccount({ id: 'a-riley', username: 'riley', display_name: 'Riley Novak', role: 'administrator', last_login_at: '2026-09-24T08:00:00Z' }),
  unitAccount({ id: 'a-jordan', username: 'jordan', display_name: 'Jordan Ellis', role: 'administrator', totp_enabled: true, revision: 2 }),
  unitAccount({ id: 'a-sam', username: 'sam', display_name: 'Sam Pending', role: 'administrator', pending: true, enabled: false }),
  unitAccount({ id: 'a-dana', username: 'dana', display_name: 'Dana Off', role: 'administrator', enabled: false }),
  unitAccount({ id: 'a-casey', username: 'casey', display_name: 'Casey Lindqvist', role: 'operator' }),
  unitAccount({ id: 'a-taylor', username: 'taylor', display_name: 'Taylor Brandt', role: 'viewer' }),
]

function renderUnit(tab = 'overview', permissions = platformPermissions) {
  return renderWithProviders(<Routes><Route path="/platform/units" element={<p>Unit list</p>} /><Route path="/platform/units/:id" element={<UnitDetail permissions={permissions} />} /><Route path="/platform/units/:id/:tab" element={<UnitDetail permissions={permissions} />} /></Routes>, { route: [`/platform/units/unit-retail/${tab}`] })
}

function row(username: string) {
  return screen.getByTestId(`account-${username}`)
}

async function confirmWithPassword(password = 'my-password') {
  const dialog = await screen.findByRole('dialog')
  await act(async () => {
    fireEvent.change(within(dialog).getByLabelText('Your password'), { target: { value: password } })
    fireEvent.submit(within(dialog).getByLabelText('Your password').closest('form')!)
    await Promise.resolve()
  })
  return dialog
}

describe('business unit detail', () => {
  beforeEach(() => {
    vi.mocked(getUnit).mockResolvedValue(businessUnit())
    vi.mocked(listUnitAccounts).mockResolvedValue({ accounts })
    vi.mocked(renameUnit).mockResolvedValue(businessUnit({ revision: 4 }))
    vi.mocked(revokeUnitAccountSessions).mockResolvedValue(undefined)
    vi.mocked(resetUnitAdminPassword).mockResolvedValue({ activation_token: 'reset-token', activation_path: '/activate#token=reset-token', expires_at: '2026-09-25T12:30:00Z', totp_enrolled: false })
    vi.mocked(inviteUnitAdmin).mockResolvedValue({ user: unitAccount({ id: 'a-new', username: 'morgan.retail', role: 'administrator', pending: true, enabled: false }), activation_token: 'invite-token', activation_path: '/activate#token=invite-token' })
    vi.mocked(disableUnit).mockResolvedValue(businessUnit({ status: 'disabled' }))
    vi.mocked(enableUnit).mockResolvedValue(businessUnit())
    vi.mocked(deleteUnit).mockResolvedValue(businessUnit({ status: 'deleting' }))
    vi.mocked(getUnitCapacity).mockResolvedValue(unitCapacity())
    vi.mocked(updateUnitCapacity).mockImplementation(async (_id, revision, value) => unitCapacity({ revision: revision + 1, capacity: { ...unitCapacity().capacity, ...value } }))
  })
  afterEach(() => vi.clearAllMocks())

  describe('accounts', () => {
    it('invites administrators only: there is no role to choose and the request names none', async () => {
      renderUnit('accounts')
      await screen.findByText('Riley Novak')
      expect(screen.queryByRole('combobox')).not.toBeInTheDocument()
      expect(screen.queryByLabelText('Role')).not.toBeInTheDocument()
      expect(screen.getByText('Administrator', { selector: '.fixed-role strong' })).toBeInTheDocument()
      fireEvent.change(screen.getByLabelText(/^Username/), { target: { value: 'bad/name' } })
      fireEvent.change(screen.getByLabelText('Your password'), { target: { value: 'my-password' } })
      fireEvent.submit(screen.getByLabelText(/^Username/).closest('form')!)
      expect(await screen.findByText(/cannot contain control characters/)).toBeInTheDocument()
      expect(inviteUnitAdmin).not.toHaveBeenCalled()

      fireEvent.change(screen.getByLabelText(/^Username/), { target: { value: ' morgan.retail ' } })
      fireEvent.change(screen.getByLabelText('Display name'), { target: { value: 'Morgan' } })
      fireEvent.submit(screen.getByLabelText(/^Username/).closest('form')!)
      await waitFor(() => expect(inviteUnitAdmin).toHaveBeenCalledWith('unit-retail', { username: 'morgan.retail', display_name: 'Morgan', password: 'my-password' }))
      expect(await screen.findByLabelText('Activation link for morgan.retail')).toHaveTextContent('/activate#token=invite-token')
      expect(screen.getByLabelText('Your password')).toHaveValue('')
    })

    it('reports a refused invitation and keeps the form closed while the unit is disabled', async () => {
      vi.mocked(inviteUnitAdmin).mockRejectedValueOnce(new APIError('username is not available', 'conflict', { username: 'username is not available' }))
      const view = renderUnit('accounts')
      await screen.findByText('Riley Novak')
      fireEvent.change(screen.getByLabelText(/^Username/), { target: { value: 'riley' } })
      fireEvent.change(screen.getByLabelText('Your password'), { target: { value: 'my-password' } })
      fireEvent.submit(screen.getByLabelText(/^Username/).closest('form')!)
      expect(await screen.findByRole('alert')).toHaveTextContent('username is not available')
      view.unmount()

      vi.mocked(getUnit).mockResolvedValue(businessUnit({ status: 'disabled' }))
      renderUnit('accounts')
      await screen.findByText('Riley Novak')
      expect(screen.getByText('Enable the unit before inviting administrators.')).toBeInTheDocument()
      expect(screen.getByLabelText(/^Username/)).toBeDisabled()
      expect(screen.getByRole('button', { name: 'Create activation link' })).toBeDisabled()
    })

    it('offers a password reset only on administrator rows that are enabled or pending', async () => {
      renderUnit('accounts')
      await screen.findByText('Riley Novak')
      expect(within(row('riley')).getByRole('button', { name: /Reset password/ })).toBeInTheDocument()
      expect(within(row('jordan')).getByRole('button', { name: /Reset password/ })).toBeInTheDocument()
      expect(within(row('sam')).getByRole('button', { name: /New activation link/ })).toBeInTheDocument()
      for (const username of ['dana', 'casey', 'taylor']) {
        expect(within(row(username)).queryByRole('button', { name: /Reset password|New activation link/ })).not.toBeInTheDocument()
      }
      for (const username of ['riley', 'jordan', 'dana', 'casey', 'taylor']) expect(within(row(username)).getByRole('button', { name: /Revoke sessions/ })).toBeInTheDocument()
      expect(within(row('sam')).queryByRole('button', { name: /Revoke sessions/ })).not.toBeInTheDocument()
      expect(within(row('casey')).getByText('casey · Operator')).toBeInTheDocument()
      expect(within(row('sam')).getByText('Pending activation')).toBeInTheDocument()
      expect(within(row('riley')).getByText('No TOTP')).toBeInTheDocument()
      expect(within(row('jordan')).getByText('TOTP on')).toBeInTheDocument()
      expect(screen.queryByText(/Enable the unit before resetting passwords/)).not.toBeInTheDocument()
    })

    it('offers no password reset or activation link while the unit is disabled, and says why', async () => {
      vi.mocked(getUnit).mockResolvedValue(businessUnit({ status: 'disabled' }))
      renderUnit('accounts')
      await screen.findByText('Riley Novak')
      expect(screen.getByText(/^Enable the unit before resetting passwords or renewing activation links\./)).toBeInTheDocument()
      for (const username of ['riley', 'jordan', 'sam', 'dana', 'casey', 'taylor']) {
        expect(within(row(username)).queryByRole('button', { name: /Reset password|New activation link/ })).not.toBeInTheDocument()
      }
      // The server still revokes the sessions of a disabled unit's accounts.
      for (const username of ['riley', 'jordan', 'dana', 'casey', 'taylor']) expect(within(row(username)).getByRole('button', { name: /Revoke sessions/ })).toBeInTheDocument()
      expect(within(row('sam')).queryByRole('button')).not.toBeInTheDocument()
    })

    it('shows a last sign-in only for an account that signed in', async () => {
      vi.mocked(listUnitAccounts).mockResolvedValue({ accounts: [
        accounts[0],
        unitAccount({ id: 'a-jordan', username: 'jordan', role: 'administrator' }),
        // A server before last_login_at was left out sent the zero time.
        unitAccount({ id: 'a-sam', username: 'sam', role: 'administrator', pending: true, enabled: false, last_login_at: '0001-01-01T00:00:00Z' }),
      ] })
      renderUnit('accounts')
      await screen.findByText('Riley Novak')
      expect(within(row('riley')).getByText(`riley · Administrator · last sign-in ${formatDateTime('2026-09-24T08:00:00Z')}`)).toBeInTheDocument()
      expect(within(row('jordan')).getByText('jordan · Administrator')).toBeInTheDocument()
      expect(within(row('sam')).getByText('sam · Administrator')).toBeInTheDocument()
    })

    it('warns that a reset link for an administrator without TOTP signs in as them, and shows the link once', async () => {
      const writeText = vi.fn().mockResolvedValue(undefined)
      Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } })
      renderUnit('accounts')
      await screen.findByText('Riley Novak')
      fireEvent.click(within(row('riley')).getByRole('button', { name: /Reset password/ }))
      const dialog = await screen.findByRole('dialog')
      expect(within(dialog).getByRole('alert')).toHaveTextContent(IMPERSONATION_WARNING)
      await confirmWithPassword()
      await waitFor(() => expect(resetUnitAdminPassword).toHaveBeenCalledWith('unit-retail', 'a-riley', 'my-password'))
      expect(await screen.findByLabelText('Password reset link for riley')).toHaveTextContent('/activate#token=reset-token')
      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
      expect(screen.getByRole('alert')).toHaveTextContent(IMPERSONATION_WARNING)
      fireEvent.click(screen.getByRole('button', { name: /Copy link/ }))
      await waitFor(() => expect(writeText).toHaveBeenCalledWith(`${window.location.origin}/activate#token=reset-token`))
      expect(await screen.findByRole('button', { name: /Copied/ })).toBeInTheDocument()
      fireEvent.click(screen.getByRole('button', { name: 'Done' }))
      expect(screen.queryByLabelText('Password reset link for riley')).not.toBeInTheDocument()
    })

    it('does not warn when the reset response says the administrator keeps TOTP', async () => {
      vi.mocked(resetUnitAdminPassword).mockResolvedValue({ activation_token: 'reset-2', activation_path: '/activate#token=reset-2', expires_at: '2026-09-25T12:30:00Z', totp_enrolled: true })
      const writeText = vi.fn().mockRejectedValue(new Error('denied'))
      Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } })
      renderUnit('accounts')
      await screen.findByText('Jordan Ellis')
      fireEvent.click(within(row('jordan')).getByRole('button', { name: /Reset password/ }))
      const dialog = await screen.findByRole('dialog')
      expect(within(dialog).getByText(/jordan uses TOTP/)).toBeInTheDocument()
      expect(within(dialog).queryByText(IMPERSONATION_WARNING)).not.toBeInTheDocument()
      await confirmWithPassword()
      await screen.findByLabelText('Password reset link for jordan')
      expect(screen.queryByText(IMPERSONATION_WARNING)).not.toBeInTheDocument()
      fireEvent.click(screen.getByRole('button', { name: /Copy link/ }))
      await waitFor(() => expect(writeText).toHaveBeenCalled())
      expect(screen.getByRole('button', { name: /Copy link/ })).toBeInTheDocument()
    })

    it('shows a new link as not copied until that link is copied', async () => {
      const writeText = vi.fn().mockResolvedValue(undefined)
      Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } })
      renderUnit('accounts')
      await screen.findByText('Riley Novak')
      fireEvent.change(screen.getByLabelText(/^Username/), { target: { value: 'morgan.retail' } })
      fireEvent.change(screen.getByLabelText('Your password'), { target: { value: 'my-password' } })
      fireEvent.submit(screen.getByLabelText(/^Username/).closest('form')!)
      expect(await screen.findByLabelText('Activation link for morgan.retail')).toHaveTextContent('/activate#token=invite-token')
      fireEvent.click(screen.getByRole('button', { name: /Copy link/ }))
      expect(await screen.findByRole('button', { name: /Copied/ })).toBeInTheDocument()
      expect(writeText).toHaveBeenLastCalledWith(`${window.location.origin}/activate#token=invite-token`)

      // A reset link replaces the invitation link without Done: it has not been copied yet.
      fireEvent.click(within(row('riley')).getByRole('button', { name: /Reset password/ }))
      await confirmWithPassword()
      expect(await screen.findByLabelText('Password reset link for riley')).toHaveTextContent('/activate#token=reset-token')
      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
      expect(screen.queryByRole('button', { name: /Copied/ })).not.toBeInTheDocument()
      fireEvent.click(screen.getByRole('button', { name: /Copy link/ }))
      expect(await screen.findByRole('button', { name: /Copied/ })).toBeInTheDocument()
      expect(writeText).toHaveBeenLastCalledWith(`${window.location.origin}/activate#token=reset-token`)
    })

    it('never says a link was copied when the browser offers no clipboard', async () => {
      Object.defineProperty(navigator, 'clipboard', { configurable: true, value: undefined })
      renderUnit('accounts')
      await screen.findByText('Riley Novak')
      fireEvent.click(within(row('riley')).getByRole('button', { name: /Reset password/ }))
      await confirmWithPassword()
      await screen.findByLabelText('Password reset link for riley')
      fireEvent.click(screen.getByRole('button', { name: /Copy link/ }))
      await act(async () => { await Promise.resolve() })
      expect(screen.queryByRole('button', { name: /Copied/ })).not.toBeInTheDocument()
      expect(screen.getByRole('button', { name: /Copy link/ })).toBeInTheDocument()
    })

    for (const { name, refusal, changed, message } of [
      {
        name: 'the unit’s administrators disabled the account',
        refusal: new APIError('disabled users cannot receive activation or password-reset links', 'user_disabled', { enabled: 'enable the account before issuing an activation or password-reset link' }, 409),
        changed: { enabled: false, revision: 2 },
        message: 'riley was disabled by Retail’s administrators. The latest state is loaded.',
      },
      {
        name: 'the unit’s administrators changed the account’s role',
        refusal: new APIError('a platform administrator resets only unit administrators', 'not_permitted', undefined, 403),
        changed: { role: 'operator' as const, revision: 2 },
        message: 'riley changed elsewhere. The latest state is loaded.',
      },
    ]) {
      it(`reloads the accounts and stops offering a reset that was refused because ${name}`, async () => {
        let riley = accounts[0]
        vi.mocked(listUnitAccounts).mockImplementation(async () => ({ accounts: [riley, ...accounts.slice(1)] }))
        vi.mocked(resetUnitAdminPassword).mockRejectedValueOnce(refusal)
        renderUnit('accounts')
        await screen.findByText('Riley Novak')
        fireEvent.click(within(row('riley')).getByRole('button', { name: /Reset password/ }))
        riley = { ...riley, ...changed }
        await confirmWithPassword()
        await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
        expect(resetUnitAdminPassword).toHaveBeenCalledWith('unit-retail', 'a-riley', 'my-password')
        expect(listUnitAccounts).toHaveBeenCalledTimes(2)
        expect(screen.getByRole('status')).toHaveTextContent(message)
        expect(screen.queryByText(/enable the account/)).not.toBeInTheDocument()
        expect(within(row('riley')).queryByRole('button', { name: /Reset password/ })).not.toBeInTheDocument()
        expect(within(row('riley')).getByRole('button', { name: /Revoke sessions/ })).toBeInTheDocument()
        expect(screen.queryByLabelText('Password reset link for riley')).not.toBeInTheDocument()
      })
    }

    it('keeps the dialog open after a refused reset when the reloaded account still allows it', async () => {
      vi.mocked(resetUnitAdminPassword).mockRejectedValueOnce(new APIError('disabled users cannot receive activation or password-reset links', 'user_disabled', { enabled: 'enable the account before issuing an activation or password-reset link' }, 409))
      vi.mocked(resetUnitAdminPassword).mockRejectedValueOnce(new APIError('password confirmation failed', 'password_invalid'))
      renderUnit('accounts')
      await screen.findByText('Riley Novak')
      fireEvent.click(within(row('riley')).getByRole('button', { name: /Reset password/ }))
      let dialog = await confirmWithPassword()
      // The reloaded list still shows riley enabled, so the refusal stays in
      // the dialog, worded for a platform administrator, who cannot enable
      // the account.
      expect(await within(dialog).findByText('riley was disabled by Retail’s administrators.')).toBeInTheDocument()
      expect(within(dialog).queryByText(/enable the account/)).not.toBeInTheDocument()
      await waitFor(() => expect(listUnitAccounts).toHaveBeenCalledTimes(2))
      dialog = await confirmWithPassword('wrong')
      expect(await within(dialog).findByText('password confirmation failed')).toBeInTheDocument()
      expect(listUnitAccounts).toHaveBeenCalledTimes(2)
    })

    it('reloads the unit after a refused reset in a unit that was disabled elsewhere', async () => {
      let current = businessUnit()
      vi.mocked(getUnit).mockImplementation(async () => current)
      vi.mocked(resetUnitAdminPassword).mockRejectedValueOnce(new APIError('the business unit is not active', 'unit_not_active', undefined, 409))
      renderUnit('accounts')
      await screen.findByText('Riley Novak')
      fireEvent.click(within(row('riley')).getByRole('button', { name: /Reset password/ }))
      current = businessUnit({ status: 'disabled', revision: 4 })
      await confirmWithPassword()
      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
      expect(screen.getByText('Retail changed elsewhere. The latest state is loaded.')).toBeInTheDocument()
      expect(await screen.findByText('This unit is disabled.')).toBeInTheDocument()
      expect(within(row('riley')).queryByRole('button', { name: /Reset password/ })).not.toBeInTheDocument()
      expect(within(row('riley')).getByRole('button', { name: /Revoke sessions/ })).toBeInTheDocument()
    })

    it('reloads the accounts after a refused session revocation of an account removed elsewhere', async () => {
      let current = accounts
      vi.mocked(listUnitAccounts).mockImplementation(async () => ({ accounts: current }))
      vi.mocked(revokeUnitAccountSessions).mockRejectedValueOnce(new APIError('account not found', 'not_found', undefined, 404))
      renderUnit('accounts')
      await screen.findByText('Casey Lindqvist')
      fireEvent.click(within(row('casey')).getByRole('button', { name: /Revoke sessions/ }))
      current = accounts.filter(account => account.username !== 'casey')
      await confirmWithPassword()
      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
      expect(screen.getByRole('status')).toHaveTextContent('casey changed elsewhere. The latest state is loaded.')
      await waitFor(() => expect(screen.queryByTestId('account-casey')).not.toBeInTheDocument())
    })

    it('revokes an account’s sessions and reports a refusal inside the dialog', async () => {
      vi.mocked(revokeUnitAccountSessions).mockRejectedValueOnce(new APIError('password confirmation failed', 'password_invalid'))
      renderUnit('accounts')
      await screen.findByText('Casey Lindqvist')
      fireEvent.click(within(row('casey')).getByRole('button', { name: /Revoke sessions/ }))
      let dialog = await confirmWithPassword('wrong')
      expect(await within(dialog).findByText('password confirmation failed')).toBeInTheDocument()
      fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
      fireEvent.click(within(row('casey')).getByRole('button', { name: /Revoke sessions/ }))
      dialog = await confirmWithPassword()
      await waitFor(() => expect(revokeUnitAccountSessions).toHaveBeenLastCalledWith('unit-retail', 'a-casey', 'my-password'))
      expect(await screen.findByText('casey was signed out of every session.')).toBeInTheDocument()
    })

    it('reports accounts that cannot be loaded, an empty unit, and hides the tab without the permission', async () => {
      vi.mocked(listUnitAccounts).mockRejectedValueOnce(new Error('offline'))
      let view = renderUnit('accounts')
      expect(await screen.findByText('Could not load the unit’s accounts.')).toBeInTheDocument()
      view.unmount()
      vi.mocked(listUnitAccounts).mockResolvedValueOnce({ accounts: [] })
      view = renderUnit('accounts')
      expect(await screen.findByText('No accounts yet. Invite the unit’s first administrator.')).toBeInTheDocument()
      view.unmount()
      renderUnit('accounts', ['units.manage'])
      expect(await screen.findByRole('heading', { name: 'Name and public link' })).toBeInTheDocument()
      expect(screen.queryByRole('link', { name: 'Accounts' })).not.toBeInTheDocument()
      expect(listUnitAccounts).toHaveBeenCalledTimes(2)
    })
  })

  describe('overview', () => {
    it('renames the unit and warns that a new slug changes the public link', async () => {
      renderUnit('overview')
      const slug = await screen.findByLabelText(/^Slug/)
      expect(screen.getByRole('link', { name: `${window.location.origin}/public/retail` })).toHaveAttribute('href', '/public/retail')
      expect(screen.getByText(/Anyone who uses the current link then gets a page that is not available/)).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Save changes' })).toBeDisabled()
      fireEvent.change(slug, { target: { value: 'Stores' } })
      expect(slug).toHaveValue('stores')
      expect(screen.getByText(`Changing the slug changes the public link: ${window.location.origin}/public/retail stops working. Share ${window.location.origin}/public/stores instead.`)).toBeInTheDocument()
      fireEvent.change(slug, { target: { value: 's' } })
      fireEvent.submit(slug.closest('form')!)
      expect(await screen.findByText('Use 2 to 40 lowercase letters, digits, or hyphens.')).toBeInTheDocument()
      fireEvent.change(slug, { target: { value: 'stores' } })
      fireEvent.change(screen.getByLabelText('Unit name'), { target: { value: ' Retail stores ' } })
      fireEvent.submit(slug.closest('form')!)
      await waitFor(() => expect(renameUnit).toHaveBeenCalledWith('unit-retail', { revision: 3, name: 'Retail stores', slug: 'stores' }))
      expect(await screen.findByText('Saved. The public page is now at /public/stores.')).toBeInTheDocument()
    })

    it('renames without sending an unchanged slug, and explains conflicts', async () => {
      vi.mocked(renameUnit)
        .mockRejectedValueOnce(new APIError('the business unit was modified; reload and try again', 'conflict', { current: businessUnit() }))
        .mockRejectedValueOnce(new APIError('name in use', 'conflict', { name: 'the name is used by another business unit' }))
      renderUnit('overview')
      const name = await screen.findByLabelText('Unit name')
      fireEvent.change(name, { target: { value: 'Stores' } })
      fireEvent.submit(name.closest('form')!)
      expect(await screen.findByText(/Another platform administrator changed this unit/)).toBeInTheDocument()
      expect(renameUnit).toHaveBeenLastCalledWith('unit-retail', { revision: 3, name: 'Stores' })
      await waitFor(() => expect(getUnit).toHaveBeenCalledTimes(2))
      fireEvent.change(screen.getByLabelText('Unit name'), { target: { value: 'Stores' } })
      fireEvent.submit(name.closest('form')!)
      expect(await screen.findByText('the name is used by another business unit')).toBeInTheDocument()
      fireEvent.change(screen.getByLabelText('Unit name'), { target: { value: ' ' } })
      fireEvent.submit(name.closest('form')!)
      expect(await screen.findByText('Enter a unit name.')).toBeInTheDocument()
      fireEvent.change(screen.getByLabelText('Unit name'), { target: { value: 'Stores' } })
      fireEvent.submit(name.closest('form')!)
      expect(await screen.findByText('Saved.')).toBeInTheDocument()
    })

    it('shows the unit’s stored scans with its other counts', async () => {
      renderUnit('overview')
      expect(await screen.findByRole('heading', { name: 'Public status page' })).toBeInTheDocument()
      expect(screen.getByText(/^\/public\/retail · 5 accounts · 7 jobs · 1,234 stored scans · created /)).toBeInTheDocument()
      const fact = screen.getByText('Stored scans', { selector: 'dt' }).closest('div')!
      expect(within(fact).getByText('1,234 scans', { selector: 'dd' })).toBeInTheDocument()
      expect(within(screen.getByText('Jobs', { selector: 'dt' }).closest('div')!).getByText('7 jobs')).toBeInTheDocument()
    })

    it('shows the default unit’s legacy public address and a disabled unit’s banner', async () => {
      vi.mocked(getUnit).mockResolvedValue(businessUnit({ is_default: true, status: 'disabled', name: 'Default', slug: 'default' }))
      renderUnit('overview')
      expect(await screen.findByText(`${window.location.origin}/public also serves this unit`)).toBeInTheDocument()
      expect(screen.getByText('This unit is disabled.')).toBeInTheDocument()
      expect(screen.getByText('The default unit holds everything that existed before business units were enabled.')).toBeInTheDocument()
    })
  })

  describe('capacity', () => {
    it('sets a unit’s caps within the deployment limits or inherits them', async () => {
      renderUnit('capacity')
      const slots = await screen.findByLabelText('Scan slot cap', { selector: 'input[type="number"]' })
      expect(slots).toHaveValue(2)
      expect(screen.getByText('Now 1 in use and 2 queued, with at most 2 slots.')).toBeInTheDocument()
      const nmapInherit = screen.getAllByLabelText('Use the deployment’s setting')[1]
      expect(nmapInherit).toBeChecked()
      fireEvent.change(slots, { target: { value: '9' } })
      expect(screen.getByText('Use a whole number from 1 to 4.')).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Save capacity' })).toBeDisabled()
      fireEvent.change(slots, { target: { value: '3' } })
      fireEvent.click(nmapInherit)
      const nmap = screen.getByLabelText('Nmap probe budget per run', { selector: 'input[type="number"]' })
      expect(nmap).toHaveValue(5_000_000)
      fireEvent.change(nmap, { target: { value: '2000000' } })
      fireEvent.click(screen.getAllByLabelText('Use the deployment’s setting')[3])
      fireEvent.submit(slots.closest('form')!)
      // Only the settings that changed are sent, with the revision the form was loaded at.
      await waitFor(() => expect(updateUnitCapacity).toHaveBeenCalledWith('unit-retail', 3, { max_concurrent_scans: 3, max_probe_count: 2_000_000, high_cost_ceiling: null }))
      expect(await screen.findByText('Capacity saved. It applies to the next scan this unit queues.')).toBeInTheDocument()
      // The saved form has nothing left to save.
      expect(screen.getByRole('button', { name: 'Save capacity' })).toBeDisabled()
      expect(screen.getByLabelText('Scan slot cap', { selector: 'input[type="number"]' })).toHaveValue(3)
    })

    it('shows a unit without a high-cost grant as not granted, and saving other settings keeps it so', async () => {
      const server = capacityServer({ max_probe_count: null, high_cost_ceiling: 0 })
      renderUnit('capacity')
      const slots = await screen.findByLabelText('Scan slot cap', { selector: 'input[type="number"]' })
      expect(screen.getByLabelText('Not granted')).toBeChecked()
      expect(screen.getByLabelText('Grant a ceiling')).not.toBeChecked()
      expect(screen.queryByLabelText('High-cost ceiling', { selector: 'input[type="number"]' })).not.toBeInTheDocument()
      expect(screen.getByText('A job approved for high-cost scanning keeps this unit’s probe budgets, whatever config.yaml sets.')).toBeInTheDocument()
      fireEvent.change(slots, { target: { value: '3' } })
      fireEvent.submit(slots.closest('form')!)
      // The ceiling that stays not granted is not sent, so the stored one is kept.
      await waitFor(() => expect(updateUnitCapacity).toHaveBeenCalledWith('unit-retail', 3, { max_concurrent_scans: 3 }))
      expect(await screen.findByText('Capacity saved. It applies to the next scan this unit queues.')).toBeInTheDocument()
      expect(server.stored.high_cost_ceiling).toBe(0)
      expect(screen.getByLabelText('Not granted')).toBeChecked()
    })

    it('grants a typed high-cost ceiling, and takes it away again', async () => {
      const server = capacityServer({ high_cost_ceiling: 0 })
      renderUnit('capacity')
      const slots = await screen.findByLabelText('Scan slot cap', { selector: 'input[type="number"]' })
      fireEvent.click(screen.getByLabelText('Grant a ceiling'))
      // A grant starts empty, so it is always a number the administrator typed.
      const ceiling = screen.getByLabelText('High-cost ceiling', { selector: 'input[type="number"]' })
      expect(ceiling).toHaveValue(null)
      const grantOption = screen.getByLabelText('Grant a ceiling').closest<HTMLElement>('.ceiling-option')!
      expect(within(grantOption).getByLabelText('High-cost ceiling', { selector: 'input[type="number"]' })).toBeInTheDocument()
      expect(within(grantOption).queryByText('Use the deployment’s setting')).not.toBeInTheDocument()
      expect(screen.getByText('Use a whole number from 1 to 100,000,000.')).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Save capacity' })).toBeDisabled()
      fireEvent.change(ceiling, { target: { value: '7000000' } })
      expect(screen.getByText('Granted ceiling: 7,000,000 probes per run. Maximum 100,000,000.')).toBeInTheDocument()
      fireEvent.submit(slots.closest('form')!)
      await waitFor(() => expect(updateUnitCapacity).toHaveBeenLastCalledWith('unit-retail', 3, { high_cost_ceiling: 7_000_000 }))
      expect(await screen.findByText('Capacity saved. It applies to the next scan this unit queues.')).toBeInTheDocument()
      expect(screen.getByLabelText('Grant a ceiling')).toBeChecked()
      expect(screen.getByLabelText('High-cost ceiling', { selector: 'input[type="number"]' })).toHaveValue(7_000_000)
      fireEvent.click(screen.getByLabelText('Not granted'))
      expect(screen.queryByLabelText('High-cost ceiling', { selector: 'input[type="number"]' })).not.toBeInTheDocument()
      fireEvent.submit(slots.closest('form')!)
      await waitFor(() => expect(updateUnitCapacity).toHaveBeenLastCalledWith('unit-retail', 4, { high_cost_ceiling: 0 }))
      await waitFor(() => expect(screen.getByLabelText('Not granted')).toBeChecked())
      expect(server.stored).toEqual({ ...unitCapacity().capacity, max_probe_count: null, high_cost_ceiling: 0 })
      fireEvent.click(screen.getByLabelText('Use the deployment’s setting', { selector: 'input[type="radio"]' }))
      expect(screen.getByText('A job approved for high-cost scanning may send up to 100,000,000 probes, the absolute probe ceiling.')).toBeInTheDocument()
    })

    it('reloads the unit after a capacity change, so a rename or a disable that follows it sends the new revision', async () => {
      // A fake server: a capacity change, like any change, moves the unit
      // to its next revision, and a stale revision is a conflict.
      let current = businessUnit()
      vi.mocked(getUnit).mockImplementation(async () => current)
      vi.mocked(getUnitCapacity).mockImplementation(async () => unitCapacity({ revision: current.revision }))
      vi.mocked(updateUnitCapacity).mockImplementation(async (_id, revision, value) => {
        if (revision !== current.revision) throw new APIError('the business unit was modified; reload and try again', 'conflict')
        current = businessUnit({ ...current, revision: current.revision + 1 })
        return unitCapacity({ revision: current.revision, capacity: { ...unitCapacity().capacity, ...value } })
      })
      vi.mocked(renameUnit).mockImplementation(async (_id, value) => {
        if (value.revision !== current.revision) throw new APIError('the business unit was modified; reload and try again', 'conflict', { current })
        current = businessUnit({ ...current, name: value.name, revision: current.revision + 1 })
        return current
      })
      vi.mocked(disableUnit).mockImplementation(async (_id, revision) => {
        if (revision !== current.revision) throw new APIError('the resource was modified; reload and try again', 'conflict')
        current = businessUnit({ ...current, status: 'disabled', revision: current.revision + 1 })
        return current
      })
      async function saveCapacity() {
        const slots = await screen.findByLabelText('Scan slot cap', { selector: 'input[type="number"]' })
        fireEvent.change(slots, { target: { value: '3' } })
        await act(async () => {
          fireEvent.submit(slots.closest('form')!)
          await Promise.resolve()
        })
        expect(await screen.findByText('Capacity saved. It applies to the next scan this unit queues.')).toBeInTheDocument()
      }
      renderUnit('capacity')
      await saveCapacity()
      fireEvent.click(screen.getByRole('link', { name: 'Overview' }))
      const name = await screen.findByLabelText('Unit name')
      fireEvent.change(name, { target: { value: 'Stores' } })
      await act(async () => {
        fireEvent.submit(name.closest('form')!)
        await Promise.resolve()
      })
      expect(await screen.findByText('Saved.')).toBeInTheDocument()
      expect(renameUnit).toHaveBeenCalledWith('unit-retail', { revision: 4, name: 'Stores' })
      expect(screen.queryByText(/Another platform administrator changed this unit/)).not.toBeInTheDocument()

      fireEvent.click(screen.getByRole('link', { name: 'Capacity' }))
      await saveCapacity()
      fireEvent.click(screen.getByRole('link', { name: 'Danger zone' }))
      fireEvent.click(await screen.findByRole('button', { name: 'Disable unit' }))
      await confirmWithPassword()
      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
      expect(disableUnit).toHaveBeenCalledTimes(1)
      expect(disableUnit).toHaveBeenCalledWith('unit-retail', 6, 'my-password')
      expect(await screen.findByRole('button', { name: 'Enable unit' })).toBeInTheDocument()
    })

    // A fake server that applies a capacity change as the handler does: an
    // absent setting is kept, and a change at a stale revision is refused.
    function capacityServer(overrides: Partial<UnitCapacitySettings> = {}) {
      const state = { revision: 3, stored: { ...unitCapacity().capacity, max_probe_count: null, ...overrides } as UnitCapacitySettings }
      vi.mocked(getUnitCapacity).mockImplementation(async () => unitCapacity({ revision: state.revision, capacity: { ...state.stored } }))
      vi.mocked(updateUnitCapacity).mockImplementation(async (_id, revision, value) => {
        if (revision !== state.revision) throw new APIError('the business unit was modified; reload and try again', 'conflict', undefined, 409)
        state.stored = { ...state.stored, ...value }
        state.revision += 1
        return unitCapacity({ revision: state.revision, capacity: { ...state.stored } })
      })
      return state
    }

    it('sends only the changed settings, so a budget that another administrator saved meanwhile is kept', async () => {
      const server = capacityServer()
      const { client } = renderUnit('capacity')
      const slots = await screen.findByLabelText('Scan slot cap', { selector: 'input[type="number"]' })
      expect(screen.getAllByLabelText('Use the deployment’s setting')[1]).toBeChecked()
      // Another platform administrator lowers the Nmap budget, and the tab
      // refreshes: a form without edits shows the stored values.
      server.stored = { ...server.stored, max_probe_count: 250_000 }
      server.revision = 4
      await act(async () => { await client.refetchQueries({ queryKey: ['platform-unit-capacity', 'unit-retail'] }) })
      expect(await screen.findByLabelText('Nmap probe budget per run', { selector: 'input[type="number"]' })).toHaveValue(250_000)
      expect(screen.queryByText(/Another platform administrator changed/)).not.toBeInTheDocument()
      fireEvent.change(slots, { target: { value: '3' } })
      await act(async () => {
        fireEvent.submit(slots.closest('form')!)
        await Promise.resolve()
      })
      expect(await screen.findByText('Capacity saved. It applies to the next scan this unit queues.')).toBeInTheDocument()
      expect(updateUnitCapacity).toHaveBeenCalledTimes(1)
      expect(updateUnitCapacity).toHaveBeenCalledWith('unit-retail', 4, { max_concurrent_scans: 3 })
      expect(server.stored).toEqual({ max_concurrent_scans: 3, max_probe_count: 250_000, max_naabu_probe_count: 1_000_000, high_cost_ceiling: 1_000_000 })
    })

    it('keeps unsaved edits over a capacity changed elsewhere, says so, and saves them only at the current revision', async () => {
      const server = capacityServer()
      const { client } = renderUnit('capacity')
      const slots = await screen.findByLabelText('Scan slot cap', { selector: 'input[type="number"]' })
      fireEvent.change(slots, { target: { value: '3' } })
      // The refresh brings another administrator's Nmap budget under the edit.
      server.stored = { ...server.stored, max_probe_count: 250_000 }
      server.revision = 4
      await act(async () => { await client.refetchQueries({ queryKey: ['platform-unit-capacity', 'unit-retail'] }) })
      expect(await screen.findByText('Another platform administrator changed this unit’s capacity. The form shows the saved values with your unsaved changes; review them before saving.')).toBeInTheDocument()
      expect(slots).toHaveValue(3)
      expect(screen.getByLabelText('Nmap probe budget per run', { selector: 'input[type="number"]' })).toHaveValue(250_000)

      // A change saved after the last refresh makes the server refuse the
      // save; the form loads it and keeps the edit.
      server.stored = { ...server.stored, max_naabu_probe_count: 2_000_000 }
      server.revision = 5
      await act(async () => {
        fireEvent.submit(slots.closest('form')!)
        await Promise.resolve()
      })
      expect(await screen.findByText('Another platform administrator changed this unit. The current values are loaded with your changes; review them and save again.')).toBeInTheDocument()
      expect(updateUnitCapacity).toHaveBeenLastCalledWith('unit-retail', 4, { max_concurrent_scans: 3 })
      await waitFor(() => expect(screen.getByLabelText('Naabu probe budget per run', { selector: 'input[type="number"]' })).toHaveValue(2_000_000))
      expect(slots).toHaveValue(3)
      expect(server.stored.max_concurrent_scans).toBe(2)

      await act(async () => {
        fireEvent.submit(slots.closest('form')!)
        await Promise.resolve()
      })
      expect(await screen.findByText('Capacity saved. It applies to the next scan this unit queues.')).toBeInTheDocument()
      expect(updateUnitCapacity).toHaveBeenLastCalledWith('unit-retail', 5, { max_concurrent_scans: 3 })
      expect(server.stored).toEqual({ max_concurrent_scans: 3, max_probe_count: 250_000, max_naabu_probe_count: 2_000_000, high_cost_ceiling: 1_000_000 })
      expect(screen.queryByText(/Another platform administrator changed/)).not.toBeInTheDocument()
    })

    it('keeps a ceiling grant that has no number yet over a refreshed capacity, and sends only the grant', async () => {
      const server = capacityServer({ high_cost_ceiling: 0 })
      const { client } = renderUnit('capacity')
      await screen.findByLabelText('Scan slot cap', { selector: 'input[type="number"]' })
      fireEvent.click(screen.getByLabelText('Grant a ceiling'))
      server.stored = { ...server.stored, max_probe_count: 250_000 }
      server.revision = 4
      await act(async () => { await client.refetchQueries({ queryKey: ['platform-unit-capacity', 'unit-retail'] }) })
      expect(await screen.findByLabelText('Nmap probe budget per run', { selector: 'input[type="number"]' })).toHaveValue(250_000)
      expect(screen.getByLabelText('Grant a ceiling')).toBeChecked()
      const ceiling = screen.getByLabelText('High-cost ceiling', { selector: 'input[type="number"]' })
      fireEvent.change(ceiling, { target: { value: '7000000' } })
      await act(async () => {
        fireEvent.submit(ceiling.closest('form')!)
        await Promise.resolve()
      })
      expect(await screen.findByText('Capacity saved. It applies to the next scan this unit queues.')).toBeInTheDocument()
      expect(updateUnitCapacity).toHaveBeenCalledWith('unit-retail', 4, { high_cost_ceiling: 7_000_000 })
      expect(server.stored).toEqual({ ...unitCapacity().capacity, max_probe_count: 250_000, high_cost_ceiling: 7_000_000 })
    })

    it('reports a refused change and a capacity that cannot be loaded', async () => {
      vi.mocked(updateUnitCapacity).mockRejectedValueOnce(new APIError('invalid', 'validation_failed', { max_probe_count: 'max_probe_count must be between 1 and 5000000' }))
      const view = renderUnit('capacity')
      const slots = await screen.findByLabelText('Scan slot cap', { selector: 'input[type="number"]' })
      // A form without changes has nothing to save.
      expect(screen.getByRole('button', { name: 'Save capacity' })).toBeDisabled()
      fireEvent.submit(slots.closest('form')!)
      expect(updateUnitCapacity).not.toHaveBeenCalled()
      fireEvent.change(slots, { target: { value: '1' } })
      fireEvent.submit(slots.closest('form')!)
      expect(await screen.findByRole('alert')).toHaveTextContent('max_probe_count must be between 1 and 5000000')
      view.unmount()
      vi.mocked(getUnitCapacity).mockRejectedValueOnce(new Error('offline'))
      renderUnit('capacity')
      expect(await screen.findByText('Could not load the unit’s capacity.')).toBeInTheDocument()
    })
  })

  describe('danger zone', () => {
    it('keeps delete unavailable until the unit is disabled, then requires the typed name and the password', async () => {
      renderUnit('danger')
      const remove = await screen.findByRole('button', { name: 'Delete unit…' })
      expect(remove).toBeDisabled()
      expect(remove).toHaveAccessibleDescription('Disable the unit first. Only a disabled unit can be deleted.')
      // Once disabled, the reloaded unit is disabled.
      vi.mocked(getUnit).mockResolvedValue(businessUnit({ status: 'disabled', revision: 4 }))
      fireEvent.click(screen.getByRole('button', { name: 'Disable unit' }))
      let dialog = await confirmWithPassword()
      await waitFor(() => expect(disableUnit).toHaveBeenCalledWith('unit-retail', 3, 'my-password'))
      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
      await waitFor(() => expect(screen.getByRole('button', { name: 'Delete unit…' })).toBeEnabled())
      expect(screen.getByRole('button', { name: 'Enable unit' })).toBeInTheDocument()
      fireEvent.click(screen.getByRole('button', { name: 'Delete unit…' }))
      dialog = await screen.findByRole('dialog')
      expect(within(dialog).getByRole('list', { name: 'Data that will be erased' })).toHaveTextContent('Accounts, sessions, and invitations')
      const confirm = within(dialog).getByRole('button', { name: 'Delete unit' })
      expect(confirm).toBeDisabled()
      fireEvent.change(within(dialog).getByLabelText('Type “Retail” to confirm'), { target: { value: 'retail' } })
      fireEvent.change(within(dialog).getByLabelText('Your password'), { target: { value: 'my-password' } })
      fireEvent.submit(confirm.closest('form')!)
      expect(await within(dialog).findByText('The confirmation text does not match.')).toBeInTheDocument()
      expect(deleteUnit).not.toHaveBeenCalled()
      fireEvent.change(within(dialog).getByLabelText('Type “Retail” to confirm'), { target: { value: 'Retail' } })
      fireEvent.submit(confirm.closest('form')!)
      await waitFor(() => expect(deleteUnit).toHaveBeenCalledWith('unit-retail', 'Retail', 'my-password'))
    })

    it('enables a disabled unit and reports a refused delete', async () => {
      vi.mocked(getUnit).mockResolvedValue(businessUnit({ status: 'disabled' }))
      vi.mocked(enableUnit).mockRejectedValueOnce(new APIError('the resource was modified; reload and try again', 'conflict'))
      vi.mocked(deleteUnit).mockRejectedValueOnce(new APIError('password confirmation failed', 'password_invalid'))
      renderUnit('danger')
      fireEvent.click(await screen.findByRole('button', { name: 'Enable unit' }))
      let dialog = await confirmWithPassword()
      expect(await within(dialog).findByText('the resource was modified; reload and try again')).toBeInTheDocument()
      fireEvent.submit(within(dialog).getByLabelText('Your password').closest('form')!)
      await waitFor(() => expect(enableUnit).toHaveBeenCalledTimes(2))
      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())

      fireEvent.click(screen.getByRole('button', { name: 'Delete unit…' }))
      dialog = await screen.findByRole('dialog')
      fireEvent.change(within(dialog).getByLabelText('Type “Retail” to confirm'), { target: { value: 'Retail' } })
      fireEvent.change(within(dialog).getByLabelText('Your password'), { target: { value: 'wrong' } })
      fireEvent.submit(within(dialog).getByLabelText('Your password').closest('form')!)
      expect(await within(dialog).findByText('password confirmation failed')).toBeInTheDocument()
      fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    })

    // A fake server that checks a unit change as checkTenantChange does: the
    // revision first, then the state.
    function lifecycleServer(start: BusinessUnit) {
      let current = start
      function check(revision: number, state: string) {
        if (revision !== current.revision) throw new APIError('the resource was modified; reload and try again', 'conflict')
        if (current.status !== state) throw new APIError(`business unit state change not permitted: it is ${current.status}`, 'unit_state')
      }
      vi.mocked(getUnit).mockImplementation(async () => current)
      vi.mocked(disableUnit).mockImplementation(async (_id, revision) => {
        check(revision, 'active')
        current = { ...current, status: 'disabled', revision: current.revision + 1 }
        return current
      })
      vi.mocked(enableUnit).mockImplementation(async (_id, revision) => {
        check(revision, 'disabled')
        current = { ...current, status: 'active', revision: current.revision + 1 }
        return current
      })
      return { change: (next: Partial<BusinessUnit>) => { current = { ...current, ...next } }, get: () => current }
    }

    for (const [start, other, opener, reverse] of [['active', 'disabled', 'Disable unit', 'Enable Retail?'], ['disabled', 'active', 'Enable unit', 'Disable Retail?']] as const) {
      it(`never turns the dialog for a ${start} unit into the opposite change after another administrator made the unit ${other}`, async () => {
        const server = lifecycleServer(businessUnit({ status: start, revision: 3 }))
        renderUnit('danger')
        fireEvent.click(await screen.findByRole('button', { name: opener }))
        server.change({ status: other, revision: 4 })
        await confirmWithPassword('pw-1')
        await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
        expect(screen.queryByRole('dialog', { name: reverse })).not.toBeInTheDocument()
        expect(screen.getByText(`Retail was ${other === 'active' ? 'enabled' : 'disabled'} elsewhere. The latest state is loaded.`)).toBeInTheDocument()
        // The page offers the change that the unit's state now allows.
        expect(await screen.findByRole('button', { name: other === 'active' ? 'Disable unit' : 'Enable unit' })).toBeInTheDocument()
        const [first, second] = start === 'active' ? [disableUnit, enableUnit] : [enableUnit, disableUnit]
        expect(first).toHaveBeenCalledTimes(1)
        expect(first).toHaveBeenCalledWith('unit-retail', 3, 'pw-1')
        expect(second).not.toHaveBeenCalled()
        expect(server.get()).toMatchObject({ status: other, revision: 4 })
      })
    }

    it('closes an open dialog when the unit is reloaded in a state that no longer allows its change', async () => {
      const server = lifecycleServer(businessUnit({ status: 'active', revision: 3 }))
      const { client } = renderUnit('danger')
      fireEvent.click(await screen.findByRole('button', { name: 'Disable unit' }))
      const dialog = await screen.findByRole('dialog', { name: 'Disable Retail?' })
      fireEvent.change(within(dialog).getByLabelText('Your password'), { target: { value: 'pw-1' } })
      // Another platform administrator disables the unit, and the page
      // reloads it, as it does when the window regains focus.
      server.change({ status: 'disabled', revision: 4 })
      await act(async () => { await client.refetchQueries({ queryKey: ['platform-unit', 'unit-retail'] }) })
      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
      expect(screen.queryByRole('dialog', { name: 'Enable Retail?' })).not.toBeInTheDocument()
      expect(screen.getByText('Retail was disabled elsewhere. The latest state is loaded.')).toBeInTheDocument()
      expect(disableUnit).not.toHaveBeenCalled()
      expect(enableUnit).not.toHaveBeenCalled()
      // The next dialog is the one for the unit's current state, with an empty password.
      fireEvent.click(screen.getByRole('button', { name: 'Enable unit' }))
      expect(within(await screen.findByRole('dialog', { name: 'Enable Retail?' })).getByLabelText('Your password')).toHaveValue('')
    })

    it('keeps the dialog for the same change when only the unit’s revision moved, and confirms it again with the new revision', async () => {
      const server = lifecycleServer(businessUnit({ status: 'active', revision: 3 }))
      renderUnit('danger')
      fireEvent.click(await screen.findByRole('button', { name: 'Disable unit' }))
      // Another platform administrator renamed the unit.
      server.change({ revision: 4 })
      const dialog = await confirmWithPassword('pw-1')
      expect(await within(dialog).findByText('the resource was modified; reload and try again')).toBeInTheDocument()
      expect(screen.getByRole('dialog', { name: 'Disable Retail?' })).toBe(dialog)
      await act(async () => {
        fireEvent.submit(within(dialog).getByLabelText('Your password').closest('form')!)
        await Promise.resolve()
      })
      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
      expect(disableUnit).toHaveBeenLastCalledWith('unit-retail', 4, 'pw-1')
      expect(enableUnit).not.toHaveBeenCalled()
      expect(server.get()).toMatchObject({ status: 'disabled', revision: 5 })
      expect(screen.queryByText(/elsewhere/)).not.toBeInTheDocument()
      expect(await screen.findByRole('button', { name: 'Enable unit' })).toBeInTheDocument()
    })

    it('reloads the unit when a delete is refused because another administrator enabled it', async () => {
      let current = businessUnit({ status: 'disabled', revision: 4 })
      vi.mocked(getUnit).mockImplementation(async () => current)
      vi.mocked(deleteUnit).mockRejectedValueOnce(new APIError('business unit state change not permitted: it is active', 'unit_state'))
      renderUnit('danger')
      fireEvent.click(await screen.findByRole('button', { name: 'Delete unit…' }))
      const dialog = await screen.findByRole('dialog')
      current = businessUnit({ status: 'active', revision: 5 })
      fireEvent.change(within(dialog).getByLabelText('Type “Retail” to confirm'), { target: { value: 'Retail' } })
      fireEvent.change(within(dialog).getByLabelText('Your password'), { target: { value: 'my-password' } })
      await act(async () => {
        fireEvent.submit(within(dialog).getByLabelText('Your password').closest('form')!)
        await Promise.resolve()
      })
      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
      expect(deleteUnit).toHaveBeenCalledWith('unit-retail', 'Retail', 'my-password')
      expect(getUnit).toHaveBeenCalledTimes(2)
      expect(screen.getByText('Retail was enabled elsewhere. The latest state is loaded.')).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Delete unit…' })).toBeDisabled()
      expect(screen.getByRole('button', { name: 'Disable unit' })).toBeInTheDocument()
    })

    it('never offers to delete the default unit', async () => {
      vi.mocked(getUnit).mockResolvedValue(businessUnit({ is_default: true, status: 'disabled' }))
      renderUnit('danger')
      const remove = await screen.findByRole('button', { name: 'Delete unit…' })
      expect(remove).toBeDisabled()
      expect(remove).toHaveAccessibleDescription(/The default unit cannot be deleted/)
    })
  })

  it('follows a deletion in progress and shows a deleted unit', async () => {
    vi.mocked(getUnit).mockResolvedValue(businessUnit({ status: 'deleting', jobs: 0, stored_scans: 40, purge: { phase: 'scan_hosts', rows: 1500 } }))
    const view = renderUnit('danger')
    expect(await screen.findByRole('heading', { name: 'Deleting Retail…' })).toBeInTheDocument()
    const progressLine = screen.getByText('Erasing scan hosts · 1,500 rows erased so far.').closest('p')!
    expect(progressLine).toHaveClass('delete-progress-line')
    expect(progressLine.querySelector('.spinner')).toBeInTheDocument()
    // The heading counts the scans that the purge has yet to erase.
    expect(screen.getByText(/ · 0 jobs · 40 stored scans · created /)).toBeInTheDocument()
    expect(screen.queryByRole('navigation', { name: 'Retail sections' })).not.toBeInTheDocument()
    view.unmount()
    vi.mocked(getUnit).mockResolvedValue(businessUnit({ status: 'deleting' }))
    const waiting = renderUnit()
    expect(await screen.findByText('Waiting to start · 0 rows erased so far.')).toBeInTheDocument()
    waiting.unmount()
    // The phases after the last table name what the deletion does instead.
    for (const [phase, activity] of [
      ['verify', 'Checking that nothing is left'],
      ['compact:baseline_host_search', 'Compacting the search indexes'],
      ['free-pages', 'Overwriting free database pages'],
      ['checkpoint', 'Truncating the database log'],
    ]) {
      vi.mocked(getUnit).mockResolvedValue(businessUnit({ status: 'deleting', purge: { phase, rows: 1500 } }))
      const maintenance = renderUnit()
      expect(await screen.findByText(`${activity} · 1,500 rows erased so far.`)).toBeInTheDocument()
      expect(screen.getByText(/a running backup can delay/)).toBeInTheDocument()
      maintenance.unmount()
    }
    vi.mocked(getUnit).mockResolvedValue(businessUnit({ status: 'deleted' }))
    renderUnit()
    expect(await screen.findByRole('heading', { name: 'Retail was deleted' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('link', { name: 'Back to business units' }))
    expect(await screen.findByText('Unit list')).toBeInTheDocument()
  })

  it('reports a unit that cannot be loaded and falls back to the overview for an unknown tab', async () => {
    vi.mocked(getUnit).mockRejectedValueOnce(new APIError('business unit not found', 'not_found'))
    const view = renderUnit()
    expect(await screen.findByRole('alert')).toHaveTextContent('This business unit could not be loaded.')
    view.unmount()
    renderUnit('notifications')
    expect(await screen.findByRole('heading', { name: 'Name and public link' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Overview' })).toHaveAttribute('aria-current', 'page')
  })
})
