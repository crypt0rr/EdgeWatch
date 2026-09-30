/** @vitest-environment jsdom */

import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { APIError, deleteUnit, disableUnit, enableUnit, getUnit, getUnitCapacity, inviteUnitAdmin, listUnitAccounts, renameUnit, resetUnitAdminPassword, revokeUnitAccountSessions, updateUnitCapacity } from '../../api'
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
    vi.mocked(updateUnitCapacity).mockImplementation(async (_id, value) => unitCapacity({ capacity: { max_concurrent_scans: null, max_probe_count: null, max_naabu_probe_count: null, high_cost_ceiling: null, ...value } }))
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
      await waitFor(() => expect(updateUnitCapacity).toHaveBeenCalledWith('unit-retail', { max_concurrent_scans: 3, max_probe_count: 2_000_000, max_naabu_probe_count: 1_000_000, high_cost_ceiling: null }))
      expect(await screen.findByText('Capacity saved. It applies to the next scan this unit queues.')).toBeInTheDocument()
    })

    it('shows a unit without a high-cost grant as not granted, and saving other settings keeps it so', async () => {
      vi.mocked(getUnitCapacity).mockResolvedValue(unitCapacity({ capacity: { ...unitCapacity().capacity, high_cost_ceiling: 0 } }))
      renderUnit('capacity')
      const slots = await screen.findByLabelText('Scan slot cap', { selector: 'input[type="number"]' })
      expect(screen.getByLabelText('Not granted')).toBeChecked()
      expect(screen.getByLabelText('Grant a ceiling')).not.toBeChecked()
      expect(screen.queryByLabelText('High-cost ceiling', { selector: 'input[type="number"]' })).not.toBeInTheDocument()
      expect(screen.getByText('A job approved for high-cost scanning keeps this unit’s probe budgets, whatever config.yaml sets.')).toBeInTheDocument()
      fireEvent.change(slots, { target: { value: '3' } })
      fireEvent.submit(slots.closest('form')!)
      await waitFor(() => expect(updateUnitCapacity).toHaveBeenCalledWith('unit-retail', { max_concurrent_scans: 3, max_probe_count: null, max_naabu_probe_count: 1_000_000, high_cost_ceiling: 0 }))
      expect(await screen.findByText('Capacity saved. It applies to the next scan this unit queues.')).toBeInTheDocument()
      expect(screen.getByLabelText('Not granted')).toBeChecked()
    })

    it('grants a typed high-cost ceiling, and takes it away again', async () => {
      vi.mocked(getUnitCapacity).mockResolvedValue(unitCapacity({ capacity: { ...unitCapacity().capacity, high_cost_ceiling: 0 } }))
      renderUnit('capacity')
      const slots = await screen.findByLabelText('Scan slot cap', { selector: 'input[type="number"]' })
      fireEvent.click(screen.getByLabelText('Grant a ceiling'))
      // A grant starts empty, so it is always a number the administrator typed.
      const ceiling = screen.getByLabelText('High-cost ceiling', { selector: 'input[type="number"]' })
      expect(ceiling).toHaveValue(null)
      expect(screen.getByText('Use a whole number from 1 to 100,000,000.')).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Save capacity' })).toBeDisabled()
      fireEvent.change(ceiling, { target: { value: '7000000' } })
      fireEvent.submit(slots.closest('form')!)
      await waitFor(() => expect(updateUnitCapacity).toHaveBeenLastCalledWith('unit-retail', { max_concurrent_scans: 2, max_probe_count: null, max_naabu_probe_count: 1_000_000, high_cost_ceiling: 7_000_000 }))
      expect(await screen.findByText('Capacity saved. It applies to the next scan this unit queues.')).toBeInTheDocument()
      expect(screen.getByLabelText('Grant a ceiling')).toBeChecked()
      expect(screen.getByLabelText('High-cost ceiling', { selector: 'input[type="number"]' })).toHaveValue(7_000_000)
      fireEvent.click(screen.getByLabelText('Not granted'))
      expect(screen.queryByLabelText('High-cost ceiling', { selector: 'input[type="number"]' })).not.toBeInTheDocument()
      fireEvent.submit(slots.closest('form')!)
      await waitFor(() => expect(updateUnitCapacity).toHaveBeenLastCalledWith('unit-retail', { max_concurrent_scans: 2, max_probe_count: null, max_naabu_probe_count: 1_000_000, high_cost_ceiling: 0 }))
      await waitFor(() => expect(screen.getByLabelText('Not granted')).toBeChecked())
      fireEvent.click(screen.getByLabelText('Use the deployment’s setting', { selector: 'input[type="radio"]' }))
      expect(screen.getByText('A job approved for high-cost scanning may send up to 100,000,000 probes, the absolute probe ceiling.')).toBeInTheDocument()
    })

    it('reloads the unit after a capacity change, so a rename or a disable that follows it sends the new revision', async () => {
      // A fake server: a capacity change, like any change, moves the unit
      // to its next revision, and a stale revision is a conflict.
      let current = businessUnit()
      vi.mocked(getUnit).mockImplementation(async () => current)
      vi.mocked(updateUnitCapacity).mockImplementation(async (_id, value) => {
        current = businessUnit({ ...current, revision: current.revision + 1 })
        return unitCapacity({ capacity: { ...unitCapacity().capacity, ...value } })
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

    it('reports a refused change and a capacity that cannot be loaded', async () => {
      vi.mocked(updateUnitCapacity).mockRejectedValueOnce(new APIError('invalid', 'validation_failed', { max_probe_count: 'max_probe_count must be between 1 and 5000000' }))
      const view = renderUnit('capacity')
      const slots = await screen.findByLabelText('Scan slot cap', { selector: 'input[type="number"]' })
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
    expect(screen.getByText('Erasing scan hosts · 1,500 rows erased so far.')).toBeInTheDocument()
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
