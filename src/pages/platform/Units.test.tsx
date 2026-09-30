/** @vitest-environment jsdom */

import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { useQuery } from '@tanstack/react-query'
import { Route, Routes, useLocation } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { APIError, createUnit, getSession, getUnitCapacity, listUnits } from '../../api'
import { businessUnit, deploymentLimits as limits, platformSession } from '../../test/platform-fixtures'
import { renderWithProviders } from '../../test/test-utils'
import { slugProblem } from './common'
import { Units } from './Units'

vi.mock('../../api', async () => {
  const actual = await vi.importActual<typeof import('../../api')>('../../api')
  return { ...actual, createUnit: vi.fn(), getSession: vi.fn(), getUnitCapacity: vi.fn(), listUnits: vi.fn() }
})

function Location() {
  return <output data-testid="location">{useLocation().pathname}</output>
}

// The console's session, as the signed-in shell reads it.
function Session() {
  useQuery({ queryKey: ['session'], queryFn: getSession })
  return null
}

function renderUnits({ session = false } = {}) {
  return renderWithProviders(<>{session && <Session />}<Routes><Route path="/platform/units" element={<Units />} /><Route path="/platform/units/:id/:tab" element={<p>Unit page</p>} /></Routes><Location /></>, { route: ['/platform/units'] })
}

async function createLogistics() {
  fireEvent.click(screen.getByRole('button', { name: /New unit/ }))
  const dialog = await screen.findByRole('dialog')
  fireEvent.change(within(dialog).getByLabelText('Unit name'), { target: { value: 'Logistics' } })
  await act(async () => { fireEvent.submit(within(dialog).getByLabelText('Unit name').closest('form')!); await Promise.resolve() })
}

describe('business unit list', () => {
  beforeEach(() => {
    vi.mocked(listUnits).mockResolvedValue({ limits, units: [
      businessUnit({ id: 'unit-default', name: 'Default', slug: 'default', is_default: true, accounts: 1, administrators: 1, jobs: 1, slots: { in_use: 0, queued: 0 } }),
      businessUnit(),
      businessUnit({ id: 'unit-old', name: 'Old', slug: 'old', status: 'deleting', purge: { phase: 'scan_hosts', rows: 1200 } }),
      businessUnit({ id: 'unit-gone', name: 'Gone', slug: 'gone', status: 'deleted' }),
    ] })
    vi.mocked(getUnitCapacity).mockImplementation(async id => {
      if (id === 'unit-default') throw new APIError('failed', 'store')
      return { unit_id: id, revision: 3, capacity: { max_concurrent_scans: 2, max_probe_count: null, max_naabu_probe_count: null, high_cost_ceiling: null }, limits, slots: { in_use: 1, queued: 2, limit: 2 } }
    })
    vi.mocked(createUnit).mockResolvedValue(businessUnit({ id: 'unit-new', name: 'Logistics', slug: 'logistics' }))
  })
  afterEach(() => vi.clearAllMocks())

  it('lists each unit with its counts and slot use against its cap, never its data', async () => {
    renderUnits()
    const retail = await screen.findByRole('link', { name: 'Open Retail' })
    expect(retail).toHaveAttribute('href', '/platform/units/unit-retail')
    expect(within(retail).getByText('/public/retail')).toBeInTheDocument()
    expect(within(retail).getByText('5 accounts · 2 admins')).toBeInTheDocument()
    expect(within(retail).getByText('7 jobs')).toBeInTheDocument()
    await waitFor(() => expect(within(retail).getByText('1 in use · 2 queued · cap 2')).toBeInTheDocument())
    const defaultUnit = screen.getByRole('link', { name: 'Open Default' })
    expect(within(defaultUnit).getByText('Default', { selector: '.pill' })).toBeInTheDocument()
    expect(within(defaultUnit).getByText('1 account · 1 admin')).toBeInTheDocument()
    await waitFor(() => expect(within(defaultUnit).getByText('0 in use · 0 queued · cap unavailable')).toBeInTheDocument())
    const deleting = screen.getByRole('link', { name: 'Open Old' })
    expect(within(deleting).getByText('Deleting · 1,200 rows erased')).toBeInTheDocument()
    expect(getUnitCapacity).not.toHaveBeenCalledWith('unit-old')
    expect(screen.queryByRole('link', { name: 'Open Gone' })).not.toBeInTheDocument()
    expect(screen.getByRole('heading', { name: '3 units' })).toBeInTheDocument()
    expect(screen.getByText(/Deployment limits: 4 scan slots · 5,000,000 Nmap and 20,000,000 Naabu probes per run/)).toBeInTheDocument()
  })

  it('shows each unit’s stored scans with its other counts, and what is left of a unit being deleted', async () => {
    vi.mocked(listUnits).mockResolvedValue({ limits, units: [
      businessUnit({ id: 'unit-default', name: 'Default', slug: 'default', is_default: true, stored_scans: 1 }),
      businessUnit(),
      businessUnit({ id: 'unit-new', name: 'New', slug: 'new', jobs: 0, stored_scans: 0 }),
      businessUnit({ id: 'unit-old', name: 'Old', slug: 'old', status: 'deleting', jobs: 0, stored_scans: 40, purge: { phase: 'scans', rows: 5200 } }),
    ] })
    renderUnits()
    const fact = (unit: string) => within(within(screen.getByRole('link', { name: `Open ${unit}` })).getByText('Stored scans').closest('div')!)
    await screen.findByRole('link', { name: 'Open Retail' })
    expect(fact('Retail').getByText('1,234 scans')).toBeInTheDocument()
    expect(fact('Default').getByText('1 scan')).toBeInTheDocument()
    expect(fact('New').getByText('0 scans')).toBeInTheDocument()
    expect(fact('Old').getByText('40 scans')).toBeInTheDocument()
    for (const [unit, slots] of [['Retail', '1 in use · 2 queued · cap 2'], ['New', '1 in use · 2 queued · cap 2'], ['Default', '1 in use · 2 queued · cap unavailable']]) {
      await waitFor(() => expect(within(screen.getByRole('link', { name: `Open ${unit}` })).getByText(slots)).toBeInTheDocument())
    }
  })

  it('creates a unit with a derived or a chosen slug and opens its accounts', async () => {
    renderUnits()
    await screen.findByRole('link', { name: 'Open Retail' })
    fireEvent.click(screen.getByRole('button', { name: /New unit/ }))
    let dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText('Unit name'), { target: { value: ' Logistics ' } })
    fireEvent.change(within(dialog).getByLabelText('Slug for the public link (optional)'), { target: { value: 'Logistics Team' } })
    fireEvent.submit(within(dialog).getByLabelText('Unit name').closest('form')!)
    expect(await within(dialog).findByText('Use 2 to 40 lowercase letters, digits, or hyphens.')).toBeInTheDocument()
    fireEvent.change(within(dialog).getByLabelText('Slug for the public link (optional)'), { target: { value: 'status' } })
    fireEvent.submit(within(dialog).getByLabelText('Unit name').closest('form')!)
    expect(await within(dialog).findByText('“status” is reserved for the console. Choose another slug.')).toBeInTheDocument()
    expect(createUnit).not.toHaveBeenCalled()

    vi.mocked(createUnit).mockRejectedValueOnce(new APIError('slug is in use', 'conflict', { slug: 'the slug is used by another business unit' }))
    fireEvent.change(within(dialog).getByLabelText('Slug for the public link (optional)'), { target: { value: 'logistics' } })
    fireEvent.submit(within(dialog).getByLabelText('Unit name').closest('form')!)
    expect(await within(dialog).findByText('the slug is used by another business unit')).toBeInTheDocument()
    expect(createUnit).toHaveBeenLastCalledWith({ name: 'Logistics', slug: 'logistics' })

    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    fireEvent.click(screen.getByRole('button', { name: /New unit/ }))
    dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText('Unit name'), { target: { value: 'Logistics' } })
    fireEvent.submit(within(dialog).getByLabelText('Unit name').closest('form')!)
    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent('/platform/units/unit-new/accounts'))
    expect(createUnit).toHaveBeenLastCalledWith({ name: 'Logistics' })
  })

  it('reads the session again after creating a unit, and opens the unit only while the session is not restricted', async () => {
    // With TOTP, the platform administrator keeps its console and opens
    // the new unit's accounts.
    vi.mocked(getSession).mockResolvedValue(platformSession())
    const view = renderUnits({ session: true })
    await screen.findByRole('link', { name: 'Open Retail' })
    await waitFor(() => expect(getSession).toHaveBeenCalledTimes(1))
    await createLogistics()
    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent('/platform/units/unit-new/accounts'))
    expect(getSession).toHaveBeenCalledTimes(2)
    expect(vi.mocked(getSession).mock.invocationCallOrder[1]).toBeGreaterThan(vi.mocked(createUnit).mock.invocationCallOrder[0])
    view.unmount()

    // Without TOTP, the second unit restricts the session: the console
    // shows the enrolment instead, so this page neither reloads the list
    // nor opens the unit.
    vi.mocked(getSession).mockReset()
    vi.mocked(getSession).mockResolvedValue(platformSession({ totp_enabled: false }))
    vi.mocked(createUnit).mockImplementationOnce(async () => {
      vi.mocked(getSession).mockResolvedValue(platformSession({ totp_enabled: false, totp_enrollment_required: true, permissions: ['account.self'] }))
      return businessUnit({ id: 'unit-new', name: 'Logistics', slug: 'logistics' })
    })
    renderUnits({ session: true })
    await screen.findByRole('link', { name: 'Open Retail' })
    await waitFor(() => expect(getSession).toHaveBeenCalledTimes(1))
    const listReads = vi.mocked(listUnits).mock.calls.length
    await createLogistics()
    await waitFor(() => expect(getSession).toHaveBeenCalledTimes(2))
    await act(async () => { await new Promise(resolve => setTimeout(resolve, 20)) })
    expect(screen.getByTestId('location')).toHaveTextContent(/^\/platform\/units$/)
    expect(listUnits).toHaveBeenCalledTimes(listReads)
  })

  it('reports a list that cannot be loaded and an empty deployment', async () => {
    vi.mocked(listUnits).mockRejectedValueOnce(new Error('offline'))
    const view = renderUnits()
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not load business units.')
    view.unmount()
    vi.mocked(listUnits).mockResolvedValueOnce({ limits, units: [] })
    renderUnits()
    expect(await screen.findByText('No business units yet.')).toBeInTheDocument()
  })

  it('mirrors the server slug rule', () => {
    expect(slugProblem('retail-2')).toBe('')
    expect(slugProblem('r')).not.toBe('')
    expect(slugProblem('a'.repeat(41))).not.toBe('')
    expect(slugProblem('Retail')).not.toBe('')
    expect(slugProblem('api')).toContain('reserved')
  })
})
