/** @vitest-environment jsdom */

import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { useLocation } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { APIError, createUnit, listUnits } from '../../api'
import type { BusinessUnit } from '../../api'
import { renderWithProviders } from '../../test/test-utils'
import { Units } from './Units'
import { plural, slugify, slugProblem } from './common'

vi.mock('../../api', async () => {
  const actual = await vi.importActual<typeof import('../../api')>('../../api')
  return { ...actual, createUnit: vi.fn(), listUnits: vi.fn() }
})

const limits = { max_concurrent_scans: 4, max_probe_count: 5_000_000, max_naabu_probe_count: 20_000_000, max_probe_count_limit: 100_000_000 }

function unit(overrides: Partial<BusinessUnit>): BusinessUnit {
  return {
    id: 'unit-x', name: 'X', slug: 'x', status: 'active', is_default: false, revision: 1, created_at: '2026-08-01T00:00:00Z', updated_at: '2026-08-01T00:00:00Z',
    accounts: 1, administrators: 1, pending_invitations: 0, public_enabled: false,
    capacity: { slot_cap: 1, slots_in_use: 0, queued: 0, max_probe_count: 1_000_000, max_naabu_probe_count: 5_000_000 }, ...overrides,
  }
}

function Location() {
  return <output data-testid="location">{useLocation().pathname}</output>
}

describe('business unit list', () => {
  beforeEach(() => {
    vi.mocked(listUnits).mockResolvedValue({ limits, units: [
      unit({ id: 'default', name: 'Default', slug: 'default', is_default: true, accounts: 3, capacity: { slot_cap: 2, slots_in_use: 2, queued: 1, max_probe_count: 5_000_000, max_naabu_probe_count: 20_000_000 } }),
      unit({ id: 'unit-retail', name: 'Retail', slug: 'retail', accounts: 5, administrators: 2, pending_invitations: 1 }),
      unit({ id: 'unit-manufacturing', name: 'Manufacturing', slug: 'manufacturing', status: 'disabled' }),
      unit({ id: 'unit-old', name: 'Old unit', slug: 'old', status: 'deleted' }),
    ] })
    vi.mocked(createUnit).mockResolvedValue(unit({ id: 'unit-new', name: 'Logistics Europe', slug: 'logistics-europe' }))
  })
  afterEach(() => vi.clearAllMocks())

  it('shows accounts, capacity, and probe budgets per unit without job data', async () => {
    renderWithProviders(<Units />)
    const retail = await screen.findByRole('link', { name: 'Open Retail' })
    expect(within(retail).getByText('/public/retail')).toBeInTheDocument()
    expect(within(retail).getByText('5 accounts · 2 admins · 1 pending')).toBeInTheDocument()
    const defaultUnit = screen.getByRole('link', { name: 'Open Default' })
    expect(within(defaultUnit).getByText('2 in use · 1 queued · cap 2')).toBeInTheDocument()
    expect(within(defaultUnit).getByText('5,000,000 Nmap · 20,000,000 Naabu')).toBeInTheDocument()
    expect(within(defaultUnit).getByText('Default', { selector: '.pill' })).toBeInTheDocument()
    expect(within(screen.getByRole('link', { name: 'Open Manufacturing' })).getByText('Disabled')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Open Old unit' })).not.toBeInTheDocument()
    expect(screen.getByRole('heading', { name: '3 units' })).toBeInTheDocument()
    expect(screen.getByText(/4 scan slots/)).toBeInTheDocument()
    for (const row of screen.getAllByRole('link', { name: /^Open / })) expect(row.textContent).not.toMatch(/job|scan result|incident/i)
  })

  it('creates a unit with a slug derived from its name and opens its accounts', async () => {
    renderWithProviders(<><Units /><Location /></>, { route: ['/platform/units'] })
    fireEvent.click(await screen.findByRole('button', { name: /New unit/ }))
    const dialog = screen.getByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText('Unit name'), { target: { value: 'Logistics Europe' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Create unit' }))
    await waitFor(() => expect(createUnit).toHaveBeenCalledWith({ name: 'Logistics Europe', slug: 'logistics-europe' }))
    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent('/platform/units/unit-new/accounts'))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('validates an explicit slug and reports server conflicts', async () => {
    vi.mocked(createUnit).mockRejectedValueOnce(new APIError('Another unit already uses this slug.', 'slug_taken'))
    renderWithProviders(<Units />)
    fireEvent.click(await screen.findByRole('button', { name: /New unit/ }))
    const dialog = screen.getByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText('Unit name'), { target: { value: 'Retail two' } })
    fireEvent.change(within(dialog).getByLabelText('Slug for the public link (optional)'), { target: { value: 'Retail!' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Create unit' }))
    expect(await within(dialog).findByText(/Use 1 to 40 lowercase letters/)).toBeInTheDocument()
    expect(createUnit).not.toHaveBeenCalled()
    fireEvent.change(within(dialog).getByLabelText('Slug for the public link (optional)'), { target: { value: 'retail' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Create unit' }))
    expect(await within(dialog).findByText('Another unit already uses this slug.')).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('reports a failed list and an empty deployment', async () => {
    vi.mocked(listUnits).mockRejectedValueOnce(new Error('offline'))
    const view = renderWithProviders(<Units />)
    expect(await screen.findByText('Could not load business units.')).toBeInTheDocument()
    view.unmount()
    vi.mocked(listUnits).mockResolvedValueOnce({ limits, units: [] })
    renderWithProviders(<Units />)
    expect(await screen.findByText('No business units yet.')).toBeInTheDocument()
  })

  it('derives and checks public-link slugs like the server', () => {
    expect(slugify('  Café Logistics — Europe ')).toBe('cafe-logistics-europe')
    expect(slugify('x'.repeat(50))).toHaveLength(40)
    expect(slugProblem('')).toMatch(/Enter a slug/)
    expect(slugProblem('-retail')).toMatch(/lowercase/)
    expect(slugProblem('retail-2')).toBe('')
    expect(plural(1, 'unit')).toBe('1 unit')
    expect(plural(2, 'unit')).toBe('2 units')
  })
})
