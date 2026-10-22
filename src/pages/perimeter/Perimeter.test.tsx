/** @vitest-environment jsdom */

import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { Route, Routes, useParams } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { APIError, declarePerimeterSeeds, deletePerimeterSeed, getPerimeter, getSession, scanSlotDemand } from '../../api'
import { emptyPerimeterOverview, perimeterMonitor, perimeterOverview, perimeterRange } from '../../test/perimeter-fixtures'
import { renderWithProviders } from '../../test/test-utils'
import { Perimeter } from './Perimeter'
import { coverageBuckets, perimeterCoverageDocsURL, perimeterDocsURL } from './presentation'

vi.mock('../../api', async () => {
  const actual = await vi.importActual<typeof import('../../api')>('../../api')
  return { ...actual, declarePerimeterSeeds: vi.fn(), deletePerimeterSeed: vi.fn(), getPerimeter: vi.fn(), getSession: vi.fn(), scanSlotDemand: vi.fn() }
})

const administrator = ['jobs.read', 'jobs.write', 'perimeter.read', 'perimeter.manage']
const operator = ['jobs.read', 'jobs.write', 'perimeter.read']

function session(permissions: string[]) {
  vi.mocked(getSession).mockResolvedValue({ role: 'administrator', user_id: 'u1', username: 'alice', permissions, csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 } } as never)
}

function renderPage(permissions = administrator) {
  session(permissions)
  return renderWithProviders(<Perimeter />, { route: ['/perimeter'] })
}

function RangeProbe() {
  return <output data-testid="range-probe">{useParams().id}</output>
}

function textarea() {
  return screen.getByRole('textbox', { name: 'Ranges, one per line' })
}

describe('Perimeter page', () => {
  beforeEach(() => {
    vi.mocked(getPerimeter).mockResolvedValue(perimeterOverview())
    vi.mocked(scanSlotDemand).mockResolvedValue({ enabled_jobs: 0, history_jobs: 0, lower_bound_jobs: 0, unestimated_jobs: 0, slots: 1, estimated_slot_seconds_per_day: 0, capacity_slot_seconds_per_day: 86400, utilization_percent: 0, over_capacity: false })
  })
  afterEach(() => {
    vi.clearAllMocks()
    vi.unstubAllGlobals()
  })

  it('shows a loading state, then the summary and the declared ranges', async () => {
    let resolve!: (value: ReturnType<typeof perimeterOverview>) => void
    vi.mocked(getPerimeter).mockReturnValueOnce(new Promise(done => { resolve = done }))
    renderPage()
    expect(screen.getByText('Loading perimeter…')).toHaveAttribute('role', 'status')
    resolve(perimeterOverview())

    const summary = await screen.findByRole('region', { name: 'Perimeter summary' })
    expect(within(summary).getByText('Declared IPv4').parentElement).toHaveTextContent('256addresses')
    const cards = Array.from(summary.querySelectorAll('.summary-card')).map(card => card.textContent)
    expect(cards).toEqual(expect.arrayContaining([
      'Full TCP covered50%128 of 256 addresses',
      'Any TCP covered100%256 of 256 addresses',
      'UDP covered0%0 of 256 addresses',
      'Cannot scan0monitors touching the perimeter',
      'Coverage not proven0covering monitors',
      'Outside the perimeter0monitored targets',
    ]))
    // Every bar has a text equivalent and is hidden from assistive technology itself.
    for (const meter of summary.querySelectorAll('meter')) expect(meter).toHaveAttribute('aria-hidden', 'true')

    const table = screen.getByRole('table')
    const row = within(table).getAllByRole('row')[1]
    expect(within(row).getByText('Owned')).toBeInTheDocument()
    expect(within(row).getByRole('link', { name: '203.0.113.0/24' })).toHaveAttribute('href', '/perimeter/ranges/range-1')
    expect(within(row).getByText('DC1 edge')).toBeInTheDocument()
    expect(within(row).getByText('128 of 256 addresses')).toBeInTheDocument()
    expect(within(row).getByRole('list', { name: 'Monitors of 203.0.113.0/24' })).toHaveTextContent('Covering 1')
    expect(screen.getByRole('region', { name: 'Declared ranges table' })).toHaveAttribute('tabindex', '0')
    // The report links how coverage is computed, not the ASN recipe.
    const coverageDocs = screen.getByRole('link', { name: /How coverage is computed/ })
    expect(coverageDocs).toHaveAttribute('href', perimeterCoverageDocsURL)
    expect(coverageDocs).toHaveAttribute('target', '_blank')
    expect(screen.getByRole('link', { name: /Seed the perimeter from an ASN/ })).toHaveAttribute('href', perimeterDocsURL)
    expect(screen.getByText('Every monitor that touches the perimeter can scan.')).toBeInTheDocument()
    expect(screen.getByText('Every covering monitor that touches the perimeter has proven its coverage.')).toBeInTheDocument()
    expect(screen.getByText('Every monitored IP and CIDR target lies inside the declared ranges.')).toBeInTheDocument()
  })

  it('shows progressing resumable work separately from proven and unproven coverage', async () => {
    const monitor = perimeterMonitor({
      last_attempt_status: 'timed_out',
      cycle_in_progress: true,
      cycle_completed_units: 1,
      cycle_total_units: 16,
    })
    vi.mocked(getPerimeter).mockResolvedValue(perimeterOverview({
      monitors: [monitor],
      totals: { ...perimeterOverview().totals, unproven_monitors: 0 },
    }))
    renderPage()

    const progress = await screen.findByRole('region', { name: 'Scan cycles in progress' })
    expect(progress).toHaveTextContent('Edge TCP')
    expect(progress).toHaveTextContent('Scan cycle in progress (1 of 16 units)')
    expect(progress).toHaveTextContent('Coverage is proven only after a successful scan matches the current security scope.')
    expect(progress).not.toHaveTextContent('Last attempt timed out')
    expect(screen.getByRole('region', { name: 'Coverage not proven' })).toHaveTextContent('Every covering monitor that touches the perimeter has proven its coverage.')
  })

  it('offers a retry when the report cannot be loaded, and keeps a loaded report when a refresh fails', async () => {
    vi.mocked(getPerimeter).mockRejectedValueOnce(new APIError('boom', 'internal_error', undefined, 500))
    const { client } = renderPage()
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not load the perimeter.')
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByRole('table')).toBeInTheDocument()
    expect(getPerimeter).toHaveBeenCalledTimes(2)

    vi.mocked(getPerimeter).mockRejectedValueOnce(new APIError('boom', 'internal_error', undefined, 500))
    await client.refetchQueries({ queryKey: ['perimeter'] })
    expect(await screen.findByText('Could not refresh the perimeter. Showing the last loaded report.')).toBeInTheDocument()
    expect(screen.getByRole('table')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Retry refresh' }))
    await waitFor(() => expect(screen.queryByText('Could not refresh the perimeter. Showing the last loaded report.')).not.toBeInTheDocument())
  })

  it('explains an empty perimeter and offers the declare form to administrators only', async () => {
    vi.mocked(getPerimeter).mockResolvedValue(emptyPerimeterOverview())
    const admin = renderPage()
    expect(await screen.findByRole('heading', { name: 'Declare the perimeter' })).toBeInTheDocument()
    expect(screen.getByText(/Declaring a range does not authorize scanning it/)).toBeInTheDocument()
    expect(textarea()).toBeInTheDocument()
    expect(screen.getByRole('radio', { name: /Owned/ })).toBeChecked()
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
    expect(screen.getByText('This business unit holds 0 ranges of at most 1,024.')).toBeInTheDocument()
    const docs = screen.getAllByRole('link', { name: /Seed the perimeter from an ASN \(opens in a new tab\)/ })
    expect(docs.length).toBeGreaterThan(0)
    for (const link of docs) {
      expect(link).toHaveAttribute('href', perimeterDocsURL)
      expect(link).toHaveAttribute('target', '_blank')
      expect(link).toHaveAttribute('rel', 'noopener noreferrer')
    }
    admin.unmount()

    renderPage(operator)
    expect(await screen.findByRole('heading', { name: 'Declare the perimeter' })).toBeInTheDocument()
    expect(screen.getByText(/An administrator of this business unit can declare its ranges/)).toBeInTheDocument()
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: /Seed the perimeter from an ASN/ })).toHaveAttribute('href', perimeterDocsURL)
  })

  it('shows the declare form and Remove only with perimeter.manage', async () => {
    const admin = renderPage()
    expect(await screen.findByRole('heading', { name: 'Declare ranges' })).toBeInTheDocument()
    expect(screen.getByText('This business unit holds 1 range of at most 1,024.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Remove 203.0.113.0/24' })).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: 'Actions' })).toBeInTheDocument()
    admin.unmount()

    renderPage(operator)
    expect(await screen.findByRole('table')).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Declare ranges' })).not.toBeInTheDocument()
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Remove/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('columnheader', { name: 'Actions' })).not.toBeInTheDocument()
  })

  it('shows IPv6 ranges as monitored counts with the max_job_hosts explanation and no percentage', async () => {
    const saturated = Number.MAX_SAFE_INTEGER
    vi.mocked(getPerimeter).mockResolvedValue(perimeterOverview({
      ranges: [perimeterRange({ id: 'range-6', value: '2001:db8::/48', label: '', family: 6, addresses: 0, excluded: 0, coverage: { full_tcp: 0, any_tcp: 0, udp: 0 }, ipv6_monitored: { full_tcp: 65536, any_tcp: saturated, udp: 1 }, monitor_ids: [] })],
      monitors: [],
      totals: { ...perimeterOverview().totals, declared_ipv4: 0, covered_full_tcp: 0, covered_any_tcp: 0, ranges: 1, ipv6_ranges: 1 },
    }))
    renderPage()
    const row = within(await screen.findByRole('table')).getAllByRole('row')[1]
    expect(within(row).getByText('65,536')).toBeInTheDocument()
    expect(within(row).getByText('at least 9,007,199,254,740,991')).toBeInTheDocument()
    expect(within(row).getByText('address monitored')).toBeInTheDocument()
    expect(within(row).queryByText(/%/)).not.toBeInTheDocument()
    expect(row.querySelector('meter')).toBeNull()
    expect(within(row).getByText('No monitors')).toBeInTheDocument()
    expect(screen.getByText(/One monitor scans at most 65,536 addresses \(scanner.max_job_hosts\), a \/112, so EdgeWatch cannot sweep an IPv6 prefix/)).toBeInTheDocument()
    const summary = screen.getByRole('region', { name: 'Perimeter summary' })
    expect(within(summary).getAllByText('No IPv4 ranges declared')).toHaveLength(3)
    expect(within(summary).getByText(/plus 1 IPv6 range/)).toBeInTheDocument()
  })

  it('shows All addresses excluded when every declared address is excluded', async () => {
    vi.mocked(getPerimeter).mockResolvedValue(perimeterOverview({
      ranges: [perimeterRange({ excluded: 256, coverage: { full_tcp: 0, any_tcp: 0, udp: 0 } })],
      totals: { ...perimeterOverview().totals, excluded_ipv4: 256, covered_full_tcp: 0, covered_any_tcp: 0 },
    }))
    renderPage()
    const summary = await screen.findByRole('region', { name: 'Perimeter summary' })
    expect(within(summary).getAllByText('All addresses excluded')).toHaveLength(3)
    expect(within(summary).getByText(/256 excluded/)).toBeInTheDocument()
    expect(within(summary).queryByText(/%/)).not.toBeInTheDocument()
    const row = within(screen.getByRole('table')).getAllByRole('row')[1]
    expect(within(row).getAllByText('All addresses excluded')).toHaveLength(3)
  })

  it('lists the monitors that cannot scan with all their reasons, and those whose coverage is not proven', async () => {
    const monitors = [
      perimeterMonitor({ job_id: 'job-paused', name: 'Paused edge', state: 'paused', reasons: ['paused'], host_discovery: true }),
      perimeterMonitor({ job_id: 'job-big', name: 'Big sweep', state: 'over_budget', reasons: ['over_budget', 'over_expansion'] }),
      perimeterMonitor({ job_id: 'job-new', name: 'New monitor', stale: true, stale_reason: 'overdue', last_success_at: null }),
      perimeterMonitor({ job_id: 'job-old', name: 'Old monitor', stale: true, stale_reason: 'overdue', last_success_at: '2026-10-01T08:00:00Z', stalled_cycle: true }),
      perimeterMonitor({ job_id: 'job-never', name: 'Never fires', stale: true, stale_reason: 'schedule never fires', last_success_at: null, last_attempt_status: 'failed' }),
      perimeterMonitor({ job_id: 'job-timeout', name: 'Slow monitor', last_attempt_status: 'timed_out' }),
      perimeterMonitor({ job_id: 'job-partial', name: 'Partial monitor', last_attempt_status: 'incomplete', host_discovery: true }),
      perimeterMonitor({ job_id: 'job-fine', name: 'Healthy monitor', host_discovery: true }),
      // Listed for its outside targets only: it touches no declared range.
      perimeterMonitor({ job_id: 'job-elsewhere', name: 'Elsewhere', state: 'paused', reasons: ['paused'] }),
    ]
    vi.mocked(getPerimeter).mockResolvedValue(perimeterOverview({
      monitors,
      ranges: [perimeterRange({ monitor_ids: monitors.filter(monitor => monitor.job_id !== 'job-elsewhere').map(monitor => monitor.job_id) })],
      totals: { ...perimeterOverview().totals, cannot_scan_monitors: 2, unproven_monitors: 5 },
    }))
    renderPage()

    const cannotScan = await screen.findByRole('region', { name: 'Monitors that cannot scan' })
    const cannotItems = within(cannotScan).getAllByRole('listitem').filter(item => item.parentElement?.classList.contains('perimeter-monitor-list'))
    expect(cannotItems).toHaveLength(2)
    expect(within(cannotScan).getByRole('link', { name: 'Paused edge' })).toHaveAttribute('href', '/jobs/job-paused')
    expect(within(cannotScan).getByText('Paused: scheduled runs do not start it.')).toBeInTheDocument()
    expect(within(cannotScan).getByText('Scans only hosts that answer host discovery')).toBeInTheDocument()
    expect(within(cannotScan).getByText('Over probe budget')).toBeInTheDocument()
    expect(within(cannotScan).getByText(/Over probe budget: its estimated probes exceed/)).toBeInTheDocument()
    expect(within(cannotScan).getByText(/Over expansion limit: its targets expand past/)).toBeInTheDocument()
    expect(within(cannotScan).queryByText('Elsewhere')).not.toBeInTheDocument()

    const unproven = screen.getByRole('region', { name: 'Coverage not proven' })
    const item = (name: string) => within(unproven).getByRole('link', { name }).closest('li') as HTMLElement
    expect(within(unproven).getAllByRole('link')).toHaveLength(5)
    expect(item('New monitor')).toHaveTextContent('Not scanned yet')
    expect(item('Old monitor')).toHaveTextContent(/No successful scan since .*2026/)
    expect(item('Old monitor')).toHaveTextContent('Scan cycle stalled')
    expect(item('Never fires')).toHaveTextContent('Schedule never fires')
    expect(item('Never fires')).toHaveTextContent('Not scanned yet')
    expect(item('Never fires')).toHaveTextContent('Last attempt failed')
    expect(item('Slow monitor')).toHaveTextContent('Last attempt timed out')
    expect(item('Partial monitor')).toHaveTextContent('Last attempt incomplete')
    expect(item('Partial monitor')).toHaveTextContent('Scans only hosts that answer host discovery')
    expect(within(unproven).queryByText('Healthy monitor')).not.toBeInTheDocument()

    expect(screen.getByRole('note')).toHaveTextContent('2 covering monitors scan only hosts that answer host discovery: Partial monitor, Healthy monitor.')
    const states = screen.getByRole('list', { name: 'Monitors of 203.0.113.0/24' })
    expect(states).toHaveTextContent('Paused 1')
    expect(states).toHaveTextContent('Over probe budget 1')
    expect(states).toHaveTextContent('Covering 6')
    expect(states).toHaveTextContent('Not proven 5')
  })

  it('shows monitor names without links when the session cannot read jobs', async () => {
    vi.mocked(getPerimeter).mockResolvedValue(perimeterOverview({
      monitors: [perimeterMonitor({ state: 'paused', reasons: ['paused'] })],
      outside: [{ job_id: 'job-edge', job_name: 'Edge TCP', state: 'paused', target: '192.0.2.0/24', partial: false, outside_addresses: 256 }],
      totals: { ...perimeterOverview().totals, outside_targets: 1 },
    }))
    renderPage(['perimeter.read'])
    const cannotScan = await screen.findByRole('region', { name: 'Monitors that cannot scan' })
    expect(within(cannotScan).getByText('Edge TCP')).toBeInTheDocument()
    expect(within(cannotScan).queryByRole('link')).not.toBeInTheDocument()
    expect(within(screen.getByRole('region', { name: 'Outside the perimeter' })).queryByRole('link')).not.toBeInTheDocument()
  })

  it('lists the targets outside the perimeter with the truncation notice', async () => {
    vi.mocked(getPerimeter).mockResolvedValue(perimeterOverview({
      monitors: [perimeterMonitor(), perimeterMonitor({ job_id: 'job-cloud', name: 'Cloud', state: 'over_budget', reasons: ['over_budget'] })],
      outside: [
        { job_id: 'job-edge', job_name: 'Edge TCP', state: 'covering', target: '203.0.112.0/23', partial: true, outside_addresses: 256 },
        { job_id: 'job-cloud', job_name: 'Cloud', state: 'over_budget', target: '192.0.2.10', partial: false, outside_addresses: 1 },
      ],
      outside_truncated: true,
      totals: { ...perimeterOverview().totals, outside_targets: 250 },
    }))
    renderPage()
    const outside = await screen.findByRole('region', { name: 'Outside the perimeter' })
    expect(within(outside).getByRole('status')).toHaveTextContent('Showing 2 of 250 targets outside the perimeter.')
    const [partial, full] = within(outside).getAllByRole('listitem')
    expect(partial).toHaveTextContent('203.0.112.0/23Partly outside256 addresses outsideEdge TCP · Covering')
    expect(full).toHaveTextContent('192.0.2.10Fully outside1 address outsideCloud · Over probe budget')
    expect(within(full).getByRole('link', { name: 'Cloud' })).toHaveAttribute('href', '/jobs/job-cloud')
    expect(within(screen.getByRole('region', { name: 'Perimeter summary' })).getByText('Outside the perimeter').parentElement).toHaveTextContent('250')
  })

  it('opens a range from anywhere on its row, but not from its other controls', async () => {
    session(administrator)
    renderWithProviders(<Routes>
      <Route path="/perimeter" element={<Perimeter />} />
      <Route path="/perimeter/ranges/:id" element={<RangeProbe />} />
    </Routes>, { route: ['/perimeter'] })
    const row = within(await screen.findByRole('table')).getAllByRole('row')[1]
    fireEvent.click(within(row).getByRole('button', { name: 'Remove 203.0.113.0/24' }))
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Cancel' }))
    expect(screen.queryByTestId('range-probe')).not.toBeInTheDocument()
    fireEvent.click(within(row).getByText('128 of 256 addresses'))
    expect(await screen.findByTestId('range-probe')).toHaveTextContent('range-1')
  })

  it('renders the ranges as cards on narrow screens', async () => {
    vi.stubGlobal('matchMedia', vi.fn().mockReturnValue({ matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn() }))
    renderPage()
    const cards = await screen.findByRole('list', { name: 'Declared ranges' })
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
    const card = within(cards).getAllByRole('listitem')[0]
    expect(within(card).getByRole('link', { name: '203.0.113.0/24' })).toHaveAttribute('href', '/perimeter/ranges/range-1')
    expect(card).toHaveTextContent('Full TCP50%128 of 256 addresses')
    expect(within(card).getByRole('button', { name: 'Remove 203.0.113.0/24' })).toBeInTheDocument()
  })

  it.each([
    { layout: 'table', narrow: false },
    { layout: 'cards', narrow: true },
  ])('explains every coverage bucket as visible text in the $layout layout', async ({ narrow }) => {
    if (narrow) vi.stubGlobal('matchMedia', vi.fn().mockReturnValue({ matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn() }))
    renderPage()
    const panel = await screen.findByRole('region', { name: 'Declared ranges' })
    expect(within(panel).queryByRole('table') === null).toBe(narrow)
    const legend = panel.querySelector('dl.perimeter-bucket-legend') as HTMLElement
    expect(Array.from(legend.querySelectorAll('dt')).map(term => term.textContent)).toEqual(['Full TCP', 'Any TCP', 'UDP'])
    for (const bucket of coverageBuckets) {
      const description = within(legend).getByText(bucket.description)
      expect(description.tagName).toBe('DD')
      expect(description).toBeVisible()
    }
    // No explanation hides in a tooltip that keyboard and touch users cannot reach.
    expect(panel.querySelector('[title]')).toBeNull()
  })

  it('removes a range only after confirmation and reports the outcome', async () => {
    vi.mocked(deletePerimeterSeed).mockResolvedValue(undefined)
    const { client } = renderPage()
    const invalidate = vi.spyOn(client, 'invalidateQueries')
    const removeButton = await screen.findByRole('button', { name: 'Remove 203.0.113.0/24' })
    // The notice is a live region before it has anything to say.
    const notice = document.querySelector('.perimeter-notice') as HTMLElement
    expect(notice).toHaveAttribute('role', 'status')
    expect(notice).not.toBeVisible()
    removeButton.focus()
    fireEvent.click(removeButton)
    const dialog = screen.getByRole('dialog', { name: 'Remove this range?' })
    expect(dialog).toHaveTextContent('Remove owned range 203.0.113.0/24 (DC1 edge) from the perimeter?')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(deletePerimeterSeed).not.toHaveBeenCalled()
    // Cancel returns focus to the Remove button that opened the dialog.
    await waitFor(() => expect(removeButton).toHaveFocus())

    // After the removal, the range's row leaves the page, so focus moves to
    // the notice instead of falling to the document body.
    vi.mocked(getPerimeter).mockResolvedValue(emptyPerimeterOverview())
    fireEvent.click(removeButton)
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Remove range' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(deletePerimeterSeed).toHaveBeenCalledWith('range-1')
    expect(screen.getByRole('status')).toBe(notice)
    expect(notice).toHaveTextContent('Removed 203.0.113.0/24 from the perimeter.')
    expect(notice).toHaveFocus()
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['perimeter'] })
    expect(await screen.findByRole('heading', { name: 'Declare the perimeter' })).toBeInTheDocument()
    expect(removeButton).not.toBeInTheDocument()
    expect(notice).toHaveFocus()
  })

  it('keeps the dialog open with the reason when a removal fails, and closes it when the range is already gone', async () => {
    vi.mocked(deletePerimeterSeed).mockRejectedValueOnce(new APIError('the action was not committed because the security audit could not be recorded', 'audit_unavailable', undefined, 503))
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: 'Remove 203.0.113.0/24' }))
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Remove range' }))
    expect(await within(screen.getByRole('dialog')).findByRole('alert')).toHaveTextContent('The range was kept because the audit record could not be written. Try again later.')

    vi.mocked(deletePerimeterSeed).mockRejectedValueOnce(new APIError('internal', 'internal_error', undefined, 500))
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Remove range' }))
    await waitFor(() => expect(within(screen.getByRole('dialog')).getByRole('alert')).toHaveTextContent('internal'))

    vi.mocked(deletePerimeterSeed).mockRejectedValueOnce(new APIError('perimeter range not found', 'not_found', undefined, 404))
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Remove range' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(screen.getByText('203.0.113.0/24 was already removed.')).toHaveFocus()
  })
})

describe('Perimeter declare form', () => {
  beforeEach(() => {
    vi.mocked(getPerimeter).mockResolvedValue(emptyPerimeterOverview())
  })
  afterEach(() => vi.clearAllMocks())

  it('sends each non-blank line as an entry with its label, and reports what was created and skipped', async () => {
    vi.mocked(declarePerimeterSeeds).mockResolvedValue({ created: 2, skipped: 1 })
    const { client } = renderPage()
    const invalidate = vi.spyOn(client, 'invalidateQueries')
    fireEvent.change(await screen.findByRole('textbox', { name: 'Ranges, one per line' }), { target: { value: '  203.0.113.0/24   DC1 edge  \n\n198.51.100.7\r\n\t\n2001:db8::/48\t Lab  network\n' } })
    expect(screen.getByText('3 of at most 256 entries')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('radio', { name: /Authorized/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Declare authorized ranges' }))
    expect(await screen.findByText('Declared 2 new ranges. 1 already declared entry was skipped.')).toBeInTheDocument()
    expect(declarePerimeterSeeds).toHaveBeenCalledWith([
      { kind: 'authorized', value: '203.0.113.0/24', label: 'DC1 edge' },
      { kind: 'authorized', value: '198.51.100.7' },
      { kind: 'authorized', value: '2001:db8::/48', label: 'Lab network' },
    ])
    expect(textarea()).toHaveValue('')
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['perimeter'] })
  })

  it('normalizes tab-separated label columns from a paste before declaring', async () => {
    vi.mocked(declarePerimeterSeeds).mockResolvedValue({ created: 1, skipped: 0 })
    renderPage()
    fireEvent.change(await screen.findByRole('textbox', { name: 'Ranges, one per line' }), { target: { value: '203.0.113.0/24\tDC1\tedge' } })
    fireEvent.click(screen.getByRole('button', { name: 'Declare owned ranges' }))
    expect(await screen.findByText('Declared 1 new range.')).toBeInTheDocument()
    expect(declarePerimeterSeeds).toHaveBeenCalledWith([
      { kind: 'prefix', value: '203.0.113.0/24', label: 'DC1 edge' },
    ])
  })

  it('keeps the result of the first declaration when the page turns into the report', async () => {
    vi.mocked(declarePerimeterSeeds).mockResolvedValue({ created: 1, skipped: 0 })
    renderPage()
    fireEvent.change(await screen.findByRole('textbox', { name: 'Ranges, one per line' }), { target: { value: '203.0.113.0/24 DC1 edge' } })
    vi.mocked(getPerimeter).mockResolvedValue(perimeterOverview())
    fireEvent.click(screen.getByRole('button', { name: 'Declare owned ranges' }))
    expect(await screen.findByRole('table')).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Declare the perimeter' })).not.toBeInTheDocument()
    expect(screen.getByRole('status')).toHaveTextContent('Declared 1 new range.')
    expect(screen.getByText('This business unit holds 1 range of at most 1,024.')).toBeInTheDocument()
  })

  it('asks for an entry instead of sending an empty declaration, and clears the request once text is typed', async () => {
    renderPage()
    fireEvent.change(await screen.findByRole('textbox', { name: 'Ranges, one per line' }), { target: { value: '\n   \n' } })
    expect(textarea()).toHaveAttribute('aria-invalid', 'false')
    fireEvent.click(screen.getByRole('button', { name: 'Declare owned ranges' }))
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('Enter at least one IP address or CIDR prefix.')
    expect(declarePerimeterSeeds).not.toHaveBeenCalled()
    // The request belongs to the textarea, which says it is invalid.
    expect(textarea()).toHaveAttribute('aria-invalid', 'true')
    expect(alert.id).not.toBe('')
    expect(textarea().getAttribute('aria-describedby')?.split(' ')).toContain(alert.id)
    expect(textarea()).toHaveAccessibleDescription(/Enter at least one IP address or CIDR prefix\./)

    fireEvent.change(textarea(), { target: { value: '192.0.2.1' } })
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(textarea()).toHaveAttribute('aria-invalid', 'false')
    expect(textarea().getAttribute('aria-describedby')?.split(' ')).not.toContain(alert.id)
    expect(screen.getByText('1 of at most 256 entries')).toBeInTheDocument()
  })

  it('refuses more than 256 non-blank lines before sending them', async () => {
    renderPage()
    const lines = Array.from({ length: 257 }, (_, index) => `198.51.100.${index % 256}`)
    fireEvent.change(await screen.findByRole('textbox', { name: 'Ranges, one per line' }), { target: { value: ['', ...lines, ''].join('\n') } })
    expect(screen.getByRole('alert')).toHaveTextContent('Declare at most 256 entries at a time; this paste has 257.')
    expect(textarea()).toHaveAttribute('aria-invalid', 'true')
    const submit = screen.getByRole('button', { name: 'Declare owned ranges' })
    expect(submit).toBeDisabled()
    fireEvent.submit(submit.closest('form') as HTMLFormElement)
    expect(declarePerimeterSeeds).not.toHaveBeenCalled()

    fireEvent.change(textarea(), { target: { value: lines.slice(0, 256).join('\n') } })
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Declare owned ranges' })).toBeEnabled()
  })

  it('maps each refused entry back to its textarea line and saves nothing', async () => {
    vi.mocked(declarePerimeterSeeds).mockRejectedValue(new APIError('Some entries were refused; nothing was saved.', 'validation_failed', { entries: [
      { index: 1, value: 'example.com', reason: 'not an IP address or CIDR prefix' },
      { index: 3, value: '10.0.0.0/8', reason: 'already declared as authorized' },
    ] }, 400))
    renderPage()
    const value = '203.0.113.0/24 Edge\n\nexample.com DNS name\n198.51.100.0/24\n\n\n10.0.0.0/8 Corporate'
    fireEvent.change(await screen.findByRole('textbox', { name: 'Ranges, one per line' }), { target: { value } })
    fireEvent.click(screen.getByRole('button', { name: 'Declare owned ranges' }))
    const refused = await screen.findByRole('list', { name: 'Refused lines' })
    expect(within(refused).getAllByRole('listitem').map(item => item.textContent)).toEqual([
      'Line 3 example.com: not an IP address or CIDR prefix',
      'Line 7 10.0.0.0/8: already declared as authorized',
    ])
    expect(screen.getByRole('alert')).toHaveTextContent('Nothing was saved: 2 lines were refused. Fix them and declare again.')
    expect(textarea()).toHaveValue(value)
    expect(textarea()).toHaveAttribute('aria-invalid', 'true')
    expect(textarea().getAttribute('aria-describedby')).toContain(refused.id)
  })

  it('explains a refusal of the whole declaration', async () => {
    renderPage()
    const cases: [unknown, string][] = [
      [new APIError('limit', 'perimeter_limit', { limit: 1024, held: 1000, new: 30 }, 400), 'Nothing was saved. A business unit holds at most 1,024 ranges; this one holds 1,000, and this declaration would add 30.'],
      [new APIError('A business unit holds at most 1024 perimeter ranges; nothing was saved.', 'perimeter_limit', undefined, 400), 'Nothing was saved. A business unit holds at most 1024 perimeter ranges; nothing was saved.'],
      [new APIError('Declare between 1 and 256 entries.', 'validation_failed', { limit: 256 }, 400), 'Nothing was saved. Declare between 1 and 256 entries at a time.'],
      [new APIError('Some entries were refused; nothing was saved.', 'validation_failed', { entries: [] }, 400), 'Nothing was saved. Some entries were refused; nothing was saved.'],
      [new APIError('the action was not committed because the security audit could not be recorded', 'audit_unavailable', undefined, 503), 'Nothing was saved because the audit record could not be written. Try again later.'],
      [new APIError('', 'internal_error', undefined, 500), 'The ranges could not be declared.'],
      [new TypeError('Failed to fetch'), 'Failed to fetch'],
      ['offline', 'The ranges could not be declared.'],
    ]
    const input = await screen.findByRole('textbox', { name: 'Ranges, one per line' })
    for (const [cause, message] of cases) {
      vi.mocked(declarePerimeterSeeds).mockRejectedValueOnce(cause)
      fireEvent.change(input, { target: { value: '203.0.113.0/24' } })
      fireEvent.click(screen.getByRole('button', { name: 'Declare owned ranges' }))
      await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(message))
    }
    expect(screen.queryByRole('list', { name: 'Refused lines' })).not.toBeInTheDocument()
  })

  it('reports a declaration whose entries were all already declared', async () => {
    vi.mocked(declarePerimeterSeeds).mockResolvedValue({ created: 0, skipped: 2 })
    renderPage()
    fireEvent.change(await screen.findByRole('textbox', { name: 'Ranges, one per line' }), { target: { value: '203.0.113.0/24\n203.0.113.0/24' } })
    fireEvent.click(screen.getByRole('button', { name: 'Declare owned ranges' }))
    expect(await screen.findByText('No new ranges were declared. 2 already declared entries were skipped.')).toBeInTheDocument()
  })
})
