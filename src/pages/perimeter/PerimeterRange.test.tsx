/** @vitest-environment jsdom */

import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { Route, Routes, useLocation } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { APIError, getPerimeter, getPerimeterRange, getSession } from '../../api'
import type { PerimeterSuggestion } from '../../generated/api-types'
import { readPerimeterPrefill } from '../../perimeter-prefill'
import { blocks, fullTCPProtocol, perimeterMonitor, perimeterOverview, perimeterRange, perimeterRangeDetail, perimeterSuggestion, selectedTCPProtocol, udpProtocol } from '../../test/perimeter-fixtures'
import { renderWithProviders } from '../../test/test-utils'
import { PerimeterRangeView } from './PerimeterRange'

vi.mock('../../api', async () => {
  const actual = await vi.importActual<typeof import('../../api')>('../../api')
  return { ...actual, getPerimeter: vi.fn(), getPerimeterRange: vi.fn(), getSession: vi.fn() }
})

const administrator = ['jobs.read', 'jobs.write', 'perimeter.read', 'perimeter.manage']

function JobsNewProbe() {
  const location = useLocation()
  return <output data-testid="jobs-new">{JSON.stringify(location.state)}</output>
}

function renderDetail(permissions = administrator, id = 'range-1') {
  vi.mocked(getSession).mockResolvedValue({ role: 'operator', user_id: 'u1', username: 'alice', permissions, csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 } } as never)
  return renderWithProviders(<Routes>
    <Route path="/perimeter/ranges/:id" element={<PerimeterRangeView />} />
    <Route path="/jobs/new" element={<JobsNewProbe />} />
  </Routes>, { route: [`/perimeter/ranges/${id}`] })
}

function modeSection(title: string) {
  return screen.getByRole('region', { name: title })
}

describe('Perimeter range detail', () => {
  beforeEach(() => {
    vi.mocked(getPerimeterRange).mockResolvedValue(perimeterRangeDetail())
    vi.mocked(getPerimeter).mockResolvedValue(perimeterOverview())
  })
  afterEach(() => vi.clearAllMocks())

  it('shows the range, its monitors, its uncovered blocks, and its suggestions per mode', async () => {
    renderDetail()
    expect(screen.getByRole('status')).toHaveTextContent('Loading range…')
    expect(await screen.findByRole('heading', { level: 1, name: '203.0.113.0/24' })).toBeInTheDocument()
    expect(getPerimeterRange).toHaveBeenCalledWith('range-1')
    expect(getPerimeter).not.toHaveBeenCalled()
    expect(screen.getByRole('link', { name: '← Perimeter' })).toHaveAttribute('href', '/perimeter')
    expect(screen.getByText('Owned')).toBeInTheDocument()
    expect(screen.getByText('DC1 edge')).toBeInTheDocument()
    expect(screen.getByText(/Declared .* by alice/)).toBeInTheDocument()

    const summary = screen.getByRole('region', { name: 'Range coverage' })
    expect(Array.from(summary.querySelectorAll('.summary-card')).map(card => card.textContent)).toEqual([
      'Addresses256None excluded',
      'Full TCP covered50%128 of 256 addresses',
      'Any TCP covered100%256 of 256 addresses',
      'UDP covered0%0 of 256 addresses',
    ])

    const monitors = screen.getByRole('region', { name: 'Monitors touching this range' })
    expect(within(monitors).getByRole('link', { name: 'Edge TCP' })).toHaveAttribute('href', '/jobs/job-edge')
    expect(within(monitors).getByText('Covering')).toBeInTheDocument()
    expect(within(monitors).getByText('Fills full TCP, any TCP')).toBeInTheDocument()

    const uncovered = screen.getByRole('region', { name: 'Uncovered blocks' })
    expect(within(uncovered).getByRole('region', { name: 'Full TCP uncovered blocks' })).toHaveTextContent('1 uncovered block203.0.113.128/25')
    expect(within(uncovered).getByRole('region', { name: 'Any TCP uncovered blocks' })).toHaveTextContent('No uncovered addresses.')
    expect(within(uncovered).getByRole('region', { name: 'UDP uncovered blocks' })).toHaveTextContent('203.0.113.0/24')
    // What fills each bucket is visible text, not a tooltip.
    expect(Array.from(uncovered.querySelectorAll('.perimeter-bucket-legend > div')).map(item => item.textContent)).toEqual([
      'Full TCPTCP with Naabu discovery and Nmap confirmation, or Nmap only over ports 1–65535.',
      'Any TCPTCP with any engine and any ports, full TCP included.',
      'UDPUDP with any ports.',
    ])

    const suggestions = screen.getByRole('region', { name: 'Suggested monitors' })
    expect(within(suggestions).getByRole('note')).toHaveTextContent('A declared range is not an authorization: confirm you may scan these addresses')
    expect(within(suggestions).getByText(/Full TCP shows a lower-bound duration at the built-in Naabu rate/)).toBeInTheDocument()
    const full = modeSection('Full TCP')
    expect(full).toHaveTextContent('Up to 305 addresses per monitor')
    expect(full).toHaveTextContent('Monitor 1 of 1203.0.113.128/25128 addresses · 8,388,480 estimated probes · TCP ports 1-65535 · at least 2h 19m 49s at the built-in Naabu rate')
    expect(within(full).getByRole('button', { name: 'Create monitor' })).toBeInTheDocument()
    expect(modeSection('Selected TCP ports')).toHaveTextContent('No gaps to fill in this mode.')
    expect(within(modeSection('Selected TCP ports')).queryByRole('button')).not.toBeInTheDocument()
    expect(within(modeSection('UDP')).getByRole('button', { name: 'Create monitor' })).toBeInTheDocument()
  })

  it('opens the guided setup with the suggestion as a one-time prefill', async () => {
    renderDetail()
    fireEvent.click(within(await screen.findByRole('region', { name: 'UDP' })).getByRole('button', { name: 'Create monitor' }))
    const state = JSON.parse((await screen.findByTestId('jobs-new')).textContent ?? 'null')
    expect(state).toEqual({ perimeterPrefill: {
      name: 'Perimeter 203.0.113.0/24 · UDP',
      targets: ['203.0.113.0/24'],
      mode: 'udp',
      protocol: udpProtocol,
      addresses: 256,
      source: '203.0.113.0/24',
    } })
    expect(readPerimeterPrefill(state)).toEqual(state.perimeterPrefill)
  })

  it('shows a bounded coalesced alternative and opens its targets in guided setup', async () => {
    // The report offers the alternative only when it needs fewer targets or
    // monitors: here one /24 instead of two gaps-only blocks.
    const gapsOnly = perimeterSuggestion({ targets: ['203.0.113.64/26', '203.0.113.128/25'], addresses: 192, estimated_probes: 12_582_720 })
    const coalesced = perimeterSuggestion({
      targets: ['203.0.113.0/24'],
      addresses: 256,
      already_covered_addresses: 64,
      estimated_probes: 16_776_960,
    })
    vi.mocked(getPerimeterRange).mockResolvedValue(perimeterRangeDetail({
      uncovered: { full_tcp: blocks(['203.0.113.64/26', '203.0.113.128/25']), any_tcp: blocks([]), udp: blocks([]) },
      monitors_needed: { full_tcp: 1, selected_tcp: 0, udp: 0 },
      suggestions: [gapsOnly],
      coalesced_monitors_needed: { full_tcp: 1, selected_tcp: 0, udp: 0 },
      coalesced_suggestions: [coalesced],
    }))
    renderDetail()

    const full = await screen.findByRole('region', { name: 'Full TCP' })
    expect(within(full).getByRole('heading', { level: 4, name: 'Gaps-only option' })).toBeInTheDocument()
    const coalescedHeading = screen.getByRole('heading', { level: 4, name: 'Coalesced alternative' })
    const coalescedPlan = coalescedHeading.parentElement
    const coalescedAlternative = coalescedPlan?.parentElement
    expect(coalescedPlan).not.toBeNull()
    expect(coalescedAlternative).not.toBeNull()
    expect(within(coalescedAlternative!).getByText(/^Offered because it needs fewer targets in total, or fewer monitors, than the gaps-only option\. Targets may include already-covered addresses\./)).toBeInTheDocument()
    expect(within(coalescedPlan!).getByText(/Includes 64 already-covered addresses/)).toBeInTheDocument()
    fireEvent.click(within(coalescedPlan!).getByRole('button', { name: 'Create monitor' }))

    const state = JSON.parse((await screen.findByTestId('jobs-new')).textContent ?? 'null')
    expect(state.perimeterPrefill).toEqual({
      name: 'Perimeter 203.0.113.0/24 · full TCP',
      targets: ['203.0.113.0/24'],
      mode: 'full_tcp',
      protocol: fullTCPProtocol,
      addresses: 256,
      source: '203.0.113.0/24',
    })
  })

  it('withholds a coalesced alternative above 16 monitors without claiming it improves anything', async () => {
    vi.mocked(getPerimeterRange).mockResolvedValue(perimeterRangeDetail({
      coalesced_monitors_needed: { full_tcp: 17, selected_tcp: 0, udp: 0 },
      coalesced_suggestions_truncated: { full_tcp: true, selected_tcp: false, udp: false },
    }))
    renderDetail()

    const full = await screen.findByRole('region', { name: 'Full TCP' })
    const coalescedPlan = within(full).getByRole('heading', { level: 4, name: 'Coalesced alternative' }).parentElement!
    const coalescedAlternative = coalescedPlan.parentElement!
    expect(coalescedPlan).toHaveTextContent('Needs more than 16 monitors The complete coalesced option is too large to list or to compare with the gaps-only option.')
    expect(within(coalescedPlan).queryByRole('button')).not.toBeInTheDocument()
    expect(within(coalescedAlternative).getByText(/^Targets may include already-covered addresses\./)).toBeInTheDocument()
    expect(coalescedAlternative).not.toHaveTextContent('Offered because')
    expect(within(full).getAllByRole('button', { name: 'Create monitor' })).toHaveLength(1)
  })

  it('shows suggestions as text without jobs.write', async () => {
    renderDetail(['jobs.read', 'perimeter.read'])
    const full = await screen.findByRole('region', { name: 'Full TCP' })
    expect(within(full).queryByRole('button')).not.toBeInTheDocument()
    expect(full).toHaveTextContent('203.0.113.128/25')
    expect(full).toHaveTextContent('Creating a monitor needs permission to write jobs.')
  })

  it('states how many monitors a mode needs above 16, and when the budget is too low', async () => {
    const many: PerimeterSuggestion[] = Array.from({ length: 17 }, (_, index) => perimeterSuggestion({ mode: 'selected_tcp', targets: [`198.51.${index}.0/24`], addresses: 256, estimated_probes: 512, protocol: selectedTCPProtocol }))
    const listed: PerimeterSuggestion[] = Array.from({ length: 16 }, (_, index) => perimeterSuggestion({ targets: [`198.51.${index}.0/24`], addresses: 256, estimated_probes: 256 * 65_535 }))
    vi.mocked(getPerimeterRange).mockResolvedValue(perimeterRangeDetail({
      range: perimeterRange({ value: '198.51.0.0/16', addresses: 65536, coverage: { full_tcp: 0, any_tcp: 0, udp: 0 } }),
      monitors_needed: { full_tcp: 16, selected_tcp: 4097, udp: 0 },
      addresses_per_monitor: { full_tcp: 305, selected_tcp: 16, udp: 0 },
      suggestions: [...listed, ...many],
      suggestions_truncated: { full_tcp: false, selected_tcp: true, udp: false },
      budget_too_low: { full_tcp: false, selected_tcp: false, udp: true },
    }))
    renderDetail()
    const full = await screen.findByRole('region', { name: 'Full TCP' })
    expect(within(full).getAllByRole('button', { name: 'Create monitor' })).toHaveLength(16)
    expect(full).toHaveTextContent('Monitor 16 of 16')
    const selected = modeSection('Selected TCP ports')
    expect(selected).toHaveTextContent('Needs 4,097 monitors of up to 16 addresses each.')
    expect(within(selected).queryByRole('button')).not.toBeInTheDocument()
    const udp = modeSection('UDP')
    expect(within(udp).getByRole('status')).toHaveTextContent('The unit’s probe budget is too small for one address in this mode.')
    expect(udp).not.toHaveTextContent('per monitor')
    expect(within(udp).queryByRole('button')).not.toBeInTheDocument()
  })

  it('suggests nothing when every address of the range is excluded', async () => {
    vi.mocked(getPerimeterRange).mockResolvedValue(perimeterRangeDetail({
      range: perimeterRange({ excluded: 256, coverage: { full_tcp: 0, any_tcp: 0, udp: 0 } }),
      uncovered: { full_tcp: blocks([]), any_tcp: blocks([]), udp: blocks([]) },
      monitors_needed: { full_tcp: 0, selected_tcp: 0, udp: 0 },
      suggestions: [],
    }))
    renderDetail()
    const summary = await screen.findByRole('region', { name: 'Range coverage' })
    expect(within(summary).getAllByText('All addresses excluded')).toHaveLength(3)
    expect(within(summary).getByText('256 in scanner.target_exclusions')).toBeInTheDocument()
    expect(screen.getByText('All addresses excluded: there is nothing to suggest.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Create monitor' })).not.toBeInTheDocument()
  })

  it('shows every state, reason, and flag of the monitors that touch the range', async () => {
    vi.mocked(getPerimeterRange).mockResolvedValue(perimeterRangeDetail({
      monitors: [
        perimeterMonitor({ job_id: 'job-x', name: 'Excluded', state: 'excluded_target', reasons: ['paused', 'invalid_config', 'excluded_target'], protocols: [], dns_targets: 2 }),
        perimeterMonitor({ job_id: 'job-y', name: 'Stalled', stalled_cycle: true, host_discovery: true, dns_targets: 1, protocols: ['udp'] }),
        perimeterMonitor({ job_id: 'job-z', name: 'Paused UDP', state: 'paused', reasons: ['paused'], protocols: ['udp'] }),
      ],
    }))
    renderDetail(['perimeter.read'])
    const monitors = await screen.findByRole('region', { name: 'Monitors touching this range' })
    const [excluded, stalled, paused] = within(monitors).getAllByRole('listitem').filter(item => item.parentElement?.classList.contains('perimeter-monitor-list'))
    expect(within(excluded).getByText('Excluded target')).toBeInTheDocument()
    expect(excluded).toHaveTextContent('Paused: scheduled runs do not start it.')
    expect(excluded).toHaveTextContent('Invalid configuration: the stored job no longer passes the scan work estimate.')
    expect(excluded).toHaveTextContent('Excluded target: a target contains an address in scanner.target_exclusions')
    expect(excluded).toHaveTextContent('2 DNS-name targets, which never count as coverage')
    expect(excluded).toHaveTextContent('Fills no coverage bucket')
    expect(within(monitors).queryByRole('link')).not.toBeInTheDocument()
    expect(stalled).toHaveTextContent('Scan cycle stalled')
    expect(stalled).toHaveTextContent('Scans only hosts that answer host discovery')
    expect(stalled).toHaveTextContent('1 DNS-name target, which never counts as coverage')
    expect(stalled).toHaveTextContent('Fills UDP')
    // A monitor that cannot scan fills nothing, whatever its settings.
    expect(paused).toHaveTextContent('Set up for UDP; fills nothing while it cannot scan')
    expect(paused).not.toHaveTextContent('Fills UDP')
  })

  it('shows uncovered blocks with their truncation, collapsed after 24', async () => {
    const cidrs = Array.from({ length: 30 }, (_, index) => `198.51.100.${index * 2}/32`)
    vi.mocked(getPerimeterRange).mockResolvedValue(perimeterRangeDetail({ uncovered: { full_tcp: blocks(cidrs, 300), any_tcp: blocks([]), udp: blocks(['203.0.113.0/24']) } }))
    renderDetail()
    const full = await screen.findByRole('region', { name: 'Full TCP uncovered blocks' })
    expect(full).toHaveTextContent('300 uncovered blocks')
    expect(full).toHaveTextContent('The report lists 30 of 300 blocks.')
    expect(within(full).getAllByRole('listitem')).toHaveLength(24)
    const toggle = within(full).getByRole('button', { name: 'Show all 30 blocks' })
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    fireEvent.click(toggle)
    expect(within(full).getAllByRole('listitem')).toHaveLength(30)
    fireEvent.click(within(full).getByRole('button', { name: 'Show fewer blocks' }))
    expect(within(full).getAllByRole('listitem')).toHaveLength(24)
  })

  it('shows an IPv6 range as monitored counts with the max_job_hosts explanation and no suggestions', async () => {
    vi.mocked(getPerimeterRange).mockResolvedValue(perimeterRangeDetail({
      range: perimeterRange({ id: 'range-6', value: '2001:db8::/48', kind: 'authorized', label: '', family: 6, addresses: 0, excluded: 0, coverage: { full_tcp: 0, any_tcp: 0, udp: 0 }, ipv6_monitored: { full_tcp: 0, any_tcp: 256, udp: 0 } }),
      uncovered: { full_tcp: blocks(['2001:db8::/48']), any_tcp: blocks(['2001:db8::100/120', '2001:db8::200/119']), udp: blocks(['2001:db8::/48']) },
      monitors_needed: { full_tcp: 0, selected_tcp: 0, udp: 0 },
      suggestions: [],
    }))
    vi.mocked(getPerimeter).mockResolvedValue(perimeterOverview({ limits: { ...perimeterOverview().limits, max_job_hosts: 1_000_000 } }))
    renderDetail(administrator, 'range-6')
    expect(await screen.findByRole('heading', { level: 1, name: '2001:db8::/48' })).toBeInTheDocument()
    expect(screen.getByText('Authorized')).toBeInTheDocument()
    const summary = screen.getByRole('region', { name: 'Range coverage' })
    expect(summary).toHaveTextContent('IPv6')
    expect(summary).toHaveTextContent('Any TCP monitored256addresses monitored')
    expect(within(summary).queryByText(/%/)).not.toBeInTheDocument()
    expect(await screen.findByText(/One monitor scans at most 1,000,000 addresses \(scanner.max_job_hosts\), more than a \/109 and less than a \/108/)).toBeInTheDocument()
    expect(getPerimeter).toHaveBeenCalledOnce()
    expect(screen.queryByRole('region', { name: 'Suggested monitors' })).not.toBeInTheDocument()
    expect(screen.getByRole('region', { name: 'Any TCP uncovered blocks' })).toHaveTextContent('2 uncovered blocks')
  })

  it('explains an IPv6 range before the limits are known', async () => {
    vi.mocked(getPerimeterRange).mockResolvedValue(perimeterRangeDetail({ range: perimeterRange({ value: '2001:db8::/48', family: 6, addresses: 0 }), suggestions: [] }))
    vi.mocked(getPerimeter).mockRejectedValue(new APIError('boom', 'internal_error', undefined, 500))
    renderDetail()
    expect(await screen.findByText(/One monitor scans a limited number of addresses \(scanner.max_job_hosts\)/)).toBeInTheDocument()
  })

  it('says that an unknown range is not found, without a retry', async () => {
    vi.mocked(getPerimeterRange).mockRejectedValue(new APIError('perimeter range not found', 'not_found', undefined, 404))
    renderDetail(administrator, 'missing')
    expect(await screen.findByRole('alert')).toHaveTextContent('This range could not be found. It may have been removed.')
    // The page keeps its level-one heading while the range is unavailable (#1680).
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent('Range unavailable')
    expect(screen.queryByRole('button', { name: 'Retry' })).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: '← Perimeter' })).toHaveAttribute('href', '/perimeter')
  })

  it('says that a range removed while it is open is gone', async () => {
    const { client } = renderDetail()
    await screen.findByRole('heading', { level: 1, name: '203.0.113.0/24' })
    vi.mocked(getPerimeterRange).mockRejectedValue(new APIError('perimeter range not found', 'not_found', undefined, 404))
    await client.invalidateQueries({ queryKey: ['perimeter'] })
    expect(await screen.findByRole('alert')).toHaveTextContent('This range could not be found. It may have been removed.')
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent('Range unavailable')
    expect(screen.queryByRole('heading', { name: '203.0.113.0/24' })).not.toBeInTheDocument()
  })

  it('offers a retry when the range cannot be loaded, and keeps a loaded range when a refresh fails', async () => {
    vi.mocked(getPerimeterRange).mockRejectedValueOnce(new APIError('boom', 'internal_error', undefined, 500))
    const { client } = renderDetail()
    expect(await screen.findByRole('alert')).toHaveTextContent('This range could not be loaded.')
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent('Range unavailable')
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByRole('heading', { level: 1, name: '203.0.113.0/24' })).toBeInTheDocument()

    vi.mocked(getPerimeterRange).mockRejectedValueOnce(new APIError('boom', 'internal_error', undefined, 500))
    await client.refetchQueries({ queryKey: ['perimeter', 'range', 'range-1'] })
    expect(await screen.findByText('Could not refresh this range. Showing the last loaded detail.')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Retry refresh' }))
    await waitFor(() => expect(screen.queryByText('Could not refresh this range. Showing the last loaded detail.')).not.toBeInTheDocument())
  })

  it('refreshes with the overview: the detail key lies under the perimeter prefix', async () => {
    const { client } = renderDetail()
    await screen.findByRole('heading', { level: 1, name: '203.0.113.0/24' })
    expect(client.getQueryData(['perimeter', 'range', 'range-1'])).toBeDefined()
    vi.mocked(getPerimeterRange).mockResolvedValue(perimeterRangeDetail({ range: perimeterRange({ label: 'Renamed edge' }) }))
    await client.invalidateQueries({ queryKey: ['perimeter'] })
    expect(await screen.findByText('Renamed edge')).toBeInTheDocument()
  })
})
