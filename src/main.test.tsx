/** @vitest-environment jsdom */

import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react'
import { act } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { useQuery } from '@tanstack/react-query'
import { useLocation } from 'react-router-dom'
import { APIError, adminStatus, getPerimeter, getPerimeterRange, getSession, incidentInboxSummary, listEvents, listIncidents, listJobs, login, logout, recordActivity, scanSlotDemand, setupStatus } from './api'
import { formatDateTimeInTimeZone, setDisplayTimeZone } from './format'
import { AppContent, AuthRoutes, createQueryClient, Jobs, ProtectedApp, retryQuery, retryQueryDelay, Shell, unitBreadcrumb } from './main'
import { perimeterOverview, perimeterRangeDetail } from './test/perimeter-fixtures'
import { renderWithProviders } from './test/test-utils'

vi.mock('./api', async () => {
  const actual = await vi.importActual<typeof import('./api')>('./api')
  return { ...actual, acceptIncident: vi.fn(), adminStatus: vi.fn(), getPerimeter: vi.fn(), getPerimeterRange: vi.fn(), getSession: vi.fn(), incidentInboxSummary: vi.fn(), listEvents: vi.fn(), listIncidents: vi.fn(), listJobs: vi.fn(), login: vi.fn(), logout: vi.fn(), recordActivity: vi.fn(), scanSlotDemand: vi.fn(), setCSRF: vi.fn(), setupStatus: vi.fn(), suppressIncident: vi.fn() }
})

class EventSourceStub {
  static instances: EventSourceStub[] = []
  static CLOSED = 2
  readyState = 0
  onopen: (() => void) | null = null
  onerror: (() => void) | null = null
  onmessage: ((event: MessageEvent) => void) | null = null
  close = vi.fn()
  constructor() { EventSourceStub.instances.push(this) }
  emit(type: string, job_id?: string, details: Record<string, unknown> | string = {}) {
    const payload = typeof details === 'string' ? { reason: details } : details
    this.onmessage?.({ data: JSON.stringify({ ...payload, type, ...(job_id ? { job_id } : {}) }) } as MessageEvent)
  }
}

function CurrentPath() {
  return <output data-testid="current-path">{useLocation().pathname}</output>
}

function CurrentSearch() {
  return <output data-testid="current-search">{useLocation().search}</output>
}

describe('application shell', () => {
  beforeEach(() => {
    vi.mocked(adminStatus).mockResolvedValue({ version: 'v0.18.70', version_release_url: 'https://github.com/crypt0rr/EdgeWatch/releases/tag/v0.18.70', updates: { available: true, status: 'update_available', latest_version: 'v0.19.0', release_url: 'https://github.com/crypt0rr/EdgeWatch/releases/tag/v0.19.0' } } as never)
    vi.mocked(listEvents).mockResolvedValue({ events: [], pagination: { limit: 20, offset: 0, total: 0, has_more: false, next_offset: null } })
    vi.mocked(incidentInboxSummary).mockResolvedValue({ active_count: 0 })
    vi.mocked(listIncidents).mockResolvedValue({ incidents: [], truncated: false, active_count: 0, server_now: new Date().toISOString(), next_follow_up_at: null, pagination: { limit: 1, offset: 0, total: 0, has_more: false, next_offset: null } })
    vi.mocked(listJobs).mockResolvedValue({ jobs: [] } as never)
    vi.mocked(scanSlotDemand).mockResolvedValue({ enabled_jobs: 0, history_jobs: 0, lower_bound_jobs: 0, unestimated_jobs: 0, slots: 1, estimated_slot_seconds_per_day: 0, capacity_slot_seconds_per_day: 86_400, utilization_percent: 0, over_capacity: false })
    vi.mocked(getSession).mockResolvedValue({ role: 'administrator', user_id: 'admin', username: 'admin', permissions: ['jobs.write', 'incidents.read', 'incidents.manage'], csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 } } as never)
    vi.mocked(login).mockResolvedValue({ role: 'administrator', username: 'admin', permissions: ['jobs.write'], csrf_token: '', totp_required: false } as never)
    vi.mocked(logout).mockResolvedValue(undefined)
    vi.mocked(recordActivity).mockResolvedValue(undefined)
    vi.mocked(setupStatus).mockResolvedValue({ configured: true } as never)
    vi.mocked(getPerimeter).mockResolvedValue(perimeterOverview())
    vi.mocked(getPerimeterRange).mockResolvedValue(perimeterRangeDetail())
    EventSourceStub.instances = []
    vi.stubGlobal('EventSource', EventSourceStub)
  })

  afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); vi.clearAllMocks(); setDisplayTimeZone(undefined) })

  it('renders permission-aware navigation, update indicator, and incident count', async () => {
    vi.mocked(incidentInboxSummary).mockResolvedValue({ active_count: 3 })
    const onLogout = vi.fn()
    renderWithProviders(<Shell displayName="Alice" role="administrator" permissions={['overview.read', 'jobs.read', 'hosts.read', 'incidents.read', 'scans.read', 'stream.read']} onLogout={onLogout} />)

    expect(screen.getByText('Alice')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Overview' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Activity' })).toBeInTheDocument()
    await waitFor(() => expect(screen.getByLabelText('3 active incidents')).toBeInTheDocument())
    expect(incidentInboxSummary).toHaveBeenCalledOnce()
    expect(listIncidents).not.toHaveBeenCalledWith(0, 1)
    const incidentsLink = screen.getByRole('link', { name: /Incidents.*3 active incidents/ })
    expect(incidentsLink).toHaveAccessibleName(/Incidents.*3 active incidents/)
    expect(screen.getByRole('link', { name: /Update available/ })).toHaveAttribute('href', 'https://github.com/crypt0rr/EdgeWatch/releases/tag/v0.19.0')
    const versionLink = screen.getByRole('link', { name: 'Release notes for EdgeWatch v0.18.70' })
    expect(versionLink).toHaveAttribute('href', 'https://github.com/crypt0rr/EdgeWatch/releases/tag/v0.18.70')
    expect(versionLink).toHaveAttribute('target', '_blank')
    expect(versionLink).toHaveAttribute('rel', 'noopener noreferrer')
    expect(versionLink).toHaveTextContent('EdgeWatch v0.18.70')
    expect(screen.getByRole('link', { name: 'Source code' })).toHaveAttribute('href', '/source')
    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }))
    expect(onLogout).toHaveBeenCalledOnce()
  })

  it('limits viewer navigation while showing the authenticated version and update indicator', async () => {
    renderWithProviders(<Shell displayName="Viewer" role="viewer" permissions={['jobs.read']} onLogout={vi.fn()} />)
    expect(screen.getByRole('link', { name: 'Jobs' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Security' })).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Overview' })).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Incidents' })).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Notifications' })).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Activity' })).not.toBeInTheDocument()
    await waitFor(() => expect(screen.getByText('EdgeWatch v0.18.70')).toBeInTheDocument())
    expect(screen.getByRole('link', { name: /Update available/ })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Source code' })).toHaveAttribute('href', '/source')
    expect(screen.getByRole('status', { name: 'Live updates unavailable' })).toHaveClass('unavailable')
    expect(adminStatus).toHaveBeenCalledOnce()
  })

  it('uses stable page labels for breadcrumbs and excludes record IDs and encoded addresses', () => {
    const links = [{ to: '/jobs', label: 'Jobs' }, { to: '/hosts', label: 'Hosts' }, { to: '/scanner-profiles', label: 'Scanner profiles' }]
    expect(unitBreadcrumb('/scanner-profiles', links)).toBe('Scanner profiles')
    expect(unitBreadcrumb('/public-dashboard', [{ to: '/public-dashboard', label: 'Public status' }])).toBe('Public status')
    expect(unitBreadcrumb('/jobs/job-123/scans/scan-456', links)).toBe('Jobs / Scan')
    expect(unitBreadcrumb('/jobs/job-123/baseline/hosts/2001%3Adb8%3A%3A1', links)).toBe('Jobs / Baseline host')
    expect(unitBreadcrumb('/scans/scan-456/hosts/2001%3Adb8%3A%3A1', links)).toBe('Hosts / Scan host')
    expect(unitBreadcrumb('/perimeter', [{ to: '/perimeter', label: 'Perimeter' }])).toBe('Perimeter')
    expect(unitBreadcrumb('/perimeter/ranges/range-123', [{ to: '/perimeter', label: 'Perimeter' }])).toBe('Perimeter / Range')
  })

  it('offers the Perimeter page and its range detail only with perimeter.read, and keeps Perimeter current on a range', async () => {
    const operator = ['jobs.read', 'jobs.write', 'perimeter.read']
    vi.mocked(getSession).mockResolvedValue({ role: 'operator', user_id: 'operator', username: 'operator', permissions: operator, csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 } } as never)
    const page = renderWithProviders(<><Shell displayName="Operator" role="operator" permissions={operator} onLogout={vi.fn()} /><CurrentPath /></>, { route: ['/perimeter'] })
    const link = screen.getByRole('link', { name: 'Perimeter' })
    expect(link).toHaveAttribute('href', '/perimeter')
    expect(link).toHaveAttribute('aria-current', 'page')
    expect(await screen.findByRole('heading', { level: 1, name: 'Perimeter' })).toBeInTheDocument()
    expect(document.title).toBe('Perimeter · EdgeWatch')
    fireEvent.click(await screen.findByRole('link', { name: '203.0.113.0/24' }))
    expect(await screen.findByRole('heading', { level: 1, name: '203.0.113.0/24' })).toBeInTheDocument()
    expect(screen.getByTestId('current-path')).toHaveTextContent('/perimeter/ranges/range-1')
    expect(screen.getByRole('link', { name: 'Perimeter' })).toHaveAttribute('aria-current', 'page')
    expect(screen.getByRole('link', { name: 'Jobs' })).not.toHaveAttribute('aria-current')
    expect(screen.getByLabelText('Breadcrumb: Perimeter / Range')).toBeInTheDocument()
    page.unmount()
    vi.mocked(getPerimeter).mockClear()
    vi.mocked(getPerimeterRange).mockClear()

    // A viewer holds no perimeter.read: no navigation item, and both routes
    // lead to the jobs, the console's fallback, without reading the report.
    for (const path of ['/perimeter', '/perimeter/ranges/range-1']) {
      const view = renderWithProviders(<><Shell displayName="Viewer" role="viewer" permissions={['jobs.read']} onLogout={vi.fn()} /><CurrentPath /></>, { route: [path] })
      await waitFor(() => expect(screen.getByTestId('current-path')).toHaveTextContent(/^\/jobs$/))
      expect(screen.queryByRole('link', { name: 'Perimeter' })).not.toBeInTheDocument()
      view.unmount()
    }
    const security = renderWithProviders(<><Shell displayName="Nobody" role="viewer" permissions={[]} onLogout={vi.fn()} /><CurrentPath /></>, { route: ['/perimeter'] })
    await waitFor(() => expect(screen.getByTestId('current-path')).toHaveTextContent(/^\/security$/))
    security.unmount()
    expect(getPerimeter).not.toHaveBeenCalled()
    expect(getPerimeterRange).not.toHaveBeenCalled()
  })

  it('provides a skip link, marks the current page, names the document, and focuses main after navigation', async () => {
    renderWithProviders(<Shell displayName="Admin" role="administrator" permissions={['jobs.read', 'hosts.read', 'stream.read']} onLogout={vi.fn()} />, { route: ['/jobs'] })
    expect(screen.getByRole('link', { name: 'Skip to content' })).toHaveAttribute('href', '#main-content')
    expect(screen.getByRole('link', { name: 'Jobs' })).toHaveAttribute('aria-current', 'page')
    expect(screen.getByLabelText('Breadcrumb: Jobs')).toBeInTheDocument()
    expect(document.title).toBe('Jobs · EdgeWatch')
    fireEvent.click(screen.getByRole('link', { name: 'Hosts' }))
    await waitFor(() => expect(document.getElementById('main-content')).toHaveFocus())
    expect(screen.getByRole('link', { name: 'Hosts' })).toHaveAttribute('aria-current', 'page')
    expect(screen.getByLabelText('Breadcrumb: Hosts')).toBeInTheDocument()
    expect(document.title).toBe('Hosts · EdgeWatch')
  })

  it('preserves focus in the Activity job filter when the query string changes', async () => {
    vi.mocked(listJobs).mockResolvedValue({ jobs: [{ id: 'job-1', revision: 1, enabled: true, archived: false, job: { name: 'Production' }, baseline: { pending: 0 } }] } as never)
    renderWithProviders(<><Shell displayName="Admin" role="administrator" permissions={['jobs.read', 'scans.read']} onLogout={vi.fn()} /><CurrentSearch /></>, { route: ['/activity'] })

    const filter = await screen.findByRole('combobox', { name: 'Filter activity by job' })
    await screen.findByRole('option', { name: 'Production' })
    filter.focus()
    expect(document.activeElement).toBe(filter)
    fireEvent.change(filter, { target: { value: 'job-1' } })
    await waitFor(() => expect(screen.getByTestId('current-search')).toHaveTextContent('job_id=job-1'))
    expect(document.activeElement).toBe(filter)
  })

  it('keeps the protected shell loading while the authenticated session is still pending', async () => {
    vi.mocked(setupStatus).mockResolvedValueOnce({ configured: true } as never)
    let resolveSession!: (session: unknown) => void
    vi.mocked(getSession).mockReturnValueOnce(new Promise(resolve => { resolveSession = resolve }) as never)
    renderWithProviders(<ProtectedApp onLogout={async () => {}} />)

    await waitFor(() => expect(screen.getByText('Loading EdgeWatch…')).toBeInTheDocument())
    await act(async () => resolveSession({ role: 'viewer', user_id: 'viewer', username: 'viewer', permissions: ['jobs.read'], csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 } }))
    await waitFor(() => expect(screen.getByText('EdgeWatch v0.18.70')).toBeInTheDocument())
  })

  it('redirects protected-app setup and expired-session states without a public version', async () => {
    vi.mocked(setupStatus).mockResolvedValueOnce({ configured: false } as never)
    vi.mocked(getSession).mockResolvedValueOnce({ role: 'viewer', user_id: 'viewer', username: 'viewer', permissions: ['jobs.read'], csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 } } as never)
    const onLogout = async () => {}
    const setupView = renderWithProviders(<><ProtectedApp onLogout={onLogout} /><CurrentPath /></>, { route: ['/console'] })
    await waitFor(() => expect(screen.getByTestId('current-path')).toHaveTextContent('/setup'))
    setupView.unmount()

    vi.mocked(setupStatus).mockResolvedValueOnce({ configured: true } as never)
    vi.mocked(getSession).mockRejectedValueOnce(new Error('unauthenticated'))
    renderWithProviders(<><ProtectedApp onLogout={onLogout} /><CurrentPath /></>, { route: ['/console'] })
    await waitFor(() => expect(screen.getByTestId('current-path')).toHaveTextContent('/login'))
  })

  it('records real user activity and coalesces rapid pointer and keyboard events', async () => {
    renderWithProviders(<Shell displayName="Admin" role="administrator" permissions={['jobs.read']} onLogout={vi.fn()} />)
    fireEvent.pointerDown(document)
    fireEvent.keyDown(document, { key: 'a' })
    fireEvent.pointerDown(document)
    await waitFor(() => expect(recordActivity).toHaveBeenCalledOnce())
  })

  it('invalidates the affected queries for live events and falls back on malformed events', async () => {
    const { client } = renderWithProviders(<Shell displayName="Admin" role="administrator" permissions={['overview.read', 'jobs.read', 'stream.read']} onLogout={vi.fn()} />)
    const invalidate = vi.spyOn(client, 'invalidateQueries')
    const skipped = vi.fn()
    window.addEventListener('edgewatch:scan-skipped', skipped)
    await waitFor(() => expect(EventSourceStub.instances).toHaveLength(1))
    const stream = EventSourceStub.instances[0]
    const liveStatus = screen.getByRole('status', { name: 'Connecting…' })
    expect(liveStatus.querySelector('.status-dot-label')).not.toHaveAttribute('aria-hidden')
    act(() => stream.emit('scan.completed', 'job-9'))
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['active-scans'] })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['jobs'] })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['job', 'job-9'] })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['perimeter'] })
    invalidate.mockClear()
    // The perimeter report follows its declarations, every scan outcome, every
    // job lifecycle change, the silence watchdog, and a discarded cycle,
    // without a full refresh.
    for (const type of [
      'perimeter.updated',
      'scan.started', 'scan.completed', 'scan-paused', 'scan-recovered', 'scan-failure', 'scan-incomplete', 'scan-canceled', 'scan-interrupted', 'scan-anomaly', 'scan-budget-exceeded',
      'job.created', 'job.updated', 'job.archived', 'job.restored', 'job.deleted', 'job.paused', 'job.resumed',
      'job-silent',
      'scan.cycle_discarded',
    ]) {
      invalidate.mockClear()
      act(() => stream.emit(type, 'job-9'))
      expect(invalidate, type).toHaveBeenCalledWith({ queryKey: ['perimeter'] })
      expect(invalidate, type).not.toHaveBeenCalledWith()
    }
    invalidate.mockClear()
    act(() => stream.emit('perimeter.updated'))
    expect(invalidate.mock.calls).toEqual([[{ queryKey: ['perimeter'] }]])
    invalidate.mockClear()
    act(() => stream.emit('changes-detected', 'job-9'))
    expect(invalidate).not.toHaveBeenCalledWith({ queryKey: ['perimeter'] })
    invalidate.mockClear()
    act(() => stream.emit('scan-interrupted', 'job-9'))
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['activity-events'] })
    expect(invalidate).not.toHaveBeenCalledWith()
    for (const [type, key] of [
      ['job.paused', ['job', 'job-9']],
      ['job.resumed', ['jobs']],
      ['change-window.updated', ['job-change-windows', 'job-9']],
      ['job-silent', ['activity-events']],
      ['baseline-approved', ['job-baseline-overview', 'job-9']],
      ['baseline-reset', ['baseline-hosts', 'job-9']],
      ['baseline-complete', ['job', 'job-9']],
      ['baseline-updated', ['job-pending-changes', 'job-9']],
      ['baseline-stalled', ['scan-cycle', 'job-9']],
      ['scan.cancellation_requested', ['active-scans']],
      ['scan.cycle_discarded', ['scan-cycle', 'job-9']],
      ['scanner-profile.changed', ['scanner-profiles']],
    ] as const) {
      invalidate.mockClear()
      act(() => stream.emit(type, 'job-9'))
      expect(invalidate, type).toHaveBeenCalledWith({ queryKey: key })
      expect(invalidate, type).not.toHaveBeenCalledWith()
    }
    invalidate.mockClear()
    act(() => stream.emit('change-window.updated', 'job-9'))
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['jobs'] })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['job', 'job-9'] })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['job-change-windows', 'job-9'] })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['job-change-window', 'job-9'] })
    invalidate.mockClear()
    act(() => stream.emit('scan-budget-exceeded', 'job-9'))
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['activity-events'] })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['job', 'job-9'] })
    expect(invalidate).not.toHaveBeenCalledWith()
    act(() => stream.emit('scan.skipped', 'job-9', 'paused'))
    expect(skipped).toHaveBeenCalledWith(expect.objectContaining({ detail: { job_id: 'job-9', reason: 'paused' } }))
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['active-scans'] })
    act(() => stream.onmessage?.({ data: '{not-json' } as MessageEvent))
    expect(invalidate).toHaveBeenCalledWith()
    act(() => stream.emit('application.update_status'))
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['admin-status'] })
    invalidate.mockClear()
    act(() => stream.emit('incident.review.updated', 'job-9'))
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['incidents'] })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['job', 'job-9'] })
    act(() => {
      for (const type of ['changes-detected', 'changes-reminder', 'changes-recovered', 'incident-opened', 'incident-closed', 'incident-accepted', 'incident-suppressed', 'incident.review.updated']) stream.emit(type, 'job-9')
      for (const type of ['job.created', 'job.updated', 'job.archived', 'job.restored', 'job.deleted']) stream.emit(type, 'job-9')
      stream.emit('notification.changed')
      stream.emit('refresh_required')
      stream.emit('unrecognised-event')
      stream.onopen?.()
    })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['activity-events'] })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['jobs'] })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['job-pending-changes', 'job-9'] })
    await waitFor(() => expect(screen.getByRole('status', { name: 'Live updates' })).toHaveClass('live'))
    expect(liveStatus.querySelector('.status-dot-label')).toHaveTextContent('Live updates')
    act(() => stream.onerror?.())
    await waitFor(() => expect(screen.getByRole('status', { name: 'Reconnecting…' })).toHaveClass('reconnecting'))
    expect(liveStatus.querySelector('.status-dot-label')).toHaveTextContent('Reconnecting…')
    window.removeEventListener('edgewatch:scan-skipped', skipped)
  })

  it('recreates a stream the browser closed and refreshes queries when it reopens', async () => {
    vi.useFakeTimers()
    const { client } = renderWithProviders(<Shell displayName="Viewer" role="viewer" permissions={['stream.read']} onLogout={vi.fn()} />, { route: ['/security'] })
    const invalidate = vi.spyOn(client, 'invalidateQueries')
    expect(EventSourceStub.instances).toHaveLength(1)
    const first = EventSourceStub.instances[0]
    act(() => first.onopen?.())
    invalidate.mockClear()

    first.readyState = EventSourceStub.CLOSED
    act(() => first.onerror?.())
    expect(screen.getByRole('status', { name: 'Reconnecting…' })).toBeInTheDocument()
    await act(async () => { await vi.advanceTimersByTimeAsync(999) })
    expect(EventSourceStub.instances).toHaveLength(1)
    await act(async () => { await vi.advanceTimersByTimeAsync(1) })
    expect(EventSourceStub.instances).toHaveLength(2)

    invalidate.mockClear()
    act(() => EventSourceStub.instances[1].onopen?.())
    expect(invalidate).toHaveBeenCalledOnce()
    expect(invalidate).toHaveBeenCalledWith()
    expect(screen.getByRole('status', { name: 'Live updates' })).toHaveClass('live')
  })

  it('refreshes pending-confirmation counts after scan and incident events', async () => {
    const jobList = (pending: number) => ({ jobs: [{
      id: 'job-1', revision: 1, enabled: true, archived: false, security_hash: 'hash', created_at: '', updated_at: '',
      job: { name: 'Live pending job' }, baseline: { status: 'ready', pending },
    }] })
    const snapshots = [jobList(0), jobList(1), jobList(2)]
    vi.mocked(listJobs).mockImplementation(async () => (snapshots.shift() ?? jobList(2)) as never)
    const { client } = renderWithProviders(<Shell displayName="Admin" role="administrator" permissions={['jobs.read', 'scans.read', 'stream.read']} onLogout={vi.fn()} />, { route: ['/activity'] })
    const invalidate = vi.spyOn(client, 'invalidateQueries')
    await waitFor(() => expect(listJobs).toHaveBeenCalledTimes(1))
    await waitFor(() => expect(screen.getByText('No changes are awaiting confirmation.')).toBeInTheDocument())
    await waitFor(() => expect(EventSourceStub.instances).toHaveLength(1))
    const stream = EventSourceStub.instances[0]

    act(() => stream.emit('scan.completed', 'job-1'))
    await waitFor(() => expect(screen.getByRole('button', { name: 'Show 1 pending change' })).toBeInTheDocument())
    expect(listJobs).toHaveBeenCalledTimes(2)

    act(() => stream.emit('changes-detected', 'job-1'))
    await waitFor(() => expect(screen.getByRole('button', { name: 'Show 2 pending changes' })).toBeInTheDocument())
    expect(listJobs).toHaveBeenCalledTimes(3)
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['jobs'] })
  })

  it('stops reconnecting and explains when the account stream limit is reached', async () => {
    renderWithProviders(<Shell displayName="Admin" role="administrator" permissions={['jobs.read', 'stream.read']} onLogout={vi.fn()} />)
    await waitFor(() => expect(EventSourceStub.instances).toHaveLength(1))
    const stream = EventSourceStub.instances[0]

    act(() => stream.emit('stream_limit', undefined, { reason: 'too many live streams for this session', retry_after: 5 }))

    const status = screen.getByRole('status', { name: 'Live updates limited' })
    expect(stream.close).toHaveBeenCalledOnce()
    expect(status).toHaveClass('limited')
    expect(status).toHaveAttribute('title', 'Live updates are limited for this account. Close another EdgeWatch tab, then reload this page to reconnect.')

    act(() => {
      stream.onerror?.()
      stream.onopen?.()
    })
    expect(screen.getByRole('status', { name: 'Live updates limited' })).toBeInTheDocument()
    expect(EventSourceStub.instances).toHaveLength(1)
  })

  it.each([
    { reason: 'too many live streams for this business unit', description: 'this business unit has reached its live-stream capacity' },
    { reason: 'too many live streams', description: 'EdgeWatch has reached its live-stream capacity' },
  ])('retries automatically after a shared stream limit: $reason', async ({ reason, description }) => {
    vi.useFakeTimers()
    renderWithProviders(<Shell displayName="Viewer" role="viewer" permissions={['stream.read']} onLogout={vi.fn()} />)
    expect(EventSourceStub.instances).toHaveLength(1)
    const firstStream = EventSourceStub.instances[0]

    act(() => firstStream.emit('stream_limit', undefined, { reason, retry_after: 5 }))

    const status = screen.getByRole('status', { name: 'Live updates limited' })
    expect(firstStream.close).toHaveBeenCalledOnce()
    expect(status.getAttribute('title')).toContain(description)
    expect(status.getAttribute('title')).toContain('Retrying automatically.')
    await act(async () => { vi.advanceTimersByTime(4_999) })
    expect(EventSourceStub.instances).toHaveLength(1)
    await act(async () => { vi.advanceTimersByTime(1) })
    expect(EventSourceStub.instances).toHaveLength(2)

    act(() => EventSourceStub.instances[1].onopen?.())
    expect(screen.getByRole('status', { name: 'Live updates' })).toBeInTheDocument()
  })

  it('backs off exponentially after repeated shared capacity refusals', async () => {
    vi.useFakeTimers()
    renderWithProviders(<Shell displayName="Viewer" role="viewer" permissions={['stream.read']} onLogout={vi.fn()} />)
    const reason = 'too many live streams for this business unit'
    act(() => EventSourceStub.instances[0].emit('stream_limit', undefined, { reason, retry_after: 5 }))
    await act(async () => { vi.advanceTimersByTime(5_000) })
    expect(EventSourceStub.instances).toHaveLength(2)

    act(() => EventSourceStub.instances[1].emit('stream_limit', undefined, { reason, retry_after: 5 }))
    await act(async () => { vi.advanceTimersByTime(9_999) })
    expect(EventSourceStub.instances).toHaveLength(2)
    await act(async () => { vi.advanceTimersByTime(1) })
    expect(EventSourceStub.instances).toHaveLength(3)

    act(() => EventSourceStub.instances[2].emit('stream_limit', undefined, { reason, retry_after: 5 }))
    await act(async () => { vi.advanceTimersByTime(19_999) })
    expect(EventSourceStub.instances).toHaveLength(3)
    await act(async () => { vi.advanceTimersByTime(1) })
    expect(EventSourceStub.instances).toHaveLength(4)

    for (const delaySeconds of [40, 80, 160, 300, 300]) {
      const currentCount = EventSourceStub.instances.length
      act(() => EventSourceStub.instances[currentCount - 1].emit('stream_limit', undefined, { reason, retry_after: 5 }))
      await act(async () => { vi.advanceTimersByTime(delaySeconds * 1_000 - 1) })
      expect(EventSourceStub.instances).toHaveLength(currentCount)
      await act(async () => { vi.advanceTimersByTime(1) })
      expect(EventSourceStub.instances).toHaveLength(currentCount + 1)
    }
  })

  it('cancels a pending capacity retry when the shell unmounts', async () => {
    vi.useFakeTimers()
    const { unmount } = renderWithProviders(<Shell displayName="Viewer" role="viewer" permissions={['stream.read']} onLogout={vi.fn()} />)
    act(() => EventSourceStub.instances[0].emit('stream_limit', undefined, { reason: 'too many live streams', retry_after: 5 }))
    unmount()
    await act(async () => { vi.advanceTimersByTime(5_000) })
    expect(EventSourceStub.instances).toHaveLength(1)
  })

  it('shows the version as plain text when the build has no published release', async () => {
    vi.mocked(adminStatus).mockResolvedValue({ version: 'dev', updates: { available: false, status: 'development_build' } } as never)
    renderWithProviders(<Shell displayName="Viewer" role="viewer" permissions={['jobs.read']} onLogout={vi.fn()} />)
    await waitFor(() => expect(screen.getByText('EdgeWatch dev')).toBeInTheDocument())
    expect(screen.queryByRole('link', { name: /Release notes for EdgeWatch/ })).not.toBeInTheDocument()
  })

  it('shows unavailable incident counts and handles status failures without hiding navigation', async () => {
    vi.mocked(incidentInboxSummary).mockRejectedValue(new Error('incident service unavailable'))
    vi.mocked(adminStatus).mockRejectedValue(new Error('status unavailable'))
    renderWithProviders(<Shell displayName="Operator" role="operator" permissions={['overview.read', 'incidents.read', 'jobs.read']} onLogout={vi.fn()} />)
    await waitFor(() => expect(screen.getByLabelText('? Active incident count unavailable; retrying')).toBeInTheDocument())
    const incidentsLink = screen.getByRole('link', { name: /Incidents.*\?.*Active incident count unavailable; retrying/ })
    expect(incidentsLink).toHaveAccessibleName(/Incidents.*\?.*Active incident count unavailable; retrying/)
    expect(incidentsLink).toHaveClass('nav-link-alert')
    expect(screen.getByRole('link', { name: 'Jobs' })).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: /Update available/ })).not.toBeInTheDocument()
  })

  it('supports keyboard focus and escape handling for the mobile drawer', async () => {
    vi.stubGlobal('matchMedia', vi.fn().mockReturnValue({ matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn() }))
    renderWithProviders(<Shell displayName="Admin" role="administrator" permissions={['jobs.read']} onLogout={vi.fn()} />)
    const open = screen.getByRole('button', { name: 'Open navigation' })
    fireEvent.click(open)
    await waitFor(() => expect(screen.getAllByRole('button', { name: 'Close navigation' }).length).toBeGreaterThan(0))
    fireEvent.keyDown(document, { key: 'Escape' })
    await waitFor(() => expect(screen.getByRole('button', { name: 'Open navigation' })).toHaveFocus())
  })

  it('traps focus at both ends of the mobile drawer and closes from the backdrop', async () => {
    vi.stubGlobal('matchMedia', vi.fn().mockReturnValue({ matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn() }))
    renderWithProviders(<Shell displayName="Admin" role="administrator" permissions={['jobs.read', 'incidents.read']} onLogout={vi.fn()} />)
    fireEvent.click(screen.getByRole('button', { name: 'Open navigation' }))
    await waitFor(() => expect(screen.getByRole('dialog')).toBeInTheDocument())
    const drawer = screen.getByRole('dialog')
    const focusables = Array.from(drawer.querySelectorAll<HTMLElement>('a[href],button:not([disabled])'))
    expect(focusables.length).toBeGreaterThan(1)
    focusables[focusables.length - 1].focus()
    fireEvent.keyDown(document, { key: 'Tab' })
    expect(document.activeElement).toBe(focusables[0])
    focusables[0].focus()
    fireEvent.keyDown(document, { key: 'Tab', shiftKey: true })
    expect(document.activeElement).toBe(focusables[focusables.length - 1])
    fireEvent.click(screen.getByRole('dialog').querySelector('button.drawer-close')!)
    await waitFor(() => expect(screen.getByRole('button', { name: 'Open navigation' })).toHaveFocus())
  })

  it('supports legacy matchMedia listeners and closes an open drawer when switching to desktop', async () => {
    const listeners: Array<() => void> = []
    vi.stubGlobal('matchMedia', vi.fn().mockReturnValue({ matches: true, addListener: (listener: () => void) => listeners.push(listener), removeListener: vi.fn() }))
    renderWithProviders(<Shell displayName="Admin" role="administrator" permissions={['jobs.read']} onLogout={vi.fn()} />)
    fireEvent.click(screen.getByRole('button', { name: 'Open navigation' }))
    await waitFor(() => expect(screen.getByRole('dialog')).toBeInTheDocument())
    expect(document.body.style.overflow).toBe('hidden')
    const media = vi.mocked(window.matchMedia).mock.results[0]?.value as MediaQueryList & { matches: boolean }
    Object.defineProperty(media, 'matches', { value: false, configurable: true })
    act(() => listeners.forEach(listener => listener()))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(document.body.style.overflow).toBe('')
  })

  it('renders job lists, archived states, and creation controls across loading, error, and empty paths', async () => {
    vi.mocked(listJobs).mockResolvedValue({ jobs: [{ id: 'job-1', revision: 2, enabled: true, archived: false, job: { name: 'TCP monitor', targets: ['198.51.100.10'], tcp: { ports: '22-23' }, baseline: { status: 'complete' }, schedule: '* * * * *' }, baseline: { status: 'complete', baseline_samples: 1 } }, { id: 'job-2', revision: 1, enabled: false, archived: true, job: { name: 'Old monitor', targets: ['198.51.100.11'], udp: { ports: '53' }, schedule: '0 * * * *' }, baseline: { status: 'learning', samples: 0 } }, { id: 'job-3', revision: 1, enabled: true, archived: false, job: { name: 'Stalled monitor', targets: ['198.51.100.12'], tcp: { ports: '443' }, schedule: '30 * * * *' }, baseline: { status: 'stalled', incomplete_attempts: 2 } }] } as never)
    renderWithProviders(<Jobs />)
    await waitFor(() => expect(screen.getByRole('heading', { name: 'TCP monitor' })).toBeInTheDocument())
    expect(screen.getByText('Archived')).toBeInTheDocument()
    expect(screen.getByText('⚠ Baseline stalled')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /New job/ }))

    cleanup()
    vi.mocked(listJobs).mockRejectedValueOnce(new Error('jobs unavailable'))
    renderWithProviders(<Jobs />)
    await waitFor(() => expect(screen.getByText('Could not load jobs.')).toBeInTheDocument())
    vi.mocked(listJobs).mockResolvedValueOnce({ jobs: [] } as never)
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    await waitFor(() => expect(screen.getByText('No jobs yet')).toBeInTheDocument())
    cleanup()
    vi.mocked(listJobs).mockResolvedValueOnce({ jobs: [] } as never)
    vi.mocked(getSession).mockResolvedValueOnce({ role: 'viewer', user_id: 'viewer', username: 'viewer', permissions: [], csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 } } as never)
    renderWithProviders(<Jobs />)
    await waitFor(() => expect(screen.getByText('No jobs configured')).toBeInTheDocument())
  })

  it('shows each job’s latest change window, reason, end time, counts, and review state', async () => {
    const base = { revision: 1, enabled: true, archived: false, job: { targets: [], schedule: '0 * * * *' }, baseline: { status: 'complete', samples: 1 } }
    vi.mocked(listJobs).mockResolvedValue({ jobs: [
      { ...base, id: 'job-due', job: { ...base.job, name: 'Review monitor' }, change_window: { id: 'window-due', start_at: '2026-10-12T08:00:00Z', end_at: '2026-10-12T09:00:00Z', closed_at: '2026-10-12T08:45:00Z', timezone: 'Europe/Amsterdam', reason: 'Router replacement', status: 'closed', end_reason: 'cancelled', review_state: 'due', new_count: 1, recovered_count: 2, known_change_count: 3, still_open_count: 1, suppressed_event_count: 4, in_flight_event_count: 2, unknown_outcome_event_count: 3, incomplete_event_count: 1 } },
      { ...base, id: 'job-active', job: { ...base.job, name: 'Active monitor' }, change_window: { id: 'window-active', start_at: '2026-10-12T08:00:00Z', end_at: '2026-10-12T09:00:00Z', closed_at: null, timezone: 'Europe/Amsterdam', reason: 'Database maintenance', status: 'active', end_reason: 'expired', review_state: 'none', new_count: 1, recovered_count: 0, known_change_count: 1, still_open_count: 1, suppressed_event_count: 1, in_flight_event_count: 0, unknown_outcome_event_count: 0, incomplete_event_count: 0 } },
      { ...base, id: 'job-scheduled', job: { ...base.job, name: 'Scheduled monitor' }, change_window: { id: 'window-scheduled', start_at: '2026-10-13T08:00:00Z', end_at: '2026-10-13T09:00:00Z', closed_at: null, timezone: 'UTC', reason: 'Planned upgrade', status: 'scheduled', review_state: 'none', new_count: 0, recovered_count: 0, known_change_count: 0, still_open_count: 0, suppressed_event_count: 0, in_flight_event_count: 0, unknown_outcome_event_count: 0, incomplete_event_count: 0 } },
      { ...base, id: 'job-reviewed', job: { ...base.job, name: 'Reviewed monitor' }, change_window: { id: 'window-reviewed', start_at: '2026-10-11T08:00:00Z', end_at: '2026-10-11T09:00:00Z', closed_at: '2026-10-11T09:00:00Z', timezone: 'UTC', reason: 'Switch change', status: 'closed', end_reason: 'expired', review_state: 'reviewed', new_count: 0, recovered_count: 0, known_change_count: 0, still_open_count: 0, suppressed_event_count: 1, in_flight_event_count: 0, unknown_outcome_event_count: 0, incomplete_event_count: 0 } },
    ] } as never)
    vi.mocked(getSession).mockResolvedValue({ role: 'viewer', user_id: 'viewer', username: 'viewer', permissions: ['jobs.read'], csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 } } as never)
    renderWithProviders(<Jobs />)

    const dueHeading = await screen.findByRole('heading', { name: 'Review monitor' })
    const dueCard = dueHeading.closest('article.job-card')!
    expect(dueCard.querySelector('.job-change-window-status')).toHaveTextContent('Review due')
    expect(dueCard).toHaveTextContent('Router replacement')
    expect(dueCard.querySelectorAll('time')[1]).toHaveAttribute('dateTime', '2026-10-12T08:45:00Z')
    expect(dueCard.querySelector('.job-change-window-counts')).toHaveTextContent('4 change events held · 1 new · 2 recovered · 1 still open · 2 in flight at close · 3 with unknown prior outcome · 1 older events with incomplete identities')
    expect(dueCard.querySelector('.job-change-window-details-link')).toHaveAttribute('href', '/jobs/job-due')
    const activeCard = screen.getByRole('heading', { name: 'Active monitor' }).closest('article.job-card')!
    expect(activeCard.querySelector('.job-change-window-status')).toHaveTextContent('Active')
    expect(activeCard.querySelector('.job-change-window-status')).toHaveTextContent('Database maintenance')
    const scheduledCard = screen.getByRole('heading', { name: 'Scheduled monitor' }).closest('article.job-card')!
    const reviewedCard = screen.getByRole('heading', { name: 'Reviewed monitor' }).closest('article.job-card')!
    expect(scheduledCard.querySelector('.job-change-window-status')).toHaveTextContent('Scheduled')
    expect(reviewedCard.querySelector('.job-change-window-status')).toHaveTextContent('Reviewed')
    expect(screen.queryByText(/private-scan/)).not.toBeInTheDocument()
  })

  it('shows paused jobs in amber on the jobs list', async () => {
    vi.mocked(listJobs).mockResolvedValue({ jobs: [{ id: 'job-paused', revision: 1, enabled: false, archived: false, job: { name: 'Paused monitor', targets: [], schedule: '0 * * * *' }, baseline: { status: 'complete', samples: 1, host_count: 0 } }] } as never)
    renderWithProviders(<Jobs />)
    const headingLink = await screen.findByRole('link', { name: 'Paused monitor' })
    const card = headingLink.closest('article.job-card')!
    expect(card.querySelector('.pill')).toHaveTextContent('Paused')
    expect(card.querySelector('.pill')).toHaveClass('amber')
  })

  it('filters the complete tenant job list by explicit attention reasons', async () => {
    const allJobs = Array.from({ length: 9 }, (_, index) => ({
      id: `job-${index + 1}`,
      revision: 1,
      enabled: true,
      archived: false,
      job: { name: `Monitor ${index + 1}`, targets: ['198.51.100.10'], tcp: { ports: '443' }, schedule: '0 * * * *' },
      baseline: { status: 'complete', samples: 1 },
      monitoring: {
        availability: 'available', history_available: true, activity: 'none', schedule_state: 'scheduled',
        next_run_at: '2026-10-12T00:00:00Z', timezone: 'UTC', latest_attempt: null,
        latest_successful_scan: null, attention_reason: index === 8 ? 'incomplete' : index === 7 ? 'probe_budget_skipped' : 'none',
      },
    }))
    vi.mocked(listJobs).mockResolvedValue({ jobs: allJobs } as never)
    vi.mocked(getSession).mockResolvedValue({ role: 'viewer', user_id: 'viewer', username: 'viewer', permissions: ['jobs.read'], csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 } } as never)
    renderWithProviders(<Jobs />)

    await waitFor(() => expect(screen.getByRole('heading', { name: 'Monitor 9' })).toBeInTheDocument())
    expect(screen.getByText('Showing 9 of 9 jobs')).toBeInTheDocument()
    fireEvent.change(screen.getByRole('combobox', { name: 'Filter jobs' }), { target: { value: 'attention' } })
    expect(screen.getByRole('heading', { name: 'Monitor 9' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Monitor 8' })).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Monitor 1' })).not.toBeInTheDocument()
    expect(screen.getByText('Showing 2 of 9 jobs')).toBeInTheDocument()
    expect(screen.getByText(/Needs attention · Latest scan incomplete/)).toBeInTheDocument()
    expect(screen.getByText(/Needs attention · Last scheduled run skipped \(probe budget\)/)).toBeInTheDocument()
  })

  it('refreshes the attention filter for a viewer without stream events', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    const jobResponse = (status: string, attention: string, nextRunAt: string) => ({ jobs: [{
      id: 'polling-job', revision: 1, enabled: true, archived: false,
      job: { name: 'Polling monitor', targets: ['198.51.100.10'], schedule: '0 * * * *' },
      baseline: { status: 'complete', samples: 1 },
      monitoring: {
        availability: 'available', history_available: true, activity: 'none', schedule_state: 'scheduled',
        next_run_at: nextRunAt, timezone: 'UTC',
        latest_attempt: { status, started_at: '2026-10-11T12:00:00Z', finished_at: '2026-10-11T12:01:00Z' },
        latest_successful_scan: null, attention_reason: attention,
      },
    }] })
    const responses = [
      jobResponse('success', 'none', '2026-10-12T00:00:00Z'),
      jobResponse('failed', 'failed', '2026-10-13T00:00:00Z'),
    ]
    vi.mocked(listJobs).mockImplementation(async () => (responses.shift() ?? jobResponse('failed', 'failed', '2026-10-13T00:00:00Z')) as never)
    vi.mocked(getSession).mockResolvedValue({ role: 'viewer', user_id: 'viewer', username: 'viewer', permissions: ['jobs.read'], csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 } } as never)
    renderWithProviders(<Jobs />)

    await waitFor(() => expect(screen.getByRole('heading', { name: 'Polling monitor' })).toBeInTheDocument())
    expect(listJobs).toHaveBeenCalledTimes(1)
    expect(screen.getByText(formatDateTimeInTimeZone('2026-10-12T00:00:00Z', 'UTC'))).toBeInTheDocument()
    fireEvent.change(screen.getByRole('combobox', { name: 'Filter jobs' }), { target: { value: 'attention' } })
    expect(screen.getByText('No available jobs need attention')).toBeInTheDocument()
    expect(EventSourceStub.instances).toHaveLength(0)

    await act(async () => { await vi.advanceTimersByTimeAsync(30_000) })
    await waitFor(() => expect(screen.getByText(/Needs attention · Latest scan failed/)).toBeInTheDocument())
    expect(screen.getByText(formatDateTimeInTimeZone('2026-10-13T00:00:00Z', 'UTC'))).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Polling monitor' })).toBeInTheDocument()
    expect(listJobs).toHaveBeenCalledTimes(2)
  })

  it('shows the next scheduled run in the job scheduler timezone', async () => {
    setDisplayTimeZone('Europe/Amsterdam')
    vi.mocked(listJobs).mockResolvedValue({ jobs: [{
      id: 'timezone-job', revision: 1, enabled: true, archived: false,
      job: { name: 'New York monitor', targets: ['198.51.100.10'], schedule: '0 3 * * *' },
      baseline: { status: 'complete', samples: 1 },
      monitoring: {
        availability: 'available', history_available: true, activity: 'none', schedule_state: 'scheduled',
        next_run_at: '2026-10-13T07:00:00Z', timezone: 'America/New_York', latest_attempt: null,
        latest_successful_scan: null, attention_reason: 'none',
      },
    }] } as never)
    vi.mocked(getSession).mockResolvedValue({ role: 'viewer', user_id: 'viewer', username: 'viewer', permissions: ['jobs.read'], csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 } } as never)
    renderWithProviders(<Jobs />)

    const heading = await screen.findByRole('heading', { name: 'New York monitor' })
    const card = heading.closest('article.job-card')!
    expect(card).toHaveTextContent(formatDateTimeInTimeZone('2026-10-13T07:00:00Z', 'America/New_York'))
    expect(card).toHaveTextContent('Scheduler timezone: America/New_York')
    expect(card).not.toHaveTextContent(formatDateTimeInTimeZone('2026-10-13T07:00:00Z', 'Europe/Amsterdam'))
  })

  it('shows progressing resumable work without latest-scan failure attention', async () => {
    vi.mocked(listJobs).mockResolvedValue({ jobs: [{
      id: 'progressing-job', revision: 1, enabled: true, archived: false,
      job: { name: 'Full TCP monitor', targets: ['198.51.100.0/24'], schedule: '0 */6 * * *' },
      baseline: { status: 'learning', samples: 1 },
      monitoring: {
        availability: 'available', history_available: true, activity: 'in_progress', schedule_state: 'scheduled',
        next_run_at: '2026-10-12T00:00:00Z', timezone: 'UTC',
        latest_attempt: { status: 'timed_out', started_at: '2026-10-11T12:00:00Z', finished_at: '2026-10-11T12:01:00Z' },
        latest_successful_scan: { status: 'success', started_at: '2026-10-11T06:00:00Z', finished_at: '2026-10-11T06:01:00Z' },
        cycle_in_progress: true, cycle_completed_units: 1, cycle_total_units: 16, attention_reason: 'none',
      },
    }] } as never)
    vi.mocked(getSession).mockResolvedValue({ role: 'viewer', user_id: 'viewer', username: 'viewer', permissions: ['jobs.read'], csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 } } as never)
    renderWithProviders(<Jobs />)

    await screen.findByRole('heading', { name: 'Full TCP monitor' })
    expect(screen.getByText('Scan cycle in progress (1 of 16 units)')).toBeInTheDocument()
    expect(screen.getByText('timed out · saved progress')).toBeInTheDocument()
    expect(screen.queryByText(/Needs attention · Latest scan failed/)).not.toBeInTheDocument()
    fireEvent.change(screen.getByRole('combobox', { name: 'Filter jobs' }), { target: { value: 'attention' } })
    expect(screen.getByText('No available jobs need attention')).toBeInTheDocument()
  })

  it('shows explicit unknown and no-scan states and gates scan links by permission', async () => {
    const monitoredJob = {
      id: 'monitoring-job', revision: 1, enabled: true, archived: false,
      job: { name: 'Monitoring permissions', targets: ['198.51.100.10'], schedule: '' },
      baseline: { status: 'learning', samples: 0 },
      monitoring: {
        availability: 'available', history_available: true, activity: 'none', schedule_state: 'manual', next_run_at: null, timezone: 'UTC',
        latest_attempt: { scan_id: 'private-scan', status: 'failed', started_at: null, finished_at: null },
        latest_successful_scan: null, attention_reason: 'failed',
      },
    }
    vi.mocked(listJobs).mockResolvedValue({ jobs: [monitoredJob] } as never)
    vi.mocked(getSession).mockResolvedValue({ role: 'viewer', user_id: 'viewer', username: 'viewer', permissions: ['jobs.read'], csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 } } as never)
    renderWithProviders(<Jobs />)
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Monitoring permissions' })).toBeInTheDocument())
    expect(screen.getByText('Unknown time')).toBeInTheDocument()
    expect(screen.getByText('No successful scan yet')).toBeInTheDocument()
    expect(screen.getByText('Manual runs only')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'View attempt' })).not.toBeInTheDocument()
    expect(screen.queryByText(/private-scan/)).not.toBeInTheDocument()

    cleanup()
    vi.mocked(getSession).mockResolvedValueOnce({ role: 'administrator', user_id: 'admin', username: 'admin', permissions: ['jobs.read', 'scans.read'], csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 } } as never)
    renderWithProviders(<Jobs />)
    const attemptLink = await screen.findByRole('link', { name: 'View attempt' })
    expect(attemptLink).toHaveAttribute('href', '/jobs/monitoring-job/scans/private-scan')
  })

  it('distinguishes unavailable history from an available no-scan job', async () => {
    vi.mocked(listJobs).mockResolvedValue({ jobs: [{
      id: 'unknown-monitor', revision: 1, enabled: false, archived: false,
      job: { name: 'Unknown monitor', targets: ['198.51.100.12'], schedule: '0 * * * *' }, baseline: { status: 'learning', samples: 0 },
      monitoring: { availability: 'unavailable', history_available: false, activity: null, schedule_state: 'paused', next_run_at: null, timezone: 'UTC', latest_attempt: null, latest_successful_scan: null, attention_reason: 'none' },
    }] } as never)
    renderWithProviders(<Jobs />)
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Unknown monitor' })).toBeInTheDocument())
    expect(screen.getAllByText('Unavailable')).toHaveLength(2)
    expect(screen.getByText('Current work status unavailable')).toBeInTheDocument()
    expect(screen.getByText('Some monitoring status is unavailable; known details remain shown.')).toBeInTheDocument()
    expect(screen.queryByText('No scan recorded yet')).not.toBeInTheDocument()
    fireEvent.change(screen.getByRole('combobox', { name: 'Filter jobs' }), { target: { value: 'attention' } })
    expect(screen.getByText('Showing 0 of 1 jobs')).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Unknown monitor' })).not.toBeInTheDocument()
    expect(screen.getByText('No available jobs need attention')).toBeInTheDocument()
    expect(screen.getByText('Monitoring data is incomplete for 1 job; known attention reasons remain visible in this filter.')).toBeInTheDocument()
  })

  it('keeps known attention reasons in the filter when monitoring data is unavailable', async () => {
    vi.mocked(listJobs).mockResolvedValue({ jobs: [{
      id: 'partial-monitor', revision: 1, enabled: true, archived: false,
      job: { name: 'Partial monitor', targets: ['198.51.100.14'], schedule: '0 * * * *' },
      baseline: { status: 'complete', samples: 1 },
      monitoring: {
        availability: 'unavailable', history_available: true, activity: null, schedule_state: 'scheduled',
        next_run_at: '2026-10-12T00:00:00Z', timezone: 'UTC',
        latest_attempt: { status: 'failed', started_at: '2026-10-11T12:00:00Z', finished_at: '2026-10-11T12:01:00Z' },
        latest_successful_scan: null, attention_reason: 'failed',
      },
    }] } as never)
    renderWithProviders(<Jobs />)

    await waitFor(() => expect(screen.getByRole('heading', { name: 'Partial monitor' })).toBeInTheDocument())
    fireEvent.change(screen.getByRole('combobox', { name: 'Filter jobs' }), { target: { value: 'attention' } })

    expect(screen.getByRole('heading', { name: 'Partial monitor' })).toBeInTheDocument()
    expect(screen.getByText('Showing 1 of 1 jobs')).toBeInTheDocument()
    expect(screen.getByText('Needs attention · Latest scan failed')).toBeInTheDocument()
    expect(screen.getByText('Monitoring data is incomplete for 1 job; known attention reasons remain visible in this filter.')).toBeInTheDocument()
  })

  it('lists a baseline whose stored scope is being updated as ready', async () => {
    vi.mocked(listJobs).mockResolvedValue({ jobs: [{ id: 'job-4', revision: 3, enabled: true, archived: false, job: { name: 'Legacy ports', targets: ['198.51.100.13'], tcp: { ports: '2, 1' }, schedule: '0 * * * *', baseline_samples: 2 }, baseline: { status: 'updating', scan_id: 'scan-4', host_count: 1, samples: 0 } }] } as never)
    renderWithProviders(<Jobs />)
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Legacy ports' })).toBeInTheDocument())
    expect(screen.getByText('● Baseline ready (updating scope)')).toHaveClass('complete')
    expect(screen.queryByText(/Collecting/)).not.toBeInTheDocument()
  })

  it('shows the viewer empty state without a creation action', async () => {
    vi.mocked(listJobs).mockResolvedValue({ jobs: [] } as never)
    vi.mocked(getSession).mockResolvedValue({ role: 'viewer', user_id: 'viewer', username: 'viewer', permissions: [], csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 } } as never)
    renderWithProviders(<Jobs />)
    await waitFor(() => expect(screen.getByText('No jobs configured')).toBeInTheDocument())
    expect(screen.queryByRole('button', { name: /New job/ })).not.toBeInTheDocument()
  })

  it('shows the administrator empty state with a creation action', async () => {
    vi.mocked(listJobs).mockResolvedValue({ jobs: [] } as never)
    vi.mocked(getSession).mockResolvedValue({ role: 'administrator', user_id: 'admin', username: 'admin', permissions: ['jobs.write'], csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 } } as never)
    renderWithProviders(<Jobs />)
    await waitFor(() => expect(screen.getByText('No jobs yet')).toBeInTheDocument())
    const create = screen.getByRole('button', { name: /Create a job/ })
    expect(create).toBeInTheDocument()
    fireEvent.click(create)
  })

  it('routes auth states and bypasses authentication for the public path', async () => {
    renderWithProviders(<AuthRoutes configured={true} />, { route: ['/unknown'] })
    await waitFor(() => expect(screen.getByRole('heading', { name: /Sign in to EdgeWatch/ })).toBeInTheDocument())
    cleanup()
    vi.mocked(setupStatus).mockResolvedValue({ configured: false } as never)
    renderWithProviders(<AuthRoutes configured={false} />, { route: ['/unknown'] })
    await waitFor(() => expect(screen.getByRole('heading', { name: /Create your administrator/ })).toBeInTheDocument())

    cleanup()
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => ({ enabled: false, title: 'Public status', introduction: '', hosts: [] }) })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<AppContent />, { route: ['/public'] })
    await waitFor(() => expect(screen.getByText(/Public status/i)).toBeInTheDocument())
    expect(setupStatus).toHaveBeenCalled()
    expect(getSession).not.toHaveBeenCalled()
    expect(String(fetchMock.mock.calls[0][0])).toBe('/api/public/v1/dashboard')
  })

  it('serves a business unit public page by its slug without setup or session requests', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => ({ title: 'Unit status', introduction: '', updated_at: '2026-09-20T12:00:00Z', hosts: [] }) })
    vi.stubGlobal('fetch', fetchMock)
    for (const [route, requested] of [
      ['/public/other', '/api/public/v1/dashboard/other'],
      ['/public/other/', '/api/public/v1/dashboard/other'],
      ['/public/a%20b', '/api/public/v1/dashboard/a%20b'],
      ['/public/%E0%A4%A', '/api/public/v1/dashboard/%25E0%25A4%25A'],
      ['/public/', '/api/public/v1/dashboard'],
    ]) {
      cleanup()
      fetchMock.mockClear()
      renderWithProviders(<AppContent />, { route: [route] })
      await waitFor(() => expect(screen.getByRole('heading', { name: 'Unit status' })).toBeInTheDocument())
      expect(fetchMock).toHaveBeenCalledTimes(1)
      expect(String(fetchMock.mock.calls[0][0])).toBe(requested)
      expect(fetchMock.mock.calls[0][1]).toMatchObject({ credentials: 'omit' })
    }
    expect(setupStatus).not.toHaveBeenCalled()
    expect(getSession).not.toHaveBeenCalled()

    // A deeper path is not a public page; it goes through sign-in.
    cleanup()
    vi.mocked(getSession).mockRejectedValueOnce(new Error('unauthenticated'))
    renderWithProviders(<AppContent />, { route: ['/public/other/extra'] })
    await waitFor(() => expect(screen.getByRole('heading', { name: /Sign in to EdgeWatch/ })).toBeInTheDocument())
  })

  it('explains that a slug page is not available without telling why', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: false, status: 404, json: async () => ({ error: { code: 'public_disabled', message: 'public status is not enabled' } }) })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<AppContent />, { route: ['/public/nobody'] })
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Public status unavailable' })).toBeInTheDocument())
    expect(screen.getByText('This status page is not enabled by the administrator.')).toBeInTheDocument()
    expect(String(fetchMock.mock.calls[0][0])).toBe('/api/public/v1/dashboard/nobody')
  })

  it('renders the application unavailable and login fallbacks', async () => {
    vi.mocked(setupStatus).mockRejectedValueOnce(new Error('offline'))
    vi.mocked(getSession).mockRejectedValueOnce(new Error('unauthenticated'))
    renderWithProviders(<AppContent />, { route: ['/'] })
    await waitFor(() => expect(screen.getByText('Unable to contact EdgeWatch.')).toBeInTheDocument())
    vi.mocked(setupStatus).mockResolvedValueOnce({ configured: true } as never)
    fireEvent.click(screen.getByRole('button', { name: 'Reload status' }))
    await waitFor(() => expect(screen.getByRole('heading', { name: /Sign in to EdgeWatch/ })).toBeInTheDocument())
    cleanup()
    vi.mocked(setupStatus).mockResolvedValueOnce({ configured: true } as never)
    vi.mocked(getSession).mockRejectedValueOnce(new Error('unauthenticated'))
    renderWithProviders(<AppContent />, { route: ['/'] })
    await waitFor(() => expect(screen.getByRole('heading', { name: /Sign in to EdgeWatch/ })).toBeInTheDocument())
  })

  it('returns to login after logout or an unauthorized event', async () => {
    renderWithProviders(<AppContent />, { route: ['/'] })
    await waitFor(() => expect(screen.getByRole('button', { name: 'Sign out' })).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }))
    await waitFor(() => expect(screen.getByRole('heading', { name: /Sign in to EdgeWatch/ })).toBeInTheDocument())
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'correct horse battery staple' } })
    fireEvent.submit(screen.getByRole('button', { name: 'Sign in' }).closest('form')!)
    await waitFor(() => expect(screen.getByRole('button', { name: 'Sign out' })).toBeInTheDocument())

    cleanup()
    vi.mocked(getSession).mockResolvedValue({ role: 'administrator', user_id: 'admin', username: 'admin', permissions: ['jobs.read'], csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 } } as never)
    renderWithProviders(<AppContent />, { route: ['/'] })
    await waitFor(() => expect(screen.getByRole('button', { name: 'Sign out' })).toBeInTheDocument())
    act(() => window.dispatchEvent(new Event('edgewatch:unauthorized')))
    await waitFor(() => expect(screen.getByRole('heading', { name: /Sign in to EdgeWatch/ })).toBeInTheDocument())
  })
})

describe('console query defaults', () => {
  it('does not retry a refused query, and retries other failures three times', async () => {
    const refused = new APIError('your account is not allowed to perform this action', 'forbidden', { permission: 'route' }, 403)
    expect(retryQuery(0, refused)).toBe(false)
    expect(retryQuery(0, new APIError('authentication required', 'unauthorized', undefined, 401))).toBe(false)
    // A request the server refuses as invalid fails the same way again.
    expect(retryQuery(0, new APIError('action prefix must be at most 64 characters', 'validation_failed', { action: 'action prefix must be at most 64 characters' }, 400))).toBe(false)
    for (const error of [new APIError('the store is unavailable', 'store', undefined, 500), new APIError('fixture failure', 'validation_failed'), new Error('offline')]) {
      expect(retryQuery(0, error)).toBe(true)
      expect(retryQuery(2, error)).toBe(true)
      expect(retryQuery(3, error)).toBe(false)
    }

    // A refused query reports at once instead of waiting through retries.
    const client = createQueryClient()
    expect(client.getDefaultOptions().queries?.retry).toBe(retryQuery)
    const queryFn = vi.fn(async () => { throw refused })
    function Probe() {
      const query = useQuery({ queryKey: ['refused'], queryFn })
      return <output data-testid="query-status">{query.status}</output>
    }
    renderWithProviders(<Probe />, { client })
    await waitFor(() => expect(screen.getByTestId('query-status')).toHaveTextContent('error'))
    expect(queryFn).toHaveBeenCalledTimes(1)
    client.clear()
  })

  it('does not retry deterministic client errors, but retries timeouts and rate limits', () => {
    // A deleted job, a pruned scan, or another unit's ID answers 404 every time.
    expect(retryQuery(0, new APIError('job not found', 'not_found', undefined, 404))).toBe(false)
    expect(retryQuery(0, new APIError('baseline changed', 'baseline_conflict', undefined, 409))).toBe(false)
    expect(retryQuery(0, new APIError('gone', 'gone', undefined, 410))).toBe(false)
    expect(retryQuery(0, new APIError('request timeout', 'timeout', undefined, 408))).toBe(true)
    const limited = new APIError('too many requests', 'rate_limited', undefined, 429, 7)
    expect(retryQuery(0, limited)).toBe(true)
    expect(retryQuery(3, limited)).toBe(false)
    // A 429 waits as long as Retry-After asks; other failures back off.
    expect(retryQueryDelay(0, limited)).toBe(7000)
    expect(retryQueryDelay(0, new APIError('too many requests', 'rate_limited', undefined, 429))).toBe(1000)
    expect(retryQueryDelay(1, new Error('offline'))).toBe(2000)
    expect(retryQueryDelay(10, new Error('offline'))).toBe(30_000)
    expect(createQueryClient().getDefaultOptions().queries?.retryDelay).toBe(retryQueryDelay)
  })
})
