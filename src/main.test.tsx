/** @vitest-environment jsdom */

import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react'
import { act } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { useLocation } from 'react-router-dom'
import { APIError, adminStatus, acceptIncident, getSession, listIncidents, listJobs, listUnits, login, logout, platformCapacity, recordActivity, setupStatus, suppressIncident, unitAudit } from './api'
import { AppContent, AuthRoutes, Incidents, Jobs, ProtectedApp, Shell } from './main'
import { renderWithProviders } from './test/test-utils'

vi.mock('./api', async () => {
  const actual = await vi.importActual<typeof import('./api')>('./api')
  return { ...actual, acceptIncident: vi.fn(), adminStatus: vi.fn(), getSession: vi.fn(), listIncidents: vi.fn(), listJobs: vi.fn(), listUnits: vi.fn(), login: vi.fn(), logout: vi.fn(), platformCapacity: vi.fn(), recordActivity: vi.fn(), setCSRF: vi.fn(), setupStatus: vi.fn(), suppressIncident: vi.fn(), unitAudit: vi.fn() }
})

class EventSourceStub {
  static instances: EventSourceStub[] = []
  onopen: (() => void) | null = null
  onerror: (() => void) | null = null
  onmessage: ((event: MessageEvent) => void) | null = null
  close = vi.fn()
  constructor() { EventSourceStub.instances.push(this) }
  emit(type: string, job_id?: string) { this.onmessage?.({ data: JSON.stringify({ type, job_id }) } as MessageEvent) }
}

function CurrentPath() {
  return <output data-testid="current-path">{useLocation().pathname}</output>
}

describe('application shell', () => {
  beforeEach(() => {
    vi.mocked(adminStatus).mockResolvedValue({ version: 'v0.18.70', version_release_url: 'https://github.com/crypt0rr/EdgeWatch/releases/tag/v0.18.70', updates: { available: true, status: 'update_available', latest_version: 'v0.19.0', release_url: 'https://github.com/crypt0rr/EdgeWatch/releases/tag/v0.19.0' } } as never)
    vi.mocked(listIncidents).mockResolvedValue({ incidents: [], pagination: { limit: 1, offset: 0, total: 0, has_more: false, next_offset: null } })
    vi.mocked(listJobs).mockResolvedValue({ jobs: [] } as never)
    vi.mocked(getSession).mockResolvedValue({ role: 'administrator', user_id: 'admin', username: 'admin', permissions: ['jobs.write', 'incidents.read'], csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 } } as never)
    vi.mocked(login).mockResolvedValue({ role: 'administrator', username: 'admin', permissions: ['jobs.write'], csrf_token: '', totp_required: false } as never)
    vi.mocked(logout).mockResolvedValue(undefined)
    vi.mocked(recordActivity).mockResolvedValue(undefined)
    vi.mocked(setupStatus).mockResolvedValue({ configured: true } as never)
    EventSourceStub.instances = []
    vi.stubGlobal('EventSource', EventSourceStub)
  })

  afterEach(() => { vi.unstubAllGlobals(); vi.clearAllMocks() })

  it('renders permission-aware navigation, update indicator, and incident count', async () => {
    vi.mocked(listIncidents).mockResolvedValue({ incidents: [], pagination: { limit: 1, offset: 0, total: 3, has_more: true, next_offset: 1 } })
    const onLogout = vi.fn()
    renderWithProviders(<Shell displayName="Alice" role="administrator" permissions={['overview.read', 'jobs.read', 'hosts.read', 'incidents.read', 'stream.read']} onLogout={onLogout} />)

    expect(screen.getByText('Alice')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Overview' })).toBeInTheDocument()
    await waitFor(() => expect(screen.getByLabelText('3 active incidents')).toBeInTheDocument())
    expect(screen.getByRole('link', { name: 'Incidents' })).toHaveAttribute('aria-describedby', 'active-incident-count')
    expect(screen.getByRole('link', { name: /Update available/ })).toHaveAttribute('href', 'https://github.com/crypt0rr/EdgeWatch/releases/tag/v0.19.0')
    const versionLink = screen.getByRole('link', { name: 'Release notes for EdgeWatch v0.18.70' })
    expect(versionLink).toHaveAttribute('href', 'https://github.com/crypt0rr/EdgeWatch/releases/tag/v0.18.70')
    expect(versionLink).toHaveAttribute('target', '_blank')
    expect(versionLink).toHaveAttribute('rel', 'noopener noreferrer')
    expect(versionLink).toHaveTextContent('EdgeWatch v0.18.70')
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
    await waitFor(() => expect(screen.getByText('EdgeWatch v0.18.70')).toBeInTheDocument())
    expect(screen.getByRole('link', { name: /Update available/ })).toBeInTheDocument()
    expect(adminStatus).toHaveBeenCalledOnce()
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
    await waitFor(() => expect(EventSourceStub.instances).toHaveLength(1))
    const stream = EventSourceStub.instances[0]
    act(() => stream.emit('scan.completed', 'job-9'))
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['active-scans'] })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['job', 'job-9'] })
    act(() => stream.onmessage?.({ data: '{not-json' } as MessageEvent))
    expect(invalidate).toHaveBeenCalledWith()
    act(() => stream.emit('application.update_status'))
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['admin-status'] })
    act(() => {
      for (const type of ['changes-detected', 'incident-opened', 'incident-closed', 'incident-accepted', 'incident-suppressed']) stream.emit(type, 'job-9')
      for (const type of ['job.created', 'job.updated', 'job.archived', 'job.restored', 'job.deleted']) stream.emit(type, 'job-9')
      stream.emit('notification.changed')
      stream.emit('stream_limit')
      stream.emit('refresh_required')
      stream.emit('unrecognised-event')
      stream.onopen?.()
    })
    await waitFor(() => expect(screen.getByText('Live updates')).toBeInTheDocument())
    act(() => stream.onerror?.())
    await waitFor(() => expect(screen.getByText('Reconnecting…')).toBeInTheDocument())
  })

  it('shows the version as plain text when the build has no published release', async () => {
    vi.mocked(adminStatus).mockResolvedValue({ version: 'dev', updates: { available: false, status: 'development_build' } } as never)
    renderWithProviders(<Shell displayName="Viewer" role="viewer" permissions={['jobs.read']} onLogout={vi.fn()} />)
    await waitFor(() => expect(screen.getByText('EdgeWatch dev')).toBeInTheDocument())
    expect(screen.queryByRole('link', { name: /Release notes for EdgeWatch/ })).not.toBeInTheDocument()
  })

  it('shows unavailable incident counts and handles status failures without hiding navigation', async () => {
    vi.mocked(listIncidents).mockRejectedValue(new Error('incident service unavailable'))
    vi.mocked(adminStatus).mockRejectedValue(new Error('status unavailable'))
    renderWithProviders(<Shell displayName="Operator" role="operator" permissions={['overview.read', 'incidents.read', 'jobs.read']} onLogout={vi.fn()} />)
    await waitFor(() => expect(screen.getByLabelText('Active incident count unavailable; retrying')).toBeInTheDocument())
    expect(screen.getByRole('link', { name: 'Incidents' })).toHaveClass('nav-link-alert')
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
    await waitFor(() => expect(screen.getByText('jobs unavailable')).toBeInTheDocument())
    cleanup()
    vi.mocked(listJobs).mockResolvedValueOnce({ jobs: [] } as never)
    vi.mocked(getSession).mockResolvedValueOnce({ role: 'viewer', user_id: 'viewer', username: 'viewer', permissions: [], csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 } } as never)
    renderWithProviders(<Jobs />)
    await waitFor(() => expect(screen.getByText('No jobs configured')).toBeInTheDocument())
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

  it('accepts and suppresses incidents, refreshes conflicts, and disables legacy actions', async () => {
    const incident = { job_id: 'job-1', job: 'TCP monitor', incident: { change: { key: 'tcp:198.51.100.10:443', kind: 'port', target: '198.51.100.10', protocol: 'tcp', port: 443, old: 'closed', new: 'open', severity: 'critical' }, opened_at: '2026-01-01T00:00:00Z', last_seen_at: '2026-01-01T00:01:00Z' } }
    const legacy = { ...incident, job_id: 'job-2', incident: { ...incident.incident, change: { ...incident.incident.change, key: undefined, old: undefined, new: undefined } } }
    vi.mocked(listIncidents).mockResolvedValue({ incidents: [incident, legacy], pagination: { limit: 50, offset: 0, total: 2, has_more: false, next_offset: null } } as never)
    renderWithProviders(<Incidents />)
    await waitFor(() => expect(screen.getAllByRole('button', { name: 'Accept change' })).toHaveLength(4))
    expect(screen.getAllByText('No before/after value recorded')).toHaveLength(2)
    expect(screen.getAllByRole('button', { name: 'Accept change' })[1]).toBeDisabled()
    fireEvent.click(screen.getAllByRole('button', { name: 'Accept change' })[0])
    fireEvent.click(screen.getByRole('dialog').querySelector('button[type="submit"]')!)
    await waitFor(() => expect(acceptIncident).toHaveBeenCalledWith('job-1', 'tcp:198.51.100.10:443', incident.incident.change))
    fireEvent.click(screen.getAllByRole('button', { name: 'Suppress 1 scan' })[0])
    fireEvent.click(screen.getByRole('dialog').querySelector('button[type="submit"]')!)
    await waitFor(() => expect(suppressIncident).toHaveBeenCalledWith('job-1', 'tcp:198.51.100.10:443', incident.incident.change))

    vi.mocked(acceptIncident).mockRejectedValueOnce(new APIError('stale incident', 'incident_conflict'))
    fireEvent.click(screen.getAllByRole('button', { name: 'Accept change' })[0])
    fireEvent.click(screen.getByRole('dialog').querySelector('button[type="submit"]')!)
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('changed while it was open'))
  })

  it('returns to the last non-empty incident page after resolving the only row on a later page', async () => {
    const incidentRow = (index: number) => ({ job_id: 'job-1', job: 'TCP monitor', incident: { change: { key: `tcp:198.51.100.10:${1000 + index}`, kind: 'port', target: '198.51.100.10', protocol: 'tcp', port: 1000 + index, old: 'closed', new: 'open', severity: 'critical' }, opened_at: '2026-01-01T00:00:00Z', last_seen_at: '2026-01-01T00:01:00Z' } })
    let active = Array.from({ length: 21 }, (_, index) => incidentRow(index))
    vi.mocked(listIncidents).mockImplementation(async (offset = 0, limit = 20) => {
      const rows = active.slice(offset, offset + limit)
      const hasMore = offset + rows.length < active.length
      return { incidents: rows, pagination: { limit, offset, total: active.length, has_more: hasMore, next_offset: hasMore ? offset + limit : null } } as never
    })
    vi.mocked(acceptIncident).mockImplementation(async (_job, key) => { active = active.filter(row => row.incident.change.key !== key) })
    renderWithProviders(<Incidents />)
    await waitFor(() => expect(screen.getByText('1–20 of 21')).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: 'Next' }))
    await waitFor(() => expect(screen.getByText('21–21 of 21')).toBeInTheDocument())

    fireEvent.click(screen.getAllByRole('button', { name: 'Accept change' })[0])
    fireEvent.click(screen.getByRole('dialog').querySelector('button[type="submit"]')!)
    await waitFor(() => expect(acceptIncident).toHaveBeenCalledWith('job-1', 'tcp:198.51.100.10:1020', expect.anything()))

    // The 20 remaining incidents now fit on the first page; the page must not
    // claim that there are no incidents or strand the operator on an empty page.
    await waitFor(() => expect(screen.getAllByText('TCP monitor')).toHaveLength(40))
    expect(vi.mocked(listIncidents)).toHaveBeenLastCalledWith(0)
    expect(screen.queryByText('No active incidents')).not.toBeInTheDocument()
  })

  it('shows the incident empty state only when no incidents remain', async () => {
    vi.mocked(listIncidents).mockResolvedValue({ incidents: [], pagination: { limit: 20, offset: 0, total: 3, has_more: false, next_offset: null } })
    renderWithProviders(<Incidents />)
    await waitFor(() => expect(screen.getByText('No incidents on this page.')).toBeInTheDocument())
    expect(screen.queryByText('No active incidents')).not.toBeInTheDocument()

    cleanup()
    vi.mocked(listIncidents).mockResolvedValue({ incidents: [], pagination: { limit: 20, offset: 0, total: 0, has_more: false, next_offset: null } })
    renderWithProviders(<Incidents />)
    await waitFor(() => expect(screen.getByText('No active incidents')).toBeInTheDocument())
  })

  it('routes auth states and bypasses authentication for the public path', async () => {
    renderWithProviders(<AuthRoutes configured={true} />, { route: ['/unknown'] })
    await waitFor(() => expect(screen.getByRole('heading', { name: /Sign in to EdgeWatch/ })).toBeInTheDocument())
    cleanup()
    renderWithProviders(<AuthRoutes configured={false} />, { route: ['/unknown'] })
    await waitFor(() => expect(screen.getByRole('heading', { name: /Create your administrator/ })).toBeInTheDocument())

    cleanup()
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => ({ enabled: false, title: 'Public status', introduction: '', hosts: [] }) })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<AppContent />, { route: ['/public'] })
    await waitFor(() => expect(screen.getByText(/Public status/i)).toBeInTheDocument())
    expect(setupStatus).toHaveBeenCalled()
    expect(getSession).not.toHaveBeenCalled()
  })

  it('mounts the platform console for main administrators and never the unit pages', async () => {
    const limits = { max_concurrent_scans: 4, max_probe_count: 5_000_000, max_naabu_probe_count: 20_000_000, max_probe_count_limit: 100_000_000 }
    vi.mocked(listUnits).mockResolvedValue({ limits, units: [] })
    vi.mocked(platformCapacity).mockResolvedValue({ version: 'v0.18.145', limits, totals: { slots_in_use: 0, queued: 0, slot_caps: 0 }, units: [] })
    vi.mocked(getSession).mockResolvedValue({ role: 'platform_admin', user_id: 'acct-morgan', username: 'morgan', display_name: 'Morgan Reyes', permissions: ['units.manage', 'platform_status.read', 'account.self'], csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 }, scope: 'platform', unit: null, multi_unit: true })
    renderWithProviders(<><ProtectedApp onLogout={async () => {}} /><CurrentPath /></>, { route: ['/incidents'] })
    await waitFor(() => expect(screen.getByTestId('current-path')).toHaveTextContent('/platform/units'))
    expect(screen.getByText('Main administration')).toBeInTheDocument()
    expect(screen.getByText('Morgan Reyes')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Incidents' })).not.toBeInTheDocument()
    expect(listIncidents).not.toHaveBeenCalled()
    expect(listJobs).not.toHaveBeenCalled()
    expect(adminStatus).not.toHaveBeenCalled()
    expect(EventSourceStub.instances).toHaveLength(0)
  })

  it('shows the business unit chip and the read-only audit page to unit administrators', async () => {
    vi.mocked(unitAudit).mockResolvedValue({ entries: [], next_before: null })
    vi.mocked(getSession).mockResolvedValue({ role: 'administrator', user_id: 'acct-riley', username: 'riley', permissions: ['jobs.read', 'audit.read'], csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 }, scope: 'unit', unit: { id: 'unit-retail', name: 'Retail', slug: 'retail' }, multi_unit: true })
    renderWithProviders(<ProtectedApp onLogout={async () => {}} />, { route: ['/audit'] })
    expect(await screen.findByRole('heading', { name: 'Audit' })).toBeInTheDocument()
    expect(screen.getByTitle('Business unit: Retail')).toHaveTextContent('Retail')
    expect(screen.getByRole('link', { name: 'Audit' })).toHaveClass('active')
    await waitFor(() => expect(unitAudit).toHaveBeenCalledWith({ before: null }))
    cleanup()

    renderWithProviders(<><Shell displayName="Operator" role="operator" permissions={['jobs.read']} onLogout={vi.fn()} /><CurrentPath /></>, { route: ['/audit'] })
    await waitFor(() => expect(screen.getByTestId('current-path')).toHaveTextContent('/jobs'))
    expect(screen.queryByRole('link', { name: 'Audit' })).not.toBeInTheDocument()
    expect(screen.queryByText('Business unit')).not.toBeInTheDocument()
  })

  it('serves a business unit public page by slug without a session', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => ({ title: 'Retail storefront status', introduction: '', updated_at: '2026-09-20T00:00:00Z', hosts: [] }) })
    vi.stubGlobal('fetch', fetchMock)
    renderWithProviders(<AppContent />, { route: ['/public/retail/'] })
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Retail storefront status' })).toBeInTheDocument())
    expect(fetchMock).toHaveBeenCalledWith('/api/public/v1/dashboard/retail', { credentials: 'omit' })
    expect(getSession).not.toHaveBeenCalled()
    cleanup()
    renderWithProviders(<AppContent />, { route: ['/public/r%C3%A9tail'] })
    await waitFor(() => expect(fetchMock).toHaveBeenLastCalledWith('/api/public/v1/dashboard/r%C3%A9tail', { credentials: 'omit' }))
  })

  it('renders the application unavailable and login fallbacks', async () => {
    vi.mocked(setupStatus).mockRejectedValueOnce(new Error('offline'))
    vi.mocked(getSession).mockRejectedValueOnce(new Error('unauthenticated'))
    renderWithProviders(<AppContent />, { route: ['/'] })
    await waitFor(() => expect(screen.getByText('Unable to contact EdgeWatch. Retry when the service is available.')).toBeInTheDocument())
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
