/** @vitest-environment jsdom */

import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { activeScans, adminStatus, cancelQueuedRun, cancelScan, getSession, listIncidents, listJobs, listScans, notificationTest, runJob } from '../api'
import type { AdminStatus, SessionUser } from '../api'
import type { ActiveScan, Job, ScanSummary } from '../types'
import { Dashboard } from './Dashboard'
import { defaultUnitScope } from '../test/test-utils'

vi.mock('../api', () => ({
  activeScans: vi.fn(),
  adminStatus: vi.fn(),
  cancelScan: vi.fn(),
  getSession: vi.fn(),
  cancelQueuedRun: vi.fn(),
  listIncidents: vi.fn(),
  listJobs: vi.fn(),
  listScans: vi.fn(),
  notificationTest: vi.fn(),
  runJob: vi.fn(),
}))

;(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true

const job = {
  id: 'job-1',
  revision: 2,
  enabled: true,
  archived: false,
  security_hash: 'security',
  created_at: '2026-09-12T07:00:00Z',
  updated_at: '2026-09-12T07:00:00Z',
  job: { name: 'demo', schedule: '0 * * * *', timezone: 'UTC', targets: ['198.51.100.10'], max_expanded_hosts: 1, timing: 'balanced', timeout: '1h', baseline_samples: 1, change_confirmations: 1, tcp: { ports: '22', service_detection: false } },
  baseline: { status: 'complete', host_count: 1 },
} as Job

const scan = {
  id: 'scan-1',
  job_id: 'job-1',
  job: 'demo',
  started_at: '2026-09-12T07:00:00Z',
  finished_at: '2026-09-12T07:01:00Z',
  status: 'success',
  config_hash: 'security',
  scanner_engine: 'nmap',
} as ScanSummary

const activeScan: ActiveScan = {
  id: 'active-1',
  job_id: 'job-1',
  job: 'demo',
  started_at: '2026-09-12T08:00:00Z',
  progress_percent: 42,
  completed_probes: 420,
  total_probes: 1000,
  phase: 'tcp discovery',
  protocol: 'tcp',
  scanner: 'naabu_nmap',
  scanner_profile_revision: 3,
  current_invocation: 1,
  total_batches: 2,
  process_progress_percent: 37,
  process_alive: true,
  elapsed_seconds: 125,
  last_output: 'probe 420',
  cycle_id: 'cycle-1',
  cycle_status: 'running',
  cycle_completed_units: 1,
  cycle_total_units: 3,
  current_unit_ports: '1-65535',
  current_unit_addresses: 1,
  discovery_ports_found: 2,
  discovery_addresses: 1,
}

const status: AdminStatus = {
  configured: true,
  username: 'admin',
  display_name: 'Alice',
  role: 'administrator',
  permissions: ['overview.read', 'jobs.read', 'jobs.write', 'scans.read', 'incidents.read', 'notifications.manage', 'users.manage'],
  version: 'v0.13.3',
  notification_destinations: 1,
  notifications: { deployment: 0, managed: 1, active: 1, locked: 0, key_state: 'ready' },
  retention: '2160h',
  max_concurrent_scans: 2,
  telemetry: { collected_at: '2026-09-12T08:00:00Z', database_bytes: 1536, jobs: 1, scans: 1, host_observations: 1, effective_hosts: 1, events: 1, scan_cycles: 1, outbox_pending: 0, outbox_retrying: 0, outbox_failed: 0 },
}

const session = (role: SessionUser['role']): SessionUser => ({
  user_id: 'user-1',
  username: 'admin',
  display_name: 'Alice',
  role,
  permissions: role === 'administrator' ? ['overview.read', 'jobs.read', 'jobs.write', 'scans.read', 'incidents.read', 'notifications.manage', 'users.manage'] : [],
  csrf_token: 'csrf',
  totp_enabled: false,
  password_requirements: { minimum_length: 12 },
  ...defaultUnitScope,
})

const pagination = { limit: 20, offset: 0, total: 1, has_more: false, next_offset: null }

function LocationProbe() {
  const location = useLocation()
  return <output data-testid="current-path">{location.pathname}</output>
}

describe('dashboard', () => {
  let root: Root
  let container: HTMLDivElement
  let queryClient: QueryClient

  beforeEach(() => {
    container = document.createElement('div')
    document.body.appendChild(container)
    root = createRoot(container)
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    vi.mocked(getSession).mockResolvedValue(session('administrator'))
    vi.mocked(adminStatus).mockResolvedValue(status)
    vi.mocked(listJobs).mockResolvedValue({ jobs: [job] })
    vi.mocked(listScans).mockResolvedValue({ scans: [scan], pagination })
    vi.mocked(activeScans).mockResolvedValue({ scans: [activeScan] })
    vi.mocked(listIncidents).mockResolvedValue({ incidents: [], pagination })
    vi.mocked(notificationTest).mockResolvedValue({ sent: 1 })
    vi.mocked(runJob).mockResolvedValue({ status: 'started', job_id: 'job-1' })
    vi.mocked(cancelScan).mockResolvedValue({ status: 'cancelling', scan_id: 'active-1' })
  })

  afterEach(() => {
    act(() => root.unmount())
    queryClient.clear()
    container.remove()
    vi.resetAllMocks()
  })

  async function renderDashboard() {
    await act(async () => {
      root.render(<QueryClientProvider client={queryClient}><MemoryRouter><Dashboard /><LocationProbe /></MemoryRouter></QueryClientProvider>)
    })
    await vi.waitFor(() => expect(container.textContent).toContain('Scans in progress'), { timeout: 1000 })
  }

  it('counts an updating baseline as ready', async () => {
    vi.mocked(listJobs).mockResolvedValue({ jobs: [{ ...job, baseline: { status: 'updating', scan_id: 'scan-1', host_count: 1, samples: 0 } }] })
    await renderDashboard()
    await vi.waitFor(() => expect(container.textContent).toContain('1 baselines ready'), { timeout: 1000 })
    const pill = Array.from(container.querySelectorAll('.dashboard-job .pill')).find(element => element.textContent === 'Ready (updating scope)')
    expect(pill?.classList.contains('green')).toBe(true)
    expect(container.querySelector('.dashboard-job')?.textContent).not.toContain('Learning')
  })

  it('shows operational metrics, detailed active progress, and actionable links', async () => {
    await renderDashboard()
    expect(container.textContent).toContain('Good day, Alice')
    expect(container.textContent).toContain('Deployment footprint')
    expect(container.textContent).toContain('1.5 KB')
    expect(container.textContent).toContain('Naabu → Nmap · tcp discovery · TCP')
    expect(container.textContent).toContain('batch 1/2')
    expect(container.textContent).toContain('2 ports found across 1 hosts')
    expect(container.textContent).toContain('Current Naabu → Nmap process: 37%')
    expect(container.textContent).toContain('probe 420')
    expect(container.querySelector('a[href="/jobs/job-1/scans/scan-1"]')).toBeTruthy()

    const run = container.querySelector('button[aria-label="Run demo"]') as HTMLButtonElement
    await act(async () => {
      run.click()
      await Promise.resolve()
      await Promise.resolve()
    })
    expect(runJob).toHaveBeenCalledWith('job-1')

    const cancel = Array.from(container.querySelectorAll('button')).find(button => button.textContent?.includes('Cancel scan')) as HTMLButtonElement
    await act(async () => {
      cancel.click()
      await Promise.resolve()
      await Promise.resolve()
    })
    expect(cancelScan).toHaveBeenCalledWith('active-1')

    const notify = Array.from(container.querySelectorAll('button')).find(button => button.textContent?.includes('Test notifications')) as HTMLButtonElement
    await act(async () => {
      notify.click()
      await Promise.resolve()
      await Promise.resolve()
    })
    expect(container.textContent).toContain('1 destination tested')
  })

  it('confirms a requested cancellation while the scanner keeps reporting progress', async () => {
    vi.mocked(activeScans).mockResolvedValue({ scans: [{ ...activeScan, phase: 'scanning', cancel_requested: true }] })
    await renderDashboard()
    await vi.waitFor(() => expect(container.querySelector('.active-scan-row .pill')?.textContent).toBe('Cancellation requested'), { timeout: 1000 })
    expect(Array.from(container.querySelectorAll('button')).some(button => button.textContent?.includes('Cancel scan'))).toBe(false)
  })

  it('shows queued runs reported by the server and cancels one', async () => {
    vi.mocked(activeScans).mockResolvedValue({ scans: [], queued_runs: [{ job_id: 'job-1', job: 'demo', queued_at: '2026-10-06T08:00:00Z', trigger: 'manual' }] })
    vi.mocked(cancelQueuedRun).mockResolvedValue({ status: 'canceled', job_id: 'job-1' })
    await renderDashboard()

    expect(container.textContent).toContain('Scans in progress or queued')
    expect(container.textContent).toContain('Manual scan · waiting for an available scan slot')
    expect(container.querySelector('.queued-scan-row .pill')?.textContent).toBe('Queued')
    expect(Array.from(container.querySelectorAll('button')).some(button => button.textContent?.includes('Cancel scan'))).toBe(false)
    const cancel = container.querySelector('.queued-scan-row button') as HTMLButtonElement
    expect(cancel.textContent).toBe('Cancel queued scan')
    await act(async () => {
      cancel.click()
      await Promise.resolve()
    })
    expect(cancelQueuedRun).toHaveBeenCalledWith('job-1')
  })

  it('reports a queued run that could no longer be canceled', async () => {
    vi.mocked(activeScans).mockResolvedValue({ scans: [], queued_runs: [{ job_id: 'job-1', job: 'demo', queued_at: '2026-10-06T08:00:00Z', trigger: 'scheduled' }] })
    vi.mocked(cancelQueuedRun).mockRejectedValueOnce(new Error('The job has no scan waiting for a slot.'))
    await renderDashboard()
    await act(async () => {
      (container.querySelector('.queued-scan-row button') as HTMLButtonElement).click()
      await Promise.resolve()
    })
    await vi.waitFor(() => expect(container.querySelector('[role="alert"]')?.textContent).toContain('no scan waiting for a slot'), { timeout: 1000 })
  })

  it('navigates to job setup from the dashboard action', async () => {
    await renderDashboard()
    const configure = Array.from(container.querySelectorAll('button')).find(button => button.textContent?.includes('Configure job')) as HTMLButtonElement
    await act(async () => configure.click())
    expect(container.querySelector('[data-testid="current-path"]')?.textContent).toBe('/jobs/new')
  })

  it('labels the legacy-job action as a status check and refreshes the status', async () => {
    vi.mocked(adminStatus).mockResolvedValue({ ...status, legacy_yaml_jobs: ['office'] })
    await renderDashboard()
    const checkAgain = Array.from(container.querySelectorAll('button')).find(button => button.textContent === 'Check again') as HTMLButtonElement
    expect(checkAgain).toBeTruthy()
    expect(container.querySelector('[aria-label="Refresh status"]')).toBeNull()
    await act(async () => {
      checkAgain.click()
      await Promise.resolve()
      await Promise.resolve()
    })
    expect(adminStatus).toHaveBeenCalledTimes(2)
  })

  it('uses neutral activity markers for incomplete scans and red only for failures', async () => {
    vi.mocked(listScans).mockResolvedValue({ scans: [{ ...scan, id: 'incomplete', status: 'incomplete' }, { ...scan, id: 'failed', status: 'failed' }], pagination: { ...pagination, total: 2 } })
    await renderDashboard()
    const dots = Array.from(container.querySelectorAll('.activity-list .activity-dot'))
    expect(dots).toHaveLength(2)
    expect(dots[0]).not.toHaveClass('fail')
    expect(dots[0]).not.toHaveClass('success')
    expect(dots[1]).toHaveClass('fail')
  })

  it('shows the total retained scan count and a date for older activity', async () => {
    vi.mocked(listScans).mockResolvedValue({ scans: [scan], pagination: { ...pagination, total: 17 } })
    await renderDashboard()
    const historyMetric = Array.from(container.querySelectorAll('.stat-card')).find(card => card.querySelector('.stat-label')?.textContent === 'Scan history')
    expect(historyMetric?.querySelector('.stat-value')?.textContent).toBe('17')
    const activityTime = container.querySelector('.activity-row time')
    expect(activityTime?.getAttribute('dateTime')).toBe(scan.finished_at)
    expect(activityTime?.textContent).toContain('2026')
    expect(container.querySelector('.latest-activity-list')).toBeTruthy()
    expect(container.querySelector('.activity-row > div > span')).toHaveAttribute('title', 'Completed successfully · Open scan details')
  })

  it('retries loading latest activity and renders it in its dashboard-specific list', async () => {
    vi.mocked(listScans).mockRejectedValueOnce(new Error('scan history unavailable'))
    await renderDashboard()
    await vi.waitFor(() => expect(container.textContent).toContain('Could not load recent scans.'), { timeout: 1000 })

    const retry = Array.from(container.querySelectorAll('.query-error')).find(alert => alert.textContent?.includes('Could not load recent scans.'))?.querySelector('button') as HTMLButtonElement
    expect(retry).toBeTruthy()
    await act(async () => {
      retry.click()
      await Promise.resolve()
      await Promise.resolve()
    })

    await vi.waitFor(() => expect(container.querySelector('.latest-activity-list .activity-row')).toBeTruthy(), { timeout: 1000 })
    expect(listScans).toHaveBeenCalledTimes(2)
  })

  it('warns about a proxy that web.trusted_proxies does not list, only when the status reports one', async () => {
    await renderDashboard()
    expect(container.textContent).not.toContain('web.trusted_proxies')
    act(() => root.unmount())
    queryClient.clear()
    root = createRoot(container)
    vi.mocked(adminStatus).mockResolvedValue({ ...status, untrusted_proxy: { peer: '10.0.0.5', header: 'X-Forwarded-For', last_seen_at: '2026-09-30T08:00:00Z' } })
    await renderDashboard()
    await vi.waitFor(() => expect(container.textContent).toContain('Requests arrive through a proxy that EdgeWatch does not trust.'), { timeout: 1000 })
    const banner = container.querySelector('[role="status"].legacy-banner')
    expect(banner?.textContent).toContain('10.0.0.5 sends X-Forwarded-For, but web.trusted_proxies does not list it')
    expect(banner?.textContent).toContain('If 10.0.0.5 is a proxy that you run, add it to web.trusted_proxies in config.yaml')
  })

  it('hides operational controls and incident metrics for viewers', async () => {
    vi.mocked(getSession).mockResolvedValue(session('viewer'))
    await act(async () => {
      root.render(<QueryClientProvider client={queryClient}><MemoryRouter><Dashboard /></MemoryRouter></QueryClientProvider>)
    })
    await vi.waitFor(() => expect(container.textContent).toContain('demo'), { timeout: 1000 })
    expect(container.textContent).not.toContain('Configure job')
    expect(container.textContent).not.toContain('Open incidents')
    expect(container.textContent).not.toContain('Scans in progress')
    expect(activeScans).not.toHaveBeenCalled()
    expect(listIncidents).not.toHaveBeenCalled()
    expect(listScans).not.toHaveBeenCalled()
    expect(container.querySelector('button[aria-label="Run demo"]')).toBeNull()
  })

  it('allows operators to run jobs without exposing administrator notification controls', async () => {
    vi.mocked(getSession).mockResolvedValue({ ...session('operator'), permissions: ['jobs.read', 'jobs.write', 'scans.read'] })
    await renderDashboard()
    expect(container.querySelector('button[aria-label="Run demo"]')).toBeTruthy()
    expect(container.textContent).toContain('Configure job')
    expect(container.textContent).not.toContain('Test notifications')
    expect(notificationTest).not.toHaveBeenCalled()
  })

  it('restores run, cancel, and notification actions after API failures', async () => {
    vi.mocked(runJob).mockRejectedValueOnce(new Error('worker unavailable'))
    vi.mocked(cancelScan).mockRejectedValueOnce(new Error('cancel unavailable'))
    vi.mocked(notificationTest).mockRejectedValueOnce(new Error('delivery unavailable'))
    await renderDashboard()

    const run = container.querySelector('button[aria-label="Run demo"]') as HTMLButtonElement
    await act(async () => { run.click(); await Promise.resolve(); await Promise.resolve() })
    expect(container.querySelector('[role="alert"]')?.textContent).toContain('worker unavailable')
    expect(run).toBeEnabled()
    await act(async () => { run.click(); await Promise.resolve(); await Promise.resolve() })
    expect(runJob).toHaveBeenCalledTimes(2)

    const cancel = Array.from(container.querySelectorAll('button')).find(button => button.textContent?.includes('Cancel scan')) as HTMLButtonElement
    await act(async () => { cancel.click(); await Promise.resolve(); await Promise.resolve() })
    expect(container.querySelector('[role="alert"]')?.textContent).toContain('cancel unavailable')
    expect(cancel).toBeEnabled()
    await act(async () => { cancel.click(); await Promise.resolve(); await Promise.resolve() })
    expect(cancelScan).toHaveBeenCalledTimes(2)

    const notify = Array.from(container.querySelectorAll('button')).find(button => button.textContent?.includes('Test notifications')) as HTMLButtonElement
    await act(async () => { notify.click(); await Promise.resolve(); await Promise.resolve() })
    expect(container.querySelector('[role="alert"]')?.textContent).toContain('delivery unavailable')
    await act(async () => { notify.click(); await Promise.resolve(); await Promise.resolve() })
    expect(container.querySelector('[role="status"]')?.textContent).toContain('1 destination tested')
    expect(notificationTest).toHaveBeenCalledTimes(2)
  })

  it('keeps the page usable when jobs fail to load', async () => {
    vi.mocked(listJobs).mockRejectedValue(new Error('database unavailable'))
    await act(async () => {
      root.render(<QueryClientProvider client={queryClient}><MemoryRouter><Dashboard /></MemoryRouter></QueryClientProvider>)
    })
    await vi.waitFor(() => expect(container.textContent).toContain('Could not load jobs.'), { timeout: 1000 })
    expect(container.querySelector('[role="alert"]')?.textContent).toContain('Could not load jobs.')
    await act(async () => {
      ;(container.querySelector('[role="alert"] button') as HTMLButtonElement).click()
      await Promise.resolve()
    })
  })

  it('shows a loading surface before the jobs query resolves', async () => {
    let resolveJobs!: (value: { jobs: Job[] }) => void
    vi.mocked(listJobs).mockImplementation(() => new Promise<{ jobs: Job[] }>(resolve => { resolveJobs = resolve }))
    await act(async () => {
      root.render(<QueryClientProvider client={queryClient}><MemoryRouter><Dashboard /></MemoryRouter></QueryClientProvider>)
    })
    expect(container.querySelector('.skeleton-list')).toBeTruthy()
    await act(async () => {
      resolveJobs({ jobs: [job] })
      await Promise.resolve()
    })
    await vi.waitFor(() => expect(container.textContent).toContain('demo'), { timeout: 1000 })
  })

  it('keeps failed metric queries unavailable instead of showing zero', async () => {
    vi.mocked(listJobs).mockRejectedValueOnce(new Error('jobs unavailable'))
    vi.mocked(listScans).mockRejectedValueOnce(new Error('scans unavailable'))
    vi.mocked(activeScans).mockRejectedValueOnce(new Error('active scans unavailable'))
    vi.mocked(listIncidents).mockRejectedValueOnce(new Error('incidents unavailable'))

    await act(async () => {
      root.render(<QueryClientProvider client={queryClient}><MemoryRouter><Dashboard /></MemoryRouter></QueryClientProvider>)
    })
    await vi.waitFor(() => expect(container.querySelectorAll('.stat-unavailable')).toHaveLength(4), { timeout: 1000 })

    expect(container.querySelectorAll('.stat-unavailable .stat-value')).toHaveLength(4)
    expect(container.textContent).toContain('Unavailable')
    expect(container.textContent).not.toContain('No scans running')
    expect(container.querySelectorAll('.stat-retry')).toHaveLength(4)

    const metricRetries = Array.from(container.querySelectorAll('.stat-retry')) as HTMLButtonElement[]
    await act(async () => {
      metricRetries.forEach(button => button.click())
      await Promise.resolve()
    })
    expect(listJobs).toHaveBeenCalledTimes(2)
    expect(listScans).toHaveBeenCalledTimes(2)
    expect(listIncidents).toHaveBeenCalledTimes(2)
  })

  it('keeps the retained scan count visible as stale and recovers it on retry', async () => {
    await renderDashboard()
    vi.mocked(activeScans).mockRejectedValueOnce(new Error('temporary polling failure'))
    const scanHistoryMetric = Array.from(container.querySelectorAll('.stat-card')).find(card => card.querySelector('.stat-label')?.textContent === 'Scan history')

    await act(async () => {
      vi.mocked(listScans).mockRejectedValueOnce(new Error('temporary scan-history polling failure'))
      await queryClient.refetchQueries({ queryKey: ['scans'], exact: true })
    })
    await vi.waitFor(() => expect(scanHistoryMetric?.querySelector('.stat-detail')?.textContent).toContain('Retained scan records · stale'))

    const retry = scanHistoryMetric?.querySelector('.stat-detail .stat-retry') as HTMLButtonElement
    expect(retry).toBeEnabled()
    await act(async () => {
      retry.click()
      await Promise.resolve()
    })
    await vi.waitFor(() => expect(scanHistoryMetric?.querySelector('.stat-detail')?.textContent).not.toContain('stale'))
    expect(scanHistoryMetric?.querySelector('.stat-detail')?.textContent).toContain('Retained scan records')
  })

  it('warns a notification manager that no destination is active', async () => {
    vi.mocked(activeScans).mockResolvedValueOnce({ scans: [activeScan] })
    vi.mocked(adminStatus).mockResolvedValue({ ...status, notification_destinations: 0 })
    await renderDashboard()

    const heading = container.querySelector('.page-heading')
    const warning = container.querySelector('.notification-warning')
    expect(warning?.textContent).toContain('No active notification destinations — alerts are not being delivered.')
    expect(warning?.querySelector('a')?.getAttribute('href')).toBe('/notifications')
    expect(heading?.textContent).not.toContain('Notifications are configured by an administrator.')
    expect(heading?.textContent).not.toContain('notification destination configured')
  })

  it('shows the enforced scanner sandbox in the deployment footprint', async () => {
    vi.mocked(adminStatus).mockResolvedValue({ ...status, scanner_sandbox: { mode: 'auto', state: 'enforced', uid: 65532, gid: 65532, process_uid: 65532, capabilities: ['NET_RAW'], no_new_privileges: true } })
    await renderDashboard()
    await vi.waitFor(() => expect(container.querySelector('.deployment-telemetry')?.textContent).toContain('Scanner sandboxEnforced · NET_RAW'), { timeout: 1000 })
    expect(container.querySelector('.scanner-sandbox-warning')).toBeNull()
  })

  it('shows the notification sandbox in the deployment footprint', async () => {
    vi.mocked(adminStatus).mockResolvedValue({ ...status, scanner_sandbox: { mode: 'auto', state: 'enforced', process_uid: 65532, capabilities: ['NET_RAW'] }, notification_sandbox: { mode: 'auto', state: 'enforced', uid: 65531, gid: 65531, process_uid: 65531, no_new_privileges: true, landlock: { mode: 'auto', state: 'enforced', abi: 6 } } })
    await renderDashboard()
    await vi.waitFor(() => expect(container.querySelector('.deployment-telemetry')?.textContent).toContain('Notification sandboxEnforced · Landlock'), { timeout: 1000 })
  })

  it('shows Landlock beside the enforced scanner sandbox', async () => {
    vi.mocked(adminStatus).mockResolvedValue({ ...status, scanner_sandbox: { mode: 'auto', state: 'enforced', uid: 65532, gid: 65532, process_uid: 65532, capabilities: ['NET_RAW', 'NET_ADMIN'], no_new_privileges: true, landlock: { mode: 'auto', state: 'enforced', abi: 6 }, seccomp: { state: 'enforced' } } })
    await renderDashboard()
    await vi.waitFor(() => expect(container.querySelector('.deployment-telemetry')?.textContent).toContain('Scanner sandboxEnforced · NET_RAW, NET_ADMIN · Landlock · seccomp'), { timeout: 1000 })
    expect(container.querySelector('.scanner-sandbox-warning')).toBeNull()
  })

  it('warns an administrator when scanner processes run as UID 0 with only Landlock', async () => {
    vi.mocked(adminStatus).mockResolvedValue({ ...status, scanner_sandbox: { mode: 'auto', state: 'unavailable', process_uid: 0, reason: 'the container does not grant KILL', landlock: { mode: 'auto', state: 'enforced', abi: 6 } } })
    await renderDashboard()
    await vi.waitFor(() => expect(container.querySelector('.scanner-sandbox-warning')?.textContent).toContain('Scanner processes run as UID 0, restricted only by Landlock. the container does not grant KILL'), { timeout: 1000 })
    expect(container.querySelector('.deployment-telemetry')?.textContent).toContain('Scanner sandboxLandlock only')
  })

  it('warns an administrator when scanner processes run unconfined as UID 0', async () => {
    vi.mocked(adminStatus).mockResolvedValue({ ...status, scanner_sandbox: { mode: 'auto', state: 'unavailable', process_uid: 0, reason: 'the container does not grant KILL, which EdgeWatch needs to start and stop scanner processes as UID 65532; add them to cap_add', landlock: { mode: 'auto', state: 'unavailable', reason: 'the kernel does not provide Landlock' } } })
    await renderDashboard()
    await vi.waitFor(() => expect(container.querySelector('.scanner-sandbox-warning')?.textContent).toContain('Scanner processes run unconfined as UID 0. the container does not grant KILL'), { timeout: 1000 })
    expect(container.querySelector('.deployment-telemetry')?.textContent).toContain('Scanner sandboxUnavailable')
  })

  it('does not warn when scanner processes already run without root', async () => {
    vi.mocked(adminStatus).mockResolvedValue({ ...status, scanner_sandbox: { mode: 'auto', state: 'unavailable', process_uid: 1000, reason: 'EdgeWatch runs as UID 1000 rather than 0' } })
    await renderDashboard()
    await vi.waitFor(() => expect(container.querySelector('.deployment-telemetry')?.textContent).toContain('Scanner sandboxUnavailable'), { timeout: 1000 })
    expect(container.querySelector('.scanner-sandbox-warning')).toBeNull()
  })

  it('labels a scanner sandbox that is off', async () => {
    vi.mocked(adminStatus).mockResolvedValue({ ...status, scanner_sandbox: { mode: 'off', state: 'disabled', process_uid: 0, reason: 'scanner.sandbox is off' } })
    await renderDashboard()
    await vi.waitFor(() => expect(container.querySelector('.deployment-telemetry')?.textContent).toContain('Scanner sandboxOff'), { timeout: 1000 })
    expect(container.querySelector('.scanner-sandbox-warning')).toBeNull()
  })

  it('does not show the scanner sandbox warning to an operator', async () => {
    vi.mocked(getSession).mockResolvedValue({ ...session('operator'), permissions: ['overview.read', 'jobs.read', 'jobs.write', 'scans.read', 'incidents.read'] })
    vi.mocked(adminStatus).mockResolvedValue({ ...status, scanner_sandbox: { mode: 'off', state: 'disabled', process_uid: 0 } })
    await renderDashboard()
    expect(container.querySelector('.scanner-sandbox-warning')).toBeNull()
  })

  it('tells an operator that an administrator configures notifications', async () => {
    vi.mocked(getSession).mockResolvedValue({ ...session('operator'), permissions: ['overview.read', 'jobs.read', 'jobs.write', 'scans.read', 'incidents.read'] })
    vi.mocked(adminStatus).mockResolvedValue({ ...status, notification_destinations: 0 })
    await renderDashboard()

    const heading = container.querySelector('.page-heading')
    expect(heading?.textContent).toContain('Notifications are configured by an administrator.')
    expect(container.querySelector('.notification-warning')).toBeNull()
  })

  it('makes no notification claim while the destination count is unknown', async () => {
    const { notification_destinations: _omitted, ...withoutCount } = status
    vi.mocked(adminStatus).mockResolvedValue(withoutCount)
    await renderDashboard()

    const heading = container.querySelector('.page-heading')
    expect(heading?.textContent).not.toContain('notification destination')
    expect(heading?.textContent).not.toContain('Notifications are configured by an administrator.')
    expect(container.querySelector('.notification-warning')).toBeNull()
  })

  it('does not report notification testing as successful when no destination was tested', async () => {
    vi.mocked(notificationTest).mockResolvedValueOnce({ sent: 0 })
    await renderDashboard()
    const notify = Array.from(container.querySelectorAll('button')).find(button => button.textContent?.includes('Test notifications')) as HTMLButtonElement
    await act(async () => {
      notify.click()
      await Promise.resolve()
      await Promise.resolve()
    })

    const feedback = container.querySelector('[role="status"].notice.warning')
    expect(feedback?.textContent).toContain('No enabled notification destinations were tested.')
    expect(container.querySelector('.success-banner')).toBeNull()
  })

  it('retries operational incident and live-scan errors', async () => {
    vi.mocked(adminStatus).mockRejectedValueOnce(new Error('status unavailable'))
    vi.mocked(activeScans).mockRejectedValueOnce(new Error('active status unavailable'))
    vi.mocked(listIncidents).mockRejectedValueOnce(new Error('incidents unavailable'))
    await act(async () => {
      root.render(<QueryClientProvider client={queryClient}><MemoryRouter><Dashboard /></MemoryRouter></QueryClientProvider>)
    })
    await vi.waitFor(() => {
      expect(container.textContent).toContain('Operational status could not be loaded.')
      expect(container.textContent).toContain('Could not load scans in progress.')
      expect(container.textContent).toContain('Could not load the incident count.')
    }, { timeout: 1000 })

    const alerts = Array.from(container.querySelectorAll('.query-error'))
    for (const message of ['Operational status could not be loaded.', 'Could not load scans in progress.', 'Could not load the incident count.']) {
      const alert = alerts.find(item => item.textContent?.includes(message))
      const retry = alert?.querySelector('button') as HTMLButtonElement
      await act(async () => { retry.click(); await Promise.resolve() })
    }
    await vi.waitFor(() => expect(container.textContent).not.toContain('Operational status could not be loaded.'), { timeout: 1000 })
    await vi.waitFor(() => expect(container.textContent).not.toContain('Could not load scans in progress.'), { timeout: 1000 })
    await vi.waitFor(() => expect(container.textContent).not.toContain('Could not load the incident count.'), { timeout: 1000 })
    expect(adminStatus).toHaveBeenCalledTimes(2)
    expect(activeScans).toHaveBeenCalledTimes(2)
    expect(listIncidents).toHaveBeenCalledTimes(2)
  })
})
