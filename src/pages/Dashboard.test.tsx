/** @vitest-environment jsdom */

import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { activeScans, adminStatus, cancelScan, getSession, listIncidents, listJobs, listScans, notificationTest, runJob } from '../api'
import type { AdminStatus, SessionUser } from '../api'
import type { ActiveScan, Job, ScanSummary } from '../types'
import { Dashboard } from './Dashboard'
import { defaultUnitScope } from '../test/test-utils'

vi.mock('../api', () => ({
  activeScans: vi.fn(),
  adminStatus: vi.fn(),
  cancelScan: vi.fn(),
  getSession: vi.fn(),
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
    vi.clearAllMocks()
  })

  async function renderDashboard() {
    await act(async () => {
      root.render(<QueryClientProvider client={queryClient}><MemoryRouter><Dashboard /></MemoryRouter></QueryClientProvider>)
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
    expect(container.textContent).toContain('Good afternoon, Alice')
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
    vi.mocked(listJobs).mockRejectedValue(new Error('jobs unavailable'))
    vi.mocked(listScans).mockRejectedValue(new Error('scans unavailable'))
    vi.mocked(activeScans).mockRejectedValue(new Error('active scans unavailable'))
    vi.mocked(listIncidents).mockRejectedValue(new Error('incidents unavailable'))

    await act(async () => {
      root.render(<QueryClientProvider client={queryClient}><MemoryRouter><Dashboard /></MemoryRouter></QueryClientProvider>)
    })
    await vi.waitFor(() => expect(container.querySelectorAll('.stat-unavailable')).toHaveLength(4), { timeout: 1000 })

    expect(container.querySelectorAll('.stat-unavailable .stat-value')).toHaveLength(4)
    expect(container.textContent).toContain('Unavailable')
    expect(container.textContent).not.toContain('No scans running')
    expect(container.querySelectorAll('.stat-retry')).toHaveLength(4)

    await act(async () => {
      ;(container.querySelector('.stat-retry') as HTMLButtonElement).click()
      await Promise.resolve()
    })
    expect(listJobs).toHaveBeenCalledTimes(2)
  })

  it('keeps the last live scan count visible as stale and recovers it on retry', async () => {
    await renderDashboard()
    vi.mocked(activeScans).mockRejectedValueOnce(new Error('temporary polling failure'))
    const recentScansMetric = Array.from(container.querySelectorAll('.stat-card')).find(card => card.querySelector('.stat-label')?.textContent === 'Recent scans')

    await act(async () => {
      await queryClient.refetchQueries({ queryKey: ['active-scans'], exact: true })
    })
    await vi.waitFor(() => expect(recentScansMetric?.querySelector('.stat-detail')?.textContent).toContain('1 in progress · stale'))

    const retry = recentScansMetric?.querySelector('.stat-detail .stat-retry') as HTMLButtonElement
    expect(retry).toBeEnabled()
    await act(async () => {
      retry.click()
      await Promise.resolve()
    })
    await vi.waitFor(() => expect(recentScansMetric?.querySelector('.stat-detail')?.textContent).not.toContain('stale'))
    expect(recentScansMetric?.querySelector('.stat-detail')?.textContent).toContain('1 in progress')
  })

  it('explains when no notification destination is configured', async () => {
    vi.mocked(adminStatus).mockResolvedValue({ ...status, notification_destinations: 0 })
    await renderDashboard()

    expect(container.querySelector('.page-heading')?.textContent).toContain('Notifications are configured by an administrator.')
    expect(container.querySelector('.page-heading')?.textContent).not.toContain('notification destination configured')
  })
})
