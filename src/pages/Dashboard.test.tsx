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
  permissions: [],
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
  permissions: [],
  csrf_token: 'csrf',
  totp_enabled: false,
  password_requirements: { minimum_length: 12 },
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

  it('keeps the page usable when jobs fail to load', async () => {
    vi.mocked(listJobs).mockRejectedValue(new Error('database unavailable'))
    await act(async () => {
      root.render(<QueryClientProvider client={queryClient}><MemoryRouter><Dashboard /></MemoryRouter></QueryClientProvider>)
    })
    await vi.waitFor(() => expect(container.textContent).toContain('Could not load jobs.'), { timeout: 1000 })
    expect(container.querySelector('[role="alert"]')?.textContent).toContain('Could not load jobs.')
  })
})
