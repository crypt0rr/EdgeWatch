/** @vitest-environment jsdom */

import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  getJob,
  getSession,
  jobBaseline,
  jobScans,
  latestSuccessfulScan,
  scanCycle,
  scanResults,
} from '../api'
import type { Job, ScanSummary } from '../types'
import { JobDetail } from './JobDetail'

vi.mock('../api', () => ({
  approveBaseline: vi.fn(),
  archiveJob: vi.fn(),
  deleteJob: vi.fn(),
  getJob: vi.fn(),
  getSession: vi.fn(),
  jobBaseline: vi.fn(),
  jobScans: vi.fn(),
  latestSuccessfulScan: vi.fn(),
  resetBaseline: vi.fn(),
  restoreJob: vi.fn(),
  runJob: vi.fn(),
  scanCycle: vi.fn(),
  discardScanCycle: vi.fn(),
  scanDetail: vi.fn(),
  scanHosts: vi.fn(),
  scanResults: vi.fn(),
}))

;(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true

const job: Job = {
  id: 'job-1',
  revision: 1,
  enabled: true,
  archived: false,
  security_hash: 'scope',
  created_at: '2026-09-13T10:00:00Z',
  updated_at: '2026-09-13T10:00:00Z',
  job: {
    name: 'production',
    schedule: '0 * * * *',
    timezone: 'UTC',
    targets: ['router.example'],
    max_expanded_hosts: 32,
    tcp: { ports: '22,443', mode: 'connect', service_detection: true },
    timing: 'balanced',
    timeout: '1h',
    baseline_samples: 1,
    change_confirmations: 1,
  },
  baseline: { status: 'complete', samples: 1, attempts: 1, scan_id: 'scan-1', host_count: 1 },
}

const summary: ScanSummary = {
  id: 'scan-1',
  job_id: 'job-1',
  job: 'production',
  started_at: '2026-09-13T10:00:00Z',
  finished_at: '2026-09-13T10:00:02Z',
  status: 'success',
  config_hash: 'scope',
}

const pagination = { limit: 10, offset: 0, total: 1, has_more: false, next_offset: null }
const baselineResponse = {
  job_id: 'job-1',
  job: 'production',
  revision: 1,
  security_hash: 'scope',
  baseline: job.baseline,
  snapshot: { units: [{ target: 'router.example', protocol: 'tcp', addresses: ['198.51.100.10'], ports: [{ port: 443, state: 'open', service: 'https' }] }], scopes: [] },
  pagination,
}
const latestResponse = { scan: summary }
const latestResultsResponse = {
  results: [{ target: 'router.example', protocol: 'tcp', addresses: ['198.51.100.10'], ports: [{ port: 443, state: 'open', service: 'https' }] }],
  pagination,
}

describe('job surface overview', () => {
  let root: Root
  let container: HTMLDivElement
  let queryClient: QueryClient

  beforeEach(() => {
    container = document.createElement('div')
    document.body.appendChild(container)
    root = createRoot(container)
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    vi.mocked(getJob).mockResolvedValue(job)
    vi.mocked(getSession).mockResolvedValue({ role: 'administrator', user_id: 'user-1', username: 'admin', permissions: [], csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 } })
    vi.mocked(jobBaseline).mockResolvedValue(baselineResponse)
    vi.mocked(latestSuccessfulScan).mockResolvedValue(latestResponse)
    vi.mocked(scanResults).mockResolvedValue(latestResultsResponse)
    vi.mocked(jobScans).mockResolvedValue({ scans: [summary], pagination })
    vi.mocked(scanCycle).mockResolvedValue({ cycle: null })
  })

  afterEach(() => {
    act(() => root.unmount())
    queryClient.clear()
    container.remove()
    vi.clearAllMocks()
  })

  function renderPage() {
    return act(async () => {
      root.render(<QueryClientProvider client={queryClient}><MemoryRouter initialEntries={['/jobs/job-1']}><Routes><Route path="/jobs/:id" element={<JobDetail />} /></Routes></MemoryRouter></QueryClientProvider>)
      await Promise.resolve()
    })
  }

  it('orders expected baseline, latest successful scan, and history vertically', async () => {
    await renderPage()
    await vi.waitFor(() => expect(container.textContent).toContain('Latest successful scan'), { timeout: 1000 })
    await vi.waitFor(() => expect(container.textContent).toContain('443/tcp'), { timeout: 1000 })
    await vi.waitFor(() => expect(vi.mocked(scanResults)).toHaveBeenCalled(), { timeout: 1000 })

    const headings = Array.from(container.querySelectorAll('h2')).map((heading) => heading.textContent)
    expect(headings.indexOf('Expected baseline')).toBeGreaterThanOrEqual(0)
    expect(headings.indexOf('Latest successful scan')).toBeGreaterThan(headings.indexOf('Expected baseline'))
    expect(headings.indexOf('Recent scans')).toBeGreaterThan(headings.indexOf('Latest successful scan'))
    expect(container.textContent).toContain('router.example')
    expect(container.textContent).toContain('https')
    expect(vi.mocked(jobBaseline)).toHaveBeenCalledWith('job-1', 0, 10)
    expect(vi.mocked(scanResults)).toHaveBeenCalledWith('job-1', 'scan-1', 0, 10)
  })

  it('limits viewers to expected baseline information', async () => {
    vi.mocked(getSession).mockResolvedValue({ role: 'viewer', user_id: 'user-2', username: 'viewer', permissions: [], csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 } })
    await renderPage()
    await vi.waitFor(() => expect(container.textContent).toContain('Expected baseline'), { timeout: 1000 })
    expect(container.textContent).toContain('router.example')
    expect(container.textContent).not.toContain('Latest successful scan')
    expect(container.textContent).not.toContain('Recent scans')
    expect(latestSuccessfulScan).not.toHaveBeenCalled()
    expect(jobScans).not.toHaveBeenCalled()
  })
})
