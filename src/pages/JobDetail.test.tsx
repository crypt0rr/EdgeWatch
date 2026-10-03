/** @vitest-environment jsdom */

import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  activeScans,
  getJob,
  getSession,
  jobBaseline,
  jobPendingChanges,
  jobScans,
  latestSuccessfulScan,
  scanDetail,
  scanCycle,
  scanHosts,
  scanResults,
} from '../api'
import type { Job, ScanSummary } from '../types'
import { JobDetail } from './JobDetail'
import { defaultUnitScope } from '../test/test-utils'

vi.mock('../api', () => ({
  activeScans: vi.fn(),
  approveBaseline: vi.fn(),
  archiveJob: vi.fn(),
  deleteJob: vi.fn(),
  getJob: vi.fn(),
  getSession: vi.fn(),
  jobBaseline: vi.fn(),
  jobPendingChanges: vi.fn(),
  jobScans: vi.fn(),
  latestSuccessfulScan: vi.fn(),
  resetBaseline: vi.fn(),
  cancelScan: vi.fn(),
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
const detailResponse = {
  scan: summary,
  changes: [],
  changes_pagination: pagination,
  current_security_hash: 'scope',
  comparison_source: 'scan_time',
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
    vi.mocked(activeScans).mockResolvedValue({ scans: [] })
    vi.mocked(getJob).mockResolvedValue(job)
    vi.mocked(getSession).mockResolvedValue({ role: 'administrator', user_id: 'user-1', username: 'admin', permissions: ['jobs.write', 'scans.read', 'baselines.read'], csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 }, ...defaultUnitScope })
    vi.mocked(jobBaseline).mockResolvedValue(baselineResponse)
    vi.mocked(jobPendingChanges).mockResolvedValue({ job_id: 'job-1', job: 'production', pending_changes: [], pagination })
    vi.mocked(latestSuccessfulScan).mockResolvedValue(latestResponse)
    vi.mocked(scanResults).mockResolvedValue(latestResultsResponse)
    vi.mocked(scanHosts).mockResolvedValue({ hosts: [], pagination } as never)
    vi.mocked(scanDetail).mockResolvedValue(detailResponse)
    vi.mocked(jobScans).mockResolvedValue({ scans: [summary], pagination })
    vi.mocked(scanCycle).mockResolvedValue({ cycle: null })
  })

  afterEach(() => {
    act(() => root.unmount())
    queryClient.clear()
    container.remove()
    vi.clearAllMocks()
  })

  function renderPage(initialEntry = '/jobs/job-1') {
    return act(async () => {
      root.render(<QueryClientProvider client={queryClient}><MemoryRouter initialEntries={[initialEntry]}><Routes><Route path="/jobs/:id/scans/:scanId" element={<JobDetail />} /><Route path="/jobs/:id" element={<JobDetail />} /></Routes></MemoryRouter></QueryClientProvider>)
      await Promise.resolve()
    })
  }

  it('retries baseline, latest-scan, history, and latest-result read errors', async () => {
    vi.mocked(jobBaseline).mockRejectedValueOnce(new Error('baseline unavailable'))
    vi.mocked(latestSuccessfulScan).mockRejectedValueOnce(new Error('latest scan unavailable'))
    vi.mocked(jobScans).mockRejectedValueOnce(new Error('scan history unavailable'))
    vi.mocked(scanResults).mockRejectedValueOnce(new Error('latest results unavailable'))
    await renderPage()
    for (const message of ['Could not load expected baseline results.', 'Could not load the latest successful scan.', 'Could not load recent scans.']) {
      await vi.waitFor(() => expect(container.textContent).toContain(message), { timeout: 1000 })
    }

    const retries = Array.from(container.querySelectorAll('.error-card button')) as HTMLButtonElement[]
    expect(retries).toHaveLength(3)
    await act(async () => {
      for (const retry of retries) retry.click()
      await Promise.resolve()
    })
    await vi.waitFor(() => expect(container.textContent).toContain('Could not load latest scan results.'), { timeout: 1000 })
    const latestResultsRetry = Array.from(container.querySelectorAll('.error-card')).find(notice => notice.textContent?.includes('Could not load latest scan results.'))?.querySelector('button') as HTMLButtonElement
    await act(async () => latestResultsRetry.click())
    await vi.waitFor(() => expect(container.textContent).toContain('443/tcp'), { timeout: 1000 })
  })

  it('retries selected scan detail and snapshot-result read errors inline', async () => {
    vi.mocked(scanDetail).mockRejectedValueOnce(new Error('scan detail unavailable'))
    vi.mocked(scanDetail).mockResolvedValueOnce(detailResponse)
    await renderPage()
    await vi.waitFor(() => expect(container.querySelector('.scan-row')).not.toBeNull(), { timeout: 1000 })
    act(() => (container.querySelector('.scan-row') as HTMLButtonElement).click())
    await vi.waitFor(() => expect(container.textContent).toContain('Could not load this scan’s details.'), { timeout: 1000 })
    const detailRetry = Array.from(container.querySelectorAll('.error-card')).find(notice => notice.textContent?.includes('Could not load this scan’s details.'))?.querySelector('button') as HTMLButtonElement
    await act(async () => detailRetry.click())
    await vi.waitFor(() => expect(container.textContent).toContain('Scan diff'), { timeout: 1000 })

    vi.mocked(scanHosts).mockRejectedValueOnce(new Error('snapshot unavailable'))
    vi.mocked(scanHosts).mockResolvedValueOnce({ hosts: [{ address: '198.51.100.10', open_ports: 1, open_filtered_ports: 0, protocols: [{ protocol: 'tcp' }] }], pagination } as never)
    act(() => (Array.from(container.querySelectorAll('button')).find(button => button.textContent === 'View results') as HTMLButtonElement).click())
    await vi.waitFor(() => expect(container.textContent).toContain('Could not load scan results.'), { timeout: 1000 })
    const resultsRetry = Array.from(container.querySelectorAll('.error-card')).find(notice => notice.textContent?.includes('Could not load scan results.'))?.querySelector('button') as HTMLButtonElement
    await act(async () => resultsRetry.click())
    await vi.waitFor(() => expect(container.textContent).toContain('View host details'), { timeout: 1000 })
  })

  it('uses a neutral tone for informational scan changes', async () => {
    vi.mocked(scanDetail).mockResolvedValue({
      ...detailResponse,
      changes: [{ key: 'service|router.example|tcp|25', kind: 'service', target: 'router.example', protocol: 'tcp', port: 25, old: 'smtp', new: 'unknown', severity: 'info' }],
    })
    await renderPage('/jobs/job-1/scans/scan-1')
    await vi.waitFor(() => expect(container.querySelector('.change-row .pill')).not.toBeNull(), { timeout: 1000 })
    expect(container.querySelector('.change-row .pill')).toHaveClass('gray')
  })

  it('uses a consistent paused tone and keeps incomplete scan activity neutral', async () => {
    vi.mocked(getJob).mockResolvedValue({ ...job, enabled: false })
    vi.mocked(jobScans).mockResolvedValue({ scans: [{ ...summary, status: 'incomplete' }, { ...summary, id: 'scan-2', status: 'failed' }], pagination: { ...pagination, total: 2 } })
    await renderPage()
    await vi.waitFor(() => expect(container.querySelectorAll('.scan-row')).toHaveLength(2), { timeout: 1000 })
    expect(container.querySelector('.title-row .pill')).toHaveClass('amber')
    const dots = Array.from(container.querySelectorAll('.scan-row .activity-dot'))
    expect(dots[0]).not.toHaveClass('fail')
    expect(dots[0]).not.toHaveClass('success')
    expect(dots[1]).toHaveClass('fail')
  })

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

  it('shows pending baseline confirmations only to scan readers', async () => {
    vi.mocked(getJob).mockResolvedValue({ ...job, baseline: { ...job.baseline, pending: 1 } })
    vi.mocked(jobPendingChanges).mockResolvedValue({ job_id: 'job-1', job: 'production', pending_changes: [{ key: 'port|router.example|tcp|443', count: 1, change: { key: 'port|router.example|tcp|443', kind: 'port', target: 'router.example', protocol: 'tcp', port: 443, old: 'not-open', new: 'open', severity: 'critical' } }], pagination })
    await renderPage()
    await vi.waitFor(() => expect(container.textContent).toContain('1 / 1 scans'), { timeout: 1000 })
    expect(container.textContent).toContain('Port opened · router.example · TCP:443 · not-open → open')
    expect(container.querySelector('#pending-changes')).toBeTruthy()
    expect(jobPendingChanges).toHaveBeenCalledWith('job-1', 0, 10)

    act(() => root.unmount())
    queryClient.clear()
    root = createRoot(container)
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    vi.mocked(getSession).mockResolvedValue({ role: 'viewer', user_id: 'viewer', username: 'viewer', permissions: ['jobs.read', 'baselines.read'], csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 }, ...defaultUnitScope })
    await renderPage()
    expect(container.querySelector('#pending-changes')).toBeNull()
    expect(jobPendingChanges).toHaveBeenCalledOnce()
  })

  it('limits viewers to expected baseline information', async () => {
    vi.mocked(getSession).mockResolvedValue({ role: 'viewer', user_id: 'user-2', username: 'viewer', permissions: [], csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 }, ...defaultUnitScope })
    await renderPage()
    await vi.waitFor(() => expect(container.textContent).toContain('Expected baseline'), { timeout: 1000 })
    expect(container.textContent).toContain('router.example')
    expect(container.textContent).not.toContain('Latest successful scan')
    expect(container.textContent).not.toContain('Recent scans')
    expect(latestSuccessfulScan).not.toHaveBeenCalled()
    expect(jobScans).not.toHaveBeenCalled()
  })

  it('shows a safe scan-progress notice and does not surface storage errors', async () => {
    vi.mocked(getJob).mockResolvedValue({ ...job, scan_cycle_error: 'cycle_status_unavailable' })
    vi.mocked(scanCycle).mockRejectedValue(new Error('SQL logic error: sensitive store detail'))
    await renderPage()

    await vi.waitFor(() => expect(container.textContent).toContain('Saved scan progress could not be loaded.'), { timeout: 1000 })
    expect(container.textContent).toContain('EdgeWatch will retry automatically')
    expect(container.textContent).not.toContain('sensitive store detail')
  })

  it('points an operator at the editor when routing selects a missing destination', async () => {
    vi.mocked(getJob).mockResolvedValue({ ...job, job: { ...job.job, notification_destinations: ['file:old-uuid'] }, missing_notification_destinations: ['file:old-uuid'] })
    await renderPage()

    await vi.waitFor(() => expect(container.textContent).toContain('Notification routing needs attention.'), { timeout: 1000 })
    expect(container.textContent).toContain('A selected notification destination no longer exists')
    expect(container.textContent).toContain('Changing a deployment URL in config.yaml creates a new destination.')
    const edit = Array.from(container.querySelectorAll('a')).find(link => link.textContent === 'Edit the job to choose a current destination.')
    expect(edit?.getAttribute('href')).toBe('/jobs/job-1/edit')
  })

  it('reports several missing destinations without an edit link for viewers', async () => {
    vi.mocked(getSession).mockResolvedValue({ role: 'viewer', user_id: 'user-2', username: 'viewer', permissions: [], csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 }, ...defaultUnitScope })
    vi.mocked(getJob).mockResolvedValue({ ...job, missing_notification_destinations: ['file:old-uuid', 'deleted-uuid'] })
    await renderPage()

    await vi.waitFor(() => expect(container.textContent).toContain('2 selected notification destinations no longer exist'), { timeout: 1000 })
    expect(container.textContent).toContain('An operator can edit the job to choose a current destination.')
    expect(Array.from(container.querySelectorAll('a')).some(link => link.textContent?.includes('Edit the job'))).toBe(false)
  })

  it('renders the selected scan detail directly beneath its row with accessible expansion state', async () => {
    await renderPage()
    await vi.waitFor(() => expect(container.querySelector('.scan-row')).not.toBeNull(), { timeout: 1000 })

    const row = container.querySelector('.scan-row') as HTMLButtonElement
    expect(row.getAttribute('aria-expanded')).toBe('false')

    act(() => row.click())
    await vi.waitFor(() => expect(container.querySelector('.scan-detail-inline')).not.toBeNull(), { timeout: 1000 })
    await vi.waitFor(() => expect(container.textContent).toContain('Scan diff'), { timeout: 1000 })

    const entry = row.closest('.scan-entry')
    expect(entry).not.toBeNull()
    expect(entry?.children[0]).toBe(row)
    expect(entry?.children[1].classList.contains('scan-detail-inline')).toBe(true)
    expect(row.getAttribute('aria-expanded')).toBe('true')
    expect(row.getAttribute('aria-controls')).toBe('scan-detail-scan-1')
    expect(container.querySelector('.scan-detail-inline')?.getAttribute('aria-labelledby')).toBe('scan-detail-title-scan-1')

    const close = container.querySelector('.scan-detail-inline .icon-button') as HTMLButtonElement
    act(() => close.click())
    await vi.waitFor(() => expect(container.querySelector('.scan-detail-inline')).toBeNull(), { timeout: 1000 })
    expect(container.querySelector('.scan-row')?.getAttribute('aria-expanded')).toBe('false')
  })

  it('moves the single inline detail section when another scan is selected', async () => {
    const secondScan: ScanSummary = { ...summary, id: 'scan-2', finished_at: '2026-09-13T10:01:02Z' }
    vi.mocked(jobScans).mockResolvedValue({ scans: [summary, secondScan], pagination: { ...pagination, total: 2 } })
    await renderPage()
    await vi.waitFor(() => expect(container.querySelectorAll('.scan-row')).toHaveLength(2), { timeout: 1000 })

    const rows = Array.from(container.querySelectorAll('.scan-row')) as HTMLButtonElement[]
    act(() => rows[0].click())
    await vi.waitFor(() => expect(rows[0].closest('.scan-entry')?.querySelector('.scan-detail-inline')).not.toBeNull(), { timeout: 1000 })
    act(() => rows[1].click())
    await vi.waitFor(() => expect(rows[1].closest('.scan-entry')?.querySelector('.scan-detail-inline')).not.toBeNull(), { timeout: 1000 })

    expect(rows[0].closest('.scan-entry')?.querySelector('.scan-detail-inline')).toBeNull()
    expect(container.querySelectorAll('.scan-detail-inline')).toHaveLength(1)
  })

  it('clears a click-selected detail when moving to another history page', async () => {
    vi.mocked(jobScans).mockResolvedValue({ scans: [summary], pagination: { ...pagination, total: 11, has_more: true, next_offset: 10 } })
    await renderPage()
    await vi.waitFor(() => expect(container.querySelector('.scan-row')).not.toBeNull(), { timeout: 1000 })

    const row = container.querySelector('.scan-row') as HTMLButtonElement
    act(() => row.click())
    await vi.waitFor(() => expect(container.querySelector('.scan-detail-inline')).not.toBeNull(), { timeout: 1000 })
    const next = container.querySelector('.pagination-actions .button:last-child') as HTMLButtonElement
    act(() => next.click())

    await vi.waitFor(() => expect(container.querySelector('.scan-detail-inline')).toBeNull(), { timeout: 1000 })
    await vi.waitFor(() => expect(container.querySelector('.scan-row')?.getAttribute('aria-expanded')).toBe('false'), { timeout: 1000 })
  })

  it('keeps direct links to scans outside the current history page usable', async () => {
    const deepLinkedScan: ScanSummary = { ...summary, id: 'scan-old' }
    vi.mocked(scanDetail).mockResolvedValue({ ...detailResponse, scan: deepLinkedScan })
    await renderPage('/jobs/job-1/scans/scan-old')
    await vi.waitFor(() => expect(container.querySelector('.scan-detail-inline')).not.toBeNull(), { timeout: 1000 })

    const fallback = container.querySelector('.selected-scan-fallback')
    const list = container.querySelector('.scan-list')
    expect(fallback).not.toBeNull()
    expect(list).not.toBeNull()
    expect(fallback!.compareDocumentPosition(list!) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
  })
})
