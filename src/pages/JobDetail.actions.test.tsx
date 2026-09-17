/** @vitest-environment jsdom */

import { fireEvent, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { Route, Routes } from 'react-router-dom'
import { approveBaseline, archiveJob, deleteJob, discardScanCycle, getJob, getSession, jobBaseline, jobScans, latestSuccessfulScan, resetBaseline, restoreJob, runJob, scanCycle, scanDetail, scanHosts, scanResults } from '../api'
import { renderWithProviders } from '../test/test-utils'
import { JobDetail } from './JobDetail'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return { ...actual, approveBaseline: vi.fn(), archiveJob: vi.fn(), deleteJob: vi.fn(), getJob: vi.fn(), getSession: vi.fn(), jobBaseline: vi.fn(), jobScans: vi.fn(), latestSuccessfulScan: vi.fn(), resetBaseline: vi.fn(), restoreJob: vi.fn(), runJob: vi.fn(), scanCycle: vi.fn(), discardScanCycle: vi.fn(), scanDetail: vi.fn(), scanHosts: vi.fn(), scanResults: vi.fn() }
})

const job = {
  id: 'job-1', revision: 7, enabled: true, archived: false, security_hash: 'scope', created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z',
  job: { name: 'Production', schedule: '0 * * * *', timezone: 'UTC', targets: ['198.51.100.10'], max_expanded_hosts: 32, tcp: { ports: '22,443', mode: 'connect', service_detection: true, engine: 'nmap' }, timing: 'balanced', timeout: '1h', resume_window: '8d', baseline_samples: 1, change_confirmations: 1 },
  baseline: { status: 'complete', samples: 1, attempts: 1, scan_id: 'scan-1', host_count: 1 },
}
const scan = { id: 'scan-1', job_id: 'job-1', job: 'Production', started_at: '2026-01-01T00:00:00Z', finished_at: '2026-01-01T00:01:00Z', status: 'success', config_hash: 'scope' }
const page = { limit: 10, offset: 0, total: 1, has_more: false, next_offset: null }

describe('job detail actions', () => {
  beforeEach(() => {
    vi.mocked(getJob).mockResolvedValue(job as never)
    vi.mocked(getSession).mockResolvedValue({ role: 'administrator', user_id: 'admin', username: 'admin', permissions: [], csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 } })
    vi.mocked(jobBaseline).mockResolvedValue({ job_id: 'job-1', job: 'Production', revision: 7, security_hash: 'scope', baseline: job.baseline, snapshot: { units: [], scopes: [] }, pagination: page } as never)
    vi.mocked(latestSuccessfulScan).mockResolvedValue({ scan } as never)
    vi.mocked(jobScans).mockResolvedValue({ scans: [scan], pagination: page } as never)
    vi.mocked(scanDetail).mockResolvedValue({ scan, changes: [], changes_pagination: page, current_security_hash: 'scope', comparison_source: 'scan_time' } as never)
    vi.mocked(scanHosts).mockResolvedValue({ hosts: [], pagination: page } as never)
    vi.mocked(scanResults).mockResolvedValue({ results: [], pagination: page } as never)
    vi.mocked(scanCycle).mockResolvedValue({ cycle: null })
    vi.mocked(runJob).mockResolvedValue({ status: 'started', job_id: 'job-1' })
    vi.mocked(resetBaseline).mockResolvedValue(undefined)
    vi.mocked(approveBaseline).mockResolvedValue(undefined)
    vi.mocked(archiveJob).mockResolvedValue(undefined)
    vi.mocked(restoreJob).mockResolvedValue(undefined)
    vi.mocked(deleteJob).mockResolvedValue(undefined)
  })
  afterEach(() => vi.clearAllMocks())

  function renderPage() {
    return renderWithProviders(<Routes><Route path="/jobs/:id/*" element={<JobDetail />} /></Routes>, { route: ['/jobs/job-1'] })
  }

  it('starts a scan and refreshes the relevant queries', async () => {
    const { client } = renderPage()
    const invalidate = vi.spyOn(client, 'invalidateQueries')
    await waitFor(() => expect(screen.getByRole('button', { name: /Scan now/ })).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: /Scan now/ }))
    await waitFor(() => expect(runJob).toHaveBeenCalledWith('job-1'))
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['latest-successful-scan', 'job-1'] })
  })

  it('resets and approves baseline evidence through guarded dialogs', async () => {
    renderPage()
    await waitFor(() => expect(screen.getByRole('button', { name: 'Reset baseline' })).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: 'Reset baseline' }))
    fireEvent.click(screen.getByRole('dialog').querySelector('button[type="submit"]')!)
    await waitFor(() => expect(resetBaseline).toHaveBeenCalledWith('job-1', 'scan-1', false))

    fireEvent.click(screen.getByRole('button', { name: /scan-1/i }))
    await waitFor(() => expect(screen.getByRole('button', { name: 'Use as baseline' })).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: 'Use as baseline' }))
    fireEvent.click(screen.getByRole('dialog').querySelector('button[type="submit"]')!)
    await waitFor(() => expect(approveBaseline).toHaveBeenCalledWith('job-1', 'scan-1', 'scan-1', false))
  })

  it('reports action failures and archives through confirmation', async () => {
    vi.mocked(runJob).mockRejectedValue(new Error('scanner unavailable'))
    renderPage()
    await waitFor(() => expect(screen.getByRole('button', { name: /Scan now/ })).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: /Scan now/ }))
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('scanner unavailable'))
    fireEvent.click(screen.getByRole('button', { name: 'Archive job' }))
    fireEvent.click(screen.getByRole('dialog').querySelector('button[type="submit"]')!)
    await waitFor(() => expect(archiveJob).toHaveBeenCalledWith('job-1', 7))
  })

  it('shows latest positive results and discards a paused resumable cycle', async () => {
    vi.mocked(scanResults).mockResolvedValue({ results: [{ target: '198.51.100.10', protocol: 'tcp', addresses: ['198.51.100.10'], ports: [{ port: 443, state: 'open', service: 'https' }] }], pagination: { ...page, total: 1 } } as never)
    vi.mocked(scanCycle).mockResolvedValue({ cycle: { id: 'cycle-1', status: 'paused', completed_units: 1, total_units: 2, completed_probes: 100, total_probes: 200, last_error: 'paused after timeout' } } as never)
    renderPage()
    await waitFor(() => expect(screen.getByText('Latest successful scan')).toBeInTheDocument())
    await waitFor(() => expect(screen.getByText('443/tcp')).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: /scan-1/i }))
    await waitFor(() => expect(screen.getByRole('button', { name: 'View results' })).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: 'View results' }))
    await waitFor(() => expect(screen.getByText('Snapshot results')).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: 'Discard saved progress' }))
    fireEvent.click(screen.getByRole('dialog').querySelector('button[type="submit"]')!)
    await waitFor(() => expect(discardScanCycle).toHaveBeenCalledWith('job-1', 'cycle-1'))
  })

  it('restores an archived job and permanently deletes it with the guarded name', async () => {
    vi.mocked(getJob).mockResolvedValue({ ...job, archived: true, enabled: false } as never)
    renderPage()
    await waitFor(() => expect(screen.getByRole('button', { name: 'Restore' })).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: 'Restore' }))
    await waitFor(() => expect(restoreJob).toHaveBeenCalledWith('job-1', 7))
    fireEvent.click(screen.getByRole('button', { name: 'Delete permanently' }))
    const input = screen.getByRole('dialog').querySelector('input')!
    fireEvent.change(input, { target: { value: 'Production' } })
    fireEvent.click(screen.getByRole('dialog').querySelector('button[type="submit"]')!)
    await waitFor(() => expect(deleteJob).toHaveBeenCalledWith('job-1', 'Production'))
  })
})
