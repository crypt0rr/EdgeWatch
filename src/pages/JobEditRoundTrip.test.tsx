/** @vitest-environment jsdom */

import { fireEvent, screen, waitFor } from '@testing-library/react'
import { Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { archiveJob, getJob, getSession, jobBaseline, jobScans, latestSuccessfulScan, listNotificationDestinations, listScannerProfiles, scanCycle, scannerCapabilities, updateJob } from '../api'
import { createQueryClient } from '../main'
import { renderWithProviders } from '../test/test-utils'
import type { Job } from '../types'
import { JobDetail } from './JobDetail'
import { JobEditor } from './JobEditor'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return { ...actual, archiveJob: vi.fn(), getJob: vi.fn(), getSession: vi.fn(), jobBaseline: vi.fn(), jobScans: vi.fn(), latestSuccessfulScan: vi.fn(), listNotificationDestinations: vi.fn(), listScannerProfiles: vi.fn(), scanCycle: vi.fn(), scannerCapabilities: vi.fn(), updateJob: vi.fn() }
})

const saved: Job = {
  id: 'job-1', revision: 3, enabled: true, archived: false, security_hash: 'scope', created_at: '2026-09-01T00:00:00Z', updated_at: '2026-09-01T00:00:00Z',
  job: { name: 'Production', schedule: '0 * * * *', timezone: 'UTC', targets: ['198.51.100.10'], max_expanded_hosts: 32, tcp: { ports: '22', mode: 'connect', service_detection: false, engine: 'nmap' }, timing: 'balanced', timeout: '1h', resume_window: '8d', baseline_samples: 1, change_confirmations: 1, notification_destinations: [] },
  baseline: { status: 'complete', samples: 1, attempts: 1, scan_id: 'scan-1', host_count: 1 },
}
const page = { limit: 10, offset: 0, total: 0, has_more: false, next_offset: null }

describe('job edit round trip without live updates', () => {
  let current: Job

  beforeEach(() => {
    current = saved
    vi.mocked(getJob).mockImplementation(async () => current)
    vi.mocked(updateJob).mockImplementation(async (_id, revision, value) => {
      current = { ...current, revision: revision + 1, enabled: value.enabled ?? current.enabled, updated_at: '2026-09-01T00:00:05Z', job: { ...current.job, ...value } }
      return current
    })
    vi.mocked(archiveJob).mockResolvedValue(undefined)
    vi.mocked(getSession).mockResolvedValue({ role: 'operator', user_id: 'operator', username: 'operator', permissions: ['jobs.write', 'scans.read', 'baselines.read'], csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 } })
    vi.mocked(listNotificationDestinations).mockResolvedValue({ destinations: [], status: { deployment: 0, managed: 0, active: 0, locked: 0, key_state: 'not_required' } })
    vi.mocked(listScannerProfiles).mockResolvedValue({ profiles: [] })
    vi.mocked(scannerCapabilities).mockResolvedValue({ engines: ['nmap'], nmap: { available: true, path: '/usr/bin/nmap', version: '7.99' }, naabu: { available: false, path: '', version: '', syn_supported: false } })
    vi.mocked(jobBaseline).mockResolvedValue({ job_id: 'job-1', job: 'Production', revision: 3, security_hash: 'scope', baseline: saved.baseline, snapshot: { units: [], scopes: [] }, pagination: page })
    vi.mocked(jobScans).mockResolvedValue({ scans: [], pagination: page })
    vi.mocked(latestSuccessfulScan).mockResolvedValue({ scan: null })
    vi.mocked(scanCycle).mockResolvedValue({ cycle: null })
  })
  afterEach(() => vi.clearAllMocks())

  it('shows the saved revision and archives it with that revision', async () => {
    // The console's own query defaults (a five-second stale time) and no
    // EventSource: nothing but the save itself can refresh the job detail.
    renderWithProviders(<Routes><Route path="/jobs/:id" element={<JobDetail />} /><Route path="/jobs/:id/edit" element={<JobEditor />} /></Routes>, { route: ['/jobs/job-1'], client: createQueryClient() })
    await waitFor(() => expect(screen.getByText('Revision 3 · Updated', { exact: false })).toBeInTheDocument())
    expect(screen.getByText('Scheduled')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /Edit/ }))
    await waitFor(() => expect(screen.getByDisplayValue('Production')).toBeInTheDocument())
    fireEvent.click(screen.getByRole('checkbox', { name: /Schedule enabled/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Save changes' }))
    await waitFor(() => expect(updateJob).toHaveBeenCalledWith('job-1', 3, expect.objectContaining({ enabled: false }), false))

    await waitFor(() => expect(screen.getByText('Revision 4 · Updated', { exact: false })).toBeInTheDocument())
    expect(screen.getByText('Paused')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Archive job' }))
    fireEvent.click(screen.getByRole('dialog').querySelector('button[type="submit"]')!)
    await waitFor(() => expect(archiveJob).toHaveBeenCalledWith('job-1', 4))
  })
})
