/** @vitest-environment jsdom */

import { fireEvent, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { jobPendingChanges, listEvents, listIncidents, listJobs } from '../api'
import type { ActivityEvent, Job } from '../types'
import { renderWithProviders } from '../test/test-utils'
import { Activity } from './Activity'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return { ...actual, jobPendingChanges: vi.fn(), listEvents: vi.fn(), listIncidents: vi.fn(), listJobs: vi.fn() }
})

const page = { limit: 20, offset: 0, total: 2, has_more: false, next_offset: null }
const job: Job = {
  id: 'job-1', revision: 1, enabled: true, archived: false, security_hash: 'scope',
  created_at: '2026-09-20T00:00:00Z', updated_at: '2026-09-20T00:00:00Z',
  job: { name: 'Production', schedule: '0 * * * *', timezone: 'UTC', targets: ['192.0.2.1'], max_expanded_hosts: 1, timing: 'balanced', timeout: '1h', baseline_samples: 1, change_confirmations: 2 },
  baseline: { status: 'complete', pending: 1 },
}
const archivedJob: Job = { ...job, id: 'job-archived', archived: true, job: { ...job.job, name: 'Archived job' } }
const events: ActivityEvent[] = [
  { type: 'incident-accepted', job_id: 'job-1', job: 'Production', scan_id: 'scan-2', message: 'A service change was accepted', changes: [{ kind: 'service', target: '192.0.2.1', protocol: 'tcp', port: 443, old: 'unknown', new: 'https', severity: 'info' }], created_at: '2026-09-20T10:00:00Z' },
  { type: 'changes-recovered', job_id: 'job-1', job: 'Production', scan_id: 'scan-1', message: 'A port change recovered', changes: [{ kind: 'port', target: '192.0.2.1', protocol: 'tcp', port: 22, old: 'open', new: 'not-open', severity: 'critical' }], created_at: '2026-09-20T09:00:00Z' },
]

describe('activity history', () => {
  beforeEach(() => {
    vi.mocked(listEvents).mockResolvedValue({ events, pagination: page })
    vi.mocked(listJobs).mockResolvedValue({ jobs: [job, archivedJob] })
    vi.mocked(listIncidents).mockResolvedValue({ incidents: [{ job_id: 'job-1', job: 'Production', incident: { change: { kind: 'port', target: '192.0.2.1', protocol: 'tcp', port: 80, old: 'not-open', new: 'open', severity: 'critical' }, scan_id: 'scan-2', opened_at: '2026-09-20T08:00:00Z', last_seen_at: '2026-09-20T10:00:00Z' } }], pagination: { ...page, total: 1 } })
    vi.mocked(jobPendingChanges).mockResolvedValue({ job_id: 'job-1', job: 'Production', pending_changes: [{ key: 'service|192.0.2.1|tcp|443', change: { kind: 'service', target: '192.0.2.1', protocol: 'tcp', port: 443, old: 'unknown', new: 'https', severity: 'info' }, count: 1 }], pagination: { limit: 10, offset: 0, total: 1, has_more: false, next_offset: null } })
  })

  it('shows active, pending, accepted, and recovered change history with contextual links', async () => {
    renderWithProviders(<Activity />)

    expect(await screen.findByRole('heading', { name: 'Activity' })).toBeInTheDocument()
    expect(await screen.findByText('Change accepted')).toBeInTheDocument()
    await waitFor(() => expect(document.querySelector('.activity-state-total')?.textContent).toContain('1 active incident'))
    expect(screen.getByRole('link', { name: 'Review →' })).toHaveAttribute('href', '/jobs/job-1/scans/scan-2')
    expect(screen.getAllByRole('link', { name: 'Open scan details →' }).map(link => link.getAttribute('href'))).toEqual(['/jobs/job-1/scans/scan-2', '/jobs/job-1/scans/scan-1'])
    expect(screen.getByText('Incident recovered')).toBeInTheDocument()
    expect(screen.getByText('Service · 192.0.2.1 · TCP:443 · unknown → https')).toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: 'Show 1 pending change' })).toHaveLength(1)
    expect(screen.getByRole('option', { name: 'Archived job (archived)' })).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Show 1 pending change' }))
    expect(await screen.findByText('1 / 2 scans')).toBeInTheDocument()
    expect(jobPendingChanges).toHaveBeenCalledWith('job-1', 0, 10)
    expect(screen.getByRole('link', { name: 'Open job →' })).toHaveAttribute('href', '/jobs/job-1#pending-changes')
  })

  it('filters by job and resets pagination when the filter changes', async () => {
    renderWithProviders(<Activity />, { route: ['/activity?job_id=job-1'] })
    await screen.findByText('Change accepted')
    expect(listEvents).toHaveBeenCalledWith(0, 20, 'job-1')
    fireEvent.change(screen.getByRole('combobox', { name: 'Filter activity by job' }), { target: { value: '' } })
    await waitFor(() => expect(listEvents).toHaveBeenCalledWith(0, 20, undefined))
  })

  it('uses the failure tone for failed scans and the API spelling for canceled scans', async () => {
    vi.mocked(listEvents).mockResolvedValue({ events: [
      { type: 'scan-failure', job_id: 'job-1', job: 'Production', message: 'Scan failed', created_at: '2026-09-20T12:00:00Z' },
      { type: 'scan-anomaly', job_id: 'job-1', job: 'Production', message: 'Coverage was incomplete', created_at: '2026-09-20T11:00:00Z' },
      { type: 'scan-canceled', job_id: 'job-1', job: 'Production', message: 'Scan canceled', created_at: '2026-09-20T10:00:00Z' },
    ], pagination: { ...page, total: 3 } })
    renderWithProviders(<Activity />)

    await waitFor(() => expect(document.querySelectorAll('.activity-event')).toHaveLength(3))
    const events = Array.from(document.querySelectorAll('.activity-event'))
    expect(events[0]).toHaveClass('failure')
    expect(events[1]).toHaveClass('warning')
    expect(events[2].querySelector('.activity-event-heading strong')).toHaveTextContent('Scan canceled')
    expect(screen.queryByText('Scan cancelled', { exact: true })).not.toBeInTheDocument()
  })

  it('shows useful empty states and reports event loading errors with retry', async () => {
    vi.mocked(listEvents).mockRejectedValueOnce(new Error('offline'))
    vi.mocked(listIncidents).mockResolvedValue({ incidents: [], pagination: { ...page, total: 0 } })
    vi.mocked(listJobs).mockResolvedValue({ jobs: [] })
    renderWithProviders(<Activity />)
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not load activity history.')
    expect(screen.getByText('No open incidents.')).toBeInTheDocument()
    expect(screen.getByText('No changes are awaiting confirmation.')).toBeInTheDocument()
  })

  it('keeps a working Previous control when pending changes shrink below the selected page', async () => {
    let remaining = Array.from({ length: 12 }, (_, index) => ({
      key: `port|192.0.2.1|tcp|${440 + index}`,
      change: { kind: 'port' as const, target: '192.0.2.1', protocol: 'tcp' as const, port: 440 + index, old: 'not-open', new: 'open', severity: 'info' as const },
      count: 1,
    }))
    vi.mocked(listJobs).mockResolvedValue({ jobs: [{ ...job, baseline: { ...job.baseline, pending: 12 } }] })
    vi.mocked(jobPendingChanges).mockImplementation(async (_jobID, offset = 0, limit = 10) => {
      const total = remaining.length
      return {
        job_id: 'job-1', job: 'Production', pending_changes: remaining.slice(offset, offset + limit),
        pagination: { limit, offset, total, has_more: offset + limit < total, next_offset: offset + limit < total ? offset + limit : null },
      }
    })
    const { client } = renderWithProviders(<Activity />)

    fireEvent.click(await screen.findByRole('button', { name: 'Show 12 pending changes' }))
    await screen.findByRole('navigation', { name: 'Pending changes for Production' })
    fireEvent.click(screen.getByRole('button', { name: 'Next' }))
    await waitFor(() => expect(jobPendingChanges).toHaveBeenCalledWith('job-1', 10, 10))
    expect(await screen.findByText(/TCP:451/)).toBeInTheDocument()

    remaining = remaining.slice(0, 3)
    await client.invalidateQueries({ queryKey: ['job-pending-changes', 'job-1', 10] })
    await waitFor(() => expect(screen.getByRole('navigation', { name: 'Pending changes for Production' })).toBeInTheDocument())
    expect(screen.getByRole('button', { name: 'Previous' })).toBeEnabled()
    fireEvent.click(screen.getByRole('button', { name: 'Previous' }))
    expect(await screen.findByText(/TCP:440/)).toBeInTheDocument()
  })

  it('shows the no-pending state only when the API total is zero', async () => {
    vi.mocked(listJobs).mockResolvedValue({ jobs: [{ ...job, baseline: { ...job.baseline, pending: 1 } }] })
    vi.mocked(jobPendingChanges).mockResolvedValue({ job_id: 'job-1', job: 'Production', pending_changes: [], pagination: { limit: 10, offset: 0, total: 0, has_more: false, next_offset: null } })
    renderWithProviders(<Activity />)

    fireEvent.click(await screen.findByRole('button', { name: 'Show 1 pending change' }))
    expect(await screen.findByText('There are no pending changes for this job.')).toBeInTheDocument()
  })
})
