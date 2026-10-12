/** @vitest-environment jsdom */

import { act, cleanup, fireEvent, screen, waitFor } from '@testing-library/react'
import { useState } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cancelJobChangeWindow, createJobChangeWindow, getJobChangeWindow, jobChangeWindows, reviewJobChangeWindow } from '../api'
import { renderWithProviders } from '../test/test-utils'
import { JobChangeWindows } from './JobChangeWindows'

vi.mock('../api', () => ({
  cancelJobChangeWindow: vi.fn(),
  createJobChangeWindow: vi.fn(),
  getJobChangeWindow: vi.fn(),
  jobChangeWindows: vi.fn(),
  reviewJobChangeWindow: vi.fn(),
}))

const windowRecord = {
  id: 'window-1',
  job_id: 'job-1',
  start_at: '2026-10-25T00:30:00Z',
  end_at: '2026-10-25T03:00:00Z',
  timezone: 'Europe/Amsterdam',
  reason: 'Router replacement',
  actor_label: 'Riley',
  created_at: '2026-10-24T12:00:00Z',
  status: 'closed',
  end_reason: 'expired',
  closed_at: '2026-10-25T03:00:00Z',
  effective_end: '2026-10-25T03:00:00Z',
  new_count: 1,
  recovered_count: 0,
  still_open_count: 1,
  suppressed_event_count: 2,
  in_flight_event_count: 1,
  unknown_outcome_event_count: 1,
  incomplete_event_count: 1,
  review_state: 'due',
  reviewed_at: null,
  reviewer_label: '',
  revision: 7,
  summary: null,
}

const fullSummary = {
  new_count: 1,
  recovered_count: 0,
  still_open_count: 1,
  suppressed_event_count: 2,
  in_flight_event_count: 1,
  unknown_outcome_event_count: 1,
  incomplete_event_count: 1,
  incomplete_reported_change_count: 3,
  known_change_details_truncated: true,
  still_open_details_truncated: true,
  known_changes: [{ key: 'port|router.example|tcp|443', kind: 'port', severity: 'critical', target: 'router.example', protocol: 'tcp', port: 443, old: 'closed', new: 'open' }],
  still_open: [{ change: { key: 'port|router.example|tcp|443', kind: 'port', severity: 'critical', target: 'router.example', protocol: 'tcp', port: 443, old: 'closed', new: 'open' }, scan_id: 'private-scan', opened_at: '2026-10-24T13:00:00Z', last_seen_at: '2026-10-25T02:00:00Z', recovery_count: 0 }],
}

function renderWindows(overrides: Partial<Parameters<typeof JobChangeWindows>[0]> = {}) {
  return renderWithProviders(<JobChangeWindows
    jobID="job-1"
    jobName="Production"
    timezone="Europe/Amsterdam"
    archived={false}
    canManageWindows={false}
    canReadIncidents={false}
    canReadScans={false}
    canManageIncidents={false}
    {...overrides}
  />, { route: ['/jobs/job-1'] })
}

describe('planned change windows', () => {
  beforeEach(() => {
    vi.mocked(jobChangeWindows).mockResolvedValue({ windows: [] } as never)
    vi.mocked(getJobChangeWindow).mockResolvedValue({ window: { ...windowRecord, summary: fullSummary } } as never)
    vi.mocked(createJobChangeWindow).mockResolvedValue({ window: windowRecord } as never)
    vi.mocked(cancelJobChangeWindow).mockResolvedValue({ window: windowRecord } as never)
    vi.mocked(reviewJobChangeWindow).mockResolvedValue({ window: { ...windowRecord, review_state: 'reviewed' } } as never)
  })

  afterEach(() => {
    cleanup()
    vi.useRealTimers()
    vi.clearAllMocks()
  })

  it('shows summary counts without incident evidence when the viewer lacks incidents.read', async () => {
    vi.mocked(jobChangeWindows).mockResolvedValue({ windows: [windowRecord] } as never)
    renderWindows()

    expect(await screen.findByText('Router replacement')).toBeInTheDocument()
    expect(screen.getByText('Older events with incomplete identities')).toBeInTheDocument()
    expect(screen.getByText('Change events held')).toBeInTheDocument()
    const inFlightCount = screen.getByText('Change events in flight at close').closest('div')!
    expect(inFlightCount.querySelector('strong')).toHaveTextContent('1')
    expect(screen.getByText('Change events with unknown prior outcome').closest('div')?.querySelector('strong')).toHaveTextContent('1')
    expect(screen.getByText('Closing summary details require incidents.read.')).toBeInTheDocument()
    expect(screen.getByText('Marking this review complete requires incidents.manage.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Mark review complete' })).not.toBeInTheDocument()
    expect(getJobChangeWindow).not.toHaveBeenCalled()
    expect(screen.queryByText(/router\.example/)).not.toBeInTheDocument()
    expect(screen.queryByText(/private-scan/)).not.toBeInTheDocument()
  })

  it('fetches incident details only when requested and gates scan evidence links', async () => {
    vi.mocked(jobChangeWindows).mockResolvedValue({ windows: [windowRecord] } as never)
    renderWindows({ canReadIncidents: true, canReadScans: false })

    expect(await screen.findByText('Router replacement')).toBeInTheDocument()
    expect(getJobChangeWindow).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'View closing summary' }))

    expect(await screen.findByRole('region', { name: 'Changes observed during the window' })).toBeInTheDocument()
    expect(getJobChangeWindow).toHaveBeenCalledWith('job-1', 'window-1', expect.any(AbortSignal))
    expect(screen.getAllByText(/router\.example/)).toHaveLength(2)
    expect(screen.getByText(/3 change entries were reported by those events; this is not a unique change count/)).toBeInTheDocument()
    expect(screen.getByText('Some change details are omitted. The new and recovered totals above remain exact.')).toBeInTheDocument()
    expect(screen.getByText('Some still-open incident details are omitted. The still-open total above remains exact.')).toBeInTheDocument()
    expect(screen.getByText(/1 change event had already started provider delivery before the window and still had a live claim with no outcome at close/)).toBeInTheDocument()
    expect(screen.getByText(/1 earlier provider attempt had no recorded outcome after the claim was released or recovered/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Open this job’s incidents' })).toHaveAttribute('href', '/incidents?job_id=job-1')
    expect(screen.queryByRole('link', { name: 'Open source scan' })).not.toBeInTheDocument()
    expect(screen.queryByText('private-scan')).not.toBeInTheDocument()
  })

  it('hides cached incident evidence immediately when incidents.read is revoked', async () => {
    vi.mocked(jobChangeWindows).mockResolvedValue({ windows: [windowRecord] } as never)
    function PermissionChangeHarness() {
      const [canReadIncidents, setCanReadIncidents] = useState(true)
      return <>
        <button onClick={() => setCanReadIncidents(false)}>Revoke incident access</button>
        <JobChangeWindows jobID="job-1" jobName="Production" timezone="Europe/Amsterdam" archived={false} canManageWindows={false} canReadIncidents={canReadIncidents} canReadScans={true} canManageIncidents={false} />
      </>
    }
    renderWithProviders(<PermissionChangeHarness />, { route: ['/jobs/job-1'] })

    fireEvent.click(await screen.findByRole('button', { name: 'View closing summary' }))
    expect(await screen.findByRole('link', { name: 'Open source scan' })).toHaveAttribute('href', '/jobs/job-1/scans/private-scan')
    fireEvent.click(screen.getByRole('button', { name: 'Revoke incident access' }))

    expect(screen.queryByText(/router\.example/)).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Open source scan' })).not.toBeInTheDocument()
    expect(screen.getByText('Closing summary details require incidents.read.')).toBeInTheDocument()
  })

  it('cancels and removes private detail queries when incidents.read is revoked during a fetch', async () => {
    vi.mocked(jobChangeWindows).mockResolvedValue({ windows: [windowRecord] } as never)
    let finishRequest!: (result: { window: Omit<typeof windowRecord, 'summary'> & { summary: typeof fullSummary } }) => void
    let requestSignal: AbortSignal | undefined
    vi.mocked(getJobChangeWindow).mockImplementation((_jobID, _windowID, signal) => {
      requestSignal = signal
      return new Promise(resolve => { finishRequest = resolve })
    })
    function PermissionChangeHarness() {
      const [canReadIncidents, setCanReadIncidents] = useState(true)
      return <>
        <button onClick={() => setCanReadIncidents(false)}>Revoke incident access</button>
        <JobChangeWindows jobID="job-1" jobName="Production" timezone="Europe/Amsterdam" archived={false} canManageWindows={false} canReadIncidents={canReadIncidents} canReadScans={true} canManageIncidents={false} />
      </>
    }
    const { client } = renderWithProviders(<PermissionChangeHarness />, { route: ['/jobs/job-1'] })

    fireEvent.click(await screen.findByRole('button', { name: 'View closing summary' }))
    await waitFor(() => expect(getJobChangeWindow).toHaveBeenCalled())
    const queryKey = ['job-change-window', 'job-1', 'window-1']
    expect(requestSignal?.aborted).toBe(false)
    fireEvent.click(screen.getByRole('button', { name: 'Revoke incident access' }))

    await waitFor(() => expect(client.getQueryData(queryKey)).toBeUndefined())
    expect(requestSignal?.aborted).toBe(true)
    expect(screen.queryByText(/router\.example/)).not.toBeInTheDocument()
    await act(async () => finishRequest({ window: { ...windowRecord, summary: fullSummary } }))
    expect(client.getQueryData(queryKey)).toBeUndefined()
  })

  it('keeps review completion available without loading incident details', async () => {
    vi.mocked(jobChangeWindows).mockResolvedValue({ windows: [windowRecord] } as never)
    renderWindows({ canManageIncidents: true })

    expect(await screen.findByRole('button', { name: 'Mark review complete' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Mark review complete' }))

    await waitFor(() => expect(reviewJobChangeWindow).toHaveBeenCalledWith('job-1', 'window-1', 7))
    expect(getJobChangeWindow).not.toHaveBeenCalled()
  })

  it('pins an older due review from the bounded job projection when it falls outside the history list', async () => {
    vi.mocked(jobChangeWindows).mockResolvedValue({ windows: [] } as never)
    const olderDue = {
      id: 'window-old-due',
      start_at: '2026-09-01T00:00:00Z',
      end_at: '2026-09-01T02:00:00Z',
      closed_at: '2026-09-01T02:00:00Z',
      timezone: 'UTC',
      reason: 'Core switch replacement',
      status: 'closed',
      end_reason: 'expired',
      review_state: 'due',
      new_count: 2,
      recovered_count: 1,
      known_change_count: 3,
      still_open_count: 1,
      suppressed_event_count: 2,
      incomplete_event_count: 0,
      revision: 4,
    }
    renderWindows({ latestWindow: olderDue as never, canManageIncidents: true })

    expect(await screen.findByText('Core switch replacement')).toBeInTheDocument()
    expect(screen.getByText('Review due')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Mark review complete' }))
    await waitFor(() => expect(reviewJobChangeWindow).toHaveBeenCalledWith('job-1', 'window-old-due', 4))
  })

  it('sends the explicitly selected UTC offset for the second occurrence of a folded time', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    vi.setSystemTime(new Date('2026-10-01T12:00:00Z'))
    renderWindows({ canManageWindows: true })

    fireEvent.click(screen.getByLabelText('Schedule for later'))
    fireEvent.change(screen.getByLabelText(/Start time/), { target: { value: '2026-10-25T02:30' } })
    fireEvent.change(screen.getByRole('combobox', { name: /Choose the UTC offset for start time/ }), { target: { value: '2026-10-25T02:30:00+01:00' } })
    fireEvent.change(screen.getByLabelText(/End time/), { target: { value: '2026-10-25T04:00' } })
    fireEvent.change(screen.getByLabelText('Reason'), { target: { value: 'Router replacement' } })

    const submit = screen.getByRole('button', { name: 'Schedule change window' })
    expect(submit).toBeEnabled()
    fireEvent.click(submit)

    await waitFor(() => expect(createJobChangeWindow).toHaveBeenCalledWith('job-1', {
      start_now: false,
      start_at: '2026-10-25T02:30:00+01:00',
      end_at: '2026-10-25T04:00:00+01:00',
      reason: 'Router replacement',
    }))
  })
})
