/** @vitest-environment jsdom */

import { fireEvent, screen, waitFor } from '@testing-library/react'
import { StrictMode, act } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { Route, Routes, useLocation, useNavigate, type MemoryRouterProps } from 'react-router-dom'
import { APIError, activeScans, approveBaseline, archiveJob, cancelQueuedRun, cancelScan, deleteJob, discardScanCycle, getJob, getSession, jobBaseline, jobScans, latestSuccessfulScan, pauseJob, resetBaseline, restoreJob, resumeJob, runJob, scanCycle, scanDetail, scanHosts, scanResults } from '../api'
import { renderWithProviders, defaultUnitScope } from '../test/test-utils'
import { consumeFirstScanIntent, issueFirstScanIntent } from '../firstScanIntent'
import { JobDetail } from './JobDetail'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return { ...actual, activeScans: vi.fn(), approveBaseline: vi.fn(), archiveJob: vi.fn(), cancelQueuedRun: vi.fn(), cancelScan: vi.fn(), deleteJob: vi.fn(), getJob: vi.fn(), getSession: vi.fn(), jobBaseline: vi.fn(), jobScans: vi.fn(), latestSuccessfulScan: vi.fn(), pauseJob: vi.fn(), resetBaseline: vi.fn(), restoreJob: vi.fn(), resumeJob: vi.fn(), runJob: vi.fn(), scanCycle: vi.fn(), discardScanCycle: vi.fn(), scanDetail: vi.fn(), scanHosts: vi.fn(), scanResults: vi.fn() }
})

const job = {
  id: 'job-1', revision: 7, enabled: true, archived: false, security_hash: 'scope', created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z',
  job: { name: 'Production', schedule: '0 * * * *', timezone: 'UTC', targets: ['198.51.100.10'], max_expanded_hosts: 32, tcp: { ports: '22,443', mode: 'connect', service_detection: true, engine: 'nmap' }, timing: 'balanced', timeout: '1h', resume_window: '8d', baseline_samples: 1, change_confirmations: 1 },
  baseline: { status: 'complete', samples: 1, attempts: 1, scan_id: 'scan-1', host_count: 1 },
}
const scan = { id: 'scan-1', job_id: 'job-1', job: 'Production', started_at: '2026-01-01T00:00:00Z', finished_at: '2026-01-01T00:01:00Z', status: 'success', config_hash: 'scope' }
const page = { limit: 10, offset: 0, total: 1, has_more: false, next_offset: null }
const administrator = { role: 'administrator' as const, user_id: 'admin', username: 'admin', permissions: ['jobs.write', 'jobs.run', 'jobs.delete', 'scans.read', 'baselines.read'], csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 }, ...defaultUnitScope }
const operator = { ...administrator, role: 'operator' as const, user_id: 'operator', username: 'operator', permissions: ['jobs.write', 'scans.read', 'baselines.read'] }
const activeScan = {
  id: 'active-scan-1', job_id: 'job-1', job: 'Production', started_at: '2026-01-01T00:00:00Z',
  progress_percent: 42, completed_probes: 42, total_probes: 100, phase: 'tcp discovery', protocol: 'tcp',
  elapsed_seconds: 17, process_alive: true, scanner: 'naabu_nmap', cycle_id: 'cycle-1', cycle_completed_units: 1, cycle_total_units: 3,
}
let routeJobTwoToken = ''

describe('job detail actions', () => {
  beforeEach(() => {
    vi.mocked(activeScans).mockResolvedValue({ scans: [] })
    vi.mocked(getJob).mockResolvedValue(job as never)
    vi.mocked(getSession).mockResolvedValue(administrator)
    vi.mocked(jobBaseline).mockResolvedValue({ job_id: 'job-1', job: 'Production', revision: 7, security_hash: 'scope', baseline: job.baseline, snapshot: { units: [], scopes: [] }, pagination: page } as never)
    vi.mocked(latestSuccessfulScan).mockResolvedValue({ scan } as never)
    vi.mocked(jobScans).mockResolvedValue({ scans: [scan], pagination: page } as never)
    vi.mocked(scanDetail).mockResolvedValue({ scan, changes: [], changes_pagination: page, current_security_hash: 'scope', comparison_source: 'scan_time' } as never)
    vi.mocked(scanHosts).mockResolvedValue({ hosts: [], pagination: page } as never)
    vi.mocked(scanResults).mockResolvedValue({ results: [], pagination: page } as never)
    vi.mocked(scanCycle).mockResolvedValue({ cycle: null })
    vi.mocked(runJob).mockResolvedValue({ status: 'accepted', job_id: 'job-1' })
    vi.mocked(cancelScan).mockResolvedValue({ status: 'cancelling', scan_id: 'active-scan-1' })
    vi.mocked(resetBaseline).mockResolvedValue(undefined)
    vi.mocked(approveBaseline).mockResolvedValue(undefined)
    vi.mocked(archiveJob).mockResolvedValue(undefined)
    vi.mocked(pauseJob).mockResolvedValue(undefined)
    vi.mocked(resumeJob).mockResolvedValue(undefined)
    vi.mocked(restoreJob).mockResolvedValue(undefined)
    vi.mocked(deleteJob).mockResolvedValue(undefined)
  })
  afterEach(() => vi.clearAllMocks())

  function RouteState() {
    const location = useLocation()
    const navigate = useNavigate()
    return <><span data-testid="route-state">{JSON.stringify(location.state)}</span><button type="button" onClick={() => navigate(-1)}>Back</button><button type="button" onClick={() => navigate(1)}>Forward</button><button type="button" onClick={() => navigate('/jobs/job-2', { state: { startFirstScanToken: routeJobTwoToken } })}>Open job 2</button></>
  }

  function renderPage(route: NonNullable<MemoryRouterProps['initialEntries']> = ['/jobs/job-1'], strict = false) {
    const content = <><Routes><Route path="/jobs/:id/scans/:scanId" element={<JobDetail />} /><Route path="/jobs/:id/*" element={<JobDetail />} /></Routes><RouteState /></>
    return renderWithProviders(strict ? <StrictMode>{content}</StrictMode> : content, { route })
  }

  it('starts a scan and refreshes the relevant queries', async () => {
    const { client } = renderPage()
    const invalidate = vi.spyOn(client, 'invalidateQueries')
    // This render starts with an empty query cache. Wait for the fetched job
    // before asserting the action and dispatching its request.
    await screen.findByRole('heading', { name: 'Production' }, { timeout: 10_000 })
    fireEvent.click(await screen.findByRole('button', { name: /Scan now/ }, { timeout: 10_000 }))
    await waitFor(() => expect(runJob).toHaveBeenCalledWith('job-1'))
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['latest-successful-scan', 'job-1'] })
  }, 15_000)

  it('consumes the create-and-start handoff once under StrictMode and clears its history state', async () => {
    const token = issueFirstScanIntent('job-1')
    renderPage([{ pathname: '/jobs/job-1', state: { startFirstScanToken: token } }], true)

    await waitFor(() => expect(runJob).toHaveBeenCalledTimes(1))
    expect(runJob).toHaveBeenCalledWith('job-1')
    expect(await screen.findByTestId('route-state')).toHaveTextContent('null')
  })

  it('does not replay a consumed history marker after reload or remount', async () => {
    const token = issueFirstScanIntent('job-1')
    expect(consumeFirstScanIntent('job-1', token)).toBe(true)
    renderPage([{ pathname: '/jobs/job-1', state: { startFirstScanToken: token } }])

    await screen.findByRole('button', { name: 'Scan now' })
    expect(runJob).not.toHaveBeenCalled()
    expect(screen.getByTestId('route-state')).toHaveTextContent('null')
  })

  it('does not dispatch again after back and forward through the cleared history entry', async () => {
    const token = issueFirstScanIntent('job-1')
    renderPage(['/jobs', { pathname: '/jobs/job-1', state: { startFirstScanToken: token } }])

    await waitFor(() => expect(runJob).toHaveBeenCalledTimes(1))
    fireEvent.click(screen.getByRole('button', { name: 'Back' }))
    await waitFor(() => expect(screen.queryByRole('heading', { name: 'Production' })).not.toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: 'Forward' }))
    await screen.findByRole('heading', { name: 'Production' })

    expect(runJob).toHaveBeenCalledTimes(1)
  })

  it('binds a delayed handoff to its job when JobDetail is reused for a second route', async () => {
    let resolveJobOne!: (value: typeof job) => void
    vi.mocked(getJob).mockImplementation((id) => id === 'job-1'
      ? new Promise((resolve) => { resolveJobOne = resolve }) as never
      : Promise.resolve({ ...job, id: 'job-2', job: { ...job.job, name: 'Development' } }) as never)
    const tokenOne = issueFirstScanIntent('job-1')
    const tokenTwo = issueFirstScanIntent('job-2')
    routeJobTwoToken = tokenTwo
    renderPage(['/jobs', { pathname: '/jobs/job-1', state: { startFirstScanToken: tokenOne } }])

    await waitFor(() => expect(getJob).toHaveBeenCalledWith('job-1'))
    await screen.findByText('Loading job…')
    fireEvent.click(screen.getByRole('button', { name: 'Open job 2' }))

    await waitFor(() => expect(runJob).toHaveBeenCalledTimes(1))
    expect(runJob).toHaveBeenCalledWith('job-2')
    expect(await screen.findByRole('heading', { name: 'Development' })).toBeInTheDocument()
    resolveJobOne(job)
    await waitFor(() => expect(runJob).toHaveBeenCalledTimes(1))
    expect(runJob).not.toHaveBeenCalledWith('job-1')
    routeJobTwoToken = ''
  })

  it('ignores a stale run response after route reuse and does not clear the new job run state', async () => {
    let rejectJobOne!: (error: Error) => void
    let resolveJobTwo!: (value: { status: string; job_id: string }) => void
    vi.mocked(runJob).mockImplementation((id) => id === 'job-1'
      ? new Promise((_resolve, reject) => { rejectJobOne = reject }) as never
      : new Promise((resolve) => { resolveJobTwo = resolve }) as never)
    vi.mocked(getJob).mockImplementation((id) => Promise.resolve(id === 'job-2'
      ? { ...job, id: 'job-2', job: { ...job.job, name: 'Development' } }
      : job) as never)
    const tokenOne = issueFirstScanIntent('job-1')
    routeJobTwoToken = ''
    renderPage(['/jobs', { pathname: '/jobs/job-1', state: { startFirstScanToken: tokenOne } }])

    await waitFor(() => expect(runJob).toHaveBeenCalledWith('job-1'))
    fireEvent.click(screen.getByRole('button', { name: 'Open job 2' }))
    await screen.findByRole('heading', { name: 'Development' })
    fireEvent.click(screen.getByRole('button', { name: 'Scan now' }))
    await waitFor(() => expect(runJob).toHaveBeenCalledWith('job-2'))
    expect(screen.getByRole('button', { name: 'Starting…' })).toBeDisabled()

    await act(async () => {
      rejectJobOne(new APIError('Old job run failed.', 'scan_failed', undefined, 422))
      await Promise.resolve()
    })
    expect(screen.getByRole('button', { name: 'Starting…' })).toBeDisabled()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()

    await act(async () => {
      resolveJobTwo({ status: 'accepted', job_id: 'job-2' })
      await Promise.resolve()
    })
    await waitFor(() => expect(screen.getByRole('button', { name: 'Queued…' })).toBeDisabled())
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    routeJobTwoToken = ''
  })

  it('keeps a created job open after first-run failure and retries only the run', async () => {
    vi.mocked(runJob).mockRejectedValueOnce(new APIError('The probe budget changed before the scan could start.', 'scan_work_budget_exceeded', undefined, 422))
    const token = issueFirstScanIntent('job-1')
    renderPage([{ pathname: '/jobs/job-1', state: { startFirstScanToken: token } }])

    expect(await screen.findByRole('alert')).toHaveTextContent('The probe budget changed before the scan could start.')
    expect(screen.getByRole('heading', { name: 'Production' })).toBeInTheDocument()
    expect(getJob).toHaveBeenCalledTimes(1)
    fireEvent.click(screen.getByRole('button', { name: 'Scan now' }))
    await waitFor(() => expect(runJob).toHaveBeenCalledTimes(2))
    expect(runJob).toHaveBeenNthCalledWith(2, 'job-1')
    expect(getJob).toHaveBeenCalledTimes(1)
  })

  it('reconciles an ambiguous run response against queued state before allowing retry', async () => {
    vi.mocked(runJob).mockImplementationOnce(async () => {
      vi.mocked(activeScans).mockResolvedValue({ scans: [], queued_runs: [{ job_id: 'job-1', job: 'Production', queued_at: '2026-10-09T10:00:00Z', trigger: 'manual' }] } as never)
      throw new TypeError('Failed to fetch')
    })
    const token = issueFirstScanIntent('job-1')
    renderPage([{ pathname: '/jobs/job-1', state: { startFirstScanToken: token } }])

    expect(await screen.findByRole('heading', { name: 'Scan queued' })).toBeInTheDocument()
    expect(runJob).toHaveBeenCalledTimes(1)
    expect(screen.getByRole('button', { name: 'Queued…' })).toBeDisabled()
    expect(screen.queryByRole('button', { name: 'Run another sample' })).not.toBeInTheDocument()
  })

  it('keeps an accepted scan visible while queued and prevents a duplicate start', async () => {
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: 'Scan now' }))

    expect(await screen.findByRole('status')).toHaveTextContent('Your scan request was accepted and is waiting for an available scan slot.')
    const queued = screen.getByRole('button', { name: 'Queued…' })
    expect(queued).toBeDisabled()
    fireEvent.click(queued)
    expect(runJob).toHaveBeenCalledTimes(1)
  })

  it('derives the queued state from the server after reload and explains a skipped run', async () => {
    const { client } = renderPage()
    await screen.findByRole('button', { name: 'Scan now' })
    client.setQueryData(['active-scans'], {
      scans: [],
      queued_runs: [{ job_id: 'job-1', job: 'Production', queued_at: '2026-10-06T10:00:00Z', trigger: 'scheduled' }],
    })

    expect(await screen.findByRole('heading', { name: 'Scan queued' })).toBeInTheDocument()
    expect(screen.getByRole('status')).toHaveTextContent('Scheduled scan accepted at')
    expect(screen.getByRole('button', { name: 'Queued…' })).toBeDisabled()

    client.setQueryData(['active-scans'], { scans: [], queued_runs: [] })
    act(() => window.dispatchEvent(new CustomEvent('edgewatch:scan-skipped', { detail: { job_id: 'job-1', reason: 'archived' } })))

    await waitFor(() => expect(screen.queryByRole('heading', { name: 'Scan queued' })).not.toBeInTheDocument())
    expect(screen.getByRole('alert')).toHaveTextContent('The job was archived before the queued scan could start.')
    expect(screen.getByRole('button', { name: 'Scan now' })).toBeEnabled()

    const skippedReasons = [
      ['busy', 'another scan already owns this job'],
      ['archived', 'job was archived'],
      ['paused', 'job was paused'],
      ['budget', 'exceeds the configured work budget'],
      ['unit_paused', 'business unit was paused'],
      ['shutting_down', 'EdgeWatch stopped'],
      ['cycle_stalled', 'saved cycle is stalled'],
      ['job_unavailable', 'job was removed'],
      ['unexpected', 'queued scan did not start'],
    ]
    for (const [reason, message] of skippedReasons) {
      act(() => window.dispatchEvent(new CustomEvent('edgewatch:scan-skipped', { detail: { job_id: 'job-1', reason } })))
      expect(screen.getByRole('alert')).toHaveTextContent(message)
    }
  })

  it('cancels a queued run from the job page', async () => {
    const queued = { scans: [], queued_runs: [{ job_id: 'job-1', job: 'Production', queued_at: '2026-10-06T10:00:00Z', trigger: 'scheduled' }] }
    vi.mocked(activeScans).mockResolvedValue(queued as never)
    vi.mocked(cancelQueuedRun).mockImplementation(async () => {
      vi.mocked(activeScans).mockResolvedValue({ scans: [], queued_runs: [] })
      return { status: 'canceled', job_id: 'job-1' }
    })
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: 'Cancel queued scan' }))
    await waitFor(() => expect(cancelQueuedRun).toHaveBeenCalledWith('job-1'))
    await waitFor(() => expect(screen.queryByRole('heading', { name: 'Scan queued' })).not.toBeInTheDocument())
    // The run's skip event confirms the cancellation without an error.
    act(() => window.dispatchEvent(new CustomEvent('edgewatch:scan-skipped', { detail: { job_id: 'job-1', reason: 'canceled' } })))
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Scan now' })).toBeEnabled()
  })

  it('offers no queued cancel before the server reports the run as queued', async () => {
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: 'Scan now' }))
    expect(await screen.findByRole('heading', { name: 'Scan queued' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Cancel queued scan' })).not.toBeInTheDocument()
  })

  it('explains why scheduled scans of an over-budget job are skipped', async () => {
    vi.mocked(getJob).mockResolvedValue({ ...job, scan_budget: { exceeded: true, estimated_probes: 999, limit: 100, approval_would_fit: true } } as never)
    const view = renderPage()
    expect(await screen.findByText(/About 999 probes exceed this unit's probe budget of 100\. Scheduled scans are skipped until an administrator approves high-cost scans for this job\./)).toBeInTheDocument()
    view.unmount()

    vi.mocked(getJob).mockResolvedValue({ ...job, job: { ...job.job, allow_high_cost: true }, scan_budget: { exceeded: true, estimated_probes: 2000000000, limit: 1000000000, approval_would_fit: false } } as never)
    renderPage()
    expect(await screen.findByText(/Scheduled scans are skipped until its scope is reduced\./)).toBeInTheDocument()
    expect(screen.getByText(/High-cost scans approved/)).toBeInTheDocument()
  })

  it('shows no budget warning for a job that fits its budget', async () => {
    vi.mocked(getJob).mockResolvedValue({ ...job, scan_budget: { exceeded: false } } as never)
    renderPage()
    await screen.findByRole('button', { name: 'Scan now' })
    expect(document.querySelector('.scan-budget-warning')).toBeNull()
    expect(screen.queryByText(/High-cost scans approved/)).not.toBeInTheDocument()
  })

  it('clears a locally queued request when the scan appears in history', async () => {
    const { client } = renderPage()
    fireEvent.click(await screen.findByRole('button', { name: 'Scan now' }))
    expect(await screen.findByRole('heading', { name: 'Scan queued' })).toBeInTheDocument()

    client.setQueryData(['active-scans'], {
      scans: [],
      queued_runs: [{ job_id: 'job-1', job: 'Production', queued_at: '2026-10-06T10:00:00Z', trigger: 'manual' }],
    })
    expect(await screen.findByRole('status')).toHaveTextContent('Scan request accepted at')

    client.setQueryData(['active-scans'], { scans: [], queued_runs: [] })
    client.setQueryData(['job-scans', 'job-1', 0], {
      scans: [{ ...scan, id: 'scan-2' }, scan],
      pagination: { ...page, total: 2 },
    })
    await waitFor(() => expect(screen.queryByRole('heading', { name: 'Scan queued' })).not.toBeInTheDocument())
    expect(screen.getByRole('button', { name: 'Scan now' })).toBeEnabled()
  })

  it('explains when a queued request disappears without a scan starting', async () => {
    const { client } = renderPage()
    fireEvent.click(await screen.findByRole('button', { name: 'Scan now' }))
    expect(await screen.findByRole('heading', { name: 'Scan queued' })).toBeInTheDocument()

    client.setQueryData(['active-scans'], {
      scans: [],
      queued_runs: [{ job_id: 'job-1', job: 'Production', queued_at: '2026-10-06T10:00:00Z', trigger: 'manual' }],
    })
    expect(await screen.findByRole('status')).toHaveTextContent('Scan request accepted at')
    client.setQueryData(['active-scans'], { scans: [], queued_runs: [] })

    await act(async () => new Promise((resolve) => window.setTimeout(resolve, 5100)))
    expect(screen.getByRole('alert')).toHaveTextContent('The queued scan did not start. Try running it again.')
    expect(screen.getByRole('button', { name: 'Scan now' })).toBeEnabled()
  }, 10_000)

  it('stops waiting for an accepted run that the page never saw queued or running', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    try {
      renderPage()
      fireEvent.click(await screen.findByRole('button', { name: 'Scan now' }))
      expect(await screen.findByRole('heading', { name: 'Scan queued' })).toBeInTheDocument()
      await act(async () => { await vi.advanceTimersByTimeAsync(10_000) })
      expect(screen.getByRole('button', { name: 'Queued…' })).toBeDisabled()

      await act(async () => { await vi.advanceTimersByTimeAsync(12_000) })
      await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('The scan request was accepted but did not start. Check the job and try again.'))
      expect(screen.queryByRole('heading', { name: 'Scan queued' })).not.toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Scan now' })).toBeEnabled()
    } finally {
      vi.useRealTimers()
    }
  })

  it('keeps waiting while the scan status cannot be read', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    try {
      renderPage()
      const scanNow = await screen.findByRole('button', { name: 'Scan now' })
      await waitFor(() => expect(activeScans).toHaveBeenCalled())
      vi.mocked(activeScans).mockRejectedValue(new Error('status unavailable'))
      fireEvent.click(scanNow)
      expect(await screen.findByRole('heading', { name: 'Scan queued' })).toBeInTheDocument()
      await act(async () => { await vi.advanceTimersByTimeAsync(30_000) })
      expect(screen.getByRole('heading', { name: 'Scan queued' })).toBeInTheDocument()
      expect(screen.queryByText(/accepted but did not start/)).not.toBeInTheDocument()
    } finally {
      vi.useRealTimers()
    }
  })

  it('does not wait for a run whose skip was reported before the request returned', async () => {
    let accept: (value: { status: string; job_id: string }) => void = () => {}
    vi.mocked(runJob).mockReturnValue(new Promise(resolve => { accept = resolve }))
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: 'Scan now' }))
    act(() => window.dispatchEvent(new CustomEvent('edgewatch:scan-skipped', { detail: { job_id: 'job-1', reason: 'busy' } })))
    await act(async () => accept({ status: 'accepted', job_id: 'job-1' }))

    expect(screen.getByRole('alert')).toHaveTextContent('another scan already owns this job')
    expect(screen.queryByRole('heading', { name: 'Scan queued' })).not.toBeInTheDocument()
    await waitFor(() => expect(screen.getByRole('button', { name: 'Scan now' })).toBeEnabled())
  })

  it('pauses and resumes the schedule from the job page with the loaded revision', async () => {
    vi.mocked(pauseJob).mockImplementation(async () => {
      vi.mocked(getJob).mockResolvedValue({ ...job, enabled: false, revision: 8 } as never)
    })
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: 'Pause schedule' }))
    await waitFor(() => expect(pauseJob).toHaveBeenCalledWith('job-1', 7))

    fireEvent.click(await screen.findByRole('button', { name: 'Resume schedule' }))
    await waitFor(() => expect(resumeJob).toHaveBeenCalledWith('job-1', 8))
  })

  it('lets an operator pause a job and explains a refusal while a scan runs', async () => {
    vi.mocked(getSession).mockResolvedValue(operator)
    vi.mocked(pauseJob).mockRejectedValueOnce(new APIError('pause or resume is unavailable while a scan is running; wait for it to finish and try again', 'job_active', undefined, 409))
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: 'Pause schedule' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('unavailable while a scan is running')
  })

  it('disables the schedule control while a scan runs and hides it for archived jobs', async () => {
    vi.mocked(activeScans).mockResolvedValue({ scans: [activeScan] } as never)
    const view = renderPage()
    await waitFor(() => expect(screen.getByRole('button', { name: 'Pause schedule' })).toBeDisabled())
    view.unmount()

    vi.mocked(activeScans).mockResolvedValue({ scans: [] })
    vi.mocked(getJob).mockResolvedValue({ ...job, archived: true, enabled: false } as never)
    renderPage()
    await screen.findByRole('button', { name: 'Restore' })
    expect(screen.queryByRole('button', { name: /schedule/ })).not.toBeInTheDocument()
  })

  it('shows the active phase and progress and allows cancellation from the job page', async () => {
    vi.mocked(activeScans).mockResolvedValueOnce({ scans: [] }).mockResolvedValue({ scans: [activeScan] } as never)
    vi.mocked(cancelScan).mockImplementation(async (id) => {
      vi.mocked(activeScans).mockResolvedValueOnce({ scans: [{ ...activeScan, phase: 'cancelling' }] } as never)
      return { status: 'cancelling', scan_id: id }
    })
    renderPage()

    await screen.findByRole('button', { name: 'Scan now' })
    await waitFor(() => expect(activeScans).toHaveBeenCalledTimes(1))
    fireEvent.click(screen.getByRole('button', { name: 'Scan now' }))

    expect(await screen.findByRole('heading', { name: 'Scan in progress' })).toBeInTheDocument()
    expect(screen.getByText('Naabu → Nmap · tcp discovery · TCP')).toBeInTheDocument()
    expect(screen.getByText('42 of 100 probes · elapsed 17s · Cycle 1/3 units')).toBeInTheDocument()
    expect(screen.getByRole('progressbar', { name: 'Progress for Production' })).toHaveValue(42)

    fireEvent.click(screen.getByRole('button', { name: 'Cancel scan' }))
    await waitFor(() => expect(cancelScan).toHaveBeenCalledWith('active-scan-1'))
    expect(await screen.findByText('Cancellation requested')).toBeInTheDocument()
  })

  it('keeps a requested cancellation visible after the scanner reports progress again', async () => {
    vi.mocked(activeScans).mockResolvedValue({ scans: [{ ...activeScan, phase: 'finalizing', cancel_requested: true }] } as never)
    renderPage()

    expect(await screen.findByRole('heading', { name: 'Scan in progress' })).toBeInTheDocument()
    expect(screen.getByText(/· finalizing/)).toBeInTheDocument()
    expect(screen.getByText('Cancellation requested')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Cancel scan' })).not.toBeInTheDocument()
  })

  it('clears the accepted state after the completed scan appears in history', async () => {
    const { client } = renderPage()
    await screen.findByRole('button', { name: /scan-1/i })
    fireEvent.click(screen.getByRole('button', { name: 'Scan now' }))
    expect(await screen.findByRole('heading', { name: 'Scan queued' })).toBeInTheDocument()

    client.setQueryData(['job-scans', 'job-1', 0], { scans: [{ ...scan, id: 'scan-2' }, scan], pagination: { ...page, total: 2 } })
    await waitFor(() => expect(screen.queryByRole('heading', { name: 'Scan queued' })).not.toBeInTheDocument())
    expect(screen.getByRole('button', { name: 'Scan now' })).toBeEnabled()
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

  it('uses the legacy baseline action when no revision guard is available', async () => {
    vi.mocked(getJob).mockResolvedValue({ ...job, baseline: { status: 'complete', samples: 1, attempts: 1 } } as never)
    renderPage()
    await waitFor(() => expect(screen.getByRole('button', { name: 'Reset baseline' })).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: 'Reset baseline' }))
    fireEvent.click(screen.getByRole('dialog').querySelector('button[type="submit"]')!)
    await waitFor(() => expect(resetBaseline).toHaveBeenCalledWith('job-1'))
  })

  it('reports action failures and archives through confirmation', async () => {
    vi.mocked(runJob).mockRejectedValue(new APIError('scanner unavailable', 'scanner_unavailable', undefined, 422))
    renderPage()
    await waitFor(() => expect(screen.getByRole('button', { name: /Scan now/ })).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: /Scan now/ }))
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('scanner unavailable'))
    expect(screen.queryByRole('heading', { name: 'Scan queued' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Scan now' })).toBeEnabled()
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

  it('hides stale cycle data after a successful poll reports no active cycle', async () => {
    vi.mocked(getJob).mockResolvedValue({
      ...job,
      scan_cycle: { id: 'cycle-1', status: 'paused', completed_units: 1, total_units: 2, completed_probes: 100, total_probes: 200 },
    } as never)
    vi.mocked(scanCycle).mockResolvedValue({ cycle: null })
    renderPage()

    await waitFor(() => expect(screen.getByText('Expected baseline')).toBeInTheDocument())
    await waitFor(() => {
      expect(screen.queryByText('Broad scan paused safely.')).not.toBeInTheDocument()
      expect(screen.queryByRole('button', { name: 'Discard saved progress' })).not.toBeInTheDocument()
    })
  })

  it('shows failed scan evidence without comparison, results, or baseline approval actions', async () => {
    const failed = { ...scan, status: 'failed', error: 'Nmap exited unsuccessfully' }
    vi.mocked(jobScans).mockResolvedValue({ scans: [failed], pagination: page } as never)
    vi.mocked(scanDetail).mockResolvedValue({
      scan: failed,
      changes: [],
      changes_pagination: page,
      comparison_state: 'not_compared',
      current_security_hash: 'scope',
      comparison_source: 'scan_time',
    } as never)
    renderPage()

    fireEvent.click(await screen.findByRole('button', { name: /scan-1/i }))
    expect(await screen.findByText('No comparison was performed for this scan.')).toBeInTheDocument()
    expect(screen.getByRole('alert')).toHaveTextContent('Nmap exited unsuccessfully')
    expect(screen.queryByRole('button', { name: 'View results' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Use as baseline' })).not.toBeInTheDocument()
  })

  const comparisonCopy = {
    sample: 'This scan was a baseline sample; no comparison was performed.',
    incompleteSample: 'This scan ran while the baseline was being learned; no comparison was performed. Incomplete scans do not count as baseline samples.',
    established: 'This scan established the baseline.',
    kept: 'This scan was not compared with the baseline.',
    failed: 'This scan was not compared because it did not complete successfully.',
    scanTime: '0 changes recorded at scan time.',
    legacy: '0 changes against the current baseline.',
  }
  it.each([
    { name: 'a successful baseline sample', status: 'success', state: 'baseline_sample', source: 'none', copy: comparisonCopy.sample, empty: 'No comparison was performed for this scan.' },
    { name: 'an incomplete scan while the baseline is learned', status: 'incomplete', state: 'baseline_sample', source: 'none', copy: comparisonCopy.incompleteSample, empty: 'No comparison was performed for this scan.' },
    { name: 'the sample that established the baseline', status: 'success', state: 'baseline_established', source: 'none', copy: comparisonCopy.established, empty: 'No comparison was performed for this scan.' },
    { name: 'a completed scan kept without a comparison', status: 'success', state: 'not_compared', source: 'none', copy: comparisonCopy.kept, empty: 'No comparison was performed for this scan.' },
    { name: 'a failed scan', status: 'failed', state: 'not_compared', source: 'none', copy: comparisonCopy.failed, empty: 'No comparison was performed for this scan.' },
    { name: 'a scan compared at scan time', status: 'success', state: 'compared', source: 'scan_time', copy: comparisonCopy.scanTime, empty: 'No changes detected.' },
    { name: 'a legacy scan compared with the current baseline', status: 'success', state: 'compared', source: 'current_baseline_legacy', copy: comparisonCopy.legacy, empty: 'No changes detected.' },
  ])('describes the comparison of $name', async ({ status, state, source, copy, empty }) => {
    const selected = { ...scan, status }
    vi.mocked(jobScans).mockResolvedValue({ scans: [selected], pagination: page } as never)
    vi.mocked(scanDetail).mockResolvedValue({
      scan: selected,
      changes: [],
      changes_pagination: { ...page, total: 0 },
      comparison_state: state,
      comparison_source: source,
      current_security_hash: 'scope',
    } as never)
    renderPage()

    fireEvent.click(await screen.findByRole('button', { name: /scan-1/i }))
    expect(await screen.findByText(copy)).toBeInTheDocument()
    expect(screen.getByText(empty)).toBeInTheDocument()
    for (const other of Object.values(comparisonCopy).filter((text) => text !== copy)) {
      expect(screen.queryByText(other)).not.toBeInTheDocument()
    }
  })

  it('restores an archived job and permanently deletes it with the guarded name', async () => {
    vi.mocked(getJob).mockResolvedValue({ ...job, archived: true, enabled: false } as never)
    renderPage()
    await waitFor(() => expect(screen.getByRole('button', { name: 'Restore' })).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: 'Restore' }))
    await waitFor(() => expect(restoreJob).toHaveBeenCalledWith('job-1', 7))
    fireEvent.click(screen.getByRole('button', { name: 'Delete permanently' }))
    expect(screen.getByRole('dialog')).toHaveTextContent('scan results, incidents, saved scan progress, and notification delivery records')
    expect(screen.getByRole('dialog')).toHaveTextContent('security audit record is kept')
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(deleteJob).not.toHaveBeenCalled()

    fireEvent.click(screen.getByRole('button', { name: 'Delete permanently' }))
    const input = screen.getByRole('dialog').querySelector('input')!
    fireEvent.change(input, { target: { value: 'Production' } })
    fireEvent.click(screen.getByRole('dialog').querySelector('button[type="submit"]')!)
    await waitFor(() => expect(deleteJob).toHaveBeenCalledWith('job-1', 'Production'))
  })

  it('does not offer permanent deletion to an operator without jobs.delete', async () => {
    vi.mocked(getSession).mockResolvedValue(operator)
    vi.mocked(getJob).mockResolvedValue({ ...job, archived: true, enabled: false } as never)
    renderPage()
    await waitFor(() => expect(screen.getByRole('button', { name: 'Restore' })).toBeInTheDocument())
    expect(screen.queryByRole('button', { name: 'Delete permanently' })).not.toBeInTheDocument()
  })

  it('refreshes a stale job after a lifecycle conflict and refreshes the job list after archiving', async () => {
    vi.mocked(archiveJob).mockRejectedValueOnce(new APIError('job was modified; reload before changing its lifecycle', 'conflict'))
    const { client } = renderPage()
    const invalidate = vi.spyOn(client, 'invalidateQueries')
    await waitFor(() => expect(screen.getByText('Revision 7 · Updated', { exact: false })).toBeInTheDocument())
    vi.mocked(getJob).mockResolvedValue({ ...job, revision: 8, enabled: false } as never)
    fireEvent.click(screen.getByRole('button', { name: 'Archive job' }))
    fireEvent.click(screen.getByRole('dialog').querySelector('button[type="submit"]')!)
    await waitFor(() => expect(archiveJob).toHaveBeenCalledWith('job-1', 7))
    await waitFor(() => expect(screen.getByText('Revision 8 · Updated', { exact: false })).toBeInTheDocument())

    fireEvent.click(screen.getByRole('dialog').querySelector('button[type="submit"]')!)
    await waitFor(() => expect(archiveJob).toHaveBeenLastCalledWith('job-1', 8))
    await waitFor(() => expect(invalidate).toHaveBeenCalledWith({ queryKey: ['jobs'] }))
  })

  it('keeps mutation errors visible and allows a guarded action to be retried', async () => {
    vi.mocked(getJob).mockResolvedValue({ ...job, archived: true, enabled: false } as never)
    vi.mocked(restoreJob).mockRejectedValueOnce(new Error('restore conflict'))
    vi.mocked(resetBaseline).mockRejectedValueOnce(new Error('baseline is busy'))
    renderPage()
    await waitFor(() => expect(screen.getByRole('button', { name: 'Restore' })).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: 'Restore' }))
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('restore conflict'))
    vi.mocked(restoreJob).mockResolvedValueOnce(undefined)
    fireEvent.click(screen.getByRole('button', { name: 'Restore' }))
    await waitFor(() => expect(restoreJob).toHaveBeenCalledTimes(2))

    fireEvent.click(screen.getByRole('button', { name: 'Reset baseline' }))
    fireEvent.click(screen.getByRole('dialog').querySelector('button[type="submit"]')!)
    await waitFor(() => expect(screen.getAllByRole('alert').some(alert => alert.textContent?.includes('baseline is busy'))).toBe(true))
  })

  it('shows learning progress without presenting an expected baseline', async () => {
    vi.mocked(getJob).mockResolvedValue({
      ...job,
      baseline: { status: 'learning', samples: 1, attempts: 1 },
    } as never)
    renderPage()
    await waitFor(() => expect(screen.getAllByText('Learning').length).toBeGreaterThan(0))
    expect(screen.getByText('1 of 1 samples')).toBeInTheDocument()
    expect(screen.getByText('1 of 1 successful samples collected.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Explore baseline/ })).not.toBeInTheDocument()
  })

  it('explains estimated scan work without promising a duration', async () => {
    vi.mocked(getJob).mockResolvedValue({
      ...job,
      scan_estimate: { probes: 65_535, hosts: 2, naabu_invocations: 1, nmap_invocations: 2, unknown_dns: 2 },
    } as never)
    renderPage()

    expect(await screen.findByRole('status')).toHaveTextContent(
      'Scan work per run: 65,535 estimated probes across 2 configured hosts/targets (1 Naabu + 2 Nmap processes). Elapsed time varies with target responses and scanner settings; DNS expansion may increase the work for 2 names.',
    )
  })

  it('keeps a directly linked older scan visible above history and closes back to the job', async () => {
    const historical = { ...scan, id: 'historical-scan', scanner_engine: 'naabu_nmap', naabu_version: '2.6.1', scanner_profile_id: 'profile-1', scanner_profile_revision: 4, discovery_ports: 3, discovery_duration_ms: 999, confirmed_ports: 2, enrichment_duration_ms: 12_000 }
    vi.mocked(scanDetail).mockResolvedValue({ scan: historical, changes: [], changes_pagination: page, current_security_hash: 'scope', comparison_source: 'scan_time' } as never)
    renderPage(['/jobs/job-1/scans/historical-scan'])

    expect(await screen.findByText('Selected scan historic is not on this history page.')).toBeInTheDocument()
    expect(screen.getByRole('region', { name: 'Scan diff' })).toBeInTheDocument()
    expect(screen.getByRole('status')).toHaveTextContent('Naabu full TCP discovery → Nmap confirmation')
    expect(screen.getByRole('status')).toHaveTextContent('3 ports · 999 ms')
    expect(screen.getByRole('status')).toHaveTextContent('2 ports · 12 s')

    fireEvent.click(screen.getByRole('button', { name: 'Close scan detail' }))
    await waitFor(() => expect(screen.queryByText('Selected scan historic is not on this history page.')).not.toBeInTheDocument())
  })

  it('presents an updating baseline as active and keeps its evidence available', async () => {
    vi.mocked(getJob).mockResolvedValue({
      ...job,
      job: { ...job.job, baseline_samples: 2 },
      baseline: { status: 'updating', samples: 0, attempts: 0, scan_id: 'scan-1', host_count: 1 },
    } as never)
    renderPage()
    await waitFor(() => expect(screen.getAllByText('Ready (updating scope)').length).toBeGreaterThan(0))
    expect(screen.getByText('Baseline is active')).toBeInTheDocument()
    expect(screen.queryByText(/Baseline is learning/)).not.toBeInTheDocument()
    expect(screen.queryByText(/0 of 2 samples/)).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: /Explore baseline/ })).toHaveAttribute('href', '/jobs/job-1/baseline')
    await waitFor(() => expect(jobBaseline).toHaveBeenCalledWith('job-1', 0, 10))
  })

  it('offers retry when the job detail cannot be loaded', async () => {
    vi.mocked(getJob).mockRejectedValueOnce(new Error('job service unavailable'))
    renderPage()
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('could not be loaded'))
    const retry = screen.getByRole('button', { name: 'Retry' })
    expect(retry).toBeInTheDocument()
    vi.mocked(getJob).mockResolvedValueOnce(job as never)
    fireEvent.click(retry)
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Production' })).toBeInTheDocument())
  })
})
