import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useRef, useState } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import {
  Archive,
  CalendarClock,
  CheckCircle2,
  Clock3,
  Edit3,
  Pause,
  Play,
  RotateCcw,
  ShieldAlert,
  Server,
  TimerReset,
} from 'lucide-react'
import {
  APIError,
  activeScans,
  approveBaseline,
  archiveJob,
  cancelScan,
  deleteJob,
  getJob,
  jobPendingChanges,
  jobScans,
  latestSuccessfulScan,
  jobBaseline,
  pauseJob,
  resetBaseline,
  resumeJob,
  restoreJob,
  runJob,
  scanCycle,
  discardScanCycle,
  getSession,
  scanDetail,
  scanHosts,
  scanResults,
} from '../api'
import { Pagination } from '../components/Pagination'
import { ActionDialog } from '../components/ActionDialog'
import { ErrorNotice } from '../components/ErrorNotice'
import { PortScopeDetails } from '../components/PortScopeDetails'
import { SurfaceUnitList } from '../components/SurfaceUnitList'
import type { ActiveScan, QueuedRun, WorkEstimate } from '../types'
import { baselinePresentation } from '../baseline'
import { formatDateTime } from '../format'
import { changeKindLabel, changeTargetLabel, jobStatePresentation, scanOutcomeTone, severityTone } from '../status'

type JobDialog = 'reset' | 'approve' | 'archive' | 'delete' | 'discard-cycle'

// A run that ends before this page sees it queued or running is reported by
// the scan.skipped live update. When that update is missed, for example
// because the live stream is unavailable, stop waiting once polling has shown
// neither the run nor a new scan for this long.
const pendingScanBackstopMs = 20_000
type PendingScanRequest = { requestedAt: number; previousScanIDs: string[] | null; observedActive: boolean; observedQueued: boolean }

// A scan route with ?results=N opens that scan's results at offset N. A host
// page uses it to return to the result list the host was opened from.
function routeResultsOffset(value: string | null): number | null {
  if (value === null) return null
  const offset = Number(value)
  return Number.isSafeInteger(offset) && offset >= 0 ? offset : 0
}

export function JobDetail() {
  const { id = '', scanId: routeScanID } = useParams()
  const [searchParams] = useSearchParams()
  const routeResults = routeScanID ? routeResultsOffset(searchParams.get('results')) : null
  const navigate = useNavigate()
  const client = useQueryClient()
  const [selectedScan, setSelectedScan] = useState(routeScanID ?? '')
  const [scanOffset, setScanOffset] = useState(0)
  const [baselineOffset, setBaselineOffset] = useState(0)
  const [latestResultsOffset, setLatestResultsOffset] = useState(0)
  const [pendingChangesOffset, setPendingChangesOffset] = useState(0)
  const [changeOffset, setChangeOffset] = useState(0)
  const [resultsOffset, setResultsOffset] = useState(routeResults ?? 0)
  const [showResults, setShowResults] = useState(routeResults !== null)
  const [actionError, setActionError] = useState('')
  const [actionBusy, setActionBusy] = useState('')
  const [cancelBusyScan, setCancelBusyScan] = useState('')
  const [pendingScanRequest, setPendingScanRequest] = useState<PendingScanRequest | null>(null)
  const pendingScanRequestRef = useRef<PendingScanRequest | null>(null)
  pendingScanRequestRef.current = pendingScanRequest
  // A skip can be reported before the run request itself returns. Remember
  // it, so the accepted request does not then wait for a run that ended.
  const runRequest = useRef({ inFlight: false, skipped: false })
  const [dialog, setDialog] = useState<JobDialog | null>(null)
  const job = useQuery({ queryKey: ['job', id], queryFn: () => getJob(id) })
  const session = useQuery({ queryKey: ['session'], queryFn: getSession })
  // Wait for the principal before enabling scan/action queries. Besides
  // avoiding a transient unauthorized request, this keeps viewer pages from
  // ever fetching scan history that their role cannot read.
  const canOperate = session.data?.permissions.includes('jobs.write') ?? false
  // Permanent deletion is administrator-only (jobs.delete); operators may
  // archive and restore, but the API rejects their delete requests.
  const canDelete = session.data?.permissions.includes('jobs.delete') ?? false
  const canReadScans = session.data?.permissions.includes('scans.read') ?? false
  const active = useQuery({
    queryKey: ['active-scans'],
    queryFn: activeScans,
    enabled: !!id && canOperate && canReadScans,
    refetchInterval: 2000,
  })
  const activeJobScan = active.data?.scans.find((scan) => scan.job_id === id)
  const activeJobQueuedRun = active.data?.queued_runs?.find((run) => run.job_id === id)
  // "updating" is an active baseline whose stored scope hash is being
  // re-keyed; its expected results remain available.
  const baselineActive = !!job.data && baselinePresentation(job.data.baseline).status === 'complete'
  const scans = useQuery({
    queryKey: ['job-scans', id, scanOffset],
    queryFn: () => jobScans(id, scanOffset),
    enabled: !!id && canReadScans,
    refetchInterval: pendingScanRequest ? 2000 : 10000,
  })
  const baseline = useQuery({
    queryKey: ['job-baseline-overview', id, baselineOffset],
    queryFn: () => jobBaseline(id, baselineOffset, 10),
    enabled: !!id && baselineActive,
  })
  const latest = useQuery({
    queryKey: ['latest-successful-scan', id],
    queryFn: () => latestSuccessfulScan(id),
    enabled: !!id && canReadScans,
    refetchInterval: 10000,
  })
  const latestScanID = latest.data?.scan?.id ?? ''
  const latestResults = useQuery({
    queryKey: ['latest-successful-results', id, latestScanID, latestResultsOffset],
    queryFn: () => scanResults(id, latestScanID, latestResultsOffset, 10),
    enabled: !!id && !!latestScanID && canReadScans,
  })
  const pendingChanges = useQuery({
    queryKey: ['job-pending-changes', id, pendingChangesOffset],
    queryFn: () => jobPendingChanges(id, pendingChangesOffset, 10),
    enabled: !!id && canReadScans && (job.data?.baseline.pending ?? 0) > 0,
    refetchInterval: 10000,
  })
  const cycle = useQuery({ queryKey: ['scan-cycle', id], queryFn: () => scanCycle(id), enabled: !!id && canOperate, refetchInterval: 5000 })
  const detail = useQuery({
    queryKey: ['scan-detail', id, selectedScan, changeOffset],
    queryFn: () => scanDetail(id, selectedScan, changeOffset),
    enabled: !!selectedScan && canReadScans,
  })
  const results = useQuery({
    queryKey: ['scan-results', id, selectedScan, resultsOffset],
    queryFn: () => scanHosts(id, selectedScan, { offset: resultsOffset }),
    enabled: !!selectedScan && showResults && canReadScans,
  })

  useEffect(() => {
    setSelectedScan(routeScanID ?? '')
    setShowResults(routeResults !== null)
    setChangeOffset(0)
    setResultsOffset(routeResults ?? 0)
  }, [routeScanID, routeResults])

  useEffect(() => {
    setLatestResultsOffset(0)
  }, [latestScanID])

  useEffect(() => {
    if (window.location.hash === '#pending-changes' && (job.data?.baseline.pending ?? 0) > 0) {
      document.getElementById('pending-changes')?.scrollIntoView({ block: 'center' })
    }
  }, [job.data?.baseline.pending])

  useEffect(() => {
    if (!pendingScanRequest) return
    if (activeJobScan) {
      if (!pendingScanRequest.observedActive) {
        setPendingScanRequest({ ...pendingScanRequest, observedActive: true })
      }
      return
    }
    if (activeJobQueuedRun) {
      if (!pendingScanRequest.observedQueued) setPendingScanRequest({ ...pendingScanRequest, observedQueued: true })
      return
    }
    if (pendingScanRequest.observedQueued) {
      const previous = pendingScanRequest.previousScanIDs
      const newScanRecorded = previous !== null && scans.data?.scans.some((scan) => !previous.includes(scan.id))
      if (newScanRecorded) {
        setPendingScanRequest(null)
        return
      }
    }
    const previousScanIDs = pendingScanRequest.previousScanIDs
    if (previousScanIDs === null) {
      if (!scans.data) return
      const alreadyFinished = scans.data.scans.some((scan) => Date.parse(scan.started_at) >= pendingScanRequest.requestedAt)
      if (alreadyFinished) setPendingScanRequest(null)
      else setPendingScanRequest({ ...pendingScanRequest, previousScanIDs: scans.data.scans.map((scan) => scan.id) })
      return
    }
    const scanStarted = scans.data?.scans.some((scan) => !previousScanIDs.includes(scan.id))
    if (pendingScanRequest.observedActive || scanStarted) setPendingScanRequest(null)
  }, [activeJobQueuedRun?.queued_at, activeJobScan?.id, pendingScanRequest, scans.data?.scans])

  useEffect(() => {
    if (!pendingScanRequest?.observedQueued || activeJobQueuedRun || activeJobScan) return
    const request = pendingScanRequest
    // Give the history query a few seconds to catch a scan that started and
    // completed between active-status polls. This timer intentionally does
    // not depend on each history refresh, so polling cannot postpone it.
    const timeout = window.setTimeout(() => {
      const current = pendingScanRequestRef.current
      if (current?.requestedAt !== request.requestedAt || !current.observedQueued) return
      const activeState = client.getQueryData<{ scans: ActiveScan[]; queued_runs?: QueuedRun[] }>(['active-scans'])
      if (activeState?.scans.some((scan) => scan.job_id === id) || activeState?.queued_runs?.some((run) => run.job_id === id)) return
      const scanState = client.getQueryData<{ scans: { id: string; started_at: string }[] }>(['job-scans', id, scanOffset])
      const started = scanState?.scans.some((scan) => current.previousScanIDs
        ? !current.previousScanIDs.includes(scan.id)
        : Date.parse(scan.started_at) >= current.requestedAt)
      setPendingScanRequest(null)
      if (!started) setActionError('The queued scan did not start. Try running it again.')
    }, 5000)
    return () => window.clearTimeout(timeout)
  }, [activeJobQueuedRun?.queued_at, activeJobScan?.id, client, id, pendingScanRequest?.observedQueued, pendingScanRequest?.requestedAt, scanOffset])

  useEffect(() => {
    if (!pendingScanRequest || pendingScanRequest.observedQueued || pendingScanRequest.observedActive) return
    const request = pendingScanRequest
    const timer = window.setInterval(() => {
      const current = pendingScanRequestRef.current
      if (current?.requestedAt !== request.requestedAt || current.observedQueued || current.observedActive) return
      if (Date.now() - current.requestedAt < pendingScanBackstopMs) return
      // Decide only on answers read after the request, so a failing poll
      // never ends the wait.
      const activeState = client.getQueryState<{ scans: ActiveScan[]; queued_runs?: QueuedRun[] }>(['active-scans'])
      const scanState = client.getQueryState<{ scans: { id: string; started_at: string }[] }>(['job-scans', id, scanOffset])
      if (!activeState?.data || !scanState?.data || activeState.dataUpdatedAt < current.requestedAt || scanState.dataUpdatedAt < current.requestedAt) return
      if (activeState.data.scans.some((scan) => scan.job_id === id) || activeState.data.queued_runs?.some((run) => run.job_id === id)) return
      const started = scanState.data.scans.some((scan) => current.previousScanIDs
        ? !current.previousScanIDs.includes(scan.id)
        : Date.parse(scan.started_at) >= current.requestedAt)
      setPendingScanRequest(null)
      if (!started) setActionError('The scan request was accepted but did not start. Check the job and try again.')
    }, 1000)
    return () => window.clearInterval(timer)
  }, [client, id, pendingScanRequest?.requestedAt, pendingScanRequest?.observedQueued, pendingScanRequest?.observedActive, scanOffset])

  useEffect(() => {
    const onSkipped = (event: Event) => {
      const detail = (event as CustomEvent<{ job_id?: string; reason?: string }>).detail
      if (!detail || detail.job_id !== id) return
      if (runRequest.current.inFlight) runRequest.current.skipped = true
      setPendingScanRequest(null)
      setActionError(scanSkippedMessage(detail.reason))
    }
    window.addEventListener('edgewatch:scan-skipped', onSkipped)
    return () => window.removeEventListener('edgewatch:scan-skipped', onSkipped)
  }, [id])

  useEffect(() => {
    // A reset or a newly converged baseline can change the number of result
    // rows. Start its independent pager at the first page in either case.
    setBaselineOffset(0)
  }, [job.data?.baseline.status, job.data?.baseline.scan_id])

  if (job.isLoading) {
    return <div className="loading"><span className="spinner" />Loading job…</div>
  }
  if (job.error || !job.data) {
    return <section className="page"><Link className="back-link" to="/jobs">← Jobs</Link><ErrorNotice message={job.error ? 'This job could not be loaded.' : 'This job could not be found.'} onRetry={job.error ? () => job.refetch() : undefined} /></section>
  }

  const value = job.data
  function openScan(scanID: string) {
    setSelectedScan(scanID)
    setChangeOffset(0)
    setResultsOffset(0)
    setShowResults(false)
  }
  function changeScanPage(offset: number) {
    setScanOffset(offset)
    // A click-selected scan belongs to the page it was opened from. Do not
    // leave its detail detached below a different history page. Route-selected
    // scans remain open so direct historical links continue to work.
    if (!routeScanID || selectedScan !== routeScanID) {
      setSelectedScan('')
      setShowResults(false)
      setChangeOffset(0)
      setResultsOffset(0)
    }
  }
  function reportActionError(err: unknown, fallback: string) {
    setActionError(err instanceof Error ? err.message : fallback)
  }
  function reportLifecycleError(err: unknown, fallback: string) {
    reportActionError(err, fallback)
    // A lifecycle conflict means this page holds an older revision. Reload
    // it so a retry sends the current revision.
    if (err instanceof APIError && err.code === 'conflict') void client.invalidateQueries({ queryKey: ['job', id] })
  }
  async function run() {
    setActionError('')
    setActionBusy('run')
    const requestedAt = Date.now()
    const previousScanIDs = scans.data?.scans.map((scan) => scan.id) ?? null
    runRequest.current = { inFlight: true, skipped: false }
    try {
      await runJob(id)
      if (!runRequest.current.skipped) setPendingScanRequest({ requestedAt, previousScanIDs, observedActive: false, observedQueued: false })
      await Promise.all([
        client.invalidateQueries({ queryKey: ['active-scans'] }),
        client.invalidateQueries({ queryKey: ['job-scans', id] }),
        client.invalidateQueries({ queryKey: ['latest-successful-scan', id] }),
        client.invalidateQueries({ queryKey: ['latest-successful-results', id] }),
        client.invalidateQueries({ queryKey: ['jobs'] }),
      ])
    } catch (err) {
      reportActionError(err, 'Could not start the scan.')
    } finally {
      runRequest.current.inFlight = false
      setActionBusy('')
    }
  }
  async function cancelActiveScan(scanID: string) {
    setActionError('')
    setCancelBusyScan(scanID)
    try {
      await cancelScan(scanID)
      await active.refetch()
    } catch (err) {
      reportActionError(err, 'Could not cancel the scan.')
    } finally {
      setCancelBusyScan('')
    }
  }
  async function reset() {
    setActionError('')
    setActionBusy('reset')
    try {
      if (value.baseline.scan_id === undefined && value.baseline.modified === undefined) {
        await resetBaseline(id)
      } else {
        await resetBaseline(id, value.baseline.scan_id ?? '', value.baseline.modified ?? false)
      }
      await client.invalidateQueries({ queryKey: ['job', id] })
      await client.invalidateQueries({ queryKey: ['job-baseline-overview', id] })
      setBaselineOffset(0)
      setDialog(null)
    } catch (err) {
      reportActionError(err, 'Could not reset the baseline.')
    } finally {
      setActionBusy('')
    }
  }
  async function approve() {
    if (!detail.data) return
    setActionError('')
    setActionBusy('approve')
    try {
      if (value.baseline.scan_id === undefined && value.baseline.modified === undefined) {
        await approveBaseline(id, detail.data.scan.id)
      } else {
        await approveBaseline(id, detail.data.scan.id, value.baseline.scan_id ?? '', value.baseline.modified ?? false)
      }
      await client.invalidateQueries({ queryKey: ['job', id] })
      await client.invalidateQueries({ queryKey: ['job-baseline-overview', id] })
      setBaselineOffset(0)
      setSelectedScan('')
      setDialog(null)
    } catch (err) {
      reportActionError(err, 'Could not approve this baseline.')
    } finally {
      setActionBusy('')
    }
  }
  async function archive() {
    setActionError('')
    setActionBusy('archive')
    try {
      await archiveJob(id, value.revision)
      await client.invalidateQueries({ queryKey: ['jobs'] })
      // Mark the detail stale without refetching it on the way out.
      void client.invalidateQueries({ queryKey: ['job', id], refetchType: 'none' })
      setDialog(null)
      navigate('/jobs')
    } catch (err) {
      reportLifecycleError(err, 'Could not archive this job.')
      setActionBusy('')
    }
  }
  async function setSchedule(enabled: boolean) {
    setActionError('')
    setActionBusy(enabled ? 'resume' : 'pause')
    try {
      await (enabled ? resumeJob : pauseJob)(id, value.revision)
      await client.invalidateQueries({ queryKey: ['job', id] })
      await client.invalidateQueries({ queryKey: ['jobs'] })
    } catch (err) {
      reportLifecycleError(err, enabled ? 'Could not resume this job.' : 'Could not pause this job.')
    } finally {
      setActionBusy('')
    }
  }
  async function restore() {
    setActionError('')
    setActionBusy('restore')
    try {
      await restoreJob(id, value.revision)
      await client.invalidateQueries({ queryKey: ['job', id] })
      await client.invalidateQueries({ queryKey: ['jobs'] })
    } catch (err) {
      reportLifecycleError(err, 'Could not restore this job.')
    } finally {
      setActionBusy('')
    }
  }
  async function permanentlyDelete(confirmation: string) {
    setActionError('')
    setActionBusy('delete')
    try {
      await deleteJob(id, confirmation)
      await client.invalidateQueries({ queryKey: ['jobs'] })
      setDialog(null)
      navigate('/jobs')
    } catch (err) {
      reportActionError(err, 'Could not permanently delete this job.')
      setActionBusy('')
    }
  }
  async function discardCycle() {
    const current = cycle.data?.cycle ?? value.scan_cycle
    if (!current) return
    setActionError('')
    setActionBusy('discard-cycle')
    try {
      await discardScanCycle(id, current.id)
      await Promise.all([cycle.refetch(), job.refetch()])
      setDialog(null)
    } catch (err) {
      reportActionError(err, 'Could not discard the paused scan cycle.')
    } finally {
      setActionBusy('')
    }
  }

  const selectedScanCanBeBaseline = Boolean(
    detail.data
      && detail.data.scan.status === 'success'
      && detail.data.scan.config_hash === detail.data.current_security_hash,
  )
  // A successful poll that returns {cycle: null} is authoritative. Falling
  // back to the job payload in that case would keep a discarded/expired cycle
  // banner visible until the next full job refetch.
  const activeCycle = canOperate ? (cycle.data ? cycle.data.cycle : value.scan_cycle) : null
  const selectedScanDetailID = selectedScan ? `scan-detail-${encodeURIComponent(selectedScan)}` : undefined
  const selectedScanTitleID = selectedScan ? `scan-detail-title-${encodeURIComponent(selectedScan)}` : undefined
  const selectedScanDetail = selectedScan ? (
    <div
      className="scan-detail-inline"
      id={selectedScanDetailID}
      role="region"
      aria-labelledby={detail.data ? selectedScanTitleID : undefined}
      aria-label={detail.data ? undefined : `Details for scan ${selectedScan.slice(0, 8)}`}
    >
      {detail.isLoading && <div className="loading"><span className="spinner" />Loading scan details…</div>}
      {detail.error && <ErrorNotice message="Could not load this scan’s details." onRetry={() => detail.refetch()} />}
      {detail.data && (
        <>
          <div className="panel-heading">
            <div>
              <h3 id={selectedScanTitleID}>Scan diff</h3>
              <p className="muted">{detail.data.comparison_state === 'not_compared' ? 'This scan was not compared because it did not complete successfully.' : `${detail.data.changes_pagination?.total ?? detail.data.changes?.length ?? 0} ${detail.data.comparison_source === 'scan_time' ? 'changes recorded at scan time.' : 'changes against the current baseline.'}`}</p>
            </div>
            <div className="heading-actions">
              {(detail.data.scan.status === 'success' || detail.data.scan.status === 'incomplete') && <button className="button ghost" onClick={() => { setShowResults((shown) => !shown); setResultsOffset(0) }}>{showResults ? 'Hide results' : 'View results'}</button>}
              <button className="icon-button" onClick={() => routeScanID ? navigate(`/jobs/${encodeURIComponent(id)}`) : setSelectedScan('')} aria-label="Close scan detail">×</button>
            </div>
          </div>
          {detail.data.scan.error && <div className="form-error scan-error" role="alert">{detail.data.scan.error}</div>}
          {selectedScanCanBeBaseline && (
            <div className="baseline-approval">
              <span className="muted">This successful scan matches the current security scope.</span>
              {canOperate && <button className="button secondary" onClick={() => { setActionError(''); setDialog('approve') }} disabled={!!actionBusy}>{actionBusy === 'approve' ? 'Approving…' : 'Use as baseline'}</button>}
            </div>
          )}
          {(detail.data.scan.scanner_engine === 'naabu_nmap' || detail.data.scan.naabu_version || detail.data.scan.scanner_profile_id) && (
            <div className="scanner-run-summary" role="status">
              <div><strong>Scanner provenance</strong><span>{detail.data.scan.scanner_engine === 'naabu_nmap' ? 'Naabu full TCP discovery → Nmap confirmation' : detail.data.scan.scanner_engine || 'Nmap'}</span></div>
              <div><strong>Profile</strong><span>{detail.data.scan.scanner_profile_id ? `${detail.data.scan.scanner_profile_id} · revision ${detail.data.scan.scanner_profile_revision ?? 'current'}` : 'Built-in'}</span></div>
              {detail.data.scan.naabu_version && <div><strong>Naabu</strong><span>{detail.data.scan.naabu_version}</span></div>}
              {detail.data.scan.discovery_ports != null && <div><strong>Discovery</strong><span>{detail.data.scan.discovery_ports.toLocaleString()} ports · {formatRunDuration(detail.data.scan.discovery_duration_ms)}</span></div>}
              {detail.data.scan.confirmed_ports != null && <div><strong>Confirmed</strong><span>{detail.data.scan.confirmed_ports.toLocaleString()} ports · {formatRunDuration(detail.data.scan.enrichment_duration_ms)}</span></div>}
            </div>
          )}
          {detail.data.changes?.length ? (
            <div className="change-list">
              {detail.data.changes.map((change, index) => (
                <div className="change-row" key={`${change.kind}-${index}`}>
                  <span className={`pill ${severityTone(change.severity)}`}>{changeKindLabel(change.kind, change.old, change.new)}</span>
                  <strong>{changeTargetLabel(change)}{change.port ? ` · ${change.protocol}:${change.port}` : ''}</strong>
                  <span className="muted">{change.old ?? '—'} → {change.new ?? '—'}</span>
                </div>
              ))}
            </div>
          ) : <div className="inline-empty">{detail.data.comparison_state === 'not_compared' ? 'No comparison was performed for this scan.' : 'No changes detected.'}</div>}
          <Pagination page={detail.data?.changes_pagination} onChange={setChangeOffset} />
          {showResults && <div className="scan-results">
            <div className="panel-heading"><div><h3>Snapshot results</h3><p className="muted">Loaded on demand; open an effective host for technical evidence.</p></div></div>
            {results.isLoading ? <div className="skeleton-list" /> : results.error ? <ErrorNotice message="Could not load scan results." onRetry={() => results.refetch()} /> : results.data?.hosts.length ? <div className="result-list">{results.data.hosts.map(host => <Link className="result-row" to={`/jobs/${id}/scans/${selectedScan}/hosts/${encodeURIComponent(host.address)}?results=${resultsOffset}`} key={host.address}><strong title={host.address}>{host.address}</strong><span className="pill blue">{host.protocols?.map(protocol => protocol.protocol.toUpperCase()).join(' + ') || 'HOST'}</span><span className="muted">{host.open_ports + host.open_filtered_ports} positive ports · View host details</span></Link>)}</div> : <div className="inline-empty">No effective hosts in this scan.</div>}
            <Pagination page={results.data?.pagination} onChange={setResultsOffset} />
          </div>}
        </>
      )}
    </div>
  ) : null
  const selectedScanIsVisible = Boolean(selectedScan && scans.data?.scans.some((scan) => scan.id === selectedScan))
  const baselineStatus = baselinePresentation(value.baseline)
  const jobStatus = jobStatePresentation(value.archived, value.enabled)

  return (
    <section className="page">
      <div className="page-heading">
        <div>
          <Link className="back-link" to="/jobs">← Jobs</Link>
          <div className="title-row">
            <h1>{value.job.name}</h1>
            <span className={`pill ${jobStatus.tone}`}>{jobStatus.label}</span>
          </div>
          <p className="muted">Revision {value.revision} · Updated {formatDateTime(value.updated_at)}</p>
        </div>
        {canOperate && <div className="heading-actions">
          <button className="button secondary" onClick={run} disabled={value.archived || !!actionBusy || !!pendingScanRequest || !!activeJobQueuedRun || !!activeJobScan}>
            <Play size={16} /> {actionBusy === 'run' ? 'Starting…' : activeJobScan ? (activeJobScan.phase === 'cancelling' ? 'Cancelling…' : 'Scanning…') : pendingScanRequest || activeJobQueuedRun ? 'Queued…' : 'Scan now'}
          </button>
          <button className="button secondary" onClick={() => navigate(`/jobs/${id}/edit`)} disabled={!!actionBusy}>
            <Edit3 size={16} /> Edit
          </button>
          {!value.archived && <button className="button secondary" onClick={() => void setSchedule(!value.enabled)} disabled={!!actionBusy || !!activeJobScan} title={activeJobScan ? 'Available when the running scan finishes' : undefined}>
            {value.enabled
              ? <><Pause size={16} /> {actionBusy === 'pause' ? 'Pausing…' : 'Pause schedule'}</>
              : <><CalendarClock size={16} /> {actionBusy === 'resume' ? 'Resuming…' : 'Resume schedule'}</>}
          </button>}
          {value.archived ? <><button className="button secondary" onClick={restore} disabled={!!actionBusy}>{actionBusy === 'restore' ? 'Restoring…' : 'Restore'}</button>{canDelete && <button className="button danger" onClick={() => { setActionError(''); setDialog('delete') }} disabled={!!actionBusy}>{actionBusy === 'delete' ? 'Deleting…' : 'Delete permanently'}</button>}</> : <button className="icon-button danger" aria-label="Archive job" onClick={() => { setActionError(''); setDialog('archive') }} disabled={!!actionBusy}><Archive size={17} /></button>}
        </div>}
      </div>
      {actionError && <div className="form-error banner" role="alert">{actionError}</div>}
      {canOperate && canReadScans && active.error && <ErrorNotice message="Could not load live scan status." onRetry={() => active.refetch()} />}
      {canOperate && canReadScans && (activeJobScan || pendingScanRequest || activeJobQueuedRun) && <JobScanStatus
        scan={activeJobScan}
        queuedRun={activeJobQueuedRun}
        cancelBusy={cancelBusyScan}
        onCancel={cancelActiveScan}
      />}

      <div className="detail-summary">
        <div className="summary-card">
          <span className="summary-label">Baseline</span>
          <strong>{baselineStatus.label}</strong>
          <span className="muted">
            {baselineStatus.status === 'complete'
              ? `Established from ${value.baseline.scan_id?.slice(0, 8) ?? 'scan'}`
              : value.baseline.status === 'stalled'
                ? `${value.baseline.incomplete_attempts ?? 0} incomplete scans; coverage is blocking baseline learning`
                : `${value.baseline.samples ?? 0} of ${value.job.baseline_samples} samples`}
          </span>
        </div>
        <div className="summary-card">
          <span className="summary-label">Targets</span>
          <strong>{value.job.targets.length}</strong>
          <div className="muted targets-summary">
            {value.job.targets.slice(0, 2).join(', ')}
            {value.job.targets.length > 2 && <details className="target-list-details">
              <summary>View all {value.job.targets.length} targets</summary>
              <ul>{value.job.targets.map((target, index) => <li key={`${target}-${index}`}>{target}</li>)}</ul>
            </details>}
          </div>
        </div>
        <div className="summary-card">
          <span className="summary-label">Schedule</span>
          <strong>{value.job.schedule}</strong>
          <span className="muted">{value.job.timezone}</span>
        </div>
        <div className="summary-card">
          <span className="summary-label">Scope</span>
          <strong>{[value.job.tcp && 'TCP', value.job.udp && 'UDP'].filter(Boolean).join(' + ')}</strong>
          <PortScopeDetails items={[
            value.job.tcp && { protocol: 'TCP', ports: value.job.tcp.ports },
            value.job.udp && { protocol: 'UDP', ports: value.job.udp.ports },
          ].filter((item): item is { protocol: string; ports: string } => Boolean(item))} />
        </div>
      </div>
      {value.scan_estimate && <div className="notice" role="status"><span><strong>Scan work per run:</strong> {value.scan_estimate.probes.toLocaleString()} estimated probes across {value.scan_estimate.hosts.toLocaleString()} configured hosts/targets ({formatEstimateProcesses(value.scan_estimate)}). Elapsed time varies with target responses and scanner settings{value.scan_estimate.unknown_dns ? `; DNS expansion may increase the work for ${value.scan_estimate.unknown_dns} name${value.scan_estimate.unknown_dns === 1 ? '' : 's'}` : ''}.</span></div>}
      {activeCycle && <div className={activeCycle.status === 'stalled' ? 'form-error banner cycle-banner' : 'notice cycle-banner'} role="status"><span className="cycle-banner-copy"><strong>{activeCycle.status === 'paused' ? 'Broad scan paused safely.' : activeCycle.status === 'stalled' ? 'Broad scan stalled.' : 'Broad scan cycle active.'}</strong> {activeCycle.completed_units} of {activeCycle.total_units} work units and {activeCycle.completed_probes.toLocaleString()} of {activeCycle.total_probes.toLocaleString()} probes complete. {activeCycle.last_error && <span>{activeCycle.last_error}</span>}</span> {canOperate && (activeCycle.status === 'paused' || activeCycle.status === 'stalled') && <button className="button ghost" onClick={() => { setActionError(''); setDialog('discard-cycle') }} disabled={!!actionBusy}>Discard saved progress</button>}</div>}
      {value.scan_cycle_error === 'cycle_status_unavailable' && !cycle.data && <div className="notice" role="status">Saved scan progress could not be loaded. EdgeWatch will retry automatically; refresh the job if this continues.</div>}
      {!!value.missing_notification_destinations?.length && <div className="notice warning" role="status"><span><strong>Notification routing needs attention.</strong> {value.missing_notification_destinations.length === 1 ? 'A selected notification destination no longer exists' : `${value.missing_notification_destinations.length} selected notification destinations no longer exist`}, so this job’s alerts do not reach {value.missing_notification_destinations.length === 1 ? 'it' : 'them'}. Changing a deployment URL in config.yaml creates a new destination. {canOperate && !value.archived ? <Link to={`/jobs/${id}/edit`}>Edit the job to choose a current destination.</Link> : 'An operator can edit the job to choose a current destination.'}</span></div>}

      <div className="detail-sections">
        <div className="panel overview-panel">
          <div className="panel-heading">
            <div>
              <h2>Expected baseline</h2>
              <p className="muted">The positive TCP and UDP surface currently considered expected.</p>
            </div>
            <ShieldAlert size={18} className="muted-icon" />
          </div>
          <div className="baseline-box">
            {baselineStatus.status === 'complete' ? (
              <>
                <CheckCircle2 className="green-icon" size={22} />
                <div>
                  <strong>Baseline is active</strong>
                  <span className="muted">
                    New changes will be confirmed after {value.job.change_confirmations} matching scan{value.job.change_confirmations === 1 ? '' : 's'}.
                    {value.baseline.status === 'updating' && ' Its stored scope uses an older port spelling and is updated by the next finalized scan or job save.'}
                  </span>
                </div>
              </>
            ) : value.baseline.status === 'stalled' ? (
              <>
                <TimerReset className="amber-icon" size={22} />
                <div>
                  <strong>Baseline learning is stalled</strong>
                  <span className="muted">{value.baseline.incomplete_attempts ?? 0} scans have incomplete host coverage. Resolve discovery or target reachability before a baseline can be established.</span>
                </div>
              </>
            ) : (
              <>
                <TimerReset className="amber-icon" size={22} />
                <div>
                  <strong>Baseline is learning</strong>
                  <span className="muted">{value.baseline.samples ?? 0} of {value.job.baseline_samples} samples collected. No expected results are active yet.</span>
                </div>
              </>
            )}
          </div>
          <div className="overview-actions">
            {canOperate && <button className="button secondary" onClick={() => { setActionError(''); setDialog('reset') }} disabled={!!actionBusy}><RotateCcw size={16} /> {actionBusy === 'reset' ? 'Resetting…' : 'Reset baseline'}</button>}
            {baselineActive && <Link className="button secondary explore-button" to={`/jobs/${id}/baseline`}><Server size={16} /> Explore baseline <span className="button-count">{value.baseline.host_count ?? 'hosts'}</span></Link>}
          </div>
          {baselineActive && (
            <div className="overview-results">
              {baseline.isLoading ? <div className="skeleton-list" /> : baseline.error ? <ErrorNotice message="Could not load expected baseline results." onRetry={() => baseline.refetch()} /> : baseline.data?.snapshot?.units?.length ? <SurfaceUnitList units={baseline.data.snapshot.units} /> : <div className="inline-empty">No positive ports are in the current baseline.</div>}
              <Pagination page={baseline.data?.pagination} onChange={setBaselineOffset} />
            </div>
          )}
          {canReadScans && (value.baseline.pending ?? 0) > 0 && <section className="pending-detail" id="pending-changes" aria-labelledby="job-pending-title">
            <div className="pending-detail-heading"><div><h3 id="job-pending-title">Pending confirmations</h3><p className="muted">These differences have not reached the {value.job.change_confirmations}-scan confirmation threshold yet.</p></div><Link to={`/activity?job_id=${encodeURIComponent(id)}`}>Activity history →</Link></div>
            {pendingChanges.isLoading ? <div className="skeleton-list pending-skeleton" aria-label="Loading pending changes" /> : pendingChanges.error ? <ErrorNotice message="Could not load pending baseline changes." onRetry={() => pendingChanges.refetch()} /> : pendingChanges.data?.pending_changes.length ? <><ul className="pending-change-list">{pendingChanges.data.pending_changes.map(item => <li key={item.key}><span>{changeKindLabel(item.change.kind, item.change.old, item.change.new)} · {changeTargetLabel(item.change)}{item.change.protocol && item.change.port ? ` · ${item.change.protocol.toUpperCase()}:${item.change.port}` : ''}{item.change.old || item.change.new ? ` · ${item.change.old || '—'} → ${item.change.new || '—'}` : ''}</span><span className="pending-count">{item.count} / {value.job.change_confirmations} scans</span></li>)}</ul><Pagination page={pendingChanges.data.pagination} onChange={setPendingChangesOffset} label="Pending changes pagination" /></> : pendingChanges.data?.pagination.total ? <Pagination page={pendingChanges.data.pagination} onChange={setPendingChangesOffset} label="Pending changes pagination" /> : <p className="inline-empty">No changes are awaiting confirmation.</p>}
          </section>}
        </div>

        {canReadScans && <div className="panel overview-panel">
          <div className="panel-heading">
            <div>
              <h2>Latest successful scan</h2>
              <p className="muted">The newest complete snapshot, kept separate from failed or incomplete attempts.</p>
            </div>
            <Clock3 size={18} className="muted-icon" />
          </div>
          {latest.isLoading ? <div className="skeleton-list" /> : latest.error ? <ErrorNotice message="Could not load the latest successful scan." onRetry={() => latest.refetch()} /> : latest.data?.scan ? (
            <>
              <div className="latest-scan-meta">
                <div><strong>{formatDateTime(latest.data.scan.finished_at)}</strong><span className="muted">Scan {latest.data.scan.id.slice(0, 8)}</span></div>
                <Link className="button ghost" to={`/jobs/${id}/scans/${encodeURIComponent(latest.data.scan.id)}`}>Open scan details →</Link>
              </div>
              <div className="overview-results">
                {latestResults.isLoading ? <div className="skeleton-list" /> : latestResults.error ? <ErrorNotice message="Could not load latest scan results." onRetry={() => latestResults.refetch()} /> : latestResults.data?.results?.length ? <SurfaceUnitList units={latestResults.data.results} emptyLabel="No positive ports were found in this scan." /> : <div className="inline-empty">No positive ports were found in this scan.</div>}
                <Pagination page={latestResults.data?.pagination} onChange={setLatestResultsOffset} />
              </div>
            </>
          ) : <div className="inline-empty">No successful scans have run yet.</div>}
        </div>}

        {canReadScans && <div className="panel">
          <div className="panel-heading">
            <div>
              <h2>Recent scans</h2>
              <p className="muted">Successful scans feed the baseline and change engine.</p>
            </div>
            <Clock3 size={18} className="muted-icon" />
          </div>
          {selectedScan && !scans.isLoading && !selectedScanIsVisible && (
            <div className="selected-scan-fallback">
              <p className="muted">Selected scan {selectedScan.slice(0, 8)} is not on this history page.</p>
              {selectedScanDetail}
            </div>
          )}
          {scans.isLoading ? <div className="skeleton-list" /> : scans.error ? <ErrorNotice message="Could not load recent scans." onRetry={() => scans.refetch()} /> : scans.data?.scans.length ? (
            <div className="scan-list">
              {scans.data.scans.map((scan) => (
                <div className={selectedScan === scan.id ? 'scan-entry expanded' : 'scan-entry'} key={scan.id}>
                  <button
                    type="button"
                    className={selectedScan === scan.id ? 'scan-row selected' : 'scan-row'}
                    onClick={() => openScan(scan.id)}
                    aria-expanded={selectedScan === scan.id}
                    aria-controls={selectedScan === scan.id ? selectedScanDetailID : undefined}
                  >
                    <span className={`activity-dot${scanOutcomeTone(scan) === 'neutral' ? '' : ` ${scanOutcomeTone(scan)}`}`} />
                    <div className="scan-row-copy">
                      <strong>{formatDateTime(scan.finished_at)}</strong>
                      <span className={scan.error ? 'scan-row-error' : undefined} title={scan.status === 'success' ? 'Completed successfully · Open results to inspect the snapshot' : scan.error ?? undefined}>
                        {scan.status === 'success'
                          ? 'Completed successfully · Open results to inspect the snapshot'
                          : scan.status === 'incomplete'
                            ? `${scan.error ?? 'Incomplete host discovery'} · Open results to inspect reachable hosts`
                            : scan.error}
                      </span>
                    </div>
                    <code className="scan-row-id">{scan.id.slice(0, 8)}</code>
                  </button>
                  {selectedScan === scan.id && selectedScanDetail}
                </div>
              ))}
            </div>
          ) : <div className="inline-empty">No scans have run yet.</div>}
          <Pagination page={scans.data?.pagination} onChange={changeScanPage} />
        </div>}
      </div>
      {dialog === 'reset' && <ActionDialog title="Reset this baseline?" description="New scans will be learned before changes are reported. Existing history is preserved." confirmLabel="Reset baseline" destructive onConfirm={() => reset()} onCancel={() => { setDialog(null); setActionError('') }} error={actionError} />}
      {dialog === 'approve' && <ActionDialog title="Use this scan as the baseline?" description="This successful scan matches the current security scope. Future scans will compare against its results." confirmLabel="Use as baseline" onConfirm={() => approve()} onCancel={() => { setDialog(null); setActionError('') }} error={actionError} />}
      {dialog === 'archive' && <ActionDialog title="Archive this job?" description="The job will stop running, but its history and incidents will be kept. If a scan is in progress, archiving waits until it reaches a terminal state and can be retried." confirmLabel="Archive job" destructive onConfirm={() => archive()} onCancel={() => { setDialog(null); setActionError('') }} error={actionError} />}
      {dialog === 'delete' && <ActionDialog title="Delete this archived job permanently?" description="This irreversibly removes this job’s scan results, incidents, saved scan progress, and notification delivery records. The security audit record is kept. Type the job name exactly to continue." confirmLabel="Delete permanently" destructive valueLabel={`Type “${value.job.name}” to confirm`} valueType="text" valueRequired expectedValue={value.job.name} placeholder={value.job.name} autoComplete="off" onConfirm={permanentlyDelete} onCancel={() => { setDialog(null); setActionError('') }} error={actionError} />}
      {dialog === 'discard-cycle' && <ActionDialog title="Discard saved broad-scan progress?" description="The next trigger will start a fresh full-range scan. Existing attempt history remains available." confirmLabel="Discard progress" destructive onConfirm={() => discardCycle()} onCancel={() => { setDialog(null); setActionError('') }} error={actionError} />}
    </section>
  )
}

function JobScanStatus({ scan, queuedRun, cancelBusy, onCancel }: {
  scan?: ActiveScan
  queuedRun?: QueuedRun
  cancelBusy: string
  onCancel: (scanID: string) => void
}) {
  if (!scan) return <section className="panel job-scan-status" aria-labelledby="job-scan-status-title">
    <div>
      <h2 id="job-scan-status-title">Scan queued</h2>
      <p className="muted" role="status">{queuedRun
        ? `${queuedRun.trigger === 'scheduled' ? 'Scheduled scan' : 'Scan request'} accepted ${queuedRun.queued_at ? `at ${formatDateTime(queuedRun.queued_at)}` : ''} and waiting for an available scan slot.`
        : 'Your scan request was accepted and is waiting for an available scan slot.'}</p>
    </div>
    <span className="pill amber">Queued</span>
  </section>

  const phase = scan.phase || 'Working'
  const scanner = scan.scanner === 'naabu_nmap' ? 'Naabu → Nmap' : 'Nmap'
  const total = scan.total_probes || scan.estimated_probes || 0
  const completed = scan.completed_probes ?? 0
  const progress = Math.max(0, Math.min(100, scan.progress_percent ?? 0))
  // The phase keeps following the scanner after a cancel request; the flag
  // stays set until the scan ends. Older servers only report the phase.
  const cancelling = scan.cancel_requested || scan.phase === 'cancelling'

  return <section className="panel job-scan-status" aria-labelledby="job-scan-status-title">
    <div className="job-scan-status-copy">
      <div className="panel-heading">
        <div>
          <h2 id="job-scan-status-title">Scan in progress</h2>
          <p className="muted" role="status">{scanner} · {phase}{scan.protocol ? ` · ${scan.protocol.toUpperCase()}` : ''}</p>
        </div>
        <span className="pill blue">{progress}%</span>
      </div>
      <p className="muted job-scan-progress-copy">
        {completed.toLocaleString()} of {total ? total.toLocaleString() : 'an unknown number of'} probes · elapsed {formatElapsedSeconds(scan.elapsed_seconds ?? 0)}
        {scan.cycle_id ? ` · Cycle ${scan.cycle_completed_units ?? 0}/${scan.cycle_total_units ?? '?'} units` : ''}
      </p>
      <progress max={100} value={progress} aria-label={`Progress for ${scan.job}`} />
    </div>
    {cancelling
      ? <span className="pill amber">Cancellation requested</span>
      : <button type="button" className="button danger" onClick={() => onCancel(scan.id)} disabled={cancelBusy === scan.id}>
        {cancelBusy === scan.id ? 'Cancelling…' : 'Cancel scan'}
      </button>}
  </section>
}

function scanSkippedMessage(reason?: string) {
  switch (reason) {
    case 'busy': return 'The scan could not start because another scan already owns this job.'
    case 'archived': return 'The job was archived before the queued scan could start.'
    case 'paused': return 'The job was paused before the scheduled scan could start.'
    case 'budget': return 'The scan could not start because it exceeds the configured work budget.'
    case 'unit_paused': return 'The business unit was paused before the queued scan could start.'
    case 'shutting_down': return 'EdgeWatch stopped before the queued scan could start.'
    case 'cycle_stalled': return 'The scan could not start because its saved cycle is stalled; retry it manually.'
    case 'job_unavailable': return 'The job was removed before the queued scan could start.'
    default: return 'The queued scan did not start. Try running it again.'
  }
}

function formatElapsedSeconds(seconds: number) {
  const safe = Math.max(0, Math.floor(seconds))
  const hours = Math.floor(safe / 3600)
  const minutes = Math.floor((safe % 3600) / 60)
  const remaining = safe % 60
  return hours ? `${hours}h ${minutes}m` : minutes ? `${minutes}m ${remaining}s` : `${remaining}s`
}

function formatEstimateProcesses(estimate: WorkEstimate) {
  const naabu = estimate.naabu_invocations ?? 0
  const nmap = estimate.nmap_invocations ?? 0
  if (naabu > 0 && nmap > 0) {
    return `${naabu.toLocaleString()} Naabu + ${nmap.toLocaleString()} Nmap processes`
  }
  if (naabu > 0) {
    return `${naabu.toLocaleString()} Naabu process${naabu === 1 ? '' : 'es'}`
  }
  return `${nmap.toLocaleString()} Nmap process${nmap === 1 ? '' : 'es'}`
}

function formatRunDuration(ms?: number) {
  if (!ms || ms < 1) return '—'
  if (ms < 1000) return `${ms} ms`
  return `${(ms / 1000).toFixed(ms >= 10000 ? 0 : 1)} s`
}
