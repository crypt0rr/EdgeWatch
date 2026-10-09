import { Link } from 'react-router-dom'
import type { ScheduleSuggestion } from '../api'
import { baselinePresentation } from '../baseline'
import { ErrorNotice } from './ErrorNotice'
import type { ActiveScan, Job, Pagination, QueuedRun, ScanCycle, ScanSummary, Unit } from '../types'

type MonitorNextActionsProps = {
  job: Job
  canRun: boolean
  canReadScans: boolean
  canReadBaseline: boolean
  canReadIncidents: boolean
  liveStatusRequested: boolean
  liveStatusReady: boolean
  liveStatusLoading: boolean
  liveStatusError: boolean
  activeScan?: ActiveScan
  queuedRun?: QueuedRun
  pendingRun: boolean
  cycleKnown: boolean
  cycle?: ScanCycle | null
  scans?: ScanSummary[]
  scansLoading: boolean
  scansError: boolean
  baseline?: { snapshot: { units: Unit[] } | null; pagination: Pagination }
  baselineLoading: boolean
  baselineError: boolean
  latestSuccessfulScan?: ScanSummary
  schedule?: ScheduleSuggestion
  scheduleLoading: boolean
  scheduleError: boolean
  runBusy: boolean
  onRun: () => void
  onRetryScans: () => void
  onRetrySchedule: () => void
}

/** A durable next step reconstructed from the saved job and scan records. */
export function MonitorNextActions({
  job,
  canRun,
  canReadScans,
  canReadBaseline,
  canReadIncidents,
  liveStatusRequested,
  liveStatusReady,
  liveStatusLoading,
  liveStatusError,
  activeScan,
  queuedRun,
  pendingRun,
  cycleKnown,
  cycle,
  scans,
  scansLoading,
  scansError,
  baseline,
  baselineLoading,
  baselineError,
  latestSuccessfulScan,
  schedule,
  scheduleLoading,
  scheduleError,
  runBusy,
  onRun,
  onRetryScans,
  onRetrySchedule,
}: MonitorNextActionsProps) {
  const presentation = baselinePresentation(job.baseline)
  const requiredSamples = Math.max(0, job.job.baseline_samples ?? 0)
  const collectedSamples = Math.max(0, job.baseline.samples ?? 0)
  const samplesRemaining = Math.max(0, requiredSamples - collectedSamples)
  const liveWorkExists = Boolean(activeScan || queuedRun || pendingRun)
  const cycleExists = cycleKnown && Boolean(cycle)
  const canOfferRun = canRun
    && canReadScans
    && !job.archived
    && job.scan_budget?.exceeded === false
    && !liveWorkExists
    && liveStatusReady
    && cycleKnown
    && (cycleExists || (presentation.status !== 'complete' && samplesRemaining > 0))
  const nextActionLabel = cycleExists
    ? 'Resume saved scan'
    : job.baseline.status === 'stalled'
      ? 'Retry baseline scan'
      : collectedSamples === 0 ? 'Run first sample' : 'Run another sample'
  const latestAttempt = scans?.[0]
  const latestFailedAttempt = latestAttempt && latestAttempt.status !== 'success' ? latestAttempt : undefined
  const zeroPositivePorts = canReadBaseline
    && !baselineLoading
    && !baselineError
    && baseline?.snapshot !== undefined
    && baseline.snapshot !== null
    && baseline.pagination.offset === 0
    && baseline.pagination.total <= baseline.snapshot.units.length
    && !baseline.pagination.has_more
    && !hasPositivePorts(baseline.snapshot.units)

  return (
    <section className="panel monitor-next-actions" aria-labelledby="monitor-next-actions-title">
      <div className="panel-heading">
        <div>
          <h2 id="monitor-next-actions-title">Next steps</h2>
          <p className="muted">Progress is based on this job’s saved scan and baseline state.</p>
        </div>
        <span className={`pill ${presentation.tone}`}>{presentation.label}</span>
      </div>

      {presentation.status === 'complete' ? (
        <div className="baseline-box">
          <span className="green-icon" aria-hidden="true">✓</span>
          <div>
            <strong>{job.baseline.status === 'updating' ? 'The existing baseline is active while its scope updates.' : 'The baseline is active for the configured coverage.'}</strong>
            <span className="muted">EdgeWatch compares the configured targets and selected TCP/UDP ports. This status does not claim coverage outside that scope.</span>
            {job.baseline.status === 'updating' && <span className="muted">The stored scope is re-keyed by the next finalized scan or job save.</span>}
            {zeroPositivePorts && <span className="muted">This is a valid complete baseline with zero positive ports in the configured coverage.</span>}
          </div>
        </div>
      ) : job.baseline.status === 'stalled' ? (
        <div className="baseline-box">
          <span className="amber-icon" aria-hidden="true">⚠</span>
          <div>
            <strong>Baseline learning is stalled.</strong>
            <span className="muted">{job.baseline.incomplete_attempts ?? 0} incomplete observations did not count as samples; {collectedSamples} of {requiredSamples} successful samples are collected. Review the scan evidence and correct target reachability or the saved scanner profile before retrying.</span>
          </div>
        </div>
      ) : (
        <div className="baseline-box">
          <span className="amber-icon" aria-hidden="true">◌</span>
          <div>
            <strong>{collectedSamples} of {requiredSamples} successful samples collected.</strong>
            <span className="muted">Only complete successful observations count toward baseline learning. Failed, canceled, timed-out, or incomplete scans do not count.</span>
          </div>
        </div>
      )}

      {liveStatusRequested && liveStatusError ? (
        <p className="notice warning">Current scan status could not be confirmed. {liveWorkExists ? 'The last known scan state may be out of date.' : ''} Another sample is unavailable until status can be checked again.</p>
      ) : liveStatusRequested && liveWorkExists ? (
        <p className="notice">
          {activeScan
            ? 'A scan is running. Its result will update baseline progress when it finishes.'
            : queuedRun
              ? 'A scan is waiting for an available unit scan slot. You can cancel it while it is queued.'
              : 'The scan request was accepted. EdgeWatch is checking whether it queued, started, or completed.'}
        </p>
      ) : liveStatusRequested && liveStatusLoading ? (
        <p className="notice">Checking for an active or queued scan before offering another sample…</p>
      ) : liveStatusRequested && !liveStatusReady ? (
        <p className="notice warning">Current scan status is not ready, so another sample is unavailable until that status loads.</p>
      ) : null}

      {presentation.status !== 'complete' && requiredSamples > 0 && samplesRemaining === 0 && job.baseline.status !== 'stalled' && !cycleExists && (
        <p className="notice">All required samples are recorded. EdgeWatch is finalizing the baseline state.</p>
      )}

      {presentation.status !== 'complete' && latestFailedAttempt && (
        <div className="notice warning">
          <span>{failedAttemptMessage(latestFailedAttempt)} This observation did not add a baseline sample.</span>
          {canReadScans && <Link to={`/jobs/${encodeURIComponent(job.id)}/scans/${encodeURIComponent(latestFailedAttempt.id)}`}>Review scan evidence →</Link>}
        </div>
      )}
      {presentation.status !== 'complete' && canReadScans && scansLoading && <p className="muted">Loading recent scan outcomes…</p>}
      {presentation.status !== 'complete' && canReadScans && scansError && <ErrorNotice message="Could not load recent scan outcomes." onRetry={onRetryScans} />}

      {presentation.status !== 'complete' && (
        <div className="monitor-next-run">
          {!job.enabled
            ? <p className="muted">The schedule is paused, so no automatic sample is planned. Resume the schedule or start a sample explicitly.</p>
            : !job.job.schedule?.trim()
              ? <p className="muted">No schedule is configured. Start each baseline sample explicitly.</p>
              : scheduleLoading
                ? <p className="muted">Checking the next scheduled sample…</p>
                : scheduleError
                  ? <ErrorNotice message="Could not load the next scheduled sample time." onRetry={onRetrySchedule} />
                  : schedule?.draft_next_run
                    ? <p className="muted">Next scheduled sample: <strong>{formatNextRun(schedule.draft_next_run, job.job.timezone)}</strong> ({job.job.timezone}).</p>
                    : <p className="muted">The next scheduled sample time is unavailable.</p>}
          {canRun && liveStatusReady && !liveWorkExists && cycleKnown && job.scan_budget?.exceeded === true && (
            <p className="notice warning">This job currently exceeds its unit probe budget. Reduce its scope or ask an administrator to approve a high-cost scan before starting or resuming a sample.</p>
          )}
          {canRun && liveStatusReady && !liveWorkExists && cycleKnown && job.scan_budget === undefined && (
            <p className="notice warning">The unit probe budget could not be confirmed, so a sample cannot start or resume until the job’s budget status loads.</p>
          )}
          {canOfferRun && <p className="muted">If all unit scan slots are busy, the request waits in the queue and can be canceled before it starts.</p>}
          {canOfferRun && <button className="button secondary" type="button" onClick={onRun} disabled={runBusy}>{runBusy ? 'Starting…' : nextActionLabel}</button>}
          {job.baseline.status === 'stalled' && canReadScans && !latestFailedAttempt && !scansLoading && !scansError && <Link className="button ghost" to={`/jobs/${encodeURIComponent(job.id)}#recent-scans`}>Review recent scan evidence →</Link>}
          {job.baseline.status === 'stalled' && canRun && !job.archived && <Link className="button ghost" to={`/jobs/${encodeURIComponent(job.id)}/edit`}>Review targets and scanner profile →</Link>}
        </div>
      )}

      {presentation.status === 'complete' && (
        <div className="overview-actions">
          {canReadBaseline && <Link className="button secondary" to={`/jobs/${encodeURIComponent(job.id)}/baseline`}>View baseline evidence →</Link>}
          {canReadScans && latestSuccessfulScan && <Link className="button ghost" to={`/jobs/${encodeURIComponent(job.id)}/scans/${encodeURIComponent(latestSuccessfulScan.id)}`}>Open latest scan →</Link>}
          {canReadScans && <Link className="button ghost" to={`/activity?job_id=${encodeURIComponent(job.id)}`}>View scan activity →</Link>}
          {canReadIncidents && <Link className="button ghost" to="/incidents">View incidents →</Link>}
        </div>
      )}
    </section>
  )
}

function hasPositivePorts(units: Unit[]) {
  return units.some((unit) => unit.ports?.some((port) => port.state === 'open' || port.state === 'open|filtered'))
}

function failedAttemptMessage(scan: ScanSummary) {
  switch (scan.status) {
    case 'incomplete': return 'The latest scan was incomplete.'
    case 'canceled': return 'The latest scan was canceled.'
    case 'timed_out': return 'The latest scan timed out.'
    default: return 'The latest scan did not complete successfully.'
  }
}

function formatNextRun(value: string, timeZone: string) {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  const options: Intl.DateTimeFormatOptions = { weekday: 'short', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit', timeZone }
  try {
    return date.toLocaleString(undefined, options)
  } catch {
    // The server has validated the IANA zone. Keep the RFC3339 offset visible
    // if this browser's Intl database does not yet recognize a newer zone.
    return value
  }
}
