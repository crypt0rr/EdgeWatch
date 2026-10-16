import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { cancelJobChangeWindow, createJobChangeWindow, getJobChangeWindow, jobChangeWindows, reviewJobChangeWindow } from '../api'
import { ActionDialog } from './ActionDialog'
import { ErrorNotice } from './ErrorNotice'
import { changeWindowLocalTime, formatChangeWindowTime, isChangeWindowTimeZoneSupported } from '../change-window-time'
import { changeKindLabel, changeTargetLabel, severityTone } from '../status'
import type { ChangeWindowStatus } from '../generated/api-types'

type Props = {
  jobID: string
  jobName: string
  timezone: string
  archived: boolean
  latestWindow?: ChangeWindowStatus | null
  canManageWindows: boolean
  canReadIncidents: boolean
  canReadScans: boolean
  canManageIncidents: boolean
}

type WindowRecord = Awaited<ReturnType<typeof jobChangeWindows>>['windows'][number] | ChangeWindowStatus

const maximumReasonBytes = 512
const maximumWindowMs = 24 * 60 * 60 * 1000

function bytes(value: string) {
  return new TextEncoder().encode(value).length
}

function windowState(window: WindowRecord) {
  if (window.review_state === 'due') return { label: 'Review due', tone: 'amber' }
  if (window.review_state === 'reviewed') return { label: 'Reviewed', tone: 'green' }
  switch (window.status) {
    case 'scheduled': return { label: 'Scheduled', tone: 'blue' }
    case 'active': return { label: 'Active', tone: 'amber' }
    case 'cancelled': return { label: 'Cancelled', tone: 'gray' }
    default: return { label: window.end_reason === 'expired' ? 'Expired' : 'Closed', tone: 'gray' }
  }
}

function changeLabel(change: { kind: string; target: string; address?: string; protocol?: string; port?: number; old?: string; new?: string }) {
  const location = changeTargetLabel(change)
  const endpoint = change.protocol && change.port ? ` · ${change.protocol.toUpperCase()}:${change.port}` : ''
  const state = change.old || change.new ? ` · ${change.old || '—'} → ${change.new || '—'}` : ''
  return `${changeKindLabel(change.kind, change.old, change.new)} · ${location}${endpoint}${state}`
}

function ChangeWindowTimeChoice({
  label,
  local,
  timeZone,
  selection,
  onLocalChange,
  onOffsetChange,
  required,
}: {
  label: string
  local: string
  timeZone: string
  selection: string
  onLocalChange: (value: string) => void
  onOffsetChange: (value: string) => void
  required?: boolean
}) {
  const candidates = useMemo(() => changeWindowLocalTime(local, timeZone), [local, timeZone])
  const selected = candidates.length === 1 ? candidates[0] : candidates.find(candidate => candidate.value === selection)
  return <>
    <label>{label} <span className="change-window-timezone">({timeZone})</span>
      <input type="datetime-local" step="60" value={local} required={required} onChange={event => onLocalChange(event.currentTarget.value)} aria-describedby={`${label.replace(/[^a-z0-9]+/gi, '-').toLowerCase()}-help`} />
      <small id={`${label.replace(/[^a-z0-9]+/gi, '-').toLowerCase()}-help`}>Enter local time in {timeZone}. The saved instant includes its UTC offset.</small>
    </label>
    {candidates.length > 1 && <label className="change-window-offset-choice">Choose the UTC offset for {label.toLowerCase()}
      <select value={selected?.value ?? ''} onChange={event => onOffsetChange(event.currentTarget.value)}>
        <option value="">Choose UTC offset</option>
        {candidates.map(candidate => <option value={candidate.value} key={candidate.value}>{candidate.offset} · {candidate.instant}</option>)}
      </select>
    </label>}
    {selected && <p className="change-window-exact-time">Will be saved as <strong>{formatChangeWindowTime(selected.instant, timeZone)}</strong>; exact instant <code>{selected.instant}</code>.</p>}
  </>
}

export function JobChangeWindows({ jobID, jobName, timezone, archived, latestWindow, canManageWindows, canReadIncidents, canReadScans, canManageIncidents }: Props) {
  const client = useQueryClient()
  const windows = useQuery({
    queryKey: ['job-change-windows', jobID],
    queryFn: () => jobChangeWindows(jobID),
    enabled: !!jobID,
    refetchInterval: 30_000,
  })
  const listedItems = windows.data?.windows ?? []
  const items = latestWindow && !listedItems.some(window => window.id === latestWindow.id)
    ? [latestWindow, ...listedItems]
    : listedItems
  const [selectedWindowID, setSelectedWindowID] = useState('')
  const detail = useQuery({
    queryKey: ['job-change-window', jobID, selectedWindowID],
    queryFn: ({ signal }) => getJobChangeWindow(jobID, selectedWindowID, signal),
    enabled: canReadIncidents && !!selectedWindowID,
  })
  useEffect(() => {
    if (canReadIncidents) return
    const queryKey = ['job-change-window', jobID]
    void client.cancelQueries({ queryKey }).finally(() => client.removeQueries({ queryKey }))
  }, [canReadIncidents, client, jobID])
  const [startNow, setStartNow] = useState(true)
  const [startLocal, setStartLocal] = useState('')
  const [startSelection, setStartSelection] = useState('')
  const [endLocal, setEndLocal] = useState('')
  const [endSelection, setEndSelection] = useState('')
  const [reason, setReason] = useState('')
  const [formError, setFormError] = useState('')
  const [formSuccess, setFormSuccess] = useState('')
  const [cancelError, setCancelError] = useState('')
  const [reviewErrors, setReviewErrors] = useState<Record<string, string>>({})
  const [creating, setCreating] = useState(false)
  const [cancelTarget, setCancelTarget] = useState<WindowRecord | null>(null)
  const [busyWindowID, setBusyWindowID] = useState('')
  const timezoneSupported = isChangeWindowTimeZoneSupported(timezone)
  const startCandidates = useMemo(() => changeWindowLocalTime(startLocal, timezone), [startLocal, timezone])
  const endCandidates = useMemo(() => changeWindowLocalTime(endLocal, timezone), [endLocal, timezone])
  const start = startCandidates.length === 1 ? startCandidates[0] : startCandidates.find(candidate => candidate.value === startSelection)
  const end = endCandidates.length === 1 ? endCandidates[0] : endCandidates.find(candidate => candidate.value === endSelection)
  const reasonBytes = bytes(reason)
  const startTimeError = !startNow && startLocal && startCandidates.length === 0
    ? `This local time does not exist in ${timezone}, or this browser cannot resolve that timezone. Choose another time.`
    : !startNow && startCandidates.length > 1 && !start
      ? `This local time occurs twice in ${timezone}. Choose the matching UTC offset.`
      : ''
  const endTimeError = endLocal && endCandidates.length === 0
    ? `This local time does not exist in ${timezone}, or this browser cannot resolve that timezone. Choose another time.`
    : endCandidates.length > 1 && !end
      ? `This local time occurs twice in ${timezone}. Choose the matching UTC offset.`
      : ''
  const startMilliseconds = startNow ? Date.now() : Date.parse(start?.instant ?? '')
  const endMilliseconds = Date.parse(end?.instant ?? '')
  const duration = endMilliseconds - startMilliseconds
  const durationError = end && (startNow || start)
    ? duration <= 0
      ? 'The end time must be in the future and after the start time.'
      : duration > maximumWindowMs
        ? 'A planned change window can last no more than 24 hours.'
        : !startNow && startMilliseconds <= Date.now()
          ? 'Choose Start now or a future start time.'
          : ''
    : ''
  const invalidReason = !reason.trim() || reasonBytes > maximumReasonBytes
  const formValid = timezoneSupported && !archived && canManageWindows && !creating && !invalidReason && !!end && !startTimeError && !endTimeError && !durationError && (startNow || !!start)

  async function refreshWindows() {
    await Promise.all([
      client.invalidateQueries({ queryKey: ['job-change-windows', jobID] }),
      client.invalidateQueries({ queryKey: ['job-change-window', jobID] }),
      client.invalidateQueries({ queryKey: ['job', jobID] }),
      client.invalidateQueries({ queryKey: ['jobs'] }),
    ])
  }

  async function create(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setFormError('')
    setFormSuccess('')
    if (!formValid || !end) return
    setCreating(true)
    try {
      await createJobChangeWindow(jobID, {
        start_now: startNow,
        start_at: startNow ? '' : start?.value ?? '',
        end_at: end.value,
        reason: reason.trim(),
      })
      setFormSuccess(startNow ? 'Change window started.' : 'Change window scheduled.')
      setReason('')
      setStartLocal('')
      setStartSelection('')
      setEndLocal('')
      setEndSelection('')
      await refreshWindows()
    } catch (cause) {
      setFormError(cause instanceof Error ? cause.message : 'Could not save the planned change window.')
      await windows.refetch()
    } finally {
      setCreating(false)
    }
  }

  async function cancel(window: WindowRecord) {
    setCancelError('')
    setBusyWindowID(window.id)
    try {
      await cancelJobChangeWindow(jobID, window.id)
      setCancelTarget(null)
      await refreshWindows()
    } catch (cause) {
      setCancelError(cause instanceof Error ? cause.message : 'Could not cancel the planned change window.')
      await windows.refetch()
    } finally {
      setBusyWindowID('')
    }
  }

  async function markReviewed(window: WindowRecord) {
    setBusyWindowID(window.id)
    setReviewErrors(current => {
      const next = { ...current }
      delete next[window.id]
      return next
    })
    try {
      const revision = window.revision
      await reviewJobChangeWindow(jobID, window.id, revision)
      await refreshWindows()
    } catch (cause) {
      setReviewErrors(current => ({ ...current, [window.id]: cause instanceof Error ? cause.message : 'Could not mark the window review complete.' }))
      await windows.refetch()
    } finally {
      setBusyWindowID('')
    }
  }

  return <section className="panel job-change-windows" aria-labelledby="job-change-windows-title">
    <div className="panel-heading">
      <div>
        <h2 id="job-change-windows-title">Planned change windows</h2>
        <p className="muted">Hold this job’s change notifications during approved work. Scans, comparisons, and incident tracking continue.</p>
      </div>
    </div>
    {canManageWindows && !archived && <form className="change-window-form" onSubmit={event => void create(event)} aria-label="Plan a change window">
      <fieldset className="change-window-start-mode">
        <legend>Window start</legend>
        <label><input type="radio" name="change-window-start" checked={startNow} onChange={() => { setStartNow(true); setStartLocal(''); setStartSelection(''); setFormError('') }} /> Start now</label>
        <label><input type="radio" name="change-window-start" checked={!startNow} onChange={() => { setStartNow(false); setFormError('') }} /> Schedule for later</label>
      </fieldset>
      {!startNow && <ChangeWindowTimeChoice label="Start time" local={startLocal} timeZone={timezone} selection={startSelection} onLocalChange={value => { setStartLocal(value); setStartSelection(''); setFormError('') }} onOffsetChange={value => { setStartSelection(value); setFormError('') }} required />}
      <ChangeWindowTimeChoice label="End time" local={endLocal} timeZone={timezone} selection={endSelection} onLocalChange={value => { setEndLocal(value); setEndSelection(''); setFormError('') }} onOffsetChange={value => { setEndSelection(value); setFormError('') }} required />
      <label>Reason
        <textarea value={reason} rows={3} onChange={event => { setReason(event.currentTarget.value); setFormError(''); setFormSuccess('') }} aria-describedby="change-window-reason-help change-window-reason-count" required />
      </label>
      <div className="change-window-reason-meta"><small id="change-window-reason-help">Required; shared with reviewers. Maximum {maximumReasonBytes} UTF-8 bytes.</small><small id="change-window-reason-count" aria-live="polite" className={reasonBytes > maximumReasonBytes ? 'over-limit' : ''}>{reasonBytes} / {maximumReasonBytes} bytes</small></div>
      {!timezoneSupported && <p className="form-error" role="alert">This browser cannot resolve the job timezone {timezone}; choose a supported browser to schedule this window.</p>}
      {startTimeError && <p className="form-error" role="alert">{startTimeError}</p>}
      {endTimeError && <p className="form-error" role="alert">{endTimeError}</p>}
      {durationError && <p className="form-error" role="alert">{durationError}</p>}
      {invalidReason && reason && <p className="form-error" role="alert">Reason must contain 1 to {maximumReasonBytes} UTF-8 bytes.</p>}
      {formError && <p className="form-error" role="alert">{formError}</p>}
      {formSuccess && <p className="success-message" role="status">{formSuccess}</p>}
      <div className="change-window-form-actions"><button className="button primary" type="submit" disabled={!formValid}>{creating ? 'Saving…' : startNow ? 'Start change window' : 'Schedule change window'}</button></div>
    </form>}
    {windows.isLoading ? <div className="skeleton-list" aria-label="Loading change windows" />
      : windows.error ? <ErrorNotice message="Could not load planned change windows." onRetry={() => windows.refetch()} />
          : items.length === 0 ? <div className="inline-empty">No planned change windows for this job.</div>
          : <div className="change-window-list">{items.map(window => {
            const presentation = windowState(window)
            const hasChangeEvidence = window.suppressed_event_count > 0 || window.in_flight_event_count > 0 || window.unknown_outcome_event_count > 0 || window.incomplete_event_count > 0 || window.review_state === 'due'
            const isSelected = selectedWindowID === window.id
            const summary = canReadIncidents && isSelected ? detail.data?.window.summary : null
            const summaryButtonID = `change-window-summary-${window.id}`
            return <article className="change-window-card" key={window.id}>
              <div className="change-window-card-heading"><div><span className={`pill ${presentation.tone}`}>{presentation.label}</span><strong>{window.reason}</strong></div>{'actor_label' in window && <span className="revision">Created by {window.actor_label}</span>}</div>
              <dl className="change-window-facts">
                <div><dt>Start</dt><dd><time dateTime={window.start_at}>{formatChangeWindowTime(window.start_at, window.timezone)}</time><code>{window.start_at}</code></dd></div>
                <div><dt>End</dt><dd><time dateTime={('effective_end' in window && window.effective_end) || (window.end_reason === 'cancelled' && window.closed_at) || window.end_at}>{formatChangeWindowTime(('effective_end' in window && window.effective_end) || (window.end_reason === 'cancelled' && window.closed_at) || window.end_at, window.timezone)}</time><code>{('effective_end' in window && window.effective_end) || (window.end_reason === 'cancelled' && window.closed_at) || window.end_at}</code></dd></div>
                {window.closed_at && <div><dt>Closed</dt><dd><time dateTime={window.closed_at}>{formatChangeWindowTime(window.closed_at, window.timezone)}</time></dd></div>}
                {window.review_state === 'reviewed' && <div><dt>Reviewed</dt><dd>{('reviewer_label' in window && window.reviewer_label) || 'Reviewer'}{'reviewed_at' in window && window.reviewed_at ? ` · ${formatChangeWindowTime(window.reviewed_at, window.timezone)}` : ''}</dd></div>}
              </dl>
              <div className="change-window-counts" aria-label="Change window summary counts">
                <div><strong>{window.new_count}</strong><span>New changes</span></div>
                <div><strong>{window.recovered_count}</strong><span>Recovered changes</span></div>
                <div><strong>{window.still_open_count}</strong><span>Still open</span></div>
                <div><strong>{window.suppressed_event_count}</strong><span>Change events held</span></div>
                <div><strong>{window.in_flight_event_count}</strong><span>Change events in flight at close</span></div>
                <div><strong>{window.unknown_outcome_event_count}</strong><span>Change events with unknown prior outcome</span></div>
                <div><strong>{window.incomplete_event_count}</strong><span>Older events with incomplete identities</span></div>
              </div>
              {hasChangeEvidence && (canReadIncidents
                ? <button className="button secondary" type="button" aria-expanded={isSelected} aria-controls={summaryButtonID} onClick={() => setSelectedWindowID(isSelected ? '' : window.id)}>{isSelected ? 'Hide closing summary' : 'View closing summary'}</button>
                : <p className="muted change-window-details-locked">Closing summary details require incidents.read.</p>)}
              {isSelected && canReadIncidents && <div id={summaryButtonID} className="change-window-summary-details" aria-label={`Closing summary for ${window.reason}`}>
                {detail.isLoading ? <div className="skeleton-list" aria-label="Loading closing summary" />
                  : detail.error ? <ErrorNotice message="Could not load the closing summary." onRetry={() => detail.refetch()} />
                    : summary ? <>
                      {summary.summary_notification_status === 'not_queued_destinations_unavailable' && <p className="muted change-window-summary-note">The summary notification was not queued because notification destinations remained unavailable for one hour. Eligible change alerts were released for individual delivery; a live provider attempt keeps its claim, and a later failure remains retryable. This closing snapshot will not change.</p>}
                      {window.in_flight_event_count > 0 && <p className="muted change-window-summary-note">{window.in_flight_event_count} change event{window.in_flight_event_count === 1 ? '' : 's'} had already started provider delivery before the window and still had a live claim with no outcome at close. These are separate from events held during the window; {summary.summary_notification_status === 'not_queued_destinations_unavailable' ? 'a later provider failure leaves the individual alert retryable without changing this closing snapshot.' : 'a later failure does not replay the individual alert or change this closing snapshot.'}</p>}
                      {window.unknown_outcome_event_count > 0 && <p className="muted change-window-summary-note">{window.unknown_outcome_event_count} earlier provider attempt{window.unknown_outcome_event_count === 1 ? '' : 's'} had no recorded outcome after the claim was released or recovered. They are not counted as currently in flight or as events held during the window; {summary.summary_notification_status === 'not_queued_destinations_unavailable' ? 'the alert remains eligible for normal outbox recovery and retry without changing this closing snapshot.' : 'EdgeWatch will not replay those stale individual alerts or change this closing snapshot.'}</p>}
                      {summary.incomplete_event_count > 0 && <p className="muted change-window-summary-note">
                        Exact identities are incomplete for {summary.incomplete_event_count} older event{summary.incomplete_event_count === 1 ? '' : 's'}. {summary.incomplete_reported_change_count > 0
                          ? `${summary.incomplete_reported_change_count} change entr${summary.incomplete_reported_change_count === 1 ? 'y was' : 'ies were'} reported by those events; this is not a unique change count.`
                          : 'Those event summaries did not report a change count.'}
                      </p>}
                      {summary.known_change_details_truncated && <p className="muted change-window-summary-note">Some change details are omitted. The new and recovered totals above remain exact.</p>}
                      {summary.still_open_details_truncated && <p className="muted change-window-summary-note">Some still-open incident details are omitted. The still-open total above remains exact.</p>}
                      {!!summary.known_changes?.length && <section aria-label="Changes observed during the window"><h3>Changes observed during the window</h3><ul>{summary.known_changes.map((change, index) => <li key={`${change.key || change.kind}-${index}`}><span className={`pill ${severityTone(change.severity)}`}>{change.severity || 'change'}</span><span>{changeLabel(change)}</span></li>)}</ul></section>}
                      {!!summary.still_open?.length && <section aria-label="Incidents still open at close"><h3>Incidents still open at close</h3><ul>{summary.still_open.map((incident, index) => <li key={`${incident.change.key || incident.change.kind}-${index}`}><span className={`pill ${severityTone(incident.change.severity)}`}>{incident.change.severity || 'change'}</span><span>{changeLabel(incident.change)}</span>{canReadScans && incident.scan_id && <Link to={`/jobs/${encodeURIComponent(jobID)}/scans/${encodeURIComponent(incident.scan_id)}`}>Open source scan</Link>}</li>)}</ul></section>}
                      <Link className="change-window-incident-link" to={`/incidents?job_id=${encodeURIComponent(jobID)}`}>Open this job’s incidents</Link>
                    </> : <p className="muted">No incident details are available for this window.</p>}
              </div>}
              {window.review_state === 'due' && (canManageIncidents
                ? <>
                  <button className="button secondary" type="button" disabled={busyWindowID === window.id} onClick={() => void markReviewed(window)}>{busyWindowID === window.id ? 'Saving…' : 'Mark review complete'}</button>
                  {reviewErrors[window.id] && <p className="form-error" role="alert">{reviewErrors[window.id]}</p>}
                </>
                : <p className="muted">Marking this review complete requires incidents.manage.</p>)}
              {(window.status === 'closed' || window.status === 'cancelled') && !hasChangeEvidence && <p className="muted change-window-no-activity">No change activity was recorded; no closing review was created.</p>}
              {canManageWindows && !archived && (window.status === 'scheduled' || window.status === 'active') && <button className="button ghost" type="button" disabled={busyWindowID === window.id} onClick={() => { setCancelError(''); setCancelTarget(window) }}>{busyWindowID === window.id ? 'Cancelling…' : 'Cancel window'}</button>}
            </article>
          })}</div>}
    {cancelTarget && <ActionDialog
      title={cancelTarget.status === 'active' ? 'End this change window early?' : 'Cancel this scheduled change window?'}
      description={cancelTarget.status === 'active'
        ? `The window for ${jobName} will close now. EdgeWatch will coalesce held change alerts and create one review if there was change activity.`
        : `The scheduled window for ${jobName} will be cancelled before it starts, with no closing review.`}
      confirmLabel={cancelTarget.status === 'active' ? 'End window now' : 'Cancel scheduled window'}
      destructive
      onConfirm={() => cancel(cancelTarget)}
      onCancel={() => { setCancelTarget(null); setCancelError('') }}
      error={cancelError}
    />}
  </section>
}
