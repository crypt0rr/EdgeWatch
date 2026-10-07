import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router-dom'
import { Clock3, ExternalLink, History, ShieldAlert } from 'lucide-react'
import { jobPendingChanges, listEvents, listIncidents, listJobs } from '../api'
import { ErrorNotice } from '../components/ErrorNotice'
import { Pagination } from '../components/Pagination'
import type { ActivityEvent, Change, Job } from '../types'
import { formatDateTime } from '../format'
import { changeKindLabel, changeTargetLabel, severityLabel, severityTone } from '../status'

const pageSize = 20

const eventLabels: Record<string, string> = {
  'changes-detected': 'Incident opened',
  'changes-reminder': 'Incident reminder',
  'changes-recovered': 'Incident recovered',
  'incident-accepted': 'Change accepted',
  'incident-suppressed': 'Incident suppressed',
  'scan-incomplete': 'Scan incomplete',
  'scan-failure': 'Scan failed',
  'scan-canceled': 'Scan canceled',
  'scan-anomaly': 'Scan anomaly',
  'application-update-available': 'Update available',
  'application-updated': 'Application updated',
  'job-silent': 'Job notification warning',
}

function eventTone(type: string) {
  if (type === 'changes-recovered' || type === 'incident-accepted') return 'recovered'
  if (type === 'changes-detected' || type === 'changes-reminder') return 'incident'
  if (type === 'scan-failure') return 'failure'
  if (type === 'scan-anomaly') return 'warning'
  return 'neutral'
}

function changeDescription(change: Change) {
  const subject = change.protocol && change.port ? ` · ${change.protocol.toUpperCase()}:${change.port}` : ''
  const transition = change.old || change.new ? ` · ${change.old || '—'} → ${change.new || '—'}` : ''
  return `${changeKindLabel(change.kind, change.old, change.new)} · ${changeTargetLabel(change)}${subject}${transition}`
}

function ActivityChange({ change }: { change: Change }) {
  return <li className="activity-change">
    <span>{changeDescription(change)}</span>
    <span className={`pill ${severityTone(change.severity)}`}>{severityLabel(change.severity)}</span>
  </li>
}

function ActivityEventRow({ event }: { event: ActivityEvent }) {
  const title = eventLabels[event.type] ?? event.type.replace(/[-_.]+/g, ' ')
  const destination = event.job_id
    ? event.scan_id
      ? `/jobs/${encodeURIComponent(event.job_id)}/scans/${encodeURIComponent(event.scan_id)}`
      : `/jobs/${encodeURIComponent(event.job_id)}`
    : undefined
  const changes = event.changes ?? []
  return <article className={`activity-event ${eventTone(event.type)}`}>
    <span className="activity-event-marker" aria-hidden="true" />
    <div className="activity-event-body">
      <div className="activity-event-heading">
        <div>
          <strong>{title}</strong>
          {event.job && <span className="activity-event-job">{event.job}</span>}
        </div>
        <time dateTime={event.created_at}>{formatDateTime(event.created_at)}</time>
      </div>
      <p>{event.message}</p>
      {changes.length > 0 && <ul className="activity-event-changes">{changes.slice(0, 5).map((change, index) => <ActivityChange key={change.key ?? `${change.target}-${change.kind}-${change.port ?? index}`} change={change} />)}</ul>}
      {event.changes_truncated && <p className="muted">Showing {changes.length} of {event.changes_count ?? 'the'} recorded changes. Open the scan for the complete change list.</p>}
      {event.release_url && <a className="activity-event-link" href={event.release_url} target="_blank" rel="noopener noreferrer">View release <ExternalLink size={13} aria-hidden="true" /></a>}
      {destination && <Link className="activity-event-link" to={destination}>{event.scan_id ? 'Open scan details' : 'Open job'} →</Link>}
    </div>
  </article>
}

function PendingJobChanges({ job }: { job: Job }) {
  const [expanded, setExpanded] = useState(false)
  const [offset, setOffset] = useState(0)
  const pending = useQuery({
    queryKey: ['job-pending-changes', job.id, offset],
    queryFn: () => jobPendingChanges(job.id, offset, 10),
    enabled: expanded,
  })
  const count = job.baseline.pending ?? 0
  return <div className="pending-job">
    <div className="pending-job-heading">
      <div><strong>{job.job.name}</strong>{job.archived && <span className="pill gray">Archived</span>}</div>
      <Link className="button ghost" to={`/jobs/${encodeURIComponent(job.id)}#pending-changes`}>Open job →</Link>
    </div>
    <button type="button" className="pending-toggle" aria-expanded={expanded} onClick={() => setExpanded(value => !value)}>
      {expanded ? 'Hide pending changes' : `Show ${count} pending change${count === 1 ? '' : 's'}`}
    </button>
    {expanded && (pending.isLoading ? <div className="skeleton-list pending-skeleton" aria-label="Loading pending changes" /> : pending.error ? <ErrorNotice message="Could not load pending changes." onRetry={() => pending.refetch()} /> : pending.data?.pending_changes.length ? (
      <>
      <ul className="pending-change-list">{pending.data.pending_changes.map(item => <li key={item.key}>
        <span>{changeDescription(item.change)}</span>
        <span className="pending-count">{item.count} / {job.job.change_confirmations} scans</span>
      </li>)}</ul>
      <Pagination page={pending.data.pagination} onChange={setOffset} label={`Pending changes for ${job.job.name}`} />
      </>
    ) : pending.data?.pagination.total ? <Pagination page={pending.data.pagination} onChange={setOffset} label={`Pending changes for ${job.job.name}`} /> : <p className="inline-empty">There are no pending changes for this job.</p>)}
  </div>
}

export function Activity() {
  const [search, setSearch] = useSearchParams()
  const selectedJob = search.get('job_id') ?? ''
  const [offset, setOffset] = useState(0)
  const [pendingOffset, setPendingOffset] = useState(0)
  const events = useQuery({
    queryKey: ['activity-events', selectedJob, offset],
    queryFn: () => listEvents(offset, pageSize, selectedJob || undefined),
  })
  const jobs = useQuery({ queryKey: ['jobs', true], queryFn: () => listJobs(true) })
  const incidents = useQuery({ queryKey: ['incidents', 'activity'], queryFn: () => listIncidents(0, 5) })
  const pendingJobs = (jobs.data?.jobs ?? []).filter(job => !job.archived && (job.baseline.pending ?? 0) > 0).sort((left, right) => left.job.name.localeCompare(right.job.name) || left.id.localeCompare(right.id))
  const pendingJobsPage = { limit: 10, offset: pendingOffset, total: pendingJobs.length, has_more: pendingOffset + 10 < pendingJobs.length, next_offset: pendingOffset + 10 < pendingJobs.length ? pendingOffset + 10 : null }
  const changeJob = (jobID: string) => {
    const next = new URLSearchParams(search)
    if (jobID) next.set('job_id', jobID)
    else next.delete('job_id')
    setSearch(next, { replace: true })
    setOffset(0)
  }
  const filteredJobMissing = selectedJob && jobs.data && !jobs.data.jobs.some(job => job.id === selectedJob)
  return <section className="page activity-page">
    <div className="page-heading">
      <div>
        <p className="eyebrow">Operations</p>
        <h1>Activity</h1>
        <p className="muted">A history of scans, changes, recoveries, and operator decisions.</p>
      </div>
      <History size={20} className="muted-icon" aria-hidden="true" />
    </div>

    <div className="activity-state-grid">
      <section className="panel" aria-labelledby="open-activity-incidents">
        <div className="panel-heading">
          <div><h2 id="open-activity-incidents">Open incidents</h2><p className="muted">Changes that still differ from the expected baseline.</p></div>
          <ShieldAlert size={18} className="muted-icon" aria-hidden="true" />
        </div>
        {incidents.isLoading ? <div className="skeleton-list" /> : incidents.error ? <ErrorNotice message="Could not load open incidents." onRetry={() => incidents.refetch()} /> : incidents.data?.pagination.total ? <>
          <p className="activity-state-total"><strong>{incidents.data.pagination.total}</strong> active incident{incidents.data.pagination.total === 1 ? '' : 's'}</p>
          <ul className="activity-state-list">{incidents.data.incidents.map(incident => <li key={`${incident.job_id}-${incident.incident.change.key ?? incident.incident.change.target}`}>
            <span><strong>{incident.job}</strong><small>{changeDescription(incident.incident.change)}</small></span>
            <Link to={incident.incident.scan_id ? `/jobs/${encodeURIComponent(incident.job_id)}/scans/${encodeURIComponent(incident.incident.scan_id)}` : `/jobs/${encodeURIComponent(incident.job_id)}`}>Review →</Link>
          </li>)}</ul>
          <Link className="button ghost" to="/incidents">View all incidents →</Link>
        </> : <p className="inline-empty">No open incidents.</p>}
      </section>

      <section className="panel" aria-labelledby="pending-activity-changes">
        <div className="panel-heading">
          <div><h2 id="pending-activity-changes">Pending confirmations</h2><p className="muted">Changes being checked against each job’s confirmation threshold.</p></div>
          <Clock3 size={18} className="muted-icon" aria-hidden="true" />
        </div>
        {jobs.isLoading ? <div className="skeleton-list" /> : jobs.error ? <ErrorNotice message="Could not load pending changes." onRetry={() => jobs.refetch()} /> : pendingJobs.length ? <><div className="pending-job-list">{pendingJobs.slice(pendingOffset, pendingOffset + pendingJobsPage.limit).map(job => <PendingJobChanges key={job.id} job={job} />)}</div><Pagination page={pendingJobsPage} onChange={setPendingOffset} label="Pending confirmations pagination" /></> : <p className="inline-empty">No changes are awaiting confirmation.</p>}
      </section>
    </div>

    <section className="panel activity-history" aria-labelledby="activity-history-title">
      <div className="panel-heading">
        <div><h2 id="activity-history-title">History</h2><p className="muted">Accepted, recovered, and scan events remain available here.</p></div>
        <label className="activity-filter">Filter by job
          <select aria-label="Filter activity by job" value={selectedJob} onChange={event => changeJob(event.target.value)}>
            <option value="">All jobs</option>
            {filteredJobMissing && <option value={selectedJob}>Selected job</option>}
            {jobs.data?.jobs.map(job => <option key={job.id} value={job.id}>{job.job.name}{job.archived ? ' (archived)' : ''}</option>)}
          </select>
        </label>
      </div>
      {events.isLoading ? <div className="skeleton-list" /> : events.error ? <ErrorNotice message="Could not load activity history." onRetry={() => events.refetch()} /> : events.data?.events.length ? <div className="activity-event-list">{events.data.events.map((event, index) => <ActivityEventRow key={`${event.created_at}-${event.type}-${event.scan_id ?? index}`} event={event} />)}</div> : <div className="empty activity-empty"><div className="empty-icon"><History size={20} /></div><h3>No activity yet</h3><p>Completed scans and baseline changes will appear here.</p></div>}
      <Pagination page={events.data?.pagination} onChange={setOffset} label="Activity history pagination" />
    </section>
  </section>
}
