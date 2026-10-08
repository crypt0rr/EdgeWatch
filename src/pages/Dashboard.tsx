import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { Activity, AlertTriangle, Bell, CheckCircle2, Clock3, Database, Play, Radar, ShieldAlert } from 'lucide-react'
import { activeScans, adminStatus, cancelQueuedRun, cancelScan, getSession, listIncidents, listJobs, listScans, notificationTest, runJob } from '../api'
import { Link, useNavigate } from 'react-router-dom'
import { formatDate, formatDateTime, formatRetention, formatTime } from '../format'
import { baselinePresentation, type BaselineStatusInfo } from '../baseline'
import { UntrustedProxyBanner } from '../components/UntrustedProxyBanner'
import { scanOutcomeTone } from '../status'
import type { QueuedRun } from '../types'

export function Dashboard() {
  const navigate = useNavigate()
  const [notifyState, setNotifyState] = useState<{ text: string; state: 'success' | 'warning' | 'error' } | null>(null)
  const [runError, setRunError] = useState('')
  const [runningJob, setRunningJob] = useState('')
  const [cancelBusy, setCancelBusy] = useState('')
  const jobs = useQuery({ queryKey: ['jobs', false], queryFn: () => listJobs(false) })
  const session = useQuery({ queryKey: ['session'], queryFn: getSession })
  const canOperate = session.data?.permissions.includes('jobs.write') ?? false
  const isAdmin = session.data?.permissions.includes('users.manage') ?? false
  const canManageNotifications = session.data?.permissions.includes('notifications.manage') ?? false
  const canReadScans = session.data?.permissions.includes('scans.read') ?? false
  const scans = useQuery({ queryKey: ['scans'], queryFn: () => listScans(0, 20), refetchInterval: 15000, enabled: session.data != null && canReadScans })
  const active = useQuery({ queryKey: ['active-scans'], queryFn: activeScans, refetchInterval: 2000, enabled: session.data != null && canOperate })
  const incidents = useQuery({ queryKey: ['incidents'], queryFn: () => listIncidents(0, 20), refetchInterval: 15000, enabled: session.data != null && canOperate })
  const setup = useQuery({ queryKey: ['admin-status'], queryFn: adminStatus })
  const queuedRuns = active.data?.queued_runs ?? []
  const incidentTotal = incidents.data?.pagination.total ?? 0
  const scanTotal = scans.data?.pagination.total ?? 0
  const ready = jobs.data?.jobs.filter(j => baselinePresentation(j.baseline).status === 'complete').length ?? 0
  const activeJobs = jobs.data?.jobs.filter(j => j.enabled && !j.archived).length ?? 0
  // The status leaves the count out while it cannot be read; say nothing about
  // delivery then rather than claim it is unconfigured.
  const notificationCount = setup.data?.notification_destinations
  const displayName = setup.data?.display_name ?? setup.data?.username ?? 'admin'
  // The scan slots are the unit's own limit. The status leaves them out when
  // they cannot be read, and the line then names only the retention.
  const slots = setup.data?.max_concurrent_scans
  const policy = setup.data?.retention ? `Retention ${formatRetention(setup.data.retention)}${slots === undefined ? '' : ` · ${slots} scan${slots === 1 ? '' : 's'} at a time`}.` : ''
  const telemetry = setup.data?.telemetry
  const scannerSandbox = setup.data?.scanner_sandbox
  // Warn only when scanner processes run as UID 0: a daemon that runs as
  // another user already starts them without root.
  const scannerUnconfinedAsRoot = isAdmin && scannerSandbox?.state === 'unavailable' && scannerSandbox.process_uid === 0
  const jobsMetricState = metricState(jobs)
  const scansMetricState = metricState(scans, canReadScans && !!session.data)
  const incidentsMetricState = metricState(incidents, canOperate && !!session.data)
  async function runConfiguredJob(id: string) {
    setRunError('')
    setRunningJob(id)
    try {
      await runJob(id)
      await scans.refetch()
      await active.refetch()
    } catch (err) {
      setRunError(err instanceof Error ? err.message : 'Could not start the scan.')
    } finally {
      setRunningJob('')
    }
  }
  async function cancelQueued(jobID: string) {
    setRunError('')
    setCancelBusy(`queued:${jobID}`)
    try {
      await cancelQueuedRun(jobID)
    } catch (err) {
      setRunError(err instanceof Error ? err.message : 'Could not cancel the queued scan.')
    } finally {
      await active.refetch()
      setCancelBusy('')
    }
  }
  async function cancelActiveScan(id: string) {
    setRunError('')
    setCancelBusy(id)
    try {
      await cancelScan(id)
      await active.refetch()
    } catch (err) {
      setRunError(err instanceof Error ? err.message : 'Could not cancel the scan.')
    } finally {
      setCancelBusy('')
    }
  }
  return <section className="page">
    <div className="page-heading"><div><p className="eyebrow">Monitoring console</p><h1>Good day, {displayName}</h1><p className="muted">A calm view of your network’s expected surface. {!canOperate ? '' : notificationCount ? `${notificationCount} notification destination${notificationCount === 1 ? '' : 's'} configured.` : !canManageNotifications ? 'Notifications are configured by an administrator.' : ''} {policy}</p></div><div className="heading-actions">{isAdmin && <button className="button secondary" onClick={async () => { try { const value = await notificationTest(); setNotifyState(value.sent === 0 ? { text: 'No enabled notification destinations were tested.', state: 'warning' } : { text: `${value.sent} destination${value.sent === 1 ? '' : 's'} tested`, state: 'success' }) } catch (err) { setNotifyState({ text: err instanceof Error ? err.message : 'Notification test failed', state: 'error' }) } }}><Bell size={16} /> Test notifications</button>}{canOperate && <button className="button secondary" onClick={() => navigate('/jobs/new')}><Radar size={16} /> Configure job</button>}</div></div>
    {notifyState && <div className={notifyState.state === 'error' ? 'form-error' : notifyState.state === 'warning' ? 'notice warning' : 'success-banner'} role={notifyState.state === 'error' ? 'alert' : 'status'}>{notifyState.state === 'success' ? <CheckCircle2 size={16} /> : <AlertTriangle size={16} />}{notifyState.text}</div>}{canManageNotifications && notificationCount === 0 && <div className="notice warning notification-warning" role="status"><AlertTriangle size={16} /><span>No active notification destinations — alerts are not being delivered. <Link to="/notifications">Add a destination</Link>.</span></div>}{runError && <div className="form-error banner" role="alert"><AlertTriangle size={16} />{runError}</div>}{setup.error && <QueryError message="Operational status could not be loaded. Some dashboard metrics may be unavailable." onRetry={() => setup.refetch()} />}{canOperate && active.error && <QueryError message="Could not load scans in progress." onRetry={() => active.refetch()} />}{canOperate && incidents.error && <QueryError message="Could not load the incident count." onRetry={() => incidents.refetch()} />}{canOperate && setup.data?.legacy_yaml_jobs?.length ? <div className="legacy-banner"><AlertTriangle size={17} /><span><strong>Legacy YAML jobs are inactive.</strong> Recreate {setup.data.legacy_yaml_jobs.join(', ')} in the console to resume scheduling.</span><button type="button" className="text-button legacy-banner-recheck" onClick={() => void setup.refetch()}>Check again</button></div> : null}<UntrustedProxyBanner proxy={setup.data?.untrusted_proxy} />{scannerUnconfinedAsRoot && <div className="notice warning scanner-sandbox-warning" role="status"><ShieldAlert size={16} /><span><strong>{scannerSandbox?.landlock?.state === 'enforced' ? 'Scanner processes run as UID 0, restricted only by Landlock.' : 'Scanner processes run unconfined as UID 0.'}</strong> {scannerSandbox?.reason ? `${scannerSandbox.reason}.` : ''} See “Container runtime hardening” in the EdgeWatch documentation.</span></div>}
    <div className="stat-grid"><Stat icon={<Radar />} label="Active jobs" value={activeJobs} detail={`${ready} baselines ready`} tone="blue" status={jobsMetricState} onRetry={() => jobs.refetch()} /><Stat icon={<CheckCircle2 />} label="Healthy baselines" value={ready} detail="Stable monitoring scopes" tone="green" status={jobsMetricState} onRetry={() => jobs.refetch()} />{canOperate && <Stat icon={<AlertTriangle />} label="Open incidents" value={incidentTotal} detail="Confirmed changes" tone="amber" status={incidentsMetricState} onRetry={() => incidents.refetch()} />}<Stat icon={<Activity />} label="Scan history" value={scanTotal} detail="Retained scan records" tone="purple" status={scansMetricState} onRetry={() => scans.refetch()} /></div>
    {isAdmin && telemetry && <div className="panel deployment-telemetry"><div className="panel-heading"><div><h2>Deployment footprint</h2><p className="muted">Cached storage and operational scale indicators.</p></div><Database size={18} className="muted-icon" /></div><div className="telemetry-grid">{telemetry.database_bytes !== undefined && <TelemetryMetric label="Database" value={formatBytes(telemetry.database_bytes)} />}<TelemetryMetric label="Effective hosts" value={telemetry.effective_hosts.toLocaleString()} /><TelemetryMetric label="Host observations" value={telemetry.host_observations.toLocaleString()} /><TelemetryMetric label="Retained scans" value={telemetry.scans.toLocaleString()} /><TelemetryMetric label="Events" value={telemetry.events.toLocaleString()} /><TelemetryMetric label="Pending delivery" value={telemetry.outbox_pending.toLocaleString()} />{scannerSandbox && <TelemetryMetric label="Scanner sandbox" value={scannerSandboxLabel(scannerSandbox)} />}</div><small className="muted telemetry-updated">Collected {formatTime(telemetry.collected_at, { hour: '2-digit', minute: '2-digit' })}</small></div>}
    {canOperate && ((active.data?.scans.length ?? 0) > 0 || queuedRuns.length > 0) ? <div className="panel active-scans-panel"><div className="panel-heading"><div><h2>{queuedRuns.length ? 'Scans in progress or queued' : 'Scans in progress'}</h2><p className="muted">Broad scans can take time; progress follows Nmap task updates when available and reports process liveness between them.</p></div><Activity size={18} className="muted-icon" /></div><div className="active-scan-list">{queuedRuns.map(run => <QueuedRunRow key={run.job_id} run={run} cancelBusy={cancelBusy} onCancel={cancelQueued} />)}{(active.data?.scans ?? []).map(scan => <ActiveScanRow key={scan.id} scan={scan} cancelBusy={cancelBusy} onCancel={cancelActiveScan} />)}</div></div> : null}
    <div className="dashboard-columns"><div className="panel"><div className="panel-heading"><div><h2>Jobs at a glance</h2><p className="muted">{canOperate ? 'Run or inspect any saved job.' : 'Inspect saved jobs and their baselines.'}</p></div><button className="text-button" onClick={() => navigate('/jobs')}>View all →</button></div>{jobs.isLoading ? <div className="skeleton-list" /> : jobs.error ? <QueryError message="Could not load jobs." onRetry={() => jobs.refetch()} /> : jobs.data?.jobs.length ? <div className="dashboard-jobs">{jobs.data.jobs.slice(0, 5).map(job => <div className="dashboard-job" key={job.id}><div className="job-icon"><Radar size={17} /></div><div className="dashboard-job-info"><strong>{job.job.name}</strong><span>{job.job.targets.length} targets · {job.job.schedule}</span></div><BaselinePill baseline={job.baseline} />{canOperate && <button aria-label={`Run ${job.job.name}`} className="icon-button" onClick={() => runConfiguredJob(job.id)} disabled={!!runningJob}>{runningJob === job.id ? <span className="spinner" /> : <Play size={15} />}</button>}</div>)}</div> : <div className="inline-empty">No jobs configured yet.</div>}</div>
      <div className="panel"><div className="panel-heading"><div><h2>Latest activity</h2><p className="muted">The most recent scan outcomes.</p></div><Clock3 size={18} className="muted-icon" /></div>{scans.isLoading ? <div className="skeleton-list" /> : scans.error ? <QueryError message="Could not load recent scans." onRetry={() => scans.refetch()} /> : scans.data?.scans.length ? <div className="activity-list latest-activity-list">{scans.data.scans.slice(0, 6).map(scan => <LatestActivityRow key={scan.id} scan={scan} />)}</div> : <div className="inline-empty">Your first scan will appear here.</div>}</div></div>
  </section>
}

type MetricState = 'loading' | 'ready' | 'stale' | 'error' | 'disabled'

function metricState(query: { isLoading: boolean; isError: boolean; data?: unknown }, enabled = true): MetricState {
  if (!enabled) return 'disabled'
  if (query.isError) return query.data ? 'stale' : 'error'
  if (query.isLoading || !query.data) return 'loading'
  return 'ready'
}

function QueryError({ message, onRetry }: { message: string; onRetry: () => Promise<unknown> }) {
  return <div className="form-error banner query-error" role="alert"><span>{message}</span><button type="button" className="button ghost" onClick={() => void onRetry()}>Retry</button></div>
}

function MetricRetry({ onRetry }: { onRetry: () => Promise<unknown> }) {
  return <button type="button" className="stat-retry" onClick={() => void onRetry()}>Retry</button>
}

function LatestActivityRow({ scan }: { scan: Awaited<ReturnType<typeof listScans>>['scans'][number] }) {
  const outcome = scanOutcomeTone(scan)
  const dateParts = { year: 'numeric', month: 'short', day: 'numeric' } as const
  const today = formatDate(new Date(), dateParts)
  const scanDate = formatDate(scan.finished_at, dateParts)
  const timeLabel = today === scanDate
    ? formatTime(scan.finished_at, { hour: '2-digit', minute: '2-digit' })
    : formatDateTime(scan.finished_at, { ...dateParts, hour: '2-digit', minute: '2-digit' })
  const content = <><span className={`activity-dot${outcome === 'neutral' ? '' : ` ${outcome}`}`} /><div><strong>{scan.job}</strong><span className={scan.error ? 'activity-error' : undefined} title={scan.status === 'success' ? 'Completed successfully · Open scan details' : scan.error ?? undefined}>{scan.status === 'success' ? 'Completed successfully · Open scan details' : scan.error ?? scan.status}</span></div><time dateTime={scan.finished_at}>{timeLabel}</time></>
  if (scan.job_id) return <Link className="activity-row" to={`/jobs/${encodeURIComponent(scan.job_id)}/scans/${encodeURIComponent(scan.id)}`} aria-label={`Open scan details for ${scan.job}`}>{content}</Link>
  return <Link className="activity-row" to={`/scans/${encodeURIComponent(scan.id)}`} aria-label={`Open scan details for ${scan.job}`}>{content}</Link>
}

type ActiveScan = Awaited<ReturnType<typeof activeScans>>['scans'][number]

function ActiveScanRow({ scan, cancelBusy, onCancel }: { scan: ActiveScan; cancelBusy: string; onCancel: (id: string) => void }) {
  const phase = scan.phase ?? 'Working'
  const protocol = scan.protocol ? ` · ${scan.protocol.toUpperCase()}` : ''
  const scanner = scan.scanner === 'naabu_nmap' ? 'Naabu → Nmap' : 'Nmap'
  const completed = scan.completed_probes?.toLocaleString() ?? 0
  const total = scan.total_probes?.toLocaleString() ?? scan.estimated_probes?.toLocaleString() ?? '?'
  const elapsed = formatElapsed(scan.elapsed_seconds ?? 0)
  const batch = scan.current_invocation && scan.total_batches ? ` · batch ${scan.current_invocation}/${scan.total_batches}` : ''
  const liveness = scan.process_alive ? ` · ${scanner} process active` : ''
  const cycle = scan.cycle_id ? `Cycle ${scan.cycle_completed_units ?? 0}/${scan.cycle_total_units ?? '?'} units · ${scan.cycle_status ?? 'running'}` : ''
  const discovery = scan.scanner === 'naabu_nmap' ? ` · ${scan.discovery_ports_found ?? 0} ports found across ${scan.discovery_addresses ?? 0} hosts` : ''
  return <div className="active-scan-row"><div className="active-scan-meta"><strong>{scan.job}</strong><span>{scanner} · {phase}{protocol} · {completed} of {total} probes · elapsed {elapsed}{batch}{discovery}{liveness}</span>{cycle && <small className="active-scan-output">{cycle}{scan.current_unit_ports ? ` · current scope ${scan.current_unit_ports} across ${scan.current_unit_addresses ?? 0} host${scan.current_unit_addresses === 1 ? '' : 's'}` : ''}</small>}<progress max={100} value={scan.progress_percent ?? 0} aria-label={`Progress for ${scan.job}`} />{scan.process_alive && scan.process_progress_percent !== undefined ? <small className="active-scan-output">Current {scanner} process: {scan.process_progress_percent}%</small> : null}{scan.last_output ? <small className="active-scan-output" aria-live="polite">Latest scanner output: {scan.last_output}</small> : null}<details className="active-scan-details"><summary>Show scan details</summary><dl><div><dt>Scanner</dt><dd>{scanner}{scan.scanner_profile_revision ? ` · profile r${scan.scanner_profile_revision}` : ''}</dd></div><div><dt>Phase</dt><dd>{phase}{protocol}</dd></div><div><dt>Elapsed</dt><dd>{elapsed}</dd></div><div><dt>Progress</dt><dd>{completed} of {total} probes ({scan.progress_percent ?? 0}%)</dd></div>{scan.scanner === 'naabu_nmap' && <><div><dt>Discovery</dt><dd>{(scan.discovery_ports_found ?? 0).toLocaleString()} ports found across {(scan.discovery_addresses ?? 0).toLocaleString()} hosts{scan.discovery_duration_ms ? ` · ${formatDurationMS(scan.discovery_duration_ms)}` : ''}</dd></div><div><dt>Enrichment</dt><dd>{scan.enrichment_duration_ms ? formatDurationMS(scan.enrichment_duration_ms) : 'In progress'}</dd></div></>}{cycle && <div><dt>Resumable cycle</dt><dd>{cycle}</dd></div>}{scan.current_unit_ports ? <div><dt>Current work unit</dt><dd>{scan.current_unit_ports} · {scan.current_unit_addresses ?? 0} host{scan.current_unit_addresses === 1 ? '' : 's'}</dd></div> : null}{scan.current_invocation && scan.total_batches ? <div><dt>Batch</dt><dd>{scan.current_invocation} of {scan.total_batches}</dd></div> : null}<div><dt>Process</dt><dd>{scan.process_alive ? `${scanner} process active${scan.process_progress_percent !== undefined ? ` · ${scan.process_progress_percent}%` : ''}` : 'Waiting for process update'}</dd></div>{scan.last_output ? <div><dt>Latest output</dt><dd className="active-scan-detail-output" aria-live="polite">{scan.last_output}</dd></div> : null}</dl></details></div>{scan.cancel_requested || scan.phase === 'cancelling' ? <span className="pill amber">Cancellation requested</span> : <button type="button" className="button danger" onClick={() => onCancel(scan.id)} disabled={cancelBusy === scan.id}>{cancelBusy === scan.id ? 'Cancelling…' : 'Cancel scan'}</button>}</div>
}

function QueuedRunRow({ run, cancelBusy, onCancel }: { run: QueuedRun; cancelBusy: string; onCancel?: (jobID: string) => void }) {
  const trigger = run.trigger === 'scheduled' ? 'Scheduled scan' : 'Manual scan'
  const busy = cancelBusy === `queued:${run.job_id}`
  return <div className="active-scan-row queued-scan-row">
    <div className="active-scan-meta"><strong>{run.job}</strong><span>{trigger} · waiting for an available scan slot · queued {formatDateTime(run.queued_at)}</span><span className="pill amber">Queued</span></div>
    {onCancel && <button type="button" className="button secondary" onClick={() => onCancel(run.job_id)} disabled={busy}>{busy ? 'Cancelling…' : 'Cancel queued scan'}</button>}
  </div>
}

function Stat({ icon, label, value, detail, tone, status = 'ready', onRetry }: { icon: React.ReactNode; label: string; value: number; detail: React.ReactNode; tone: string; status?: MetricState; onRetry?: () => Promise<unknown> }) {
  const display = status === 'loading' ? '…' : status === 'error' || status === 'disabled' ? '—' : value
  const statusText = status === 'loading' ? 'Loading…' : status === 'error' ? <><span>Unavailable</span>{onRetry && <MetricRetry onRetry={onRetry} />}</> : status === 'disabled' ? 'Not available for this account' : status === 'stale' ? <><span>{detail}</span>{onRetry && <><span className="metric-stale"> · stale</span><MetricRetry onRetry={onRetry} /></>}</> : detail
  return <div className={`stat-card${status === 'error' ? ' stat-unavailable' : ''}`} aria-busy={status === 'loading' || status === 'stale' ? true : undefined}><div className={`stat-icon ${tone}`}>{icon}</div><div><span className="stat-label">{label}</span><strong className="stat-value">{display}</strong><span className="stat-detail">{statusText}</span></div></div>
}

function BaselinePill({ baseline }: { baseline: BaselineStatusInfo }) {
  const presentation = baselinePresentation(baseline)
  return <span className={`pill ${presentation.tone}`}>{presentation.label}</span>
}

function scannerSandboxLabel(status: NonNullable<Awaited<ReturnType<typeof adminStatus>>['scanner_sandbox']>) {
  const landlock = status.landlock?.state === 'enforced'
  if (status.state === 'enforced') return [status.capabilities?.length ? `Enforced · ${status.capabilities.join(', ')}` : 'Enforced', ...(landlock ? ['Landlock'] : [])].join(' · ')
  if (landlock) return 'Landlock only'
  if (status.state === 'disabled') return 'Off'
  return 'Unavailable'
}

function TelemetryMetric({ label, value }: { label: string; value: string }) { return <div className="telemetry-metric"><span>{label}</span><strong>{value}</strong></div> }

function formatBytes(value: number) {
  if (!Number.isFinite(value) || value < 1024) return `${Math.max(0, Math.round(value || 0))} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let amount = value
  let unit = -1
  while (amount >= 1024 && unit < units.length - 1) { amount /= 1024; unit += 1 }
  return `${amount >= 10 ? amount.toFixed(0) : amount.toFixed(1)} ${units[unit]}`
}

function formatElapsed(seconds: number) {
  const value = Math.max(0, Math.floor(seconds))
  const minutes = Math.floor(value / 60)
  const remainder = value % 60
  return minutes ? `${minutes}m ${remainder}s` : `${remainder}s`
}

function formatDurationMS(milliseconds: number) {
  return formatElapsed(Math.floor(Math.max(0, milliseconds) / 1000))
}
