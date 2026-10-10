import { useQuery } from '@tanstack/react-query'
import { useId, useState } from 'react'
import { Activity, AlertTriangle, Bell, Check, CheckCircle2, Clock3, Database, Minus, Play, Radar, ShieldAlert, ShieldCheck, ShieldHalf, ShieldOff, ShieldX, X } from 'lucide-react'
import { activeScans, adminStatus, cancelQueuedRun, cancelScan, getSession, listIncidents, listJobs, listScans, notificationTest, runJob, type DeploymentTelemetry, type ScannerSandboxStatus } from '../api'
import { Link, useNavigate } from 'react-router-dom'
import { formatDate, formatDateTime, formatRetention, formatTime } from '../format'
import { baselinePresentation, type BaselineStatusInfo } from '../baseline'
import { UntrustedProxyBanner } from '../components/UntrustedProxyBanner'
import { ScheduledBackupBanner } from '../components/ScheduledBackupBanner'
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
  // Each control follows the permission its endpoint checks, so a role
  // that may run scans without editing jobs, or the reverse, sees exactly
  // the controls the API accepts from it.
  const canOperate = session.data?.permissions.includes('jobs.write') ?? false
  const canRun = session.data?.permissions.includes('jobs.run') ?? false
  const isAdmin = session.data?.permissions.includes('users.manage') ?? false
  const canManageNotifications = session.data?.permissions.includes('notifications.manage') ?? false
  const canReadScans = session.data?.permissions.includes('scans.read') ?? false
  const canReadIncidents = session.data?.permissions.includes('incidents.read') ?? false
  const scans = useQuery({ queryKey: ['scans'], queryFn: () => listScans(0, 20), refetchInterval: 15000, enabled: session.data != null && canReadScans })
  const active = useQuery({ queryKey: ['active-scans'], queryFn: activeScans, refetchInterval: 2000, enabled: session.data != null && canReadScans })
  const incidents = useQuery({ queryKey: ['incidents'], queryFn: () => listIncidents(0, 20), refetchInterval: 15000, enabled: session.data != null && canReadIncidents })
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
  const notificationSandbox = setup.data?.notification_sandbox
  // Warn only when scanner processes run as UID 0: a daemon that runs as
  // another user already starts them without root.
  const scannerUnconfinedAsRoot = isAdmin && scannerSandbox?.state === 'unavailable' && scannerSandbox.process_uid === 0
  const jobsMetricState = metricState(jobs)
  const scansMetricState = metricState(scans, canReadScans && !!session.data)
  const incidentsMetricState = metricState(incidents, canReadIncidents && !!session.data)
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
    <div className="page-heading"><div><p className="eyebrow">Monitoring console</p><h1>Good day, {displayName}</h1><p className="muted">A calm view of your network’s expected surface. {!canOperate ? '' : notificationCount ? `${notificationCount} notification destination${notificationCount === 1 ? '' : 's'} configured.` : !canManageNotifications ? 'Notifications are configured by an administrator.' : ''} {policy}</p></div><div className="heading-actions">{canManageNotifications && <button className="button secondary" onClick={async () => { try { const value = await notificationTest(); setNotifyState(value.sent === 0 ? { text: 'No enabled notification destinations were tested.', state: 'warning' } : { text: `${value.sent} destination${value.sent === 1 ? '' : 's'} tested`, state: 'success' }) } catch (err) { setNotifyState({ text: err instanceof Error ? err.message : 'Notification test failed', state: 'error' }) } }}><Bell size={16} /> Test notifications</button>}{canOperate && <button className="button secondary" onClick={() => navigate('/jobs/new')}><Radar size={16} /> Set up a monitor</button>}</div></div>
    {notifyState && <div className={notifyState.state === 'error' ? 'form-error' : notifyState.state === 'warning' ? 'notice warning' : 'success-banner'} role={notifyState.state === 'error' ? 'alert' : 'status'}>{notifyState.state === 'success' ? <CheckCircle2 size={16} /> : <AlertTriangle size={16} />}{notifyState.text}</div>}{canManageNotifications && notificationCount === 0 && <div className="notice warning notification-warning" role="status"><AlertTriangle size={16} /><span>No active notification destinations — alerts are not being delivered. <Link to="/notifications">Add a destination</Link>.</span></div>}{runError && <div className="form-error banner" role="alert"><AlertTriangle size={16} />{runError}</div>}{setup.error && <QueryError message="Operational status could not be loaded. Some dashboard metrics may be unavailable." onRetry={() => setup.refetch()} />}{canReadScans && active.error && <QueryError message="Could not load scans in progress." onRetry={() => active.refetch()} />}{canReadIncidents && incidents.error && <QueryError message="Could not load the incident count." onRetry={() => incidents.refetch()} />}{canOperate && setup.data?.legacy_yaml_jobs?.length ? <div className="legacy-banner"><AlertTriangle size={17} /><span><strong>Legacy YAML jobs are inactive.</strong> Recreate {setup.data.legacy_yaml_jobs.join(', ')} in the console to resume scheduling.</span><button type="button" className="text-button legacy-banner-recheck" onClick={() => void setup.refetch()}>Check again</button></div> : null}<UntrustedProxyBanner proxy={setup.data?.untrusted_proxy} /><ScheduledBackupBanner backups={setup.data?.backups} />{scannerUnconfinedAsRoot && <div className="notice warning scanner-sandbox-warning" role="status"><ShieldAlert size={16} /><span><strong>{scannerSandbox?.landlock?.state === 'enforced' ? 'Scanner processes run as UID 0, restricted only by Landlock.' : 'Scanner processes run unconfined as UID 0.'}</strong> {scannerSandbox?.reason ? `${scannerSandbox.reason}.` : ''} See “Container runtime hardening” in the EdgeWatch documentation.</span></div>}
    <div className="stat-grid"><Stat icon={<Radar />} label="Active jobs" value={activeJobs} detail={`${ready} baselines ready`} tone="blue" status={jobsMetricState} onRetry={() => jobs.refetch()} /><Stat icon={<CheckCircle2 />} label="Healthy baselines" value={ready} detail="Stable monitoring scopes" tone="green" status={jobsMetricState} onRetry={() => jobs.refetch()} />{canReadIncidents && <Stat icon={<AlertTriangle />} label="Open incidents" value={incidentTotal} detail="Confirmed changes" tone="amber" status={incidentsMetricState} onRetry={() => incidents.refetch()} />}<Stat icon={<Activity />} label="Scan history" value={scanTotal} detail="Retained scan records" tone="purple" status={scansMetricState} onRetry={() => scans.refetch()} /></div>
    {isAdmin && telemetry && <DeploymentFootprint telemetry={telemetry} scannerSandbox={scannerSandbox} notificationSandbox={notificationSandbox} />}
    {canReadScans && ((active.data?.scans.length ?? 0) > 0 || queuedRuns.length > 0) ? <div className="panel active-scans-panel"><div className="panel-heading"><div><h2>{queuedRuns.length ? 'Scans in progress or queued' : 'Scans in progress'}</h2><p className="muted">Broad scans can take time; progress follows Nmap task updates when available and reports process liveness between them.</p></div><Activity size={18} className="muted-icon" /></div><div className="active-scan-list">{queuedRuns.map(run => <QueuedRunRow key={run.job_id} run={run} cancelBusy={cancelBusy} onCancel={canRun ? cancelQueued : undefined} />)}{(active.data?.scans ?? []).map(scan => <ActiveScanRow key={scan.id} scan={scan} cancelBusy={cancelBusy} onCancel={canRun ? cancelActiveScan : undefined} />)}</div></div> : null}
    <div className="dashboard-columns"><div className="panel"><div className="panel-heading"><div><h2>Jobs at a glance</h2><p className="muted">{canRun ? 'Run or inspect any saved job.' : 'Inspect saved jobs and their baselines.'}</p></div><button className="text-button" onClick={() => navigate('/jobs')}>View all →</button></div>{jobs.isLoading ? <div className="skeleton-list" /> : jobs.error ? <QueryError message="Could not load jobs." onRetry={() => jobs.refetch()} /> : jobs.data?.jobs.length ? <div className="dashboard-jobs">{jobs.data.jobs.slice(0, 5).map(job => <div className="dashboard-job" key={job.id}><div className="job-icon"><Radar size={17} /></div><div className="dashboard-job-info"><strong>{job.job.name}</strong><span>{job.job.targets.length} targets · {job.job.schedule}</span></div><BaselinePill baseline={job.baseline} />{canRun && <button aria-label={`Run ${job.job.name}`} className="icon-button" onClick={() => runConfiguredJob(job.id)} disabled={!!runningJob}>{runningJob === job.id ? <span className="spinner" /> : <Play size={15} />}</button>}</div>)}</div> : <div className="inline-empty">No jobs configured yet.{canOperate && <button type="button" className="text-button" onClick={() => navigate('/jobs/new')}>Set up your first monitor</button>}</div>}</div>
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

function ActiveScanRow({ scan, cancelBusy, onCancel }: { scan: ActiveScan; cancelBusy: string; onCancel?: (id: string) => void }) {
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
  return <div className="active-scan-row"><div className="active-scan-meta"><strong>{scan.job}</strong><span>{scanner} · {phase}{protocol} · {completed} of {total} probes · elapsed {elapsed}{batch}{discovery}{liveness}</span>{cycle && <small className="active-scan-output">{cycle}{scan.current_unit_ports ? ` · current scope ${scan.current_unit_ports} across ${scan.current_unit_addresses ?? 0} host${scan.current_unit_addresses === 1 ? '' : 's'}` : ''}</small>}<progress max={100} value={scan.progress_percent ?? 0} aria-label={`Progress for ${scan.job}`} />{scan.process_alive && scan.process_progress_percent !== undefined ? <small className="active-scan-output">Current {scanner} process: {scan.process_progress_percent}%</small> : null}{scan.last_output ? <small className="active-scan-output">Latest scanner output: {scan.last_output}</small> : null}<details className="active-scan-details"><summary>Show scan details</summary><dl><div><dt>Scanner</dt><dd>{scanner}{scan.scanner_profile_revision ? ` · profile r${scan.scanner_profile_revision}` : ''}</dd></div><div><dt>Phase</dt><dd>{phase}{protocol}</dd></div><div><dt>Elapsed</dt><dd>{elapsed}</dd></div><div><dt>Progress</dt><dd>{completed} of {total} probes ({scan.progress_percent ?? 0}%)</dd></div>{scan.scanner === 'naabu_nmap' && <><div><dt>Discovery</dt><dd>{(scan.discovery_ports_found ?? 0).toLocaleString()} ports found across {(scan.discovery_addresses ?? 0).toLocaleString()} hosts{scan.discovery_duration_ms ? ` · ${formatDurationMS(scan.discovery_duration_ms)}` : ''}</dd></div><div><dt>Enrichment</dt><dd>{scan.enrichment_duration_ms ? formatDurationMS(scan.enrichment_duration_ms) : 'In progress'}</dd></div></>}{cycle && <div><dt>Resumable cycle</dt><dd>{cycle}</dd></div>}{scan.current_unit_ports ? <div><dt>Current work unit</dt><dd>{scan.current_unit_ports} · {scan.current_unit_addresses ?? 0} host{scan.current_unit_addresses === 1 ? '' : 's'}</dd></div> : null}{scan.current_invocation && scan.total_batches ? <div><dt>Batch</dt><dd>{scan.current_invocation} of {scan.total_batches}</dd></div> : null}<div><dt>Process</dt><dd>{scan.process_alive ? `${scanner} process active${scan.process_progress_percent !== undefined ? ` · ${scan.process_progress_percent}%` : ''}` : 'Waiting for process update'}</dd></div>{scan.last_output ? <div><dt>Latest output</dt><dd className="active-scan-detail-output">{scan.last_output}</dd></div> : null}</dl></details></div>{scan.cancel_requested || scan.phase === 'cancelling' ? <span className="pill amber">Cancellation requested</span> : onCancel && <button type="button" className="button danger" onClick={() => onCancel(scan.id)} disabled={cancelBusy === scan.id}>{cancelBusy === scan.id ? 'Cancelling…' : 'Cancel scan'}</button>}</div>
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

// The footprint shows the cached counters in one strip, then how the scanner
// and notification processes are isolated. Either sandbox may be absent on an
// older daemon, and a unit view leaves out the database size.
function DeploymentFootprint({ telemetry, scannerSandbox, notificationSandbox }: { telemetry: DeploymentTelemetry; scannerSandbox?: ScannerSandboxStatus; notificationSandbox?: ScannerSandboxStatus }) {
  const isolationID = useId()
  const metrics = [
    ...(telemetry.database_bytes === undefined ? [] : [{ label: 'Database', value: formatBytes(telemetry.database_bytes) }]),
    { label: 'Effective hosts', value: telemetry.effective_hosts.toLocaleString() },
    { label: 'Host observations', value: telemetry.host_observations.toLocaleString() },
    { label: 'Retained scans', value: telemetry.scans.toLocaleString() },
    { label: 'Events', value: telemetry.events.toLocaleString() },
    { label: 'Pending delivery', value: telemetry.outbox_pending.toLocaleString() },
  ]
  const sandboxes = ([['Scanners', scannerSandbox], ['Notifications', notificationSandbox]] as const).flatMap(([name, status]) => status ? [{ name, status }] : [])
  return <div className="panel deployment-telemetry">
    <div className="panel-heading"><div><h2>Deployment footprint</h2><p className="muted">{sandboxes.length ? 'Storage, scale, and process isolation of this deployment.' : 'Cached storage and operational scale indicators.'}</p></div><div className="telemetry-heading-meta"><span className="telemetry-updated">Collected <time dateTime={telemetry.collected_at}>{formatTime(telemetry.collected_at, { hour: '2-digit', minute: '2-digit' })}</time></span><Database size={18} className="muted-icon" aria-hidden="true" /></div></div>
    <div className="telemetry-strip" data-columns={metrics.length}>
      <dl className="telemetry-metrics">{metrics.map(({ label, value }) => <div key={label} className="telemetry-metric"><dt>{label}</dt><dd>{value}</dd></div>)}</dl>
      {sandboxes.length > 0 && <div className="telemetry-isolation"><h3 id={isolationID}>Process isolation</h3><ul className="isolation-list" role="list" aria-labelledby={isolationID}>{sandboxes.map(({ name, status }) => <SandboxEntry key={name} name={name} status={status} />)}</ul></div>}
    </div>
  </div>
}

type SandboxLayer = { name: string; label: string; state: string; reason?: string }

const layerStateText: Record<string, string> = { enforced: 'enforced', disabled: 'off', unavailable: 'unavailable' }

function SandboxEntry({ name, status }: { name: string; status: ScannerSandboxStatus }) {
  const { label, tone, Icon } = sandboxPresentation(status)
  const layers = sandboxLayers(status)
  const reasons = layerReasons(layers)
  return <li className="isolation-entry">
    <span className="isolation-name">{name}</span>
    <span className={`pill ${tone} isolation-state`}><Icon size={12} aria-hidden="true" />{label}</span>
    <div className="isolation-details">
      <div className="isolation-layer-row"><ul className="isolation-layers" role="list" aria-label={`${name} layers`}>{layers.map(layer => {
        const LayerIcon = layer.state === 'enforced' ? Check : layer.state === 'disabled' ? Minus : X
        return <li key={layer.name} className={`isolation-layer ${layer.state === 'enforced' ? 'holds' : layer.state === 'disabled' ? 'off' : 'fails'}`}><LayerIcon size={12} strokeWidth={2.5} aria-hidden="true" />{layer.label}<span className="sr-only">: {layerStateText[layer.state] ?? layer.state}</span></li>
      })}</ul>{status.state === 'enforced' && status.capabilities?.length ? <span className="isolation-capabilities">Keeps {status.capabilities.join(', ')}</span> : null}</div>
      {reasons.length > 0 && <ul className="isolation-reasons" role="list">{reasons.map(({ names, reason }) => <li key={names.join()}><span className="isolation-reason-layers">{names.join(', ')}:</span> <SandboxReason text={reason} /></li>)}</ul>}
    </div>
  </li>
}

// A sandbox confines its processes in up to three layers: the sandbox
// identity, Landlock, and the seccomp filter. The capabilities the confined
// identity keeps are shown after the layers, since they grant rather than
// confine. Older daemons report no Landlock or seccomp state; those layers are
// left out rather than shown as missing.
function sandboxLayers(status: ScannerSandboxStatus): SandboxLayer[] {
  return [
    { name: 'Identity', label: status.state === 'enforced' ? `UID ${status.uid ?? status.process_uid}` : 'Identity', state: status.state, reason: status.reason },
    ...(status.landlock ? [{ name: 'Landlock', label: 'Landlock', state: status.landlock.state, reason: status.landlock.reason }] : []),
    ...(status.seccomp ? [{ name: 'seccomp', label: 'seccomp', state: status.seccomp.state, reason: status.seccomp.reason }] : []),
  ]
}

// Enforced only when every reported layer holds, so a sandbox whose seccomp
// filter failed never shows green. Off is the configured opt-out; Partial
// still confines the processes in some layer, and Unavailable in none.
function sandboxPresentation(status: ScannerSandboxStatus) {
  const layers = sandboxLayers(status)
  const holding = layers.filter(layer => layer.state === 'enforced').length
  if (holding === layers.length) return { label: 'Enforced', tone: 'green', Icon: ShieldCheck }
  if (status.state === 'disabled' && holding === 0) return { label: 'Off', tone: 'gray', Icon: ShieldOff }
  if (holding > 0) return { label: 'Partial', tone: 'amber', Icon: ShieldHalf }
  return { label: 'Unavailable', tone: 'red', Icon: ShieldX }
}

// One line per reason, naming the layers it explains. The seccomp filter is
// installed with Landlock, so while Landlock does not hold, seccomp shares its
// reason; layers whose reasons are the same share one line.
function layerReasons(layers: SandboxLayer[]) {
  const landlockHolds = layers.find(layer => layer.name === 'Landlock')?.state === 'enforced'
  const lines: { names: string[]; reason: string }[] = []
  for (const layer of layers) {
    if (layer.state === 'enforced') continue
    const reason = (layer.name === 'seccomp' && !landlockHolds ? layers.find(candidate => candidate.name === 'Landlock')?.reason : layer.reason)?.trim()
    if (!reason) continue
    const line = lines.find(candidate => candidate.reason === reason)
    if (line) line.names.push(layer.name)
    else lines.push({ names: [layer.name], reason })
  }
  return lines
}

// Reasons arrive as lowercase clauses. Start a sentence with them, except
// when the clause opens with a configuration key such as scanner.sandbox,
// which keeps its case and is set as code.
function SandboxReason({ text }: { text: string }) {
  const [first = '', ...rest] = text.replace(/[\s.]+$/, '').split(' ')
  const tail = `${rest.length ? ` ${rest.join(' ')}` : ''}.`
  if (/^[a-z_]+(\.[a-z_]+)+$/.test(first)) return <><code>{first}</code>{tail}</>
  return <>{first.charAt(0).toUpperCase() + first.slice(1) + tail}</>
}

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
