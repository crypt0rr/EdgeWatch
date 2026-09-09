import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { Activity, AlertTriangle, Bell, CheckCircle2, Clock3, Database, Play, Radar } from 'lucide-react'
import { activeScans, adminStatus, cancelScan, getSession, listIncidents, listJobs, listScans, notificationTest, runJob } from '../api'
import { useNavigate } from 'react-router-dom'
import { formatRetention } from '../format'

export function Dashboard() {
  const navigate = useNavigate()
  const [notifyState, setNotifyState] = useState<{ text: string; error: boolean } | null>(null)
  const [runError, setRunError] = useState('')
  const [runningJob, setRunningJob] = useState('')
  const [cancelBusy, setCancelBusy] = useState('')
  const jobs = useQuery({ queryKey: ['jobs'], queryFn: () => listJobs(false) })
  const session = useQuery({ queryKey: ['session'], queryFn: getSession })
  const canOperate = session.data?.role !== 'viewer'
  const isAdmin = session.data?.role === 'administrator'
  const canReadScans = session.data?.role !== 'viewer'
  const scans = useQuery({ queryKey: ['scans'], queryFn: () => listScans(0, 20), refetchInterval: 15000, enabled: session.data != null && canReadScans })
  const active = useQuery({ queryKey: ['active-scans'], queryFn: activeScans, refetchInterval: 2000, enabled: session.data != null && canOperate })
  const incidents = useQuery({ queryKey: ['incidents'], queryFn: () => listIncidents(0, 20), refetchInterval: 15000, enabled: session.data != null && canOperate })
  const setup = useQuery({ queryKey: ['admin-status'], queryFn: adminStatus })
  const running = active.data?.scans.length ?? 0
  const incidentTotal = incidents.data?.pagination.total ?? 0
  const scanTotal = scans.data?.pagination.total ?? 0
  const ready = jobs.data?.jobs.filter(j => j.baseline.status === 'complete').length ?? 0
  const activeJobs = jobs.data?.jobs.filter(j => j.enabled && !j.archived).length ?? 0
  const notificationCount = setup.data?.notification_destinations ?? 0
  const displayName = setup.data?.display_name ?? setup.data?.username ?? 'admin'
  const policy = setup.data?.retention ? `Retention ${formatRetention(setup.data.retention)} · ${setup.data.max_concurrent_scans ?? 1} scan${setup.data.max_concurrent_scans === 1 ? '' : 's'} at a time.` : ''
  const telemetry = setup.data?.telemetry
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
    <div className="page-heading"><div><p className="eyebrow">Monitoring console</p><h1>Good afternoon, {displayName}</h1><p className="muted">A calm view of your network’s expected surface. {canOperate && notificationCount ? `${notificationCount} notification destination${notificationCount === 1 ? '' : 's'} configured.` : canOperate ? 'Notifications are configured by an administrator.' : ''} {policy}</p></div><div className="heading-actions">{isAdmin && <button className="button secondary" onClick={async () => { try { const value = await notificationTest(); setNotifyState({ text: `${value.sent} destination${value.sent === 1 ? '' : 's'} tested`, error: false }) } catch (err) { setNotifyState({ text: err instanceof Error ? err.message : 'Notification test failed', error: true }) } }}><Bell size={16} /> Test notifications</button>}{canOperate && <button className="button secondary" onClick={() => navigate('/jobs/new')}><Radar size={16} /> Configure job</button>}</div></div>
    {notifyState && <div className={notifyState.error ? 'form-error' : 'success-banner'} role={notifyState.error ? 'alert' : 'status'}>{notifyState.error ? <AlertTriangle size={16} /> : <CheckCircle2 size={16} />}{notifyState.text}</div>}{runError && <div className="form-error banner" role="alert"><AlertTriangle size={16} />{runError}</div>}{canOperate && setup.data?.legacy_yaml_jobs?.length ? <div className="legacy-banner"><AlertTriangle size={17} /><span><strong>Legacy YAML jobs are inactive.</strong> Recreate {setup.data.legacy_yaml_jobs.join(', ')} in the console to resume scheduling.</span><button className="icon-button" onClick={() => setup.refetch()} aria-label="Refresh status">×</button></div> : null}
    <div className="stat-grid"><Stat icon={<Radar />} label="Active jobs" value={activeJobs} detail={`${ready} baselines ready`} tone="blue" /><Stat icon={<CheckCircle2 />} label="Healthy baselines" value={ready} detail="Stable monitoring scopes" tone="green" />{canOperate && <Stat icon={<AlertTriangle />} label="Open incidents" value={incidentTotal} detail="Confirmed changes" tone="amber" />}<Stat icon={<Activity />} label="Recent scans" value={scanTotal} detail={running ? `${running} in progress` : 'No scans running'} tone="purple" /></div>
    {isAdmin && telemetry && <div className="panel deployment-telemetry"><div className="panel-heading"><div><h2>Deployment footprint</h2><p className="muted">Cached storage and operational scale indicators.</p></div><Database size={18} className="muted-icon" /></div><div className="telemetry-grid"><TelemetryMetric label="Database" value={formatBytes(telemetry.database_bytes)} /><TelemetryMetric label="Effective hosts" value={telemetry.effective_hosts.toLocaleString()} /><TelemetryMetric label="Host observations" value={telemetry.host_observations.toLocaleString()} /><TelemetryMetric label="Retained scans" value={telemetry.scans.toLocaleString()} /><TelemetryMetric label="Events" value={telemetry.events.toLocaleString()} /><TelemetryMetric label="Pending delivery" value={telemetry.outbox_pending.toLocaleString()} /></div><small className="muted telemetry-updated">Collected {new Date(telemetry.collected_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</small></div>}
    {canOperate && active.data?.scans.length ? <div className="panel active-scans-panel"><div className="panel-heading"><div><h2>Scans in progress</h2><p className="muted">Broad scans can take time; progress includes process liveness and Nmap timing updates.</p></div><Activity size={18} className="muted-icon" /></div><div className="active-scan-list">{active.data.scans.map(scan => <ActiveScanRow key={scan.id} scan={scan} cancelBusy={cancelBusy} onCancel={cancelActiveScan} />)}</div></div> : null}
    <div className="dashboard-columns"><div className="panel"><div className="panel-heading"><div><h2>Jobs at a glance</h2><p className="muted">{canOperate ? 'Run or inspect any saved job.' : 'Inspect saved jobs and their baselines.'}</p></div><button className="text-button" onClick={() => navigate('/jobs')}>View all →</button></div>{jobs.isLoading ? <div className="skeleton-list" /> : jobs.data?.jobs.length ? <div className="dashboard-jobs">{jobs.data.jobs.slice(0, 5).map(job => <div className="dashboard-job" key={job.id}><div className="job-icon"><Radar size={17} /></div><div className="dashboard-job-info"><strong>{job.job.name}</strong><span>{job.job.targets.length} targets · {job.job.schedule}</span></div><span className={job.baseline.status === 'complete' ? 'pill green' : 'pill amber'}>{job.baseline.status === 'complete' ? 'Ready' : 'Learning'}</span>{canOperate && <button aria-label={`Run ${job.job.name}`} className="icon-button" onClick={() => runConfiguredJob(job.id)} disabled={!!runningJob}>{runningJob === job.id ? <span className="spinner" /> : <Play size={15} />}</button>}</div>)}</div> : <div className="inline-empty">No jobs configured yet.</div>}</div>
      <div className="panel"><div className="panel-heading"><div><h2>Latest activity</h2><p className="muted">The most recent scan outcomes.</p></div><Clock3 size={18} className="muted-icon" /></div>{scans.isLoading ? <div className="skeleton-list" /> : scans.data?.scans.length ? <div className="activity-list">{scans.data.scans.slice(0, 6).map(scan => <div className="activity-row" key={scan.id}><span className={scan.status === 'success' ? 'activity-dot success' : scan.status === 'failed' ? 'activity-dot fail' : 'activity-dot'} /><div><strong>{scan.job}</strong><span>{scan.status === 'success' ? 'Completed successfully' : scan.error ?? scan.status}</span></div><time>{new Date(scan.finished_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</time></div>)}</div> : <div className="inline-empty">Your first scan will appear here.</div>}</div></div>
  </section>
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
  return <div className="active-scan-row"><div className="active-scan-meta"><strong>{scan.job}</strong><span>{scanner} · {phase}{protocol} · {completed} of {total} probes · elapsed {elapsed}{batch}{discovery}{liveness}</span>{cycle && <small className="active-scan-output">{cycle}{scan.current_unit_ports ? ` · current scope ${scan.current_unit_ports} across ${scan.current_unit_addresses ?? 0} host${scan.current_unit_addresses === 1 ? '' : 's'}` : ''}</small>}<progress max={100} value={scan.progress_percent ?? 0} aria-label={`Progress for ${scan.job}`} />{scan.process_alive && scan.process_progress_percent !== undefined ? <small className="active-scan-output">Current {scanner} process: {scan.process_progress_percent}%</small> : null}{scan.last_output ? <small className="active-scan-output" aria-live="polite">Latest scanner output: {scan.last_output}</small> : null}<details className="active-scan-details"><summary>Show scan details</summary><dl><div><dt>Scanner</dt><dd>{scanner}{scan.scanner_profile_revision ? ` · profile r${scan.scanner_profile_revision}` : ''}</dd></div><div><dt>Phase</dt><dd>{phase}{protocol}</dd></div><div><dt>Elapsed</dt><dd>{elapsed}</dd></div><div><dt>Progress</dt><dd>{completed} of {total} probes ({scan.progress_percent ?? 0}%)</dd></div>{scan.scanner === 'naabu_nmap' && <><div><dt>Discovery</dt><dd>{(scan.discovery_ports_found ?? 0).toLocaleString()} ports found across {(scan.discovery_addresses ?? 0).toLocaleString()} hosts{scan.discovery_duration_ms ? ` · ${formatDurationMS(scan.discovery_duration_ms)}` : ''}</dd></div><div><dt>Enrichment</dt><dd>{scan.enrichment_duration_ms ? formatDurationMS(scan.enrichment_duration_ms) : 'In progress'}</dd></div></>}{cycle && <div><dt>Resumable cycle</dt><dd>{cycle}</dd></div>}{scan.current_unit_ports ? <div><dt>Current work unit</dt><dd>{scan.current_unit_ports} · {scan.current_unit_addresses ?? 0} host{scan.current_unit_addresses === 1 ? '' : 's'}</dd></div> : null}{scan.current_invocation && scan.total_batches ? <div><dt>Batch</dt><dd>{scan.current_invocation} of {scan.total_batches}</dd></div> : null}<div><dt>Process</dt><dd>{scan.process_alive ? `${scanner} process active${scan.process_progress_percent !== undefined ? ` · ${scan.process_progress_percent}%` : ''}` : 'Waiting for process update'}</dd></div>{scan.last_output ? <div><dt>Latest output</dt><dd className="active-scan-detail-output" aria-live="polite">{scan.last_output}</dd></div> : null}</dl></details></div><button type="button" className="button danger" onClick={() => onCancel(scan.id)} disabled={cancelBusy === scan.id}>{cancelBusy === scan.id ? 'Cancelling…' : 'Cancel scan'}</button></div>
}

function Stat({ icon, label, value, detail, tone }: { icon: React.ReactNode; label: string; value: number; detail: string; tone: string }) { return <div className="stat-card"><div className={`stat-icon ${tone}`}>{icon}</div><div><span className="stat-label">{label}</span><strong className="stat-value">{value}</strong><span className="stat-detail">{detail}</span></div></div> }

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
