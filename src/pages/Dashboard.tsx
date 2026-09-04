import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { Activity, AlertTriangle, Bell, CheckCircle2, Clock3, Play, Radar } from 'lucide-react'
import { activeScans, adminStatus, listIncidents, listJobs, listScans, notificationTest, runJob } from '../api'
import { useNavigate } from 'react-router-dom'

export function Dashboard() {
  const navigate = useNavigate()
  const [notifyState, setNotifyState] = useState<{ text: string; error: boolean } | null>(null)
  const [runError, setRunError] = useState('')
  const [runningJob, setRunningJob] = useState('')
  const jobs = useQuery({ queryKey: ['jobs'], queryFn: () => listJobs(false) })
  const scans = useQuery({ queryKey: ['scans'], queryFn: () => listScans(0, 20), refetchInterval: 15000 })
  const active = useQuery({ queryKey: ['active-scans'], queryFn: activeScans, refetchInterval: 2000 })
  const incidents = useQuery({ queryKey: ['incidents'], queryFn: () => listIncidents(0, 20), refetchInterval: 15000 })
  const setup = useQuery({ queryKey: ['admin-status'], queryFn: adminStatus })
  const running = active.data?.scans.length ?? 0
  const incidentTotal = incidents.data?.pagination.total ?? 0
  const scanTotal = scans.data?.pagination.total ?? 0
  const ready = jobs.data?.jobs.filter(j => j.baseline.status === 'complete').length ?? 0
  const activeJobs = jobs.data?.jobs.filter(j => j.enabled && !j.archived).length ?? 0
  const notificationCount = setup.data?.notification_destinations ?? 0
  const policy = setup.data?.retention ? `Retention ${setup.data.retention} · ${setup.data.max_concurrent_scans ?? 1} scan${setup.data.max_concurrent_scans === 1 ? '' : 's'} at a time.` : ''
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
  return <section className="page"><div className="page-heading"><div><p className="eyebrow">Monitoring console</p><h1>Good afternoon, admin</h1><p className="muted">A calm view of your network’s expected surface. {notificationCount ? `${notificationCount} notification destination${notificationCount === 1 ? '' : 's'} configured.` : 'Notifications are not configured.'} {policy}</p></div><div className="heading-actions"><button className="button secondary" onClick={async () => { try { const value = await notificationTest(); setNotifyState({ text: `${value.sent} destination${value.sent === 1 ? '' : 's'} tested`, error: false }) } catch (err) { setNotifyState({ text: err instanceof Error ? err.message : 'Notification test failed', error: true }) } }}><Bell size={16} /> Test notifications</button><button className="button secondary" onClick={() => navigate('/jobs/new')}><Radar size={16} /> Configure job</button></div></div>{notifyState && <div className={notifyState.error ? 'form-error' : 'success-banner'} role={notifyState.error ? 'alert' : 'status'}>{notifyState.error ? <AlertTriangle size={16} /> : <CheckCircle2 size={16} />}{notifyState.text}</div>}{runError && <div className="form-error banner" role="alert"><AlertTriangle size={16} />{runError}</div>}{setup.data?.legacy_yaml_jobs?.length ? <div className="legacy-banner"><AlertTriangle size={17} /><span><strong>Legacy YAML jobs are inactive.</strong> Recreate {setup.data.legacy_yaml_jobs.join(', ')} in the console to resume scheduling.</span><button className="icon-button" onClick={() => setup.refetch()} aria-label="Refresh status">×</button></div> : null}
    <div className="stat-grid"><Stat icon={<Radar />} label="Active jobs" value={activeJobs} detail={`${ready} baselines ready`} tone="blue" /><Stat icon={<CheckCircle2 />} label="Healthy baselines" value={ready} detail="Stable monitoring scopes" tone="green" /><Stat icon={<AlertTriangle />} label="Open incidents" value={incidentTotal} detail="Confirmed changes" tone="amber" /><Stat icon={<Activity />} label="Recent scans" value={scanTotal} detail={running ? `${running} in progress` : 'No scans running'} tone="purple" /></div>
    <div className="dashboard-columns"><div className="panel"><div className="panel-heading"><div><h2>Jobs at a glance</h2><p className="muted">Run or inspect any saved job.</p></div><button className="text-button" onClick={() => navigate('/jobs')}>View all →</button></div>{jobs.isLoading ? <div className="skeleton-list" /> : jobs.data?.jobs.length ? <div className="dashboard-jobs">{jobs.data.jobs.slice(0, 5).map(job => <div className="dashboard-job" key={job.id}><div className="job-icon"><Radar size={17} /></div><div className="dashboard-job-info"><strong>{job.job.name}</strong><span>{job.job.targets.length} targets · {job.job.schedule}</span></div><span className={job.baseline.status === 'complete' ? 'pill green' : 'pill amber'}>{job.baseline.status === 'complete' ? 'Ready' : 'Learning'}</span><button aria-label={`Run ${job.job.name}`} className="icon-button" onClick={() => runConfiguredJob(job.id)} disabled={!!runningJob}>{runningJob === job.id ? <span className="spinner" /> : <Play size={15} />}</button></div>)}</div> : <div className="inline-empty">No jobs configured yet. <button className="text-button" onClick={() => navigate('/jobs/new')}>Create one</button></div>}</div>
      <div className="panel"><div className="panel-heading"><div><h2>Latest activity</h2><p className="muted">The most recent scan outcomes.</p></div><Clock3 size={18} className="muted-icon" /></div>{scans.isLoading ? <div className="skeleton-list" /> : scans.data?.scans.length ? <div className="activity-list">{scans.data.scans.slice(0, 6).map(scan => <div className="activity-row" key={scan.id}><span className={scan.status === 'success' ? 'activity-dot success' : scan.status === 'failed' ? 'activity-dot fail' : 'activity-dot'} /><div><strong>{scan.job}</strong><span>{scan.status === 'success' ? 'Completed successfully' : scan.error ?? scan.status}</span></div><time>{new Date(scan.finished_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</time></div>)}</div> : <div className="inline-empty">Your first scan will appear here.</div>}</div></div>
  </section>
}

function Stat({ icon, label, value, detail, tone }: { icon: React.ReactNode; label: string; value: number; detail: string; tone: string }) { return <div className="stat-card"><div className={`stat-icon ${tone}`}>{icon}</div><div><span className="stat-label">{label}</span><strong className="stat-value">{value}</strong><span className="stat-detail">{detail}</span></div></div> }
