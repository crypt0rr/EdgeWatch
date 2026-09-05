import { StrictMode, useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClient, QueryClientProvider, useQuery, useQueryClient } from '@tanstack/react-query'
import { BrowserRouter, Link, Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom'
import { Activity, Bell, Boxes, ClipboardList, Gauge, LogOut, Menu, Server, ShieldCheck, Wifi } from 'lucide-react'
import { acceptIncident, getSession, listIncidents, listJobs, setCSRF, setupStatus, suppressIncident, logout as apiLogout } from './api'
import { Dashboard } from './pages/Dashboard'
import { JobEditor } from './pages/JobEditor'
import { JobDetail } from './pages/JobDetail'
import { Login, Setup } from './pages/Auth'
import { Security } from './pages/Security'
import { Notifications } from './pages/Notifications'
import { BaselineHosts } from './pages/BaselineHosts'
import { HostDetail } from './pages/HostDetail'
import { Hosts } from './pages/Hosts'
import { Pagination } from './components/Pagination'
import type { Incident } from './types'
import './tailwind.css'
import './styles.css'

const queryClient = new QueryClient({ defaultOptions: { queries: { staleTime: 5000, refetchOnWindowFocus: true } } })

function Shell({ username, version, onLogout }: { username: string; version: string; onLogout: () => void }) {
  const [open, setOpen] = useState(false)
  const [liveState, setLiveState] = useState<'connecting' | 'live' | 'reconnecting'>('connecting')
  const location = useLocation()
  const client = useQueryClient()
  const incidentSummary = useQuery({ queryKey: ['incidents', 'navigation'], queryFn: () => listIncidents(0, 1), refetchInterval: 15000 })
  const incidentCount = incidentSummary.data?.pagination.total ?? 0
  useEffect(() => {
    const stream = new EventSource('/api/v1/stream')
    stream.onopen = () => setLiveState('live')
    stream.onerror = () => setLiveState('reconnecting')
    stream.onmessage = (message) => {
      try {
        const event = JSON.parse(message.data) as { type?: string; job_id?: string }
        switch (event.type) {
          case 'scan.started':
          case 'scan.completed':
            void client.invalidateQueries({ queryKey: ['active-scans'] })
            void client.invalidateQueries({ queryKey: ['scans'] })
            void client.invalidateQueries({ queryKey: ['hosts'] })
            if (event.job_id) void client.invalidateQueries({ queryKey: ['job-scans', event.job_id] })
            break
          case 'changes-detected':
          case 'incident-opened':
          case 'incident-closed':
          case 'incident-accepted':
          case 'incident-suppressed':
            void client.invalidateQueries({ queryKey: ['incidents'] })
            if (event.job_id) void client.invalidateQueries({ queryKey: ['job', event.job_id] })
            if (event.type === 'incident-accepted') {
              void client.invalidateQueries({ queryKey: ['baseline-hosts', event.job_id] })
              void client.invalidateQueries({ queryKey: ['host-detail'] })
            }
            break
          case 'job.created':
          case 'job.updated':
          case 'job.archived':
          case 'job.restored':
          case 'job.deleted':
            void client.invalidateQueries({ queryKey: ['jobs'] })
            if (event.job_id) void client.invalidateQueries({ queryKey: ['job', event.job_id] })
            break
          case 'notification.changed':
            void client.invalidateQueries({ queryKey: ['notifications'] })
            void client.invalidateQueries({ queryKey: ['admin-status'] })
            break
          case 'refresh_required':
          default:
            // Unknown events and a replay gap deliberately trigger a full
            // refresh so a newly deployed server cannot leave stale UI state.
            void client.invalidateQueries()
        }
      } catch {
        void client.invalidateQueries()
      }
    }
    return () => stream.close()
  }, [client])
  const links = [
    { to: '/', label: 'Overview', icon: Gauge },
    { to: '/jobs', label: 'Jobs', icon: Boxes },
    { to: '/hosts', label: 'Hosts', icon: Server },
    { to: '/incidents', label: 'Incidents', icon: Activity },
    { to: '/notifications', label: 'Notifications', icon: Bell },
    { to: '/security', label: 'Security', icon: ShieldCheck },
  ]
  return <div className="app-shell">
    <aside className={open ? 'sidebar open' : 'sidebar'}>
      <div className="brand"><span className="brand-mark"><Wifi size={19} /></span><span>EdgeWatch</span></div>
      <nav>{links.map(({ to, label, icon: Icon }) => { const active = location.pathname === to || (to === '/jobs' && location.pathname.startsWith('/jobs')) || (to === '/hosts' && location.pathname.startsWith('/scans/')); const incidents = to === '/incidents'; const attention = incidents && incidentCount > 0; return <Link key={to} to={to} onClick={() => setOpen(false)} aria-label={incidents ? 'Incidents' : undefined} aria-describedby={attention ? 'active-incident-count' : undefined} className={`nav-link${active ? ' active' : ''}${attention ? ' nav-link-alert' : ''}`}><Icon size={18} /><span className="nav-link-label">{label}</span>{attention && <span id="active-incident-count" className="nav-count" aria-live="polite" aria-label={`${incidentCount} active incident${incidentCount === 1 ? '' : 's'}`}>{incidentCount > 99 ? '99+' : incidentCount}</span>}</Link> })}</nav>
      <div className="sidebar-bottom"><div className="user-chip"><span className="avatar">A</span><span><small className="app-version">EdgeWatch {version}</small><strong>{username}</strong><small>Administrator</small></span></div><button className="nav-link quiet" onClick={onLogout}><LogOut size={17} />Sign out</button></div>
    </aside>
    {open && <button aria-label="Close navigation" className="backdrop" onClick={() => setOpen(false)} />}
    <main className="main"><header className="topbar"><button aria-label="Open navigation" className="menu-button" onClick={() => setOpen(true)}><Menu size={21} /></button><div className="breadcrumb">{location.pathname === '/' ? 'Overview' : location.pathname.split('/').filter(Boolean).map(v => v[0].toUpperCase() + v.slice(1)).join(' / ')}</div><div className="topbar-actions"><span className="status-dot"><i /> {liveState === 'live' ? 'Live updates' : liveState === 'reconnecting' ? 'Reconnecting…' : 'Connecting…'}</span><Bell size={18} /></div></header><div className="content"><Routes><Route path="/" element={<Dashboard />} /><Route path="/jobs" element={<Jobs />} /><Route path="/jobs/new" element={<JobEditor />} /><Route path="/jobs/:id" element={<JobDetail />} /><Route path="/jobs/:id/edit" element={<JobEditor />} /><Route path="/jobs/:id/baseline" element={<BaselineHosts />} /><Route path="/jobs/:id/baseline/hosts/:address" element={<HostDetail />} /><Route path="/jobs/:id/scans/:scanId/hosts/:address" element={<HostDetail />} /><Route path="/hosts" element={<Hosts />} /><Route path="/scans/:scanId/hosts/:address" element={<HostDetail />} /><Route path="/incidents" element={<Incidents />} /><Route path="/notifications" element={<Notifications />} /><Route path="/security" element={<Security />} /><Route path="*" element={<Navigate to="/" replace />} /></Routes></div></main>
  </div>
}

function Jobs() {
  const navigate = useNavigate()
  const jobs = useQuery({ queryKey: ['jobs'], queryFn: () => listJobs(true) })
  return <section className="page"><div className="page-heading"><div><p className="eyebrow">Configuration</p><h1>Jobs</h1><p className="muted">Each job owns its targets, protocols, schedule, and baseline.</p></div><button className="button primary" onClick={() => navigate('/jobs/new')}>＋ New job</button></div>{jobs.isLoading ? <Loading /> : jobs.error ? <ErrorCard message={jobs.error.message} /> : <div className="job-grid">{jobs.data?.jobs.map(job => <Link className={job.archived ? 'job-card archived' : 'job-card'} to={`/jobs/${job.id}`} key={job.id}><div className="job-card-top"><span className={job.enabled && !job.archived ? 'pill green' : 'pill gray'}>{job.archived ? 'Archived' : job.enabled ? 'Scheduled' : 'Paused'}</span><span className="revision">r{job.revision}</span></div><h3>{job.job.name}</h3><p className="muted">{job.job.targets.length} target{job.job.targets.length === 1 ? '' : 's'} · {protocolSummary(job)}</p><div className="job-card-bottom"><span className={job.baseline.status === 'complete' ? 'baseline complete' : 'baseline'}>{job.baseline.status === 'complete' ? '● Baseline ready' : `◌ Collecting ${job.baseline.samples ?? 0}/${job.job.baseline_samples}`}</span><span>{job.job.schedule}</span></div></Link>)}{!jobs.data?.jobs.length && <Empty title="No jobs yet" body="Create your first TCP or UDP monitoring job." action={<button className="button primary" onClick={() => navigate('/jobs/new')}>Create a job</button>} />}</div>}</section>
}

function protocolSummary(job: { job: { tcp?: { ports: string }; udp?: { ports: string } } }) { return [job.job.tcp && `TCP ${job.job.tcp.ports}`, job.job.udp && `UDP ${job.job.udp.ports}`].filter(Boolean).join(' · ') }

function Incidents() {
  const [offset, setOffset] = useState(0)
  const [busy, setBusy] = useState('')
  const [actionError, setActionError] = useState('')
  const client = useQueryClient()
  const incidents = useQuery({ queryKey: ['incidents', offset], queryFn: () => listIncidents(offset) })
  async function act(row: Incident, action: 'accept' | 'suppress') {
    const key = row.incident.change.key
    if (!key) {
      setActionError('This legacy incident has no actionable key. Run a newer scan before changing it.')
      return
    }
    const message = action === 'accept'
      ? `Accept this change into the baseline for “${row.job}”? Future scans will treat it as expected.`
      : 'Suppress this incident for the next successful scan? If it is still present after that scan, it will be reported again.'
    if (!window.confirm(message)) return
    const actionID = `${action}:${row.job_id}:${key}`
    setBusy(actionID)
    setActionError('')
    try {
      if (action === 'accept') await acceptIncident(row.job_id, key)
      else await suppressIncident(row.job_id, key)
      await client.invalidateQueries({ queryKey: ['incidents'] })
      await client.invalidateQueries({ queryKey: ['job', row.job_id] })
      if (action === 'accept') {
        await client.invalidateQueries({ queryKey: ['baseline-hosts', row.job_id] })
        await client.invalidateQueries({ queryKey: ['host-detail'] })
      }
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'The incident action could not be completed.')
    } finally {
      setBusy('')
    }
  }
  return <section className="page"><div className="page-heading"><div><p className="eyebrow">Change tracking</p><h1>Incidents</h1><p className="muted">Confirmed changes detected against active baselines.</p></div></div>{actionError && <div className="form-error banner" role="alert">{actionError}</div>}{incidents.isLoading ? <Loading /> : incidents.data?.incidents.length ? <><div className="table-card"><table><thead><tr><th>Job</th><th>Target</th><th>Change</th><th>Severity</th><th>Last seen</th><th>Actions</th></tr></thead><tbody>{incidents.data.incidents.map((row, i) => { const key = row.incident.change.key; const acceptID = `accept:${row.job_id}:${key ?? i}`; const suppressID = `suppress:${row.job_id}:${key ?? i}`; return <tr key={`${row.job_id}-${key ?? i}`}><td><strong>{row.job}</strong></td><td>{row.incident.change.target}</td><td>{row.incident.change.kind}{row.incident.change.port ? ` / ${row.incident.change.protocol}:${row.incident.change.port}` : ''}</td><td><span className={`pill ${row.incident.change.severity === 'critical' ? 'red' : 'amber'}`}>{row.incident.change.severity}</span></td><td>{new Date(row.incident.last_seen_at).toLocaleString()}</td><td><div className="incident-actions"><button className="button secondary" type="button" onClick={() => void act(row, 'accept')} disabled={!key || !!busy}>{busy === acceptID ? 'Accepting…' : 'Accept change'}</button><button className="button ghost" type="button" onClick={() => void act(row, 'suppress')} disabled={!key || !!busy}>{busy === suppressID ? 'Suppressing…' : 'Suppress 1 scan'}</button></div></td></tr> })}</tbody></table></div><Pagination page={incidents.data.pagination} onChange={setOffset} /></> : <Empty icon={<ClipboardList />} title="No active incidents" body="EdgeWatch will show confirmed port, service, or DNS changes here." />}</section>
}

function ProtectedApp({ version, onLogout }: { version: string; onLogout: () => Promise<void> }) { const status = useQuery({ queryKey: ['setup-status'], queryFn: setupStatus }); const session = useQuery({ queryKey: ['session'], queryFn: async () => { const value = await getSession(); setCSRF(value.csrf_token); return value }, retry: false }); const navigate = useNavigate(); useEffect(() => { if (session.error && status.data?.configured) navigate('/login') }, [session.error, status.data, navigate]); if (status.isLoading || session.isLoading) return <Loading />; if (!status.data?.configured) return <Navigate to="/setup" replace />; if (session.error) return <Navigate to="/login" replace />; return <Shell username={session.data?.username ?? 'admin'} version={version} onLogout={onLogout} /> }

function AuthRoutes({ configured }: { configured: boolean }) { const location = useLocation(); return <Routes><Route path="/setup" element={<Setup />} /><Route path="/login" element={<Login />} /><Route path="*" element={configured ? <Navigate to="/login" replace state={{ from: { pathname: location.pathname, search: location.search } }} /> : <Navigate to="/setup" replace />} /></Routes> }

function App() { const [signedOut, setSignedOut] = useState(false); const status = useQuery({ queryKey: ['setup-status'], queryFn: setupStatus, retry: false }); const session = useQuery({ queryKey: ['session'], queryFn: async () => { const value = await getSession(); setCSRF(value.csrf_token); return value }, retry: false }); useEffect(() => { if (session.data) setSignedOut(false) }, [session.data]); const authenticated = !signedOut && !!session.data && !session.error; async function handleLogout() { try { await apiLogout() } catch { /* The server clears the cookie before reporting audit errors. */ } finally { setCSRF(''); queryClient.clear(); queryClient.setQueryData(['session'], null); setSignedOut(true) } } return <BrowserRouter>{status.isLoading || session.isLoading ? <Loading /> : status.error ? <ErrorCard message="Unable to contact EdgeWatch. Retry when the service is available." /> : status.data?.configured && authenticated ? <ProtectedApp version={status.data.version ?? 'dev'} onLogout={handleLogout} /> : <AuthGate statusConfigured={!!status.data?.configured} />}</BrowserRouter> }

function AuthGate({ statusConfigured }: { statusConfigured: boolean }) { return <AuthRoutes configured={statusConfigured} /> }

function Loading() { return <div className="loading"><span className="spinner" />Loading EdgeWatch…</div> }
function ErrorCard({ message }: { message: string }) { return <div className="error-card">{message}</div> }
function Empty({ icon, title, body, action }: { icon?: React.ReactNode; title: string; body: string; action?: React.ReactNode }) { return <div className="empty"><div className="empty-icon">{icon ?? <Boxes size={23} />}</div><h3>{title}</h3><p>{body}</p>{action}</div> }

createRoot(document.getElementById('root')!).render(<StrictMode><QueryClientProvider client={queryClient}><App /></QueryClientProvider></StrictMode>)
