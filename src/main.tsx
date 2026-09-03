import { StrictMode, useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClient, QueryClientProvider, useQuery, useQueryClient } from '@tanstack/react-query'
import { BrowserRouter, Link, Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom'
import { Activity, Bell, Boxes, ClipboardList, Gauge, LogOut, Menu, ShieldCheck, Wifi } from 'lucide-react'
import { getSession, listIncidents, listJobs, setCSRF, setupStatus, logout as apiLogout } from './api'
import { Dashboard } from './pages/Dashboard'
import { JobEditor } from './pages/JobEditor'
import { JobDetail } from './pages/JobDetail'
import { Login, Setup } from './pages/Auth'
import { Security } from './pages/Security'
import { Pagination } from './components/Pagination'
import './tailwind.css'
import './styles.css'

const queryClient = new QueryClient({ defaultOptions: { queries: { staleTime: 5000, refetchOnWindowFocus: true } } })

function Shell({ username, onLogout }: { username: string; onLogout: () => void }) {
  const [open, setOpen] = useState(false)
  const location = useLocation()
  const client = useQueryClient()
  useEffect(() => {
    const stream = new EventSource('/api/v1/stream')
    stream.onmessage = () => { void client.invalidateQueries() }
    return () => stream.close()
  }, [client])
  const links = [
    { to: '/', label: 'Overview', icon: Gauge },
    { to: '/jobs', label: 'Jobs', icon: Boxes },
    { to: '/incidents', label: 'Incidents', icon: Activity },
    { to: '/security', label: 'Security', icon: ShieldCheck },
  ]
  return <div className="app-shell">
    <aside className={open ? 'sidebar open' : 'sidebar'}>
      <div className="brand"><span className="brand-mark"><Wifi size={19} /></span><span>EdgeWatch</span></div>
      <nav>{links.map(({ to, label, icon: Icon }) => <Link key={to} to={to} onClick={() => setOpen(false)} className={location.pathname === to || (to === '/jobs' && location.pathname.startsWith('/jobs')) ? 'nav-link active' : 'nav-link'}><Icon size={18} />{label}</Link>)}</nav>
      <div className="sidebar-bottom"><div className="user-chip"><span className="avatar">A</span><span><strong>{username}</strong><small>Administrator</small></span></div><button className="nav-link quiet" onClick={onLogout}><LogOut size={17} />Sign out</button></div>
    </aside>
    {open && <button aria-label="Close navigation" className="backdrop" onClick={() => setOpen(false)} />}
    <main className="main"><header className="topbar"><button aria-label="Open navigation" className="menu-button" onClick={() => setOpen(true)}><Menu size={21} /></button><div className="breadcrumb">{location.pathname === '/' ? 'Overview' : location.pathname.split('/').filter(Boolean).map(v => v[0].toUpperCase() + v.slice(1)).join(' / ')}</div><div className="topbar-actions"><span className="status-dot"><i /> Engine online</span><Bell size={18} /></div></header><div className="content"><Routes><Route path="/" element={<Dashboard />} /><Route path="/jobs" element={<Jobs />} /><Route path="/jobs/new" element={<JobEditor />} /><Route path="/jobs/:id" element={<JobDetail />} /><Route path="/jobs/:id/edit" element={<JobEditor />} /><Route path="/incidents" element={<Incidents />} /><Route path="/security" element={<Security />} /><Route path="*" element={<Navigate to="/" replace />} /></Routes></div></main>
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
  const incidents = useQuery({ queryKey: ['incidents', offset], queryFn: () => listIncidents(offset) })
  return <section className="page"><div className="page-heading"><div><p className="eyebrow">Change tracking</p><h1>Incidents</h1><p className="muted">Confirmed changes detected against active baselines.</p></div></div>{incidents.isLoading ? <Loading /> : incidents.data?.incidents.length ? <><div className="table-card"><table><thead><tr><th>Job</th><th>Target</th><th>Change</th><th>Severity</th><th>Last seen</th></tr></thead><tbody>{incidents.data.incidents.map((row, i) => <tr key={`${row.job_id}-${row.incident.change.key ?? i}`}><td><strong>{row.job}</strong></td><td>{row.incident.change.target}</td><td>{row.incident.change.kind}{row.incident.change.port ? ` / ${row.incident.change.protocol}:${row.incident.change.port}` : ''}</td><td><span className={`pill ${row.incident.change.severity === 'critical' ? 'red' : 'amber'}`}>{row.incident.change.severity}</span></td><td>{new Date(row.incident.last_seen_at).toLocaleString()}</td></tr>)}</tbody></table></div><Pagination page={incidents.data.pagination} onChange={setOffset} /></> : <Empty icon={<ClipboardList />} title="No active incidents" body="EdgeWatch will show confirmed port, service, or DNS changes here." />}</section>
}

function ProtectedApp() { const status = useQuery({ queryKey: ['setup-status'], queryFn: setupStatus }); const session = useQuery({ queryKey: ['session'], queryFn: async () => { const value = await getSession(); setCSRF(value.csrf_token); return value }, retry: false }); const navigate = useNavigate(); useEffect(() => { if (session.error && status.data?.configured) navigate('/login') }, [session.error, status.data, navigate]); if (status.isLoading || session.isLoading) return <Loading />; if (!status.data?.configured) return <Navigate to="/setup" replace />; if (session.error) return <Navigate to="/login" replace />; return <Shell username={session.data?.username ?? 'admin'} onLogout={async () => { await apiLogout(); setCSRF(''); queryClient.clear(); navigate('/login') }} /> }

function AuthRoutes() { const status = useQuery({ queryKey: ['setup-status'], queryFn: setupStatus }); return <Routes><Route path="/setup" element={<Setup />} /><Route path="/login" element={<Login />} /><Route path="*" element={status.data?.configured ? <Navigate to="/login" replace /> : <Navigate to="/setup" replace />} /></Routes> }

function App() { const status = useQuery({ queryKey: ['setup-status'], queryFn: setupStatus }); const session = useQuery({ queryKey: ['session'], queryFn: async () => { const value = await getSession(); setCSRF(value.csrf_token); return value }, retry: false }); const authenticated = !!session.data && !session.error; return <BrowserRouter>{status.data?.configured && authenticated ? <ProtectedApp /> : <AuthGate statusConfigured={!!status.data?.configured} authenticated={authenticated} />}</BrowserRouter> }

function AuthGate({ statusConfigured, authenticated }: { statusConfigured: boolean; authenticated: boolean }) { if (authenticated) return <ProtectedApp />; return statusConfigured ? <AuthRoutes /> : <AuthRoutes /> }

function Loading() { return <div className="loading"><span className="spinner" />Loading EdgeWatch…</div> }
function ErrorCard({ message }: { message: string }) { return <div className="error-card">{message}</div> }
function Empty({ icon, title, body, action }: { icon?: React.ReactNode; title: string; body: string; action?: React.ReactNode }) { return <div className="empty"><div className="empty-icon">{icon ?? <Boxes size={23} />}</div><h3>{title}</h3><p>{body}</p>{action}</div> }

createRoot(document.getElementById('root')!).render(<StrictMode><QueryClientProvider client={queryClient}><App /></QueryClientProvider></StrictMode>)
