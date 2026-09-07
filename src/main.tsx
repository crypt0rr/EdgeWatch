import { StrictMode, useEffect, useRef, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClient, QueryClientProvider, useQuery, useQueryClient } from '@tanstack/react-query'
import { BrowserRouter, Link, Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom'
import { Activity, Bell, Boxes, ClipboardList, Gauge, Globe2, LogOut, Menu, Server, ShieldCheck, UserRound, Wifi, X } from 'lucide-react'
import { acceptIncident, getSession, listIncidents, listJobs, setCSRF, setupStatus, suppressIncident, logout as apiLogout } from './api'
import { Dashboard } from './pages/Dashboard'
import { JobEditor } from './pages/JobEditor'
import { JobDetail } from './pages/JobDetail'
import { Activate, Login, Setup } from './pages/Auth'
import { Security } from './pages/Security'
import { Notifications } from './pages/Notifications'
import { BaselineHosts } from './pages/BaselineHosts'
import { HostDetail } from './pages/HostDetail'
import { Hosts } from './pages/Hosts'
import { Users } from './pages/Users'
import { PublicDashboard, PublicDashboardAdmin } from './pages/PublicDashboard'
import type { Role } from './api'
import { Pagination } from './components/Pagination'
import { ActionDialog } from './components/ActionDialog'
import { compactPortExpression } from './components/PortScopeDetails'
import type { Incident } from './types'
import './tailwind.css'
import './styles.css'

const queryClient = new QueryClient({ defaultOptions: { queries: { staleTime: 5000, refetchOnWindowFocus: true } } })
const navigationFocusableSelector = 'a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])'

function useIsMobile() {
  const [mobile, setMobile] = useState(() => typeof window !== 'undefined' && typeof window.matchMedia === 'function' && window.matchMedia('(max-width: 760px)').matches)
  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return
    const media = window.matchMedia('(max-width: 760px)')
    const update = () => setMobile(media.matches)
    update()
    if (media.addEventListener) media.addEventListener('change', update)
    else media.addListener?.(update)
    return () => {
      if (media.removeEventListener) media.removeEventListener('change', update)
      else media.removeListener?.(update)
    }
  }, [])
  return mobile
}

function Shell({ displayName, version, role, publicDashboardEnabled, onLogout }: { displayName: string; version: string; role: Role; publicDashboardEnabled: boolean; onLogout: () => void }) {
  const [open, setOpen] = useState(false)
  const [liveState, setLiveState] = useState<'connecting' | 'live' | 'reconnecting'>('connecting')
  const isMobile = useIsMobile()
  const menuButtonRef = useRef<HTMLButtonElement>(null)
  const drawerRef = useRef<HTMLElement>(null)
  const wasOpenRef = useRef(false)
  const location = useLocation()
  const client = useQueryClient()
  const incidentSummary = useQuery({ queryKey: ['incidents', 'navigation'], queryFn: () => listIncidents(0, 1), refetchInterval: 15000, enabled: role !== 'viewer' })
  const incidentCount = incidentSummary.data?.pagination.total ?? 0
  useEffect(() => {
    if (!isMobile && open) setOpen(false)
  }, [isMobile, open])
  useEffect(() => {
    if (!isMobile || !open) return
    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => { document.body.style.overflow = previousOverflow }
  }, [isMobile, open])
  useEffect(() => {
    if (!isMobile) {
      wasOpenRef.current = false
      return
    }
    if (open && !wasOpenRef.current) {
      const first = drawerRef.current?.querySelector<HTMLElement>(navigationFocusableSelector)
      first?.focus({ preventScroll: true })
    } else if (!open && wasOpenRef.current) {
      menuButtonRef.current?.focus({ preventScroll: true })
    }
    wasOpenRef.current = open
  }, [isMobile, open])
  useEffect(() => {
    if (!isMobile || !open) return
    const drawer = drawerRef.current
    function focusables() {
      return Array.from(drawer?.querySelectorAll<HTMLElement>(navigationFocusableSelector) ?? [])
    }
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        event.preventDefault()
        setOpen(false)
        return
      }
      if (event.key !== 'Tab') return
      const items = focusables()
      if (!items.length) {
        event.preventDefault()
        return
      }
      const first = items[0]
      const last = items[items.length - 1]
      const active = document.activeElement
      if (event.shiftKey && (active === first || !drawer?.contains(active))) {
        event.preventDefault()
        last.focus()
      } else if (!event.shiftKey && (active === last || !drawer?.contains(active))) {
        event.preventDefault()
        first.focus()
      }
    }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [isMobile, open])
  useEffect(() => {
    if (role === 'viewer') return
    const stream = new EventSource('/api/v1/stream')
    stream.onopen = () => setLiveState('live')
    stream.onerror = () => setLiveState('reconnecting')
    stream.onmessage = (message) => {
      try {
        const event = JSON.parse(message.data) as { type?: string; job_id?: string }
        switch (event.type) {
          case 'scan.started':
          case 'scan.completed':
          case 'scan-paused':
          case 'scan-recovered':
          case 'scan-failure':
          case 'scan-canceled':
            void client.invalidateQueries({ queryKey: ['active-scans'] })
            void client.invalidateQueries({ queryKey: ['scans'] })
            void client.invalidateQueries({ queryKey: ['hosts'] })
            if (event.job_id) {
              void client.invalidateQueries({ queryKey: ['job-scans', event.job_id] })
              void client.invalidateQueries({ queryKey: ['scan-cycle', event.job_id] })
              void client.invalidateQueries({ queryKey: ['job', event.job_id] })
            }
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
  }, [client, role])
  const links = [
    { to: '/', label: 'Overview', icon: Gauge },
    ...(role === 'viewer' && publicDashboardEnabled ? [{ to: '/highlights', label: 'Highlights', icon: Globe2 }] : []),
    { to: '/jobs', label: 'Jobs', icon: Boxes },
    ...(role !== 'viewer' ? [{ to: '/hosts', label: 'Hosts', icon: Server }] : []),
    ...(role !== 'viewer' ? [{ to: '/incidents', label: 'Incidents', icon: Activity }] : []),
    ...(role === 'administrator' ? [{ to: '/notifications', label: 'Notifications', icon: Bell }, { to: '/users', label: 'Users', icon: UserRound }, { to: '/public-dashboard', label: 'Public status', icon: Globe2 }] : []),
    { to: '/security', label: 'Security', icon: ShieldCheck },
  ]
  const breadcrumb = location.pathname === '/' ? 'Overview' : location.pathname.split('/').filter(Boolean).map(v => v[0].toUpperCase() + v.slice(1)).join(' / ')
  return <div className="app-shell">
    <aside id="primary-navigation" ref={drawerRef} role={isMobile && open ? 'dialog' : undefined} aria-label="Primary navigation" aria-modal={isMobile && open ? true : undefined} aria-hidden={isMobile ? !open : undefined} inert={isMobile ? !open : undefined} className={open ? 'sidebar open' : 'sidebar'}>
      <div className="brand"><span className="brand-mark"><Wifi size={19} /></span><span>EdgeWatch</span><button type="button" className="drawer-close" aria-label="Close navigation" onClick={() => setOpen(false)}><X size={19} /></button></div>
      <nav>{links.map(({ to, label, icon: Icon }) => { const active = location.pathname === to || (to === '/jobs' && location.pathname.startsWith('/jobs')) || (to === '/hosts' && location.pathname.startsWith('/scans/')); const incidents = to === '/incidents'; const attention = incidents && incidentCount > 0; return <Link key={to} to={to} onClick={() => setOpen(false)} aria-label={incidents ? 'Incidents' : undefined} aria-describedby={attention ? 'active-incident-count' : undefined} className={`nav-link${active ? ' active' : ''}${attention ? ' nav-link-alert' : ''}`}><Icon size={18} /><span className="nav-link-label">{label}</span>{attention && <span id="active-incident-count" className="nav-count" aria-live="polite" aria-label={`${incidentCount} active incident${incidentCount === 1 ? '' : 's'}`}>{incidentCount > 99 ? '99+' : incidentCount}</span>}</Link> })}</nav>
      <div className="sidebar-bottom"><div className="user-chip"><span className="avatar">{displayName.trim().charAt(0).toUpperCase() || 'A'}</span><span><small className="app-version">EdgeWatch {version}</small><strong>{displayName}</strong><small>{role === 'administrator' ? 'Administrator' : role === 'operator' ? 'Operator' : 'Viewer · read only'}</small></span></div><button className="nav-link quiet" onClick={onLogout}><LogOut size={17} />Sign out</button></div>
    </aside>
    {open && isMobile && <button type="button" aria-label="Close navigation" tabIndex={-1} className="backdrop" onClick={() => setOpen(false)} />}
    <main className="main" inert={isMobile && open ? true : undefined} aria-hidden={isMobile && open ? true : undefined}><header className="topbar"><button ref={menuButtonRef} type="button" aria-label={open ? 'Close navigation' : 'Open navigation'} aria-controls="primary-navigation" aria-expanded={isMobile ? open : false} className="menu-button" onClick={() => setOpen(true)}><Menu size={21} /></button><nav className="breadcrumb" title={breadcrumb} aria-label={`Breadcrumb: ${breadcrumb}`}>{breadcrumb}</nav><div className="topbar-actions"><span className="status-dot"><i /> {liveState === 'live' ? 'Live updates' : liveState === 'reconnecting' ? 'Reconnecting…' : 'Connecting…'}</span><Bell size={18} /></div></header><div className="content"><Routes><Route path="/" element={role === 'viewer' && publicDashboardEnabled ? <Navigate to="/highlights" replace /> : <Dashboard />} /><Route path="/highlights" element={<PublicDashboard />} /><Route path="/jobs" element={<Jobs />} /><Route path="/jobs/new" element={<JobEditor />} /><Route path="/jobs/:id" element={<JobDetail />} /><Route path="/jobs/:id/edit" element={<JobEditor />} /><Route path="/jobs/:id/baseline" element={<BaselineHosts />} /><Route path="/jobs/:id/baseline/hosts/:address" element={<HostDetail />} /><Route path="/jobs/:id/scans/:scanId/hosts/:address" element={<HostDetail />} /><Route path="/hosts" element={<Hosts />} /><Route path="/scans/:scanId/hosts/:address" element={<HostDetail />} /><Route path="/incidents" element={<Incidents />} /><Route path="/notifications" element={<Notifications />} /><Route path="/users" element={<Users />} /><Route path="/public-dashboard" element={<PublicDashboardAdmin />} /><Route path="/security" element={<Security />} /><Route path="*" element={<Navigate to="/" replace />} /></Routes></div></main>
  </div>
}

function Jobs() {
  const navigate = useNavigate()
  const jobs = useQuery({ queryKey: ['jobs'], queryFn: () => listJobs(true) })
  const session = useQuery({ queryKey: ['session'], queryFn: getSession })
  const canWrite = session.data?.role !== 'viewer'
  return <section className="page"><div className="page-heading"><div><p className="eyebrow">Configuration</p><h1>Jobs</h1><p className="muted">Each job owns its targets, protocols, schedule, and baseline.</p></div>{canWrite && <button className="button primary" onClick={() => navigate('/jobs/new')}>＋ New job</button>}</div>{jobs.isLoading ? <Loading /> : jobs.error ? <ErrorCard message={jobs.error.message} /> : <div className="job-grid">{jobs.data?.jobs.map(job => <Link className={job.archived ? 'job-card archived' : 'job-card'} to={`/jobs/${job.id}`} key={job.id}><div className="job-card-top"><span className={job.enabled && !job.archived ? 'pill green' : 'pill gray'}>{job.archived ? 'Archived' : job.enabled ? 'Scheduled' : 'Paused'}</span><span className="revision">r{job.revision}</span></div><h3>{job.job.name}</h3><p className="muted">{job.job.targets.length} target{job.job.targets.length === 1 ? '' : 's'} · {protocolSummary(job)}</p><div className="job-card-bottom"><span className={job.baseline.status === 'complete' ? 'baseline complete' : 'baseline'}>{job.baseline.status === 'complete' ? '● Baseline ready' : `◌ Collecting ${job.baseline.samples ?? 0}/${job.job.baseline_samples}`}</span><span>{job.job.schedule}</span></div></Link>)}{!jobs.data?.jobs.length && canWrite && <Empty title="No jobs yet" body="Create your first TCP or UDP monitoring job." action={<button className="button primary" onClick={() => navigate('/jobs/new')}>Create a job</button>} />}{!jobs.data?.jobs.length && !canWrite && <Empty title="No jobs configured" body="An operator can create a monitoring job for this EdgeWatch instance." />}</div>}</section>
}

function protocolSummary(job: { job: { tcp?: { ports: string }; udp?: { ports: string } } }) {
  return [
    job.job.tcp && `TCP · ${compactPortExpression(job.job.tcp.ports)}`,
    job.job.udp && `UDP · ${compactPortExpression(job.job.udp.ports)}`,
  ].filter(Boolean).join(' · ')
}

function Incidents() {
  const [offset, setOffset] = useState(0)
  const [busy, setBusy] = useState('')
  const [actionError, setActionError] = useState('')
  const [pendingAction, setPendingAction] = useState<{ row: Incident; action: 'accept' | 'suppress' } | null>(null)
  const client = useQueryClient()
  const incidents = useQuery({ queryKey: ['incidents', offset], queryFn: () => listIncidents(offset) })
  async function act(row: Incident, action: 'accept' | 'suppress') {
    const key = row.incident.change.key
    if (!key) {
      setActionError('This legacy incident has no actionable key. Run a newer scan before changing it.')
      return
    }
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
      setPendingAction(null)
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'The incident action could not be completed.')
    } finally {
      setBusy('')
    }
  }
  const actionFor = (row: Incident, action: 'accept' | 'suppress') => {
    setActionError('')
    setPendingAction({ row, action })
  }
  return <section className="page"><div className="page-heading"><div><p className="eyebrow">Change tracking</p><h1>Incidents</h1><p className="muted">Confirmed changes detected against active baselines.</p></div></div>{actionError && <div className="form-error banner" role="alert">{actionError}</div>}{incidents.isLoading ? <Loading /> : incidents.data?.incidents.length ? <><div className="table-card incident-table-card"><div className="desktop-incident-table"><table><thead><tr><th scope="col">Job</th><th scope="col">Target</th><th scope="col">Change</th><th scope="col">Severity</th><th scope="col">Last seen</th><th scope="col">Actions</th></tr></thead><tbody>{incidents.data.incidents.map((row, i) => <IncidentTableRow key={`${row.job_id}-${row.incident.change.key ?? i}`} row={row} busy={busy} onAction={actionFor} />)}</tbody></table></div><div className="mobile-incident-list" aria-label="Incidents">{incidents.data.incidents.map((row, i) => <IncidentCard key={`${row.job_id}-${row.incident.change.key ?? i}`} row={row} busy={busy} onAction={actionFor} />)}</div></div><Pagination page={incidents.data.pagination} onChange={setOffset} /></> : <Empty icon={<ClipboardList />} title="No active incidents" body="EdgeWatch will show confirmed port, service, or DNS changes here." />}{pendingAction && <ActionDialog title={pendingAction.action === 'accept' ? 'Accept this change?' : 'Suppress this incident for one scan?'} description={pendingAction.action === 'accept' ? `Accept this change into the baseline for “${pendingAction.row.job}”? Future scans will treat it as expected.` : 'The incident will be suppressed for the next successful scan. If it is still present after that scan, it will be reported again.'} confirmLabel={pendingAction.action === 'accept' ? 'Accept change' : 'Suppress 1 scan'} destructive={pendingAction.action === 'suppress'} onConfirm={() => act(pendingAction.row, pendingAction.action)} onCancel={() => { setPendingAction(null); setActionError('') }} error={actionError} />}</section>
}

function IncidentTableRow({ row, busy, onAction }: { row: Incident; busy: string; onAction: (row: Incident, action: 'accept' | 'suppress') => void }) {
  const key = row.incident.change.key
  const acceptID = `accept:${row.job_id}:${key ?? ''}`
  const suppressID = `suppress:${row.job_id}:${key ?? ''}`
  return <tr><td><strong>{row.job}</strong></td><td>{row.incident.change.target}</td><td>{row.incident.change.kind}{row.incident.change.port ? ` / ${row.incident.change.protocol}:${row.incident.change.port}` : ''}</td><td><span className={`pill ${row.incident.change.severity === 'critical' ? 'red' : 'amber'}`}>{row.incident.change.severity}</span></td><td>{new Date(row.incident.last_seen_at).toLocaleString()}</td><td><IncidentActions row={row} busy={busy} acceptID={acceptID} suppressID={suppressID} onAction={onAction} /></td></tr>
}

function IncidentCard({ row, busy, onAction }: { row: Incident; busy: string; onAction: (row: Incident, action: 'accept' | 'suppress') => void }) {
  const key = row.incident.change.key
  const acceptID = `accept:${row.job_id}:${key ?? ''}`
  const suppressID = `suppress:${row.job_id}:${key ?? ''}`
  return <article className="incident-card" aria-label={`Incident for ${row.job}`}><div className="incident-card-heading"><strong>{row.job}</strong><span className={`pill ${row.incident.change.severity === 'critical' ? 'red' : 'amber'}`}>{row.incident.change.severity}</span></div><dl className="incident-facts"><div><dt>Target</dt><dd>{row.incident.change.target}</dd></div><div><dt>Change</dt><dd>{row.incident.change.kind}{row.incident.change.port ? ` / ${row.incident.change.protocol}:${row.incident.change.port}` : ''}</dd></div><div><dt>Last seen</dt><dd>{new Date(row.incident.last_seen_at).toLocaleString()}</dd></div></dl><IncidentActions row={row} busy={busy} acceptID={acceptID} suppressID={suppressID} onAction={onAction} /></article>
}

function IncidentActions({ row, busy, acceptID, suppressID, onAction }: { row: Incident; busy: string; acceptID: string; suppressID: string; onAction: (row: Incident, action: 'accept' | 'suppress') => void }) {
  const key = row.incident.change.key
  return <div className="incident-actions"><button className="button secondary" type="button" onClick={() => onAction(row, 'accept')} disabled={!key || !!busy}>{busy === acceptID ? 'Accepting…' : 'Accept change'}</button><button className="button ghost" type="button" onClick={() => onAction(row, 'suppress')} disabled={!key || !!busy}>{busy === suppressID ? 'Suppressing…' : 'Suppress 1 scan'}</button></div>
}

function ProtectedApp({ version, onLogout }: { version: string; onLogout: () => Promise<void> }) { const status = useQuery({ queryKey: ['setup-status'], queryFn: setupStatus }); const session = useQuery({ queryKey: ['session'], queryFn: async () => { const value = await getSession(); setCSRF(value.csrf_token); return value }, retry: false }); const navigate = useNavigate(); useEffect(() => { if (session.error && status.data?.configured) navigate('/login') }, [session.error, status.data, navigate]); if (status.isLoading || session.isLoading) return <Loading />; if (!status.data?.configured) return <Navigate to="/setup" replace />; if (session.error) return <Navigate to="/login" replace />; return <Shell displayName={session.data?.display_name ?? session.data?.username ?? 'admin'} role={session.data?.role ?? 'administrator'} publicDashboardEnabled={!!status.data.public_dashboard_enabled} version={version} onLogout={onLogout} /> }

function AuthRoutes({ configured }: { configured: boolean }) { const location = useLocation(); return <Routes><Route path="/setup" element={<Setup />} /><Route path="/activate" element={<Activate />} /><Route path="/login" element={<Login />} /><Route path="*" element={configured ? <Navigate to="/login" replace state={{ from: { pathname: location.pathname, search: location.search } }} /> : <Navigate to="/setup" replace />} /></Routes> }

function App() { return <BrowserRouter><AppContent /></BrowserRouter> }

function AppContent() {
  const location = useLocation()
  const isPublic = location.pathname === '/public' || location.pathname === '/public/'
  const [signedOut, setSignedOut] = useState(false)
  // The public highlights page is deliberately independent of setup/session
  // state. This avoids an unnecessary authenticated request and keeps the
  // unauthenticated route usable while the administrator is signed out.
  const status = useQuery({ queryKey: ['setup-status'], queryFn: setupStatus, retry: false, enabled: !isPublic })
  const session = useQuery({ queryKey: ['session'], queryFn: async () => { const value = await getSession(); setCSRF(value.csrf_token); return value }, retry: false, enabled: !isPublic })
  useEffect(() => { if (session.data) setSignedOut(false) }, [session.data])
  const authenticated = !signedOut && !!session.data && !session.error
  async function handleLogout() {
    try { await apiLogout() } catch { /* The server clears the cookie before reporting audit errors. */ }
    finally { setCSRF(''); queryClient.clear(); queryClient.setQueryData(['session'], null); setSignedOut(true) }
  }
  if (isPublic) return <PublicDashboard />
  if (status.isLoading || session.isLoading) return <Loading />
  if (status.error) return <ErrorCard message="Unable to contact EdgeWatch. Retry when the service is available." />
  return status.data?.configured && authenticated ? <ProtectedApp version={status.data.version ?? 'dev'} onLogout={handleLogout} /> : <AuthGate statusConfigured={!!status.data?.configured} />
}

function AuthGate({ statusConfigured }: { statusConfigured: boolean }) { return <AuthRoutes configured={statusConfigured} /> }

function Loading() { return <div className="loading"><span className="spinner" />Loading EdgeWatch…</div> }
function ErrorCard({ message }: { message: string }) { return <div className="error-card">{message}</div> }
function Empty({ icon, title, body, action }: { icon?: React.ReactNode; title: string; body: string; action?: React.ReactNode }) { return <div className="empty"><div className="empty-icon">{icon ?? <Boxes size={23} />}</div><h3>{title}</h3><p>{body}</p>{action}</div> }

createRoot(document.getElementById('root')!).render(<StrictMode><QueryClientProvider client={queryClient}><App /></QueryClientProvider></StrictMode>)
