import { StrictMode, useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClient, QueryClientProvider, useQuery, useQueryClient } from '@tanstack/react-query'
import { BrowserRouter, Link, Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom'
import { Activity, ArrowUp, Bell, Boxes, Building2, ClipboardList, Code2, Gauge, Globe2, LogOut, Menu, ScrollText, Server, ShieldCheck, UserRound, Wifi, X } from 'lucide-react'
import { acceptIncident, adminStatus, APIError, getSession, listIncidents, listJobs, setCSRF, setupStatus, suppressIncident, logout as apiLogout } from './api'
import type { UnitRef } from './api'
import { useActivityHeartbeat, useNavigationDrawer } from './components/navigation'
import { Audit } from './pages/Audit'
import { PlatformShell } from './pages/platform/PlatformShell'
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
import { ScannerProfiles } from './pages/ScannerProfiles'
import { ScanDetail } from './pages/ScanDetail'
import type { Role } from './api'
import { Pagination } from './components/Pagination'
import { ActionDialog } from './components/ActionDialog'
import { compactPortExpression } from './components/PortScopeDetails'
import type { Incident } from './types'
import { baselinePresentation } from './baseline'
import { formatDateTime } from './format'
import './tailwind.css'
import './styles.css'

/** The console's query defaults, shared by the browser bootstrap and tests. */
export function createQueryClient() {
  return new QueryClient({ defaultOptions: { queries: { staleTime: 5000, refetchOnWindowFocus: true } } })
}
const queryClient = createQueryClient()

/**
 * The application shell is exported so it can be exercised with a jsdom
 * router/query harness.  Keeping the browser bootstrap below this component
 * makes the entrypoint side-effect free in tests while preserving the single
 * embedded SPA bundle in production.
 */
export function Shell({ displayName, role, permissions, onLogout, unit }: { displayName: string; role: Role; permissions: string[]; onLogout: () => void; unit?: UnitRef | null }) {
  const [liveState, setLiveState] = useState<'connecting' | 'live' | 'reconnecting'>('connecting')
  const { open, setOpen, isMobile, menuButtonRef, drawerRef } = useNavigationDrawer()
  useActivityHeartbeat()
  const location = useLocation()
  const client = useQueryClient()
  const hasPermission = (permission: string) => permissions.includes(permission)
  const updateStatus = useQuery({ queryKey: ['admin-status'], queryFn: adminStatus, refetchInterval: 60_000, enabled: hasPermission('jobs.read') })
  const version = updateStatus.data?.version ?? 'dev'
  const versionReleaseURL = updateStatus.data?.version_release_url
  const update = updateStatus.data?.updates
  const updateAvailable = !!update && (update.available === true || update.status === 'update_available')
  const incidentSummary = useQuery({ queryKey: ['incidents', 'navigation'], queryFn: () => listIncidents(0, 1), refetchInterval: 15000, enabled: hasPermission('incidents.read') })
  const incidentCount = incidentSummary.data?.pagination.total ?? 0
  const incidentCountUnavailable = incidentSummary.isError
  useEffect(() => {
    if (!hasPermission('stream.read')) return
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
          case 'scan-incomplete':
          case 'scan-canceled':
          case 'scan-anomaly':
            void client.invalidateQueries({ queryKey: ['active-scans'] })
            void client.invalidateQueries({ queryKey: ['scans'] })
            void client.invalidateQueries({ queryKey: ['hosts'] })
            if (event.job_id) {
              void client.invalidateQueries({ queryKey: ['job-scans', event.job_id] })
              void client.invalidateQueries({ queryKey: ['job-baseline-overview', event.job_id] })
              void client.invalidateQueries({ queryKey: ['latest-successful-scan', event.job_id] })
              void client.invalidateQueries({ queryKey: ['latest-successful-results', event.job_id] })
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
              void client.invalidateQueries({ queryKey: ['job-baseline-overview', event.job_id] })
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
          case 'application.update_status':
          case 'application-updated':
          case 'application-update-available':
            void client.invalidateQueries({ queryKey: ['admin-status'] })
            break
          case 'stream_limit':
            // The server has sent an in-band backoff marker and will close
            // this EventSource cleanly. EventSource automatically reconnects
            // using the advertised retry delay; avoid invalidating every
            // query while the subscriber limit is under pressure.
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
  }, [client, permissions])
  const links = [
    ...(hasPermission('overview.read') ? [{ to: '/', label: 'Overview', icon: Gauge }] : []),
    ...(hasPermission('jobs.read') ? [{ to: '/jobs', label: 'Jobs', icon: Boxes }] : []),
    ...(hasPermission('hosts.read') ? [{ to: '/hosts', label: 'Hosts', icon: Server }] : []),
    ...(hasPermission('incidents.read') ? [{ to: '/incidents', label: 'Incidents', icon: Activity }] : []),
    ...(hasPermission('notifications.manage') ? [{ to: '/notifications', label: 'Notifications', icon: Bell }] : []),
    ...(hasPermission('users.manage') ? [{ to: '/users', label: 'Users', icon: UserRound }] : []),
    ...(hasPermission('audit.read') ? [{ to: '/audit', label: 'Audit', icon: ScrollText }] : []),
    ...(hasPermission('public_dashboard.manage') ? [{ to: '/public-dashboard', label: 'Public status', icon: Globe2 }] : []),
    ...(hasPermission('scanner_profiles.read') ? [{ to: '/scanner-profiles', label: 'Scanner profiles', icon: Code2 }] : []),
    { to: '/security', label: 'Security', icon: ShieldCheck },
  ]
  const breadcrumb = location.pathname === '/' ? 'Overview' : location.pathname.split('/').filter(Boolean).map(v => v[0].toUpperCase() + v.slice(1)).join(' / ')
  return <div className="app-shell">
    <aside id="primary-navigation" ref={drawerRef} role={isMobile && open ? 'dialog' : undefined} aria-label="Primary navigation" aria-modal={isMobile && open ? true : undefined} aria-hidden={isMobile ? !open : undefined} inert={isMobile ? !open : undefined} className={open ? 'sidebar open' : 'sidebar'}>
      <div className="brand"><span className="brand-mark"><Wifi size={19} /></span><span>EdgeWatch</span><button type="button" className="drawer-close" aria-label="Close navigation" onClick={() => setOpen(false)}><X size={19} /></button></div>
      {unit && <div className="unit-chip" title={`Business unit: ${unit.name}`}><Building2 size={15} aria-hidden="true" /><span><small>Business unit</small><strong>{unit.name}</strong></span></div>}
      <nav>{links.map(({ to, label, icon: Icon }) => { const active = location.pathname === to || (to === '/jobs' && location.pathname.startsWith('/jobs')) || (to === '/hosts' && location.pathname.startsWith('/scans/')); const incidents = to === '/incidents'; const attention = incidents && (incidentCountUnavailable || incidentCount > 0); return <Link key={to} to={to} onClick={() => setOpen(false)} aria-label={incidents ? 'Incidents' : undefined} aria-describedby={attention ? 'active-incident-count' : undefined} className={`nav-link${active ? ' active' : ''}${attention ? ' nav-link-alert' : ''}`}><Icon size={18} /><span className="nav-link-label">{label}</span>{attention && <span id="active-incident-count" className={`nav-count${incidentCountUnavailable ? ' nav-count-error' : ''}`} aria-live="polite" aria-label={incidentCountUnavailable ? 'Active incident count unavailable; retrying' : `${incidentCount} active incident${incidentCount === 1 ? '' : 's'}`} title={incidentCountUnavailable ? 'Active incident count unavailable; retrying' : undefined}>{incidentCountUnavailable ? '?' : incidentCount > 99 ? '99+' : incidentCount}</span>}</Link> })}</nav>
      <div className="sidebar-bottom"><div className="user-chip"><span className="avatar">{displayName.trim().charAt(0).toUpperCase() || 'A'}</span><span><small className="app-version">{versionReleaseURL ? <a className="version-link" href={versionReleaseURL} target="_blank" rel="noopener noreferrer" aria-label={`Release notes for EdgeWatch ${version}`} title={`Release notes for EdgeWatch ${version}`}>EdgeWatch {version}</a> : <>EdgeWatch {version}</>}{updateAvailable && update.release_url && <a className="version-update" href={update.release_url} target="_blank" rel="noopener noreferrer" aria-label={`Update available: ${version} to ${update.latest_version ?? 'new release'}`} title={`Update available: ${version} to ${update.latest_version ?? 'new release'}`}><ArrowUp size={13} aria-hidden="true" /></a>}</small><strong>{displayName}</strong><small>{role === 'administrator' ? 'Administrator' : role === 'operator' ? 'Operator' : 'Viewer · read only'}</small></span></div><button className="nav-link quiet" onClick={onLogout}><LogOut size={17} />Sign out</button></div>
    </aside>
    {open && isMobile && <button type="button" aria-label="Close navigation" tabIndex={-1} className="backdrop" onClick={() => setOpen(false)} />}
    <main className="main" inert={isMobile && open ? true : undefined} aria-hidden={isMobile && open ? true : undefined}><header className="topbar"><button ref={menuButtonRef} type="button" aria-label={open ? 'Close navigation' : 'Open navigation'} aria-controls="primary-navigation" aria-expanded={isMobile ? open : false} className="menu-button" onClick={() => setOpen(true)}><Menu size={21} /></button><nav className="breadcrumb" title={breadcrumb} aria-label={`Breadcrumb: ${breadcrumb}`}>{breadcrumb}</nav><div className="topbar-actions"><span className="status-dot"><i /> {liveState === 'live' ? 'Live updates' : liveState === 'reconnecting' ? 'Reconnecting…' : 'Connecting…'}</span><Bell size={18} /></div></header><div className="content"><Routes><Route path="/" element={hasPermission('overview.read') ? <Dashboard /> : <Navigate to="/jobs" replace />} /><Route path="/highlights" element={hasPermission('overview.read') ? <PublicDashboard /> : <Navigate to="/jobs" replace />} /><Route path="/jobs" element={hasPermission('jobs.read') ? <Jobs /> : <Navigate to="/jobs" replace />} /><Route path="/jobs/new" element={hasPermission('jobs.write') ? <JobEditor /> : <Navigate to="/jobs" replace />} /><Route path="/jobs/:id/scans/:scanId" element={hasPermission('scans.read') ? <JobDetail /> : <Navigate to="/jobs" replace />} /><Route path="/jobs/:id" element={hasPermission('jobs.read') ? <JobDetail /> : <Navigate to="/jobs" replace />} /><Route path="/jobs/:id/edit" element={hasPermission('jobs.write') ? <JobEditor /> : <Navigate to="/jobs" replace />} /><Route path="/jobs/:id/baseline" element={hasPermission('baselines.read') ? <BaselineHosts /> : <Navigate to="/jobs" replace />} /><Route path="/jobs/:id/baseline/hosts/:address" element={hasPermission('baselines.read') ? <HostDetail /> : <Navigate to="/jobs" replace />} /><Route path="/jobs/:id/scans/:scanId/hosts/:address" element={hasPermission('scans.read') ? <HostDetail /> : <Navigate to="/jobs" replace />} /><Route path="/hosts" element={hasPermission('hosts.read') ? <Hosts /> : <Navigate to="/jobs" replace />} /><Route path="/scans/:scanId" element={hasPermission('scans.read') ? <ScanDetail /> : <Navigate to="/jobs" replace />} /><Route path="/scans/:scanId/hosts/:address" element={hasPermission('scans.read') ? <HostDetail /> : <Navigate to="/jobs" replace />} /><Route path="/incidents" element={hasPermission('incidents.read') ? <Incidents /> : <Navigate to="/jobs" replace />} /><Route path="/notifications" element={hasPermission('notifications.manage') ? <Notifications /> : <Navigate to="/jobs" replace />} /><Route path="/users" element={hasPermission('users.manage') ? <Users /> : <Navigate to="/jobs" replace />} /><Route path="/audit" element={hasPermission('audit.read') ? <Audit /> : <Navigate to="/jobs" replace />} /><Route path="/public-dashboard" element={hasPermission('public_dashboard.manage') ? <PublicDashboardAdmin /> : <Navigate to="/jobs" replace />} /><Route path="/scanner-profiles" element={hasPermission('scanner_profiles.read') ? <ScannerProfiles /> : <Navigate to="/jobs" replace />} /><Route path="/security" element={<Security />} /><Route path="*" element={<Navigate to={hasPermission('overview.read') ? '/' : '/jobs'} replace />} /></Routes></div></main>
  </div>
}

export function Jobs() {
  const navigate = useNavigate()
  const jobs = useQuery({ queryKey: ['jobs', true], queryFn: () => listJobs(true) })
  const session = useQuery({ queryKey: ['session'], queryFn: getSession })
  const canWrite = session.data?.permissions.includes('jobs.write') ?? false
  return <section className="page"><div className="page-heading"><div><p className="eyebrow">Configuration</p><h1>Jobs</h1><p className="muted">Each job owns its targets, protocols, schedule, and baseline.</p></div>{canWrite && <button className="button primary" onClick={() => navigate('/jobs/new')}>＋ New job</button>}</div>{jobs.isLoading ? <Loading /> : jobs.error ? <ErrorCard message={jobs.error.message} /> : <div className="job-grid">{jobs.data?.jobs.map(job => { const baseline = baselinePresentation(job.baseline); return <Link className={job.archived ? 'job-card archived' : 'job-card'} to={`/jobs/${job.id}`} key={job.id}><div className="job-card-top"><span className={job.enabled && !job.archived ? 'pill green' : 'pill gray'}>{job.archived ? 'Archived' : job.enabled ? 'Scheduled' : 'Paused'}</span><span className="revision">r{job.revision}</span></div><h3>{job.job.name}</h3><p className="muted">{job.job.targets.length} target{job.job.targets.length === 1 ? '' : 's'} · {protocolSummary(job)}</p><div className="job-card-bottom"><span className={`baseline${baseline.status === 'complete' ? ' complete' : baseline.status === 'stalled' ? ' stalled' : ''}`}>{baseline.marker} {baseline.status === 'complete' ? `Baseline ${baseline.label.toLowerCase()}` : baseline.status === 'stalled' ? 'Baseline stalled' : `Collecting ${job.baseline.samples ?? 0}/${job.job.baseline_samples}`}</span><span>{job.job.schedule}</span></div></Link> })}{!jobs.data?.jobs.length && canWrite && <Empty title="No jobs yet" body="Create your first TCP or UDP monitoring job." action={<button className="button primary" onClick={() => navigate('/jobs/new')}>Create a job</button>} />}{!jobs.data?.jobs.length && !canWrite && <Empty title="No jobs configured" body="An operator can create a monitoring job for this EdgeWatch instance." />}</div>}</section>
}

function protocolSummary(job: { job: { tcp?: { ports: string }; udp?: { ports: string } } }) {
  return [
    job.job.tcp && `TCP · ${compactPortExpression(job.job.tcp.ports)}`,
    job.job.udp && `UDP · ${compactPortExpression(job.job.udp.ports)}`,
  ].filter(Boolean).join(' · ')
}

export function Incidents() {
  const [offset, setOffset] = useState(0)
  const [busy, setBusy] = useState('')
  const [actionError, setActionError] = useState('')
  const [pendingAction, setPendingAction] = useState<{ row: Incident; action: 'accept' | 'suppress' } | null>(null)
  const client = useQueryClient()
  const incidents = useQuery({ queryKey: ['incidents', offset], queryFn: () => listIncidents(offset) })
  const incidentPage = incidents.data?.pagination
  const pageIsPastEnd = !!incidents.data && !incidents.data.incidents.length && !!incidentPage?.total && offset > 0
  useEffect(() => {
    // Resolving the last row of a later page, or a scan closing incidents,
    // can leave this page empty while earlier pages still hold incidents.
    // Step back to the last page that has rows instead of an empty page.
    if (!pageIsPastEnd || !incidentPage) return
    const lastPage = Math.floor((incidentPage.total - 1) / incidentPage.limit) * incidentPage.limit
    setOffset(Math.max(0, Math.min(lastPage, offset - incidentPage.limit)))
  }, [pageIsPastEnd, incidentPage, offset])
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
      if (action === 'accept') await acceptIncident(row.job_id, key, row.incident.change)
      else await suppressIncident(row.job_id, key, row.incident.change)
      await client.invalidateQueries({ queryKey: ['incidents'] })
      await client.invalidateQueries({ queryKey: ['job', row.job_id] })
      if (action === 'accept') {
        await client.invalidateQueries({ queryKey: ['baseline-hosts', row.job_id] })
        await client.invalidateQueries({ queryKey: ['host-detail'] })
      }
      setPendingAction(null)
    } catch (error) {
      if (error instanceof APIError && error.code === 'incident_conflict') {
        // The reviewed evidence is no longer current. Close the stale dialog
        // and reload the list so the administrator sees the new observation
        // before deciding again.
        setPendingAction(null)
        await client.invalidateQueries({ queryKey: ['incidents'] })
        setActionError('This incident changed while it was open. The incident list was refreshed; review the new evidence before retrying.')
      } else {
        setActionError(error instanceof Error ? error.message : 'The incident action could not be completed.')
      }
    } finally {
      setBusy('')
    }
  }
  const actionFor = (row: Incident, action: 'accept' | 'suppress') => {
    setActionError('')
    setPendingAction({ row, action })
  }
  return <section className="page"><div className="page-heading"><div><p className="eyebrow">Change tracking</p><h1>Incidents</h1><p className="muted">Confirmed changes detected against active baselines.</p></div></div>{actionError && <div className="form-error banner" role="alert">{actionError}</div>}{incidents.isLoading ? <Loading /> : incidents.error ? <div className="error-card" role="alert">Could not load active incidents.</div> : incidents.data?.incidents.length ? <><div className="table-card incident-table-card"><div className="desktop-incident-table"><table><thead><tr><th scope="col">Job</th><th scope="col">Target</th><th scope="col">Change</th><th scope="col">Severity</th><th scope="col">Last seen</th><th scope="col">Actions</th></tr></thead><tbody>{incidents.data.incidents.map((row, i) => <IncidentTableRow key={`${row.job_id}-${row.incident.change.key ?? i}`} row={row} busy={busy} onAction={actionFor} />)}</tbody></table></div><div className="mobile-incident-list" aria-label="Incidents">{incidents.data.incidents.map((row, i) => <IncidentCard key={`${row.job_id}-${row.incident.change.key ?? i}`} row={row} busy={busy} onAction={actionFor} />)}</div></div><Pagination page={incidents.data.pagination} onChange={setOffset} /></> : incidents.data?.pagination.total ? <><div className="inline-empty">No incidents on this page.</div><Pagination page={incidents.data.pagination} onChange={setOffset} /></> : <Empty icon={<ClipboardList />} title="No active incidents" body="EdgeWatch will show confirmed port, service, or DNS changes here." />}{pendingAction && <ActionDialog title={pendingAction.action === 'accept' ? 'Accept this change?' : 'Suppress this incident for one scan?'} description={pendingAction.action === 'accept' ? `Accept this change into the baseline for “${pendingAction.row.job}”? Future scans will treat it as expected.` : 'The incident will be suppressed for the next successful scan. If it is still present after that scan, it will be reported again.'} confirmLabel={pendingAction.action === 'accept' ? 'Accept change' : 'Suppress 1 scan'} destructive={pendingAction.action === 'suppress'} onConfirm={() => act(pendingAction.row, pendingAction.action)} onCancel={() => { setPendingAction(null); setActionError('') }} error={actionError} />}</section>
}

function IncidentTableRow({ row, busy, onAction }: { row: Incident; busy: string; onAction: (row: Incident, action: 'accept' | 'suppress') => void }) {
  const key = row.incident.change.key
  const acceptID = `accept:${row.job_id}:${key ?? ''}`
  const suppressID = `suppress:${row.job_id}:${key ?? ''}`
  return <tr><td><strong>{row.job}</strong></td><td>{row.incident.change.target}</td><td><strong>{formatIncidentChange(row.incident.change)}</strong><br /><span className="muted">{changeValues(row.incident.change)}</span></td><td><span className={`pill ${row.incident.change.severity === 'critical' ? 'red' : 'amber'}`}>{row.incident.change.severity}</span></td><td>{formatDateTime(row.incident.last_seen_at)}</td><td><IncidentActions row={row} busy={busy} acceptID={acceptID} suppressID={suppressID} onAction={onAction} /></td></tr>
}

function IncidentCard({ row, busy, onAction }: { row: Incident; busy: string; onAction: (row: Incident, action: 'accept' | 'suppress') => void }) {
  const key = row.incident.change.key
  const acceptID = `accept:${row.job_id}:${key ?? ''}`
  const suppressID = `suppress:${row.job_id}:${key ?? ''}`
  return <article className="incident-card" aria-label={`Incident for ${row.job}`}><div className="incident-card-heading"><strong>{row.job}</strong><span className={`pill ${row.incident.change.severity === 'critical' ? 'red' : 'amber'}`}>{row.incident.change.severity}</span></div><dl className="incident-facts"><div><dt>Target</dt><dd>{row.incident.change.target}</dd></div><div><dt>Change</dt><dd><strong>{formatIncidentChange(row.incident.change)}</strong><br /><span className="muted">{changeValues(row.incident.change)}</span></dd></div><div><dt>Last seen</dt><dd>{formatDateTime(row.incident.last_seen_at)}</dd></div></dl><IncidentActions row={row} busy={busy} acceptID={acceptID} suppressID={suppressID} onAction={onAction} /></article>
}

function formatIncidentChange(change: Incident['incident']['change']) {
  return `${change.kind}${change.port ? ` / ${change.protocol}:${change.port}` : ''}`
}

function changeValues(change: Incident['incident']['change']) {
  if (change.old || change.new) return `${change.old ?? '—'} → ${change.new ?? '—'}`
  return 'No before/after value recorded'
}

function IncidentActions({ row, busy, acceptID, suppressID, onAction }: { row: Incident; busy: string; acceptID: string; suppressID: string; onAction: (row: Incident, action: 'accept' | 'suppress') => void }) {
  const key = row.incident.change.key
  return <div className="incident-actions"><button className="button secondary" type="button" onClick={() => onAction(row, 'accept')} disabled={!key || !!busy}>{busy === acceptID ? 'Accepting…' : 'Accept change'}</button><button className="button ghost" type="button" onClick={() => onAction(row, 'suppress')} disabled={!key || !!busy}>{busy === suppressID ? 'Suppressing…' : 'Suppress 1 scan'}</button></div>
}

export function ProtectedApp({ onLogout }: { onLogout: () => Promise<void> }) { const status = useQuery({ queryKey: ['setup-status'], queryFn: setupStatus }); const session = useQuery({ queryKey: ['session'], queryFn: async () => { const value = await getSession(); setCSRF(value.csrf_token); return value }, retry: false }); const navigate = useNavigate(); useEffect(() => { if (session.error && status.data?.configured) navigate('/login') }, [session.error, status.data, navigate]); if (status.isLoading || session.isLoading) return <Loading />; if (!status.data?.configured) return <Navigate to="/setup" replace />; if (session.error) return <Navigate to="/login" replace />; const displayName = session.data?.display_name ?? session.data?.username ?? 'admin'; const permissions = session.data?.permissions ?? []
  // A main administrator gets the platform console, which never mounts the
  // unit pages (jobs, hosts, incidents); unit routes redirect to its units.
  if (session.data?.scope === 'platform') return <PlatformShell displayName={displayName} permissions={permissions} onLogout={onLogout} />
  return <Shell displayName={displayName} role={session.data?.role ?? 'viewer'} permissions={permissions} onLogout={onLogout} unit={session.data?.multi_unit ? session.data.unit : null} /> }

export function AuthRoutes({ configured }: { configured: boolean }) { const location = useLocation(); return <Routes><Route path="/setup" element={<Setup />} /><Route path="/activate" element={<Activate />} /><Route path="/login" element={<Login />} /><Route path="*" element={configured ? <Navigate to="/login" replace state={{ from: { pathname: location.pathname, search: location.search } }} /> : <Navigate to="/setup" replace />} /></Routes> }

export function App() { return <BrowserRouter><AppContent /></BrowserRouter> }

export function AppContent() {
  const location = useLocation()
  const client = useQueryClient()
  // /public serves the default business unit; /public/<slug> serves a unit's
  // own public status page.
  const publicMatch = /^\/public(?:\/([^/]+))?\/?$/.exec(location.pathname)
  const isPublic = !!publicMatch
  const publicSlug = publicMatch?.[1] ? decodePathSegment(publicMatch[1]) : undefined
  const [signedOut, setSignedOut] = useState(false)
  // The public highlights page is deliberately independent of setup/session
  // state. This avoids an unnecessary authenticated request and keeps the
  // unauthenticated route usable while the administrator is signed out.
  const status = useQuery({ queryKey: ['setup-status'], queryFn: setupStatus, retry: false, enabled: !isPublic })
  const session = useQuery({ queryKey: ['session'], queryFn: async () => { const value = await getSession(); setCSRF(value.csrf_token); return value }, retry: false, enabled: !isPublic })
  useEffect(() => {
    function handleUnauthorized() {
      setCSRF('')
      client.setQueryData(['session'], null)
      setSignedOut(true)
    }
    function handleAuthenticated() { setSignedOut(false) }
    window.addEventListener('edgewatch:unauthorized', handleUnauthorized)
    window.addEventListener('edgewatch:authenticated', handleAuthenticated)
    return () => {
      window.removeEventListener('edgewatch:unauthorized', handleUnauthorized)
      window.removeEventListener('edgewatch:authenticated', handleAuthenticated)
    }
  }, [client])
  const authenticated = !signedOut && !!session.data && !session.error
  async function handleLogout() {
    try { await apiLogout() } catch { /* The server clears the cookie before reporting audit errors. */ }
    finally { setCSRF(''); client.clear(); client.setQueryData(['session'], null); setSignedOut(true) }
  }
  if (isPublic) return <PublicDashboard slug={publicSlug} />
  if (status.isLoading || session.isLoading) return <Loading />
  if (status.error) return <ErrorCard message="Unable to contact EdgeWatch. Retry when the service is available." />
  return status.data?.configured && authenticated ? <ProtectedApp onLogout={handleLogout} /> : <AuthGate statusConfigured={!!status.data?.configured} />
}

function AuthGate({ statusConfigured }: { statusConfigured: boolean }) { return <AuthRoutes configured={statusConfigured} /> }

function decodePathSegment(value: string) {
  try { return decodeURIComponent(value) } catch { return value }
}

function Loading() { return <div className="loading"><span className="spinner" />Loading EdgeWatch…</div> }
function ErrorCard({ message }: { message: string }) { return <div className="error-card">{message}</div> }
function Empty({ icon, title, body, action }: { icon?: React.ReactNode; title: string; body: string; action?: React.ReactNode }) { return <div className="empty"><div className="empty-icon">{icon ?? <Boxes size={23} />}</div><h3>{title}</h3><p>{body}</p>{action}</div> }

const rootElement = document.getElementById('root')
if (rootElement) createRoot(rootElement).render(<StrictMode><QueryClientProvider client={queryClient}><App /></QueryClientProvider></StrictMode>)
