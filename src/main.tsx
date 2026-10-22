import { StrictMode, useEffect, useRef, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClient, QueryClientProvider, useQuery, useQueryClient } from '@tanstack/react-query'
import { BrowserRouter, Link, Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom'
import { Activity, ArrowUp, Bell, Boxes, Building2, Code2, Fence, Gauge, Globe2, History, LogOut, Menu, ScrollText, Server, ShieldCheck, UserRound, Wifi, X } from 'lucide-react'
import { adminStatus, APIError, getSession, incidentInboxSummary, listIncidents, listJobs, setCSRF, setForbiddenHandler, setupStatus, logout as apiLogout } from './api'
import type { SessionUser, UnitRef } from './api'
import { useActivityHeartbeat, useNavigationDrawer } from './components/navigation'
import { ErrorNotice } from './components/ErrorNotice'
import { ScanSlotDemandNotice } from './components/ScanSlotDemand'
import { PageErrorBoundary } from './components/PageErrorBoundary'
import { Audit } from './pages/Audit'
import { PlatformShell } from './pages/platform/PlatformShell'
import { TotpEnrollmentShell } from './pages/TotpEnrollment'
import { Dashboard } from './pages/Dashboard'
import { Activity as ActivityPage } from './pages/Activity'
import { JobEditor } from './pages/JobEditor'
import { MonitorSetup } from './pages/MonitorSetup'
import { JobCreationDraftProvider } from './job-creation-draft'
import { JobDetail } from './pages/JobDetail'
import { Activate, activationTokenFromLocation, Login, Setup, SignedInActivation, signInReturnPath } from './pages/Auth'
import { Security } from './pages/Security'
import { Notifications } from './pages/Notifications'
import { BaselineHosts } from './pages/BaselineHosts'
import { HostDetail } from './pages/HostDetail'
import { Hosts } from './pages/Hosts'
import { Perimeter } from './pages/perimeter/Perimeter'
import { PerimeterRangeView } from './pages/perimeter/PerimeterRange'
import { Users } from './pages/Users'
import { PublicDashboard, PublicDashboardAdmin } from './pages/PublicDashboard'
import { ScannerProfiles } from './pages/ScannerProfiles'
import { ScanDetail } from './pages/ScanDetail'
import type { Role } from './api'
import { Incidents } from './pages/Incidents'
export { Incidents } from './pages/Incidents'
import { compactPortExpression } from './components/PortScopeDetails'
import { baselinePresentation } from './baseline'
import { jobStatePresentation } from './status'
import { formatDateTime, formatDateTimeInTimeZone } from './format'
import { formatChangeWindowTime } from './change-window-time'
import type { Job } from './types'
import type { ChangeWindowStatus } from './generated/api-types'
import './tailwind.css'
import './styles.css'

/** The console's query defaults, shared by the browser bootstrap and tests. */
export function createQueryClient() {
  return new QueryClient({ defaultOptions: { queries: { staleTime: 5000, refetchOnWindowFocus: true, retry: retryQuery, retryDelay: retryQueryDelay } } })
}

/**
 * A refused request is not retried: a 4xx answer fails the same way again
 * (a 404 is as deterministic as a 400, and another unit's ID answers 404
 * too), a 401 ends the session, and a 403 makes the console re-read its
 * session, which may now be restricted. A timeout (408) or a rate limit
 * (429) may pass later; they and other failures keep React Query's default
 * of three retries, and a 429 waits as long as its Retry-After asks.
 */
export function retryQuery(failureCount: number, error: Error) {
  if (error instanceof APIError && error.status !== undefined && error.status >= 400 && error.status < 500 && error.status !== 408 && error.status !== 429) return false
  return failureCount < 3
}

/** React Query's default backoff, or the delay a 429 asked for. */
export function retryQueryDelay(failureCount: number, error: Error) {
  if (error instanceof APIError && error.status === 429 && error.retryAfterSeconds) return error.retryAfterSeconds * 1000
  return Math.min(1000 * 2 ** failureCount, 30_000)
}
const queryClient = createQueryClient()

export function unitBreadcrumb(pathname: string, links: { to: string; label: string }[]) {
  const fixedRoutes: Array<{ path: RegExp; label: string }> = [
    { path: /^\/jobs\/new\/advanced\/?$/, label: 'Jobs / New job / Advanced' },
    { path: /^\/jobs\/new\/?$/, label: 'Jobs / New job' },
    { path: /^\/jobs\/[^/]+\/edit\/?$/, label: 'Jobs / Edit job' },
    { path: /^\/jobs\/[^/]+\/scans\/[^/]+\/hosts\/[^/]+\/?$/, label: 'Jobs / Scan host' },
    { path: /^\/jobs\/[^/]+\/baseline\/hosts\/[^/]+\/?$/, label: 'Jobs / Baseline host' },
    { path: /^\/jobs\/[^/]+\/scans\/[^/]+\/?$/, label: 'Jobs / Scan' },
    { path: /^\/jobs\/[^/]+\/baseline\/?$/, label: 'Jobs / Baseline' },
    { path: /^\/jobs\/[^/]+\/?$/, label: 'Jobs / Job details' },
    { path: /^\/scans\/[^/]+\/hosts\/[^/]+\/?$/, label: 'Hosts / Scan host' },
    { path: /^\/scans\/[^/]+\/?$/, label: 'Hosts / Scan' },
    { path: /^\/perimeter\/ranges\/[^/]+\/?$/, label: 'Perimeter / Range' },
  ]
  const fixed = fixedRoutes.find(route => route.path.test(pathname))
  if (fixed) return fixed.label
  return links.find(link => pathname === link.to || (link.to !== '/' && pathname.startsWith(`${link.to}/`)))?.label ?? 'EdgeWatch'
}

/**
 * The application shell is exported so it can be exercised with a jsdom
 * router/query harness.  Keeping the browser bootstrap below this component
 * makes the entrypoint side-effect free in tests while preserving the single
 * embedded SPA bundle in production.
 */
export function Shell({ displayName, role, permissions, onLogout, unit }: { displayName: string; role: Role; permissions: string[]; onLogout: () => void; unit?: UnitRef | null }) {
  const [liveState, setLiveState] = useState<'connecting' | 'live' | 'reconnecting' | 'limited'>('connecting')
  const [streamLimitScope, setStreamLimitScope] = useState<'account' | 'unit' | 'deployment' | null>(null)
  const { open, setOpen, isMobile, menuButtonRef, drawerRef } = useNavigationDrawer()
  useActivityHeartbeat()
  const location = useLocation()
  const mainRef = useRef<HTMLElement | null>(null)
  const previousPath = useRef(location.pathname)
  const client = useQueryClient()
  const hasPermission = (permission: string) => permissions.includes(permission)
  const updateStatus = useQuery({ queryKey: ['admin-status'], queryFn: adminStatus, refetchInterval: 60_000, enabled: hasPermission('jobs.read') })
  const version = updateStatus.data?.version ?? 'dev'
  const versionReleaseURL = updateStatus.data?.version_release_url
  const update = updateStatus.data?.updates
  const updateAvailable = !!update && (update.available === true || update.status === 'update_available')
  const incidentSummary = useQuery({ queryKey: ['incidents', 'navigation'], queryFn: incidentInboxSummary, refetchInterval: 15000, enabled: hasPermission('incidents.read') })
  const incidentCount = incidentSummary.data?.active_count ?? 0
  const incidentCountUnavailable = incidentSummary.isError
  useEffect(() => {
    if (!hasPermission('stream.read')) return
    let stream: EventSource | undefined
    let retryTimer: ReturnType<typeof setTimeout> | undefined
    let stableTimer: ReturnType<typeof setTimeout> | undefined
    let retryCount = 0
    let hasConnected = false
    let disposed = false
    const connect = () => {
      if (disposed) return
      let streamLimited = false
      const source = new EventSource('/api/v1/stream')
      stream = source
      source.onopen = () => {
        if (streamLimited || disposed || stream !== source) return
        if (hasConnected) void client.invalidateQueries()
        hasConnected = true
        setStreamLimitScope(null)
        setLiveState('live')
        if (stableTimer !== undefined) clearTimeout(stableTimer)
        stableTimer = setTimeout(() => {
          retryCount = 0
          stableTimer = undefined
        }, 30_000)
      }
      source.onerror = () => {
        if (streamLimited || disposed || stream !== source) return
        setLiveState('reconnecting')
        if (source.readyState !== EventSource.CLOSED || retryTimer !== undefined) return
        const delay = Math.min(1_000 * (2 ** retryCount), 5 * 60 * 1_000)
        retryCount++
        retryTimer = setTimeout(() => {
          retryTimer = undefined
          if (!disposed && stream === source) connect()
        }, delay)
      }
      source.onmessage = (message) => {
        try {
          const event = JSON.parse(message.data) as { type?: string; job_id?: string; reason?: string; retry_after?: number }
          switch (event.type) {
            case 'scan.started':
            case 'scan.completed':
            case 'scan-paused':
            case 'scan-recovered':
            case 'scan-failure':
            case 'scan-incomplete':
            case 'scan-canceled':
            case 'scan-interrupted':
            case 'scan-anomaly':
            case 'scan-budget-exceeded':
              void client.invalidateQueries({ queryKey: ['jobs'] })
              void client.invalidateQueries({ queryKey: ['active-scans'] })
              void client.invalidateQueries({ queryKey: ['scans'] })
              void client.invalidateQueries({ queryKey: ['hosts'] })
              void client.invalidateQueries({ queryKey: ['activity-events'] })
              // A scan's outcome decides whether the perimeter report calls
              // its monitor's coverage proven.
              void client.invalidateQueries({ queryKey: ['perimeter'] })
              if (event.job_id) {
                void client.invalidateQueries({ queryKey: ['job-scans', event.job_id] })
                void client.invalidateQueries({ queryKey: ['job-baseline-overview', event.job_id] })
                void client.invalidateQueries({ queryKey: ['latest-successful-scan', event.job_id] })
                void client.invalidateQueries({ queryKey: ['latest-successful-results', event.job_id] })
                void client.invalidateQueries({ queryKey: ['scan-cycle', event.job_id] })
                void client.invalidateQueries({ queryKey: ['job', event.job_id] })
                void client.invalidateQueries({ queryKey: ['job-pending-changes', event.job_id] })
              }
              break
            case 'changes-detected':
            case 'changes-reminder':
            case 'changes-recovered':
            case 'incident-opened':
            case 'incident-closed':
            case 'incident-accepted':
            case 'incident-suppressed':
            case 'incident.review.updated':
              void client.invalidateQueries({ queryKey: ['jobs'] })
              void client.invalidateQueries({ queryKey: ['incidents'] })
              void client.invalidateQueries({ queryKey: ['activity-events'] })
              if (event.job_id) {
                void client.invalidateQueries({ queryKey: ['job', event.job_id] })
                void client.invalidateQueries({ queryKey: ['job-pending-changes', event.job_id] })
              }
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
            case 'job.paused':
            case 'job.resumed':
              void client.invalidateQueries({ queryKey: ['jobs'] })
              void client.invalidateQueries({ queryKey: ['activity-events'] })
              // The perimeter report classifies every unarchived job from its
              // configuration, so each job change can change its coverage.
              void client.invalidateQueries({ queryKey: ['perimeter'] })
              if (event.job_id) void client.invalidateQueries({ queryKey: ['job', event.job_id] })
              break
            case 'change-window.updated':
              void client.invalidateQueries({ queryKey: ['jobs'] })
              if (event.job_id) {
                void client.invalidateQueries({ queryKey: ['job', event.job_id] })
                void client.invalidateQueries({ queryKey: ['job-change-windows', event.job_id] })
                void client.invalidateQueries({ queryKey: ['job-change-window', event.job_id] })
              }
              break
            case 'job-silent':
              void client.invalidateQueries({ queryKey: ['jobs'] })
              void client.invalidateQueries({ queryKey: ['activity-events'] })
              // The report's stale flag follows the same overdue rule.
              void client.invalidateQueries({ queryKey: ['perimeter'] })
              break
            case 'perimeter.updated':
              // The prefix covers the overview and every range detail.
              void client.invalidateQueries({ queryKey: ['perimeter'] })
              break
            case 'baseline-approved':
            case 'baseline-reset':
            case 'baseline-complete':
            case 'baseline-updated':
            case 'baseline-stalled':
              void client.invalidateQueries({ queryKey: ['jobs'] })
              void client.invalidateQueries({ queryKey: ['activity-events'] })
              void client.invalidateQueries({ queryKey: ['incidents'] })
              if (event.job_id) {
                void client.invalidateQueries({ queryKey: ['job', event.job_id] })
                void client.invalidateQueries({ queryKey: ['job-baseline-overview', event.job_id] })
                void client.invalidateQueries({ queryKey: ['baseline-hosts', event.job_id] })
                void client.invalidateQueries({ queryKey: ['job-pending-changes', event.job_id] })
                void client.invalidateQueries({ queryKey: ['scan-cycle', event.job_id] })
              }
              break
            case 'scan.cancellation_requested':
              void client.invalidateQueries({ queryKey: ['active-scans'] })
              break
            case 'scan.cycle_discarded':
              void client.invalidateQueries({ queryKey: ['jobs'] })
              // Discarding a stalled cycle clears the report's stalled flag.
              void client.invalidateQueries({ queryKey: ['perimeter'] })
              if (event.job_id) {
                void client.invalidateQueries({ queryKey: ['job', event.job_id] })
                void client.invalidateQueries({ queryKey: ['scan-cycle', event.job_id] })
              }
              break
            case 'scanner-profile.changed':
              void client.invalidateQueries({ queryKey: ['scanner-profiles'] })
              break
            case 'notification.changed':
              void client.invalidateQueries({ queryKey: ['notifications'] })
              void client.invalidateQueries({ queryKey: ['admin-status'] })
              break
            case 'application.update_status':
            case 'application-updated':
            case 'application-update-available':
              void client.invalidateQueries({ queryKey: ['admin-status'] })
              if (event.type !== 'application.update_status') void client.invalidateQueries({ queryKey: ['activity-events'] })
              break
            case 'scan.skipped':
              void client.invalidateQueries({ queryKey: ['jobs'] })
              void client.invalidateQueries({ queryKey: ['active-scans'] })
              if (event.job_id) {
                void client.invalidateQueries({ queryKey: ['job', event.job_id] })
                window.dispatchEvent(new CustomEvent('edgewatch:scan-skipped', { detail: { job_id: event.job_id, reason: event.reason } }))
              }
              break
            case 'stream_limit': {
              // EventSource otherwise reconnects after the server closes a
              // limited stream, repeatedly consuming connection slots. Stop
              // this source; shared limits retry with bounded backoff, while
              // an account limit still requires the user to close another tab.
              streamLimited = true
              source.close()
              if (stableTimer !== undefined) {
                clearTimeout(stableTimer)
                stableTimer = undefined
              }
              const scope = event.reason === 'too many live streams for this business unit'
                ? 'unit'
                : event.reason === 'too many live streams'
                  ? 'deployment'
                  : 'account'
              setStreamLimitScope(scope)
              setLiveState('limited')
              if (scope !== 'account') {
                const reportedSeconds = typeof event.retry_after === 'number' && Number.isFinite(event.retry_after) ? event.retry_after : 5
                const retrySeconds = Math.min(Math.max(reportedSeconds, 1), 300)
                const delay = Math.min(retrySeconds * 1000 * (2 ** retryCount), 5 * 60 * 1000)
                retryCount++
                retryTimer = setTimeout(() => {
                  retryTimer = undefined
                  if (!disposed) {
                    setLiveState('reconnecting')
                    connect()
                  }
                }, delay)
              }
              break
            }
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
    }
    connect()
    return () => {
      disposed = true
      if (retryTimer !== undefined) clearTimeout(retryTimer)
      if (stableTimer !== undefined) clearTimeout(stableTimer)
      stream?.close()
    }
  }, [client, permissions])
  const links = [
    ...(hasPermission('overview.read') ? [{ to: '/', label: 'Overview', icon: Gauge }] : []),
    ...(hasPermission('jobs.read') ? [{ to: '/jobs', label: 'Jobs', icon: Boxes }] : []),
    ...(hasPermission('hosts.read') ? [{ to: '/hosts', label: 'Hosts', icon: Server }] : []),
    ...(hasPermission('perimeter.read') ? [{ to: '/perimeter', label: 'Perimeter', icon: Fence }] : []),
    ...(hasPermission('incidents.read') ? [{ to: '/incidents', label: 'Incidents', icon: Activity }] : []),
    ...(hasPermission('scans.read') ? [{ to: '/activity', label: 'Activity', icon: History }] : []),
    ...(hasPermission('notifications.manage') ? [{ to: '/notifications', label: 'Notifications', icon: Bell }] : []),
    ...(hasPermission('users.manage') ? [{ to: '/users', label: 'Users', icon: UserRound }] : []),
    ...(hasPermission('audit.read') ? [{ to: '/audit', label: 'Audit', icon: ScrollText }] : []),
    ...(hasPermission('public_dashboard.manage') ? [{ to: '/public-dashboard', label: 'Public status', icon: Globe2 }] : []),
    ...(hasPermission('scanner_profiles.read') ? [{ to: '/scanner-profiles', label: 'Scanner profiles', icon: Code2 }] : []),
    { to: '/security', label: 'Security', icon: ShieldCheck },
  ]
  // A page that the session may not open redirects to one that it may: the
  // jobs, or Security, which every session opens, when it cannot read jobs.
  // A redirect therefore never leads to a page that redirects again.
  const fallback = hasPermission('jobs.read') ? '/jobs' : '/security'
  const home = hasPermission('overview.read') ? '/' : fallback
  const breadcrumb = unitBreadcrumb(location.pathname, links)
  const streamAvailable = hasPermission('stream.read')
  const visibleLiveState = streamAvailable ? liveState : 'unavailable'
  const liveLabel = visibleLiveState === 'live' ? 'Live updates' : visibleLiveState === 'reconnecting' ? 'Reconnecting…' : visibleLiveState === 'connecting' ? 'Connecting…' : visibleLiveState === 'limited' ? 'Live updates limited' : 'Live updates unavailable'
  const liveDescription = visibleLiveState === 'limited'
    ? streamLimitScope === 'unit'
      ? 'Live updates are paused because this business unit has reached its live-stream capacity. Retrying automatically.'
      : streamLimitScope === 'deployment'
        ? 'Live updates are paused because EdgeWatch has reached its live-stream capacity. Retrying automatically.'
        : 'Live updates are limited for this account. Close another EdgeWatch tab, then reload this page to reconnect.'
    : liveLabel
  useEffect(() => {
    document.title = `${breadcrumb} · EdgeWatch`
    if (previousPath.current !== location.pathname) {
      previousPath.current = location.pathname
      mainRef.current?.focus({ preventScroll: true })
    }
  }, [breadcrumb, location.pathname])
  return <div className="app-shell">
    <a className="skip-link" href="#main-content">Skip to content</a>
    <aside id="primary-navigation" ref={drawerRef} role={isMobile && open ? 'dialog' : undefined} aria-label="Primary navigation" aria-modal={isMobile && open ? true : undefined} aria-hidden={isMobile ? !open : undefined} inert={isMobile ? !open : undefined} className={open ? 'sidebar open' : 'sidebar'}>
      <div className="brand"><span className="brand-mark"><Wifi size={19} /></span><span>EdgeWatch</span><button type="button" className="drawer-close" aria-label="Close navigation" onClick={() => setOpen(false)}><X size={19} /></button></div>
      {unit && <div className="unit-chip" title={`Business unit: ${unit.name}`}><Building2 size={15} aria-hidden="true" /><span><small>Business unit</small><strong>{unit.name}</strong></span></div>}
      <nav>{links.map(({ to, label, icon: Icon }) => {
        const active = location.pathname === to || (to === '/jobs' && location.pathname.startsWith('/jobs')) || (to === '/hosts' && location.pathname.startsWith('/scans/')) || (to === '/perimeter' && location.pathname.startsWith('/perimeter/'))
        const incidents = to === '/incidents'
        const attention = incidents && (incidentCountUnavailable || incidentCount > 0)
        const incidentCountLabel = incidentCountUnavailable
          ? '? Active incident count unavailable; retrying'
          : `${incidentCount > 99 ? '99+' : incidentCount} active incident${incidentCount === 1 ? '' : 's'}`
        return (
          <Link key={to} to={to} onClick={() => setOpen(false)} aria-current={active ? 'page' : undefined} className={`nav-link${active ? ' active' : ''}${attention ? ' nav-link-alert' : ''}`}>
            <Icon size={18} />
            <span className="nav-link-label">{label}</span>
            {attention && <span id="active-incident-count" className={`nav-count${incidentCountUnavailable ? ' nav-count-error' : ''}`} aria-live="polite" aria-label={incidentCountLabel} title={incidentCountUnavailable ? 'Active incident count unavailable; retrying' : undefined}>{incidentCountUnavailable ? '?' : incidentCount > 99 ? '99+' : incidentCount}</span>}
          </Link>
        )
      })}</nav>
      <div className="sidebar-bottom"><div className="user-chip"><span className="avatar">{displayName.trim().charAt(0).toUpperCase() || 'A'}</span><span><small className="app-version">{versionReleaseURL ? <a className="version-link" href={versionReleaseURL} target="_blank" rel="noopener noreferrer" aria-label={`Release notes for EdgeWatch ${version}`} title={`Release notes for EdgeWatch ${version}`}>EdgeWatch {version}</a> : <>EdgeWatch {version}</>}{updateAvailable && update.release_url && <a className="version-update" href={update.release_url} target="_blank" rel="noopener noreferrer" aria-label={`Update available: ${version} to ${update.latest_version ?? 'new release'}`} title={`Update available: ${version} to ${update.latest_version ?? 'new release'}`}><ArrowUp size={13} aria-hidden="true" /></a>}</small><strong>{displayName}</strong><small>{role === 'administrator' ? 'Administrator' : role === 'operator' ? 'Operator' : 'Viewer · read only'}</small></span></div><a className="nav-link quiet" href="/source" target="_blank" rel="noopener noreferrer"><Code2 size={17} aria-hidden="true" />Source code</a><button className="nav-link quiet" onClick={onLogout}><LogOut size={17} />Sign out</button></div>
    </aside>
    {open && isMobile && <button type="button" aria-label="Close navigation" tabIndex={-1} className="backdrop" onClick={() => setOpen(false)} />}
    <main ref={mainRef} id="main-content" tabIndex={-1} className="main" inert={isMobile && open ? true : undefined} aria-hidden={isMobile && open ? true : undefined}><header className="topbar"><button ref={menuButtonRef} type="button" aria-label={open ? 'Close navigation' : 'Open navigation'} aria-controls="primary-navigation" aria-expanded={isMobile ? open : false} className="menu-button" onClick={() => setOpen(true)}><Menu size={21} /></button><nav className="breadcrumb" title={breadcrumb} aria-label={`Breadcrumb: ${breadcrumb}`}>{breadcrumb}</nav><div className="topbar-actions"><span className={`status-dot ${visibleLiveState}`} role="status" aria-label={liveLabel} title={liveDescription}><i aria-hidden="true" /><span className="status-dot-label">{liveLabel}</span></span></div></header><div className="content"><PageErrorBoundary resetKey={location.key} homePath={home} homeLabel={home === '/' ? 'Overview' : home === '/jobs' ? 'Jobs' : 'Security'}><Routes><Route path="/" element={hasPermission('overview.read') ? <Dashboard /> : <Navigate to={fallback} replace />} /><Route path="/highlights" element={<Navigate to={hasPermission('public_dashboard.manage') ? '/public-dashboard' : home} replace />} /><Route path="/jobs" element={hasPermission('jobs.read') ? <Jobs /> : <Navigate to={fallback} replace />} /><Route path="/jobs/new/*" element={hasPermission('jobs.write') ? <JobCreationJourney /> : <Navigate to={fallback} replace />} /><Route path="/jobs/:id/scans/:scanId" element={hasPermission('scans.read') ? <JobDetail /> : <Navigate to={fallback} replace />} /><Route path="/jobs/:id" element={hasPermission('jobs.read') ? <JobDetail /> : <Navigate to={fallback} replace />} /><Route path="/jobs/:id/edit" element={hasPermission('jobs.write') ? <JobEditor /> : <Navigate to={fallback} replace />} /><Route path="/jobs/:id/baseline" element={hasPermission('baselines.read') ? <BaselineHosts /> : <Navigate to={fallback} replace />} /><Route path="/jobs/:id/baseline/hosts/:address" element={hasPermission('baselines.read') ? <HostDetail /> : <Navigate to={fallback} replace />} /><Route path="/jobs/:id/scans/:scanId/hosts/:address" element={hasPermission('scans.read') ? <HostDetail /> : <Navigate to={fallback} replace />} /><Route path="/hosts" element={hasPermission('hosts.read') ? <Hosts /> : <Navigate to={fallback} replace />} /><Route path="/perimeter" element={hasPermission('perimeter.read') ? <Perimeter /> : <Navigate to={fallback} replace />} /><Route path="/perimeter/ranges/:id" element={hasPermission('perimeter.read') ? <PerimeterRangeView /> : <Navigate to={fallback} replace />} /><Route path="/scans/:scanId" element={hasPermission('scans.read') ? <ScanDetail /> : <Navigate to={fallback} replace />} /><Route path="/scans/:scanId/hosts/:address" element={hasPermission('scans.read') ? <HostDetail /> : <Navigate to={fallback} replace />} /><Route path="/incidents" element={hasPermission('incidents.read') ? <Incidents /> : <Navigate to={fallback} replace />} /><Route path="/activity" element={hasPermission('scans.read') ? <ActivityPage /> : <Navigate to={fallback} replace />} /><Route path="/notifications" element={hasPermission('notifications.manage') ? <Notifications /> : <Navigate to={fallback} replace />} /><Route path="/users" element={hasPermission('users.manage') ? <Users /> : <Navigate to={fallback} replace />} /><Route path="/audit" element={hasPermission('audit.read') ? <Audit /> : <Navigate to={home} replace />} /><Route path="/public-dashboard" element={hasPermission('public_dashboard.manage') ? <PublicDashboardAdmin publicSlug={unit?.slug} /> : <Navigate to={fallback} replace />} /><Route path="/scanner-profiles" element={hasPermission('scanner_profiles.read') ? <ScannerProfiles /> : <Navigate to={fallback} replace />} /><Route path="/security" element={<Security />} /><Route path="*" element={<Navigate to={home} replace />} /></Routes></PageErrorBoundary></div></main>
  </div>
}

function JobCreationJourney() {
  return <JobCreationDraftProvider>
    <Routes>
      <Route index element={<MonitorSetup />} />
      <Route path="advanced" element={<JobEditor />} />
      <Route path="*" element={<Navigate to="/jobs/new" replace />} />
    </Routes>
  </JobCreationDraftProvider>
}

export function Jobs() {
  const navigate = useNavigate()
  const jobs = useQuery({ queryKey: ['jobs', true], queryFn: () => listJobs(true), refetchInterval: 30_000 })
  const session = useQuery({ queryKey: ['session'], queryFn: getSession })
  const [filter, setFilter] = useState<'all' | 'attention'>('all')
  const canWrite = session.data?.permissions.includes('jobs.write') ?? false
  const canReadScans = session.data?.permissions.includes('scans.read') ?? false
  const allJobs = jobs.data?.jobs ?? []
  const visibleJobs = filter === 'attention' ? allJobs.filter(job => job.monitoring?.attention_reason !== undefined && job.monitoring.attention_reason !== 'none') : allJobs
  const unavailableMonitoringCount = allJobs.filter(job => !job.monitoring || job.monitoring.availability !== 'available').length
  return (
    <section className="page">
      <div className="page-heading">
        <div>
          <p className="eyebrow">Configuration</p>
          <h1>Jobs</h1>
          <p className="muted">Each job owns its targets, protocols, schedule, and baseline.</p>
        </div>
        {canWrite && <button className="button primary" onClick={() => navigate('/jobs/new')}>＋ New job</button>}
      </div>
      <ScanSlotDemandNotice />
      {jobs.isLoading ? <Loading /> : jobs.error ? <ErrorNotice message="Could not load jobs." onRetry={() => jobs.refetch()} /> : (
        <>
          <div className="job-list-controls">
            <label htmlFor="jobs-filter">Filter jobs
              <select id="jobs-filter" value={filter} onChange={event => setFilter(event.target.value as 'all' | 'attention')}>
                <option value="all">All jobs</option>
                <option value="attention">Needs attention</option>
              </select>
            </label>
            <p className="muted" role="status" aria-live="polite">Showing {visibleJobs.length} of {allJobs.length} jobs</p>
          </div>
          {filter === 'attention' && unavailableMonitoringCount > 0 ? <p className="job-monitoring-unavailable" role="status">Monitoring data is incomplete for {unavailableMonitoringCount} job{unavailableMonitoringCount === 1 ? '' : 's'}; known attention reasons remain visible in this filter.</p> : null}
          {filter === 'attention' && allJobs.length > 0 && visibleJobs.length === 0 ? <div className="empty"><h3>No available jobs need attention</h3><p>No available job shows a latest failed or incomplete attempt, a stalled cycle, or a saved probe-budget skip.</p></div> : null}
          <div className="job-grid">
          {visibleJobs.map(job => {
            const baseline = baselinePresentation(job.baseline)
            const state = jobStatePresentation(job.archived, job.enabled)
            return (
              <article className={job.archived ? 'job-card archived' : 'job-card'} key={job.id} aria-labelledby={`job-title-${job.id}`}>
                <div className="job-card-top">
                  <span className={`pill ${state.tone}`}>{state.label}</span>
                  <span className="revision">r{job.revision}</span>
                </div>
                <h3 id={`job-title-${job.id}`}><Link to={`/jobs/${job.id}`}>{job.job.name}</Link></h3>
                <p className="muted">{job.job.targets.length} target{job.job.targets.length === 1 ? '' : 's'} · {protocolSummary(job)}</p>
                <div className="job-card-bottom">
                  <span className={`baseline${baseline.status === 'complete' ? ' complete' : baseline.status === 'stalled' ? ' stalled' : ''}`}>
                    {baseline.marker} {baseline.status === 'complete' ? `Baseline ${baseline.label.toLowerCase()}` : baseline.status === 'stalled' ? 'Baseline stalled' : `Collecting ${job.baseline.samples ?? 0}/${job.job.baseline_samples}`}
                  </span>
                  <span>{job.job.schedule}</span>
                </div>
                <JobMonitoringStatus job={job} canReadScans={canReadScans} />
                <JobChangeWindowStatus status={job.change_window} jobID={job.id} />
              </article>
            )
          })}
          {!allJobs.length && canWrite && <Empty title="No jobs yet" body="Create your first TCP or UDP monitoring job." action={<button className="button primary" onClick={() => navigate('/jobs/new')}>Create a job</button>} />}
          {!allJobs.length && !canWrite && <Empty title="No jobs configured" body="An operator can create a monitoring job for this EdgeWatch instance." />}
          </div>
        </>
      )}
    </section>
  )
}

function JobMonitoringStatus({ job, canReadScans }: { job: Job; canReadScans: boolean }) {
  const monitoring = job.monitoring
  if (!monitoring) {
    return <p className="job-monitoring-unavailable" role="status">Monitoring status unavailable.</p>
  }
  const attempt = monitoring.latest_attempt
  const successful = monitoring.latest_successful_scan
  const attemptTime = attempt?.finished_at || attempt?.started_at
  const successTime = successful?.finished_at || successful?.started_at
  const activityLabel = monitoring.activity === 'queued' ? 'Queued'
    : monitoring.activity === 'running' ? 'Running'
      : monitoring.activity === 'in_progress' ? `Scan cycle in progress (${monitoring.cycle_completed_units} of ${monitoring.cycle_total_units} units)`
      : monitoring.activity === 'resumable' ? 'Saved work can be resumed'
        : monitoring.activity === 'stalled' ? 'Stalled cycle needs a manual retry'
          : monitoring.activity === 'none' ? 'No current scan or resumable cycle'
            : 'Current work status unavailable'
  const scheduleLabel = monitoring.schedule_state === 'paused' ? 'Paused · no scheduled run'
    : monitoring.schedule_state === 'manual' ? 'Manual runs only'
      : monitoring.schedule_state === 'archived' ? 'Archived · no scheduled run'
        : 'Schedule unavailable'
  const attentionLabel = monitoring.attention_reason === 'failed' ? 'Latest scan failed'
    : monitoring.attention_reason === 'incomplete' ? 'Latest scan incomplete'
      : monitoring.attention_reason === 'stalled_cycle' ? 'Scan cycle stalled'
        : monitoring.attention_reason === 'probe_budget_skipped' ? 'Last scheduled run skipped (probe budget)'
        : undefined
  return (
    <div className="job-monitoring" aria-label={`Monitoring summary for ${job.job.name}`}>
      <div className="job-monitoring-heading">
        <strong>Monitoring</strong>
        {attentionLabel && <span className="pill amber">Needs attention · {attentionLabel}</span>}
      </div>
      {monitoring.availability === 'unavailable' && <p className="job-monitoring-unavailable" role="status">Some monitoring status is unavailable; known details remain shown.</p>}
      <dl className="job-monitoring-grid">
        <div>
          <dt>Latest attempt</dt>
          <dd>{!monitoring.history_available ? 'Unavailable' : attempt ? `${attempt.status.replaceAll('_', ' ')}${monitoring.cycle_in_progress ? ' · saved progress' : ''}` : 'No scan recorded yet'}</dd>
          {monitoring.history_available && attempt && <small>{attemptTime ? formatDateTime(attemptTime) : 'Unknown time'}</small>}
          {canReadScans && attempt?.scan_id && <Link className="job-scan-link" to={`/jobs/${job.id}/scans/${attempt.scan_id}`}>View attempt</Link>}
        </div>
        <div>
          <dt>Last successful scan</dt>
          <dd>{!monitoring.history_available ? 'Unavailable' : successful ? (successTime ? formatDateTime(successTime) : 'Unknown time') : 'No successful scan yet'}</dd>
          {canReadScans && successful?.scan_id && <Link className="job-scan-link" to={`/jobs/${job.id}/scans/${successful.scan_id}`}>View successful scan</Link>}
        </div>
        <div>
          <dt>Current work</dt>
          <dd>{activityLabel}</dd>
          {monitoring.activity === 'resumable' && <small>Resume saved progress from job details.</small>}
          {monitoring.activity === 'in_progress' && <small>Resume saved progress from job details.</small>}
          {monitoring.attention_reason === 'stalled_cycle' && <small>Review the saved cycle from job details.</small>}
        </div>
        <div>
          <dt>Next scheduled run</dt>
          <dd>{monitoring.schedule_state === 'scheduled' && monitoring.next_run_at ? formatDateTimeInTimeZone(monitoring.next_run_at, monitoring.timezone) : scheduleLabel}</dd>
          {monitoring.schedule_state === 'scheduled' && monitoring.next_run_at && <small>Scheduler timezone: {monitoring.timezone}</small>}
        </div>
      </dl>
    </div>
  )
}

function JobChangeWindowStatus({ status, jobID }: { status: ChangeWindowStatus | null | undefined; jobID: string }) {
  if (!status) return null
  const label = status.review_state === 'due' ? 'Review due'
    : status.review_state === 'reviewed' ? 'Reviewed'
      : status.status === 'scheduled' ? 'Scheduled'
        : status.status === 'active' ? 'Active'
          : status.status === 'cancelled' ? 'Cancelled'
            : status.end_reason === 'expired' ? 'Expired'
              : 'Closed'
  const tone = status.review_state === 'due' || status.status === 'active' ? 'amber'
    : status.review_state === 'reviewed' ? 'green'
      : status.status === 'scheduled' ? 'blue'
        : 'gray'
  const end = status.closed_at || status.end_at
  const eventCount = status.suppressed_event_count
  return <div className="job-change-window-status" aria-label={`Planned change window for job ${jobID}`}>
    <div className="job-change-window-status-heading"><strong>Planned change window</strong><span className={`pill ${tone}`}>{label}</span></div>
    <p>{status.reason}</p>
    <dl>
      <div><dt>Start</dt><dd><time dateTime={status.start_at}>{formatChangeWindowTime(status.start_at, status.timezone)}</time></dd></div>
      <div><dt>End</dt><dd><time dateTime={end}>{formatChangeWindowTime(end, status.timezone)}</time></dd></div>
    </dl>
    <p className="job-change-window-counts">{eventCount} change event{eventCount === 1 ? '' : 's'} held · {status.new_count} new · {status.recovered_count} recovered · {status.still_open_count} still open{status.in_flight_event_count > 0 ? ` · ${status.in_flight_event_count} in flight at close` : ''}{status.unknown_outcome_event_count > 0 ? ` · ${status.unknown_outcome_event_count} with unknown prior outcome` : ''}{status.incomplete_event_count > 0 ? ` · ${status.incomplete_event_count} older events with incomplete identities` : ''}</p>
    <Link className="job-change-window-details-link" to={`/jobs/${encodeURIComponent(jobID)}`}>Open window details</Link>
  </div>
}

function protocolSummary(job: { job: { tcp?: { ports: string }; udp?: { ports: string } } }) {
  return [
    job.job.tcp && `TCP · ${compactPortExpression(job.job.tcp.ports)}`,
    job.job.udp && `UDP · ${compactPortExpression(job.job.udp.ports)}`,
  ].filter(Boolean).join(' · ')
}

export function ProtectedApp({ onLogout }: { onLogout: () => Promise<void> }) { const status = useQuery({ queryKey: ['setup-status'], queryFn: setupStatus }); const session = useQuery({ queryKey: ['session'], queryFn: async () => { const value = await getSession(); setCSRF(value.csrf_token); return value }, retry: false }); const navigate = useNavigate(); const location = useLocation(); useEffect(() => { if (session.error && !session.data && status.data?.configured) navigate('/login') }, [session.error, session.data, status.data, navigate])
  // A refused request re-reads the session, so the console follows a session
  // that changed on the server: a second business unit restricts an
  // administrator without TOTP to the enrolment below, and a role change
  // changes the navigation. A refusal that arrives while a read is in flight
  // waits for that read instead of starting another.
  const client = useQueryClient(); useEffect(() => setForbiddenHandler(() => client.refetchQueries({ queryKey: ['session'], exact: true }, { cancelRefetch: false })), [client])
  // Enabling TOTP lifts the enrolment requirement while the one-time recovery
  // codes are still on screen. Stay on the enrolment screen until sign-out,
  // which ends it, so a session refresh cannot unmount the codes.
  const mustEnrol = !!session.data?.totp_enrollment_required; const [enrolling, setEnrolling] = useState(false); useEffect(() => { if (mustEnrol) setEnrolling(true) }, [mustEnrol])
  if (status.isLoading || session.isLoading) return <Loading />; if (!status.data?.configured) return <Navigate to="/setup" replace />
  // A read that fails keeps the session that the console holds; only a
  // session that ended (401) or never began leaves it without one.
  if (!session.data) return <Navigate to="/login" replace />; const displayName = session.data?.display_name ?? session.data?.username ?? 'admin'; const permissions = session.data?.permissions ?? []
  // An administrator who must enrol TOTP first gets only the enrolment, a
  // password change, and sign-out. A platform administrator gets the
  // platform console, which never mounts a unit's pages.
  if (mustEnrol || enrolling) return <TotpEnrollmentShell displayName={displayName} onLogout={onLogout} />
  // Signing in mounts this console while the address is still the sign-in
  // page, before the sign-in page's own navigation lands, and every shell
  // sends /login to its home page. Open the page that sent the visitor to
  // sign in instead. Its permission redirects still apply, and its address
  // records no return path, so this redirect happens once.
  const returnPath = location.pathname === '/login' ? signInReturnPath(location.state) : null
  if (returnPath) return <><Navigate to={returnPath} replace /><Loading /></>
  if (session.data?.scope === 'platform') return <PlatformShell displayName={displayName} permissions={permissions} onLogout={onLogout} />
  return <Shell displayName={displayName} role={session.data?.role ?? 'viewer'} permissions={permissions} onLogout={onLogout} unit={session.data?.multi_unit ? session.data.unit : null} /> }

export function AuthRoutes({ configured }: { configured: boolean }) { const location = useLocation(); return <Routes><Route path="/setup" element={<Setup />} /><Route path="/activate" element={<Activate />} /><Route path="/login" element={<Login />} /><Route path="*" element={configured ? <Navigate to="/login" replace state={{ from: { pathname: location.pathname, search: location.search } }} /> : <Navigate to="/setup" replace />} /></Routes> }

export function App() { return <BrowserRouter><AppContent /></BrowserRouter> }

/**
 * The account and business unit that a session belongs to. The console's
 * cached data belongs to them.
 */
function sessionIdentity(session: SessionUser | null | undefined) {
  return session ? JSON.stringify([session.user_id, session.scope, session.unit?.id ?? null]) : null
}

/**
 * While EdgeWatch does not answer, as while it restarts, a read that failed
 * after an earlier one succeeded is repeated this often, in milliseconds,
 * until it answers.
 */
const reconnectInterval = 3_000

function reconnectWhileFailing(query: { state: { status: string; data: unknown; error: unknown } }) {
  // An initial transient failure has no cached data either. Only a 401 is an
  // authoritative sign-out; other failures can recover while the cookie is
  // still valid, including when the service was restarting on first load.
  const endedSession = query.state.error instanceof APIError && query.state.error.status === 401
  return query.state.status === 'error' && !endedSession ? reconnectInterval : false
}

export function AppContent() {
  const location = useLocation()
  const client = useQueryClient()
  // /public serves the default business unit's page, and /public/<slug> the
  // page of the business unit with that slug.
  const publicMatch = /^\/public(?:\/([^/]+))?\/?$/.exec(location.pathname)
  const isPublic = publicMatch !== null
  const publicSlug = publicMatch?.[1] ? decodePathSegment(publicMatch[1]) : undefined
  const [signedOut, setSignedOut] = useState(false)
  // The public highlights page is deliberately independent of setup/session
  // state. This avoids an unnecessary authenticated request and keeps the
  // unauthenticated route usable while the administrator is signed out.
  // A read that fails while the console holds a session and the setup
  // status, as while EdgeWatch restarts, keeps both and is repeated until
  // it answers.
  // Unlike the authenticated session read, status has to recover when a
  // service is unavailable on the very first page load (there is no cached
  // value yet). Keep retrying this safe, unauthenticated endpoint while it
  // fails so the connection screen can return to the application on its own.
  const status = useQuery({ queryKey: ['setup-status'], queryFn: setupStatus, retry: false, refetchInterval: query => query.state.status === 'error' ? reconnectInterval : false, enabled: !isPublic })
  const session = useQuery({ queryKey: ['session'], queryFn: async () => { const value = await getSession(); setCSRF(value.csrf_token); return value }, retry: false, refetchInterval: reconnectWhileFailing, enabled: !isPublic })
  useEffect(() => {
    // A session that ends on the server, by idle expiry, revocation, or its
    // account or unit being disabled, leaves nothing of its account behind,
    // as a sign-out does: the next account to sign in on this tab must not
    // see the previous one's cached data. Only the anonymous setup status is
    // kept, together with its read in flight, so the sign-in page shows at
    // once.
    function handleUnauthorized() {
      setCSRF('')
      client.removeQueries({ predicate: query => query.queryKey[0] !== 'setup-status' })
      client.getMutationCache().clear()
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
  useEffect(() => {
    // A session read can find another account than the one whose data the
    // cache holds without any 401: another tab of the browser signed out and
    // signed in as someone else, which replaced the shared cookie. That
    // account must not see the previous one's cached data either, so the
    // cache is dropped as after a 401, keeping the setup status and the new
    // session, before the console renders the new session. A read that finds
    // the same account keeps the cache. Every page's session query shares
    // this entry, so the check follows the cache, not one query function,
    // and it applies the CSRF token of the session that was read.
    let identity = sessionIdentity(client.getQueryData<SessionUser | null>(['session']))
    return client.getQueryCache().subscribe(event => {
      if (event.type !== 'updated' || event.action.type !== 'success' || event.query.queryKey.length !== 1 || event.query.queryKey[0] !== 'session') return
      const value = event.query.state.data as SessionUser | null | undefined
      const next = sessionIdentity(value)
      if (identity !== null && next !== null && next !== identity) {
        client.removeQueries({ predicate: query => query.queryKey[0] !== 'setup-status' && query !== event.query })
        client.getMutationCache().clear()
      }
      identity = next
      if (value) setCSRF(value.csrf_token)
    })
  }, [client])
  // Only a session that ended signs the console out, which the 401 handler
  // above records. A read that fails otherwise, with a network error or a
  // 5xx, keeps the console and what was typed in it, says that it
  // reconnects, and is repeated until EdgeWatch answers.
  const authenticated = !signedOut && !!session.data
  const reconnecting = (!!session.data && (session.isError || session.failureCount > 0)) || (!!status.data && (status.isError || status.failureCount > 0))
  // An activation or password-reset link sets the password of the account it
  // was issued for, so a browser that holds a session keeps it until the
  // visitor signs out instead of opening the signed-in console on it.
  const activationLink = /^\/activate\/?$/.test(location.pathname) && activationTokenFromLocation(location.search, location.hash) !== ''
  async function handleLogout() {
    try { await apiLogout() } catch { /* The server clears the cookie before reporting audit errors. */ }
    finally { setCSRF(''); client.clear(); client.setQueryData(['session'], null); setSignedOut(true) }
  }
  if (isPublic) return <PublicDashboard slug={publicSlug} />
  if (status.isLoading || session.isLoading) return <Loading />
  if (status.error && !status.data) return <main className="connection-error-page"><section className="connection-error-card"><div className="brand light"><span className="brand-mark"><Wifi size={19} /></span><span>EdgeWatch</span></div><div><p className="eyebrow">Service connection</p><h1>EdgeWatch is not responding</h1><p className="muted">Check that the service is running, then retry. The page will also reconnect automatically.</p></div><ErrorNotice message="Unable to contact EdgeWatch." retryLabel="Reload status" onRetry={() => status.refetch()} /></section></main>
  const notice = reconnecting ? <div className="connection-notice" role="status">Cannot reach EdgeWatch. Reconnecting…</div> : null
  if (!status.data?.configured || !authenticated) return <>{notice}<AuthGate statusConfigured={!!status.data?.configured} /></>
  if (activationLink) return <>{notice}<SignedInActivation displayName={session.data?.display_name} username={session.data?.username ?? ''} onSignOut={handleLogout} /></>
  // Another account's session mounts a new console, which keeps nothing of
  // the previous account's pages.
  return <>{notice}<ProtectedApp key={sessionIdentity(session.data)} onLogout={handleLogout} /></>
}

function AuthGate({ statusConfigured }: { statusConfigured: boolean }) { return <AuthRoutes configured={statusConfigured} /> }

// A malformed escape is passed on as typed; the server answers it as a page
// that is not published.
function decodePathSegment(value: string) {
  try { return decodeURIComponent(value) } catch { return value }
}

function Loading() { return <div className="loading"><span className="spinner" />Loading EdgeWatch…</div> }
function Empty({ icon, title, body, action }: { icon?: React.ReactNode; title: string; body: string; action?: React.ReactNode }) { return <div className="empty"><div className="empty-icon">{icon ?? <Boxes size={23} />}</div><h3>{title}</h3><p>{body}</p>{action}</div> }

const rootElement = document.getElementById('root')
if (rootElement) createRoot(rootElement).render(<StrictMode><QueryClientProvider client={queryClient}><App /></QueryClientProvider></StrictMode>)
