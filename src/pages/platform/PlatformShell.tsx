import type { ReactNode } from 'react'
import { useEffect, useRef } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link, Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { Activity, ArrowUp, BellRing, Building2, Code2, Landmark, LogOut, Menu, ScrollText, ShieldCheck, UsersRound, Wifi, X } from 'lucide-react'
import { platformStatus } from '../../api'
import { useActivityHeartbeat, useNavigationDrawer } from '../../components/navigation'
import { PageErrorBoundary } from '../../components/PageErrorBoundary'
import { Security } from '../Security'
import { Units } from './Units'
import { UnitDetail } from './UnitDetail'
import { PlatformAdmins } from './PlatformAdmins'
import { PlatformNotifications } from './PlatformNotifications'
import { PlatformAudit } from './PlatformAudit'
import { PlatformStatusPage } from './PlatformStatus'

/**
 * The console of a platform administrator. It manages the business units,
 * their administrators and capacity, the platform administrators, and the
 * platform's own notifications, and reads the platform audit and status. It
 * has no route to a unit's pages: the overview, jobs, hosts, incidents, and
 * every other unit address lead to the platform's home, so no unit data is
 * ever requested here, and there is no live-update stream.
 */
export function PlatformShell({ displayName, permissions, onLogout }: { displayName: string; permissions: string[]; onLogout: () => void }) {
  const { open, setOpen, isMobile, menuButtonRef, drawerRef } = useNavigationDrawer()
  useActivityHeartbeat()
  const location = useLocation()
  const mainRef = useRef<HTMLElement | null>(null)
  const previousPath = useRef(location.pathname)
  const has = (permission: string) => permissions.includes(permission)
  const status = useQuery({ queryKey: ['platform-status'], queryFn: platformStatus, enabled: has('platform_status.read'), staleTime: 60_000, refetchInterval: 60_000 })
  const version = status.data?.version ?? 'dev'
  const versionReleaseURL = status.data?.version_release_url
  const update = status.data?.updates
  const updateAvailable = !!update && (update.available === true || update.status === 'update_available')
  const links = [
    ...(has('units.manage') ? [{ to: '/platform/units', label: 'Units', icon: Building2 }] : []),
    ...(has('unit_accounts.manage') ? [{ to: '/platform/admins', label: 'Platform admins', icon: UsersRound }] : []),
    ...(has('platform_notifications.manage') ? [{ to: '/platform/notifications', label: 'Notifications', icon: BellRing }] : []),
    ...(has('platform_audit.read') ? [{ to: '/platform/audit', label: 'Audit', icon: ScrollText }] : []),
    ...(has('platform_status.read') ? [{ to: '/platform/status', label: 'Status', icon: Activity }] : []),
    { to: '/security', label: 'Security', icon: ShieldCheck },
  ]
  const home = links[0].to
  const isActive = (to: string) => location.pathname === to || location.pathname.startsWith(`${to}/`)
  const currentLabel = links.find(link => isActive(link.to))?.label ?? links[0].label
  const breadcrumb = `Platform / ${currentLabel}`
  const guard = (permission: string, element: ReactNode) => has(permission) ? element : <Navigate to={home} replace />
  useEffect(() => {
    document.title = `${currentLabel} · EdgeWatch`
    if (previousPath.current !== location.pathname) {
      previousPath.current = location.pathname
      mainRef.current?.focus({ preventScroll: true })
    }
  }, [currentLabel, location.pathname])
  return <div className="app-shell platform-shell">
    <a className="skip-link" href="#main-content">Skip to content</a>
    <aside id="primary-navigation" ref={drawerRef} role={isMobile && open ? 'dialog' : undefined} aria-label="Primary navigation" aria-modal={isMobile && open ? true : undefined} aria-hidden={isMobile ? !open : undefined} inert={isMobile ? !open : undefined} className={open ? 'sidebar open' : 'sidebar'}>
      <div className="brand"><span className="brand-mark"><Wifi size={19} /></span><span>EdgeWatch</span><button type="button" className="drawer-close" aria-label="Close navigation" onClick={() => setOpen(false)}><X size={19} /></button></div>
      <div className="unit-chip platform" title="Platform console: no unit data"><Landmark size={15} aria-hidden="true" /><span><small>Platform console</small><strong>All business units</strong></span></div>
      <nav>{links.map(({ to, label, icon: Icon }) => <Link key={to} to={to} onClick={() => setOpen(false)} aria-current={isActive(to) ? 'page' : undefined} className={`nav-link${isActive(to) ? ' active' : ''}`}><Icon size={18} /><span className="nav-link-label">{label}</span></Link>)}</nav>
      <div className="sidebar-bottom"><div className="user-chip"><span className="avatar">{displayName.trim().charAt(0).toUpperCase() || 'P'}</span><span><small className="app-version">{versionReleaseURL ? <a className="version-link" href={versionReleaseURL} target="_blank" rel="noopener noreferrer" aria-label={`Release notes for EdgeWatch ${version}`} title={`Release notes for EdgeWatch ${version}`}>EdgeWatch {version}</a> : <>EdgeWatch {version}</>}{updateAvailable && update.release_url && <a className="version-update" href={update.release_url} target="_blank" rel="noopener noreferrer" aria-label={`Update available: ${version} to ${update.latest_version ?? 'new release'}`} title={`Update available: ${version} to ${update.latest_version ?? 'new release'}`}><ArrowUp size={13} aria-hidden="true" /></a>}</small><strong>{displayName}</strong><small>Platform administrator</small></span></div><a className="nav-link quiet" href="/source" target="_blank" rel="noopener noreferrer"><Code2 size={17} aria-hidden="true" />Source code</a><button className="nav-link quiet" onClick={onLogout}><LogOut size={17} />Sign out</button></div>
    </aside>
    {open && isMobile && <button type="button" aria-label="Close navigation" tabIndex={-1} className="backdrop" onClick={() => setOpen(false)} />}
    <main ref={mainRef} id="main-content" tabIndex={-1} className="main" inert={isMobile && open ? true : undefined} aria-hidden={isMobile && open ? true : undefined}>
      <header className="topbar"><button ref={menuButtonRef} type="button" aria-label={open ? 'Close navigation' : 'Open navigation'} aria-controls="primary-navigation" aria-expanded={isMobile ? open : false} className="menu-button" onClick={() => setOpen(true)}><Menu size={21} /></button><nav className="breadcrumb" title={breadcrumb} aria-label={`Breadcrumb: ${breadcrumb}`}><span className="platform-breadcrumb-prefix">Platform / </span><span>{currentLabel}</span></nav><div className="topbar-actions"><span className="pill amber" title="The platform console never shows a unit's jobs, scans, hosts, or incidents">Platform console</span></div></header>
      <div className="content"><PageErrorBoundary resetKey={location.key} homePath={home} homeLabel={links[0].label}><Routes>
        <Route path="/platform/units" element={guard('units.manage', <Units />)} />
        <Route path="/platform/units/:id" element={guard('units.manage', <UnitDetail permissions={permissions} />)} />
        <Route path="/platform/units/:id/:tab" element={guard('units.manage', <UnitDetail permissions={permissions} />)} />
        <Route path="/platform/admins" element={guard('unit_accounts.manage', <PlatformAdmins />)} />
        <Route path="/platform/notifications" element={guard('platform_notifications.manage', <PlatformNotifications />)} />
        <Route path="/platform/audit" element={guard('platform_audit.read', <PlatformAudit />)} />
        <Route path="/platform/status" element={guard('platform_status.read', <PlatformStatusPage />)} />
        <Route path="/security" element={<Security />} />
        <Route path="*" element={<Navigate to={home} replace />} />
      </Routes></PageErrorBoundary></div>
    </main>
  </div>
}
