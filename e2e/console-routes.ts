import { rolePermissions, type ConsoleRole } from './mock-console'

export type ConsoleRouteCase = {
  path: string
  scope: 'unit' | 'platform' | 'shared'
  permission?: string
  allowedPath?: string
  deniedToHome?: boolean
  redirectToHome?: boolean
}

/**
 * Representative paths for every route rendered by the authenticated unit
 * console, including the nested job-creation routes and both host-detail
 * routes. The auth pages (/setup, /activate, /login) and public status routes
 * (/public and /public/:slug) are outside either console shell and have their
 * own browser coverage: admin.spec.ts enters /setup from /, sign-in-return and
 * signed-in-account-link exercise /login and /activate, and public-dashboard
 * and real-stack-units exercise the public routes. Redirect-only console
 * routes remain in this inventory so each role's actual route behavior is
 * still checked.
 */
export const unitConsoleRoutes: ConsoleRouteCase[] = [
  { path: '/', scope: 'unit', permission: 'overview.read' },
  { path: '/highlights', scope: 'unit', permission: 'public_dashboard.manage', allowedPath: '/public-dashboard', deniedToHome: true },
  { path: '/jobs', scope: 'unit', permission: 'jobs.read' },
  { path: '/jobs/new', scope: 'unit', permission: 'jobs.write' },
  { path: '/jobs/new/advanced', scope: 'unit', permission: 'jobs.write' },
  { path: '/jobs/new/unmatched/branch', scope: 'unit', permission: 'jobs.write', allowedPath: '/jobs/new' },
  { path: '/jobs/job-1', scope: 'unit', permission: 'jobs.read' },
  { path: '/jobs/job-1/edit', scope: 'unit', permission: 'jobs.write' },
  { path: '/jobs/job-1/baseline', scope: 'unit', permission: 'baselines.read' },
  { path: '/jobs/job-1/baseline/hosts/192.0.2.10', scope: 'unit', permission: 'baselines.read' },
  { path: '/jobs/job-1/scans/scan-1', scope: 'unit', permission: 'scans.read' },
  { path: '/jobs/job-1/scans/scan-1/hosts/192.0.2.10', scope: 'unit', permission: 'scans.read' },
  { path: '/hosts', scope: 'unit', permission: 'hosts.read' },
  { path: '/perimeter', scope: 'unit', permission: 'perimeter.read' },
  { path: '/perimeter/ranges/range-1', scope: 'unit', permission: 'perimeter.read' },
  { path: '/scans/scan-1', scope: 'unit', permission: 'scans.read' },
  { path: '/scans/scan-1/hosts/192.0.2.10', scope: 'unit', permission: 'scans.read' },
  { path: '/incidents', scope: 'unit', permission: 'incidents.read' },
  { path: '/activity', scope: 'unit', permission: 'scans.read' },
  { path: '/notifications', scope: 'unit', permission: 'notifications.manage' },
  { path: '/users', scope: 'unit', permission: 'users.manage' },
  { path: '/audit', scope: 'unit', permission: 'audit.read', deniedToHome: true },
  { path: '/public-dashboard', scope: 'unit', permission: 'public_dashboard.manage' },
  { path: '/scanner-profiles', scope: 'unit', permission: 'scanner_profiles.read' },
  { path: '/console-unknown', scope: 'unit', redirectToHome: true },
]

/** Every concrete platform page, including each supported unit-detail tab. */
export const platformConsoleRoutes: ConsoleRouteCase[] = [
  { path: '/platform/units', scope: 'platform', permission: 'units.manage' },
  { path: '/platform/units/unit-retail', scope: 'platform', permission: 'units.manage' },
  { path: '/platform/units/unit-retail/overview', scope: 'platform', permission: 'units.manage' },
  { path: '/platform/units/unit-retail/accounts', scope: 'platform', permission: 'units.manage' },
  { path: '/platform/units/unit-retail/capacity', scope: 'platform', permission: 'units.manage' },
  { path: '/platform/units/unit-retail/danger', scope: 'platform', permission: 'units.manage' },
  { path: '/platform/admins', scope: 'platform', permission: 'unit_accounts.manage' },
  { path: '/platform/notifications', scope: 'platform', permission: 'platform_notifications.manage' },
  { path: '/platform/audit', scope: 'platform', permission: 'platform_audit.read' },
  { path: '/platform/status', scope: 'platform', permission: 'platform_status.read' },
  { path: '/platform/unknown', scope: 'platform', redirectToHome: true },
  { path: '/security', scope: 'shared', permission: 'account.self' },
]

export const allConsoleRoutes = [...unitConsoleRoutes, ...platformConsoleRoutes]

function unitHome(role: ConsoleRole) {
  if (rolePermissions[role].includes('overview.read')) return '/'
  return rolePermissions[role].includes('jobs.read') ? '/jobs' : '/security'
}

function unitFallback(role: ConsoleRole) {
  return rolePermissions[role].includes('jobs.read') ? '/jobs' : '/security'
}

/** The final path after the console's real permission guard or shell redirect. */
export function expectedConsolePath(role: ConsoleRole, route: ConsoleRouteCase) {
  if (route.scope === 'unit' && role === 'platform_admin') return '/platform/units'
  if (route.scope === 'platform' && role !== 'platform_admin') return unitHome(role)
  if (route.redirectToHome) return role === 'platform_admin' ? '/platform/units' : unitHome(role)

  if (!route.permission || rolePermissions[role].includes(route.permission)) return route.allowedPath ?? route.path
  if (route.deniedToHome) return role === 'platform_admin' ? '/platform/units' : unitHome(role)
  return role === 'platform_admin' ? '/platform/units' : unitFallback(role)
}
