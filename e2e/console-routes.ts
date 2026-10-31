import { rolePermissions, type ConsoleRole } from './mock-console'

/**
 * This file is the inventory of every page the console renders. The axe
 * audit in route-accessibility.spec.ts and the role matrix in
 * role-matrix.spec.ts iterate it, and src/console-route-inventory.test.ts,
 * which `npm run test:coverage` runs before the browser tests, compares it
 * with the routers: every `<Route>` in src, every page that src chooses from
 * the path outside a `<Route>`, and every UnitDetail tab needs an entry here
 * or a reasoned exclusion in `routesWithoutInventoryEntry`, and every entry
 * must still reach the route it stands for. Paths are concrete
 * examples; the check matches them with React Router, so `:id` and the other
 * parameters match any value.
 */
export type ConsoleRouteCase = {
  path: string
  /** unit: the unit console (Shell); platform: PlatformShell; shared: both shells. */
  scope: 'unit' | 'platform' | 'shared'
  permission?: string
  allowedPath?: string
  deniedToHome?: boolean
  redirectToHome?: boolean
}

/**
 * Representative paths for every route rendered by the authenticated unit
 * console, including the nested job-creation routes and both host-detail
 * routes. The pages outside either console shell are in `entrySurfaces`.
 * Redirect-only console routes remain in this inventory so each role's
 * actual route behavior is still checked.
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

/**
 * The router of each console scope, named by the component that renders its
 * `<Routes>`. A shared entry must reach a page in each of them.
 */
export const consoleScopeRouters: Record<ConsoleRouteCase['scope'], string[]> = {
  unit: ['Shell'],
  platform: ['PlatformShell'],
  shared: ['Shell', 'PlatformShell'],
}

export type EntrySurfaceCase = {
  /** The address to open. The inventory check reads only its path. */
  path: string
  /**
   * The component whose `<Routes>` serve the page, or AppContent for the
   * pages that it chooses from the path before any router: the public status
   * pages, and the account-link notice that a signed-in browser shows for an
   * activation or password-reset link. Its `pathReaders` entry in
   * src/console-route-inventory.test.ts lists the routes it serves.
   */
  router: 'AuthRoutes' | 'TotpEnrollmentShell' | 'AppContent'
  /**
   * The session that shows the page: signed-out and unconfigured have no
   * session, on an installation that is set up or not; signed-in is an
   * administrator's session; enrolment is a platform administrator without
   * TOTP once two units exist, which may only enrol; public needs none and
   * reads no console data.
   */
  state: 'signed-out' | 'unconfigured' | 'signed-in' | 'enrolment' | 'public'
  /** The level-one heading that shows that the page rendered. */
  heading: string
}

/**
 * The pages a visitor reaches outside either console shell: sign-in,
 * first-run setup, account activation, both signed out and in a browser
 * that is still signed in, the TOTP enrolment that restricts a session until
 * it is done, and the public status pages, both published and unavailable.
 * The axe audit opens each with the mock console's fixtures.
 */
export const entrySurfaces: EntrySurfaceCase[] = [
  { path: '/login', router: 'AuthRoutes', state: 'signed-out', heading: 'Sign in to EdgeWatch' },
  { path: '/setup', router: 'AuthRoutes', state: 'unconfigured', heading: 'Create your administrator' },
  { path: '/activate#token=FIXTURE-TOKEN', router: 'AuthRoutes', state: 'signed-out', heading: 'Choose your password' },
  { path: '/activate#token=FIXTURE-TOKEN', router: 'AppContent', state: 'signed-in', heading: 'You are already signed in' },
  { path: '/security', router: 'TotpEnrollmentShell', state: 'enrolment', heading: 'Set up an authenticator' },
  { path: '/public', router: 'AppContent', state: 'public', heading: 'Fixture public status' },
  { path: '/public/retail', router: 'AppContent', state: 'public', heading: 'Retail status' },
  { path: '/public/unpublished', router: 'AppContent', state: 'public', heading: 'Public status unavailable' },
]

export type RouteExclusion = {
  /** The component that renders the route's `<Routes>`. */
  router: string
  /** The route's full path pattern, as the inventory check reports it. */
  path: string
  reason: string
}

/**
 * Routes that render no page of their own and so have no inventory entry.
 * The inventory check fails when a route is neither listed above nor here,
 * and when an exclusion no longer names a route.
 */
export const routesWithoutInventoryEntry: RouteExclusion[] = [
  {
    router: 'AuthRoutes',
    path: '*',
    reason: 'Renders no page: it sends every other signed-out address to /login with the requested page as its return path, or to /setup before setup; sign-in-return.spec.ts checks the redirect and the return.',
  },
  {
    router: 'TotpEnrollmentShell',
    path: '*',
    reason: 'Renders no page: it sends every address of a session that must enrol TOTP to /security, the enrolment page in entrySurfaces; platform-console.spec.ts checks that the session lands there.',
  },
]

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
