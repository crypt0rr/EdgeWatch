import AxeBuilder from '@axe-core/playwright'
import { expect, test, type Page, type TestInfo } from '@playwright/test'
import { allConsoleRoutes, entrySurfaces, expectedConsolePath, type EntrySurfaceCase } from './console-routes'
import { mockConsole, mockPublicStatus, rolePermissions, type ConsoleRole } from './mock-console'

const roles: ConsoleRole[] = ['administrator', 'operator', 'viewer', 'platform_admin']
const auditedProjects = new Set(['desktop', 'mobile-narrow', 'iphone-13'])
const labelNameMismatchRule = 'label-content-name-mismatch'
// Each route starts a fresh document and then runs axe. Keep each test under
// Playwright's default 30-second limit even when an early route is complex.
const routeBatchSize = 3
const routeBatches = Array.from(
  { length: Math.ceil(allConsoleRoutes.length / routeBatchSize) },
  (_, index) => allConsoleRoutes.slice(index * routeBatchSize, (index + 1) * routeBatchSize),
)

// Axe rates these document-structure rules moderate, below the serious and
// critical violations that fail every audit, but a skipped heading level, a
// page without a level-one heading, or a missing or duplicated landmark
// breaks navigation by headings and regions, so they fail the gate too.
const structureRules = new Set(['heading-order', 'page-has-heading-one'])

type AxeViolation = Awaited<ReturnType<AxeBuilder['analyze']>>['violations'][number]

function gatesViolation(violation: AxeViolation) {
  return violation.impact === 'serious' || violation.impact === 'critical' || structureRules.has(violation.id) || violation.id.startsWith('landmark-')
}

type AxeAllowance = {
  rule: string
  /** The audited surface, as expectAccessible names it. */
  surface: string
  /** The node's axe target, its selectors joined by spaces. */
  target: string
  reason: string
}

/**
 * Violations that the gate accepts on one surface and node, each with its
 * reason. An entry that no longer matches a violation fails its audit, so
 * the list cannot outlive the markup it excuses. Every audited surface
 * passes without one today.
 */
const axeAllowances: AxeAllowance[] = []

/**
 * The gated violations of an axe run on one surface, one per node, except
 * the nodes that an allowance for that surface accepts, and the allowances
 * for the surface that accepted nothing.
 */
function gateFindings(violations: AxeViolation[], surface: string, allowances: AxeAllowance[]) {
  const candidates = allowances.filter(allowance => allowance.surface === surface)
  const used = new Set<AxeAllowance>()
  const blocking = violations.filter(gatesViolation).flatMap(violation => violation.nodes.flatMap(node => {
    const target = node.target.map(String).join(' ')
    const allowance = candidates.find(item => item.rule === violation.id && item.target === target)
    if (allowance) { used.add(allowance); return [] }
    return [`${violation.id} (${violation.impact}) at ${target}`]
  }))
  return { blocking, unused: candidates.filter(allowance => !used.has(allowance)).map(allowance => `${allowance.rule} at ${allowance.target}`) }
}

/**
 * Runs axe and fails on a visible label missing from an accessible name, on
 * every serious or critical violation, and on the structure rules above,
 * except where axeAllowances accepts the node.
 */
async function expectAccessible(page: Page, surface: string, context: string) {
  const results = await consoleAxe(page).analyze()
  const labelMismatches = results.violations.filter(violation => violation.id === labelNameMismatchRule)
  expect(labelMismatches, `${context} has visible link or button text missing from its accessible name`).toEqual([])
  const { blocking, unused } = gateFindings(results.violations, surface, axeAllowances)
  expect(blocking, `${context}: ${blocking.join('; ')}`).toEqual([])
  expect(unused, `${context} no longer has the violations that these axeAllowances entries accept; remove them`).toEqual([])
}

async function expectProjectDevice(page: Page, testInfo: TestInfo) {
  const { viewport } = testInfo.project.use
  expect(page.viewportSize()).toEqual(viewport)
  if (testInfo.project.name !== 'iphone-13') return

  const { screen, deviceScaleFactor, hasTouch, userAgent } = testInfo.project.use
  const device = await page.evaluate(() => ({
    screen: { width: window.screen.width, height: window.screen.height },
    deviceScaleFactor: window.devicePixelRatio,
    hasTouch: navigator.maxTouchPoints > 0,
    userAgent: navigator.userAgent,
  }))
  expect(device).toEqual({ screen, deviceScaleFactor, hasTouch, userAgent })
}

function consoleAxe(page: Page) {
  // Axe 4.13 tags this rule experimental and excludes it from the default run.
  return new AxeBuilder({ page }).options({
    rules: { [labelNameMismatchRule]: { enabled: true } },
  })
}

async function expectRouteDataReady(page: Page, routePath: string) {
  if (routePath === '/activity') {
    await expect(page.locator('.activity-event')).toContainText('Fixture activity event confirms a baseline change.')
  }
  if (routePath === '/scans/scan-1') {
    await expect(page.getByRole('heading', { name: 'fixture-job', exact: true })).toBeVisible()
    await expect(page.getByText('Scan scan-1', { exact: true })).toBeVisible()
    await expect(page.getByRole('heading', { name: 'Effective hosts', exact: true })).toBeVisible()
    await expect(page.getByRole('link', { name: /192\.0\.2\.10/ })).toBeVisible()
  }
  if (routePath === '/jobs' || routePath === '/perimeter') {
    const demand = page.getByRole('region', { name: 'Scan-slot demand' })
    await expect(demand).toContainText('Estimated scheduled demand is 1 slot-hours/day (50% of 2 available slot-hours/day across 2 scan slots).')
  }
}

function routeIsRenderedForRole(role: ConsoleRole, routePath: string) {
  const route = allConsoleRoutes.find(item => item.path === routePath)
  // The route matrix still checks these requested paths and their actual
  // destination. Aliases (/highlights and the unmatched job-creation branch),
  // permission redirects, and catch-all paths do not render a separate page;
  // their rendered destinations are audited through their own route entries.
  if (!route || route.redirectToHome || route.allowedPath) return false
  if (route.scope === 'shared') return true
  if (route.scope === 'platform') return role === 'platform_admin'
  return role !== 'platform_admin' && (!route.permission || rolePermissions[role].includes(route.permission))
}

for (const role of roles) {
  for (const [batchIndex, routes] of routeBatches.entries()) {
    test(`axe route batch ${batchIndex + 1}/${routeBatches.length} checks every rendered console route for ${role}`, async ({ page }, testInfo) => {
      test.skip(!auditedProjects.has(testInfo.project.name), 'The complete route matrix runs at desktop, narrow-mobile, and iPhone 13 widths; Pixel 7 covers additional phone regressions.')

      await expectProjectDevice(page, testInfo)
      await mockConsole(page, role, { routeAuditFixtures: true })

      for (const route of routes) {
        await page.goto(route.path)
        const expectedPath = expectedConsolePath(role, route)
        await expect.poll(() => new URL(page.url()).pathname).toBe(expectedPath)

        // A role that cannot open a page is sent to its permitted home or
        // fallback. The route matrix checks every requested path and final
        // destination; axe runs on pages the role can actually see.
        if (!routeIsRenderedForRole(role, route.path) || expectedPath !== route.path) continue

        const content = page.locator('#main-content .content')
        await expect(content.locator('.page').last()).toBeVisible()
        await page.waitForLoadState('networkidle')
        await expect(content.locator('.loading, .skeleton-list')).toHaveCount(0)
        await expectRouteDataReady(page, route.path)

        await expectAccessible(page, route.path, `${role} on ${route.path}`)
      }
    })
  }
}

/** The fixture state that shows each entry surface. */
async function openEntrySurface(page: Page, surface: EntrySurfaceCase) {
  switch (surface.state) {
    case 'signed-out': await mockConsole(page, 'administrator', { signedOut: true }); break
    case 'unconfigured': await mockConsole(page, 'administrator', { unconfigured: true }); break
    case 'enrolment': await mockConsole(page, 'platform_admin', { enrolmentRequired: true }); break
    case 'public': await mockConsole(page, 'administrator', { signedOut: true }); await mockPublicStatus(page); break
  }
  await page.goto(surface.path)
}

// The pages outside either console shell: sign-in, first-run setup,
// activation with a fixture token, the forced TOTP enrolment, and the public
// status pages. Each opens in a fresh page because each needs another
// session state.
for (const surface of entrySurfaces) {
  test(`axe audits the ${surface.state} surface at ${surface.path}`, async ({ page }, testInfo) => {
    test.skip(!auditedProjects.has(testInfo.project.name), 'The entry surfaces are audited at desktop, narrow-mobile, and iPhone 13 widths.')

    await expectProjectDevice(page, testInfo)
    await openEntrySurface(page, surface)
    await expect(page.getByRole('heading', { level: 1, name: surface.heading, exact: true })).toBeVisible()
    await expect.poll(() => new URL(page.url()).pathname).toBe(new URL(surface.path, page.url()).pathname)
    await page.waitForLoadState('networkidle')
    await expect(page.locator('.loading')).toHaveCount(0)
    await expectAccessible(page, surface.path, `${surface.state} visitor on ${surface.path}`)
  })
}

async function settle(page: Page) {
  await page.waitForLoadState('networkidle')
  await expect(page.locator('.loading, .skeleton-list')).toHaveCount(0)
}

// Page states that the route audit's default fixtures never render.
test('axe audits an open action dialog and its failed confirmation', async ({ page }, testInfo) => {
  test.skip(!auditedProjects.has(testInfo.project.name), 'The page states are audited at desktop, narrow-mobile, and iPhone 13 widths.')

  await expectProjectDevice(page, testInfo)
  const controls = await mockConsole(page, 'administrator', { routeAuditFixtures: true })
  await page.goto('/perimeter')
  await settle(page)
  await page.getByRole('button', { name: 'Remove 192.0.2.128/30' }).click()
  const dialog = page.getByRole('dialog', { name: 'Remove this range?' })
  await expect(dialog).toBeVisible()
  // While an aria-modal dialog is open, axe checks the dialog, including its
  // accessible name, instead of the page's level-one heading and landmarks.
  await expectAccessible(page, 'open action dialog', 'the open Remove this range? dialog')

  controls.failNext('perimeter-remove')
  await dialog.getByRole('button', { name: 'Remove range' }).click()
  await expect(dialog.getByRole('alert')).toContainText('The range was kept because the audit record could not be written.')
  await expectAccessible(page, 'action dialog with a failed confirmation', 'the Remove this range? dialog after its confirmation failed')
})

// A 4xx answer is not retried, so each page shows its error notice at once.
const readErrors = [
  { path: '/scans/scan-1', api: '/api/v1/scans/scan-1/summary', heading: 'Scan unavailable', notice: 'This scan could not be loaded.' },
  { path: '/jobs/job-1', api: '/api/v1/jobs/job-1', heading: 'Job unavailable', notice: 'This job could not be loaded.' },
  { path: '/scans/scan-1/hosts/192.0.2.10', api: '/api/v1/scans/scan-1/hosts/192.0.2.10', heading: 'Host unavailable', notice: 'Host evidence could not be loaded.' },
  { path: '/perimeter/ranges/range-1', api: '/api/v1/perimeter/seeds/range-1', heading: 'Range unavailable', notice: 'This range could not be loaded.' },
]

test('axe audits the error notice of pages whose read failed', async ({ page }, testInfo) => {
  test.skip(!auditedProjects.has(testInfo.project.name), 'The page states are audited at desktop, narrow-mobile, and iPhone 13 widths.')

  await expectProjectDevice(page, testInfo)
  await mockConsole(page, 'administrator', { routeAuditFixtures: true })
  for (const failure of readErrors) {
    await page.route(`**${failure.api}`, route => route.request().method() === 'GET'
      ? route.fulfill({ status: 400, contentType: 'application/json', body: JSON.stringify({ error: { code: 'invalid_request', message: 'fixture read failed' } }) })
      : route.fallback())
  }
  for (const failure of readErrors) {
    await page.goto(failure.path)
    await expect(page.getByRole('heading', { level: 1, name: failure.heading, exact: true })).toBeVisible()
    await expect(page.locator('#main-content .content').getByRole('alert')).toContainText(failure.notice)
    await expect(page.getByRole('button', { name: 'Retry' })).toBeVisible()
    await settle(page)
    await expectAccessible(page, `read error on ${failure.path}`, `the read error on ${failure.path}`)
  }
})

test('axe audits a business unit whose read failed', async ({ page }, testInfo) => {
  test.skip(!auditedProjects.has(testInfo.project.name), 'The page states are audited at desktop, narrow-mobile, and iPhone 13 widths.')

  await expectProjectDevice(page, testInfo)
  await mockConsole(page, 'platform_admin')
  await page.route('**/api/v1/platform/units/unit-retail', route => route.request().method() === 'GET'
    ? route.fulfill({ status: 400, contentType: 'application/json', body: JSON.stringify({ error: { code: 'invalid_request', message: 'fixture read failed' } }) })
    : route.fallback())
  await page.goto('/platform/units/unit-retail')
  await expect(page.getByRole('heading', { level: 1, name: 'Business unit unavailable', exact: true })).toBeVisible()
  await expect(page.locator('#main-content .content').getByRole('alert')).toContainText('This business unit could not be loaded.')
  await settle(page)
  await expectAccessible(page, 'read error on /platform/units/unit-retail', 'the read error on /platform/units/unit-retail')
})

// Each empty state stands directly under its page's level-one heading.
const emptyStates = [
  { path: '/incidents', heading: 'No matching incidents' },
  { path: '/jobs/job-1/baseline', heading: 'No active baseline' },
]

test('axe audits the empty investigation inbox and a job without a baseline', async ({ page }, testInfo) => {
  test.skip(!auditedProjects.has(testInfo.project.name), 'The page states are audited at desktop, narrow-mobile, and iPhone 13 widths.')

  await expectProjectDevice(page, testInfo)
  await mockConsole(page, 'administrator', { routeAuditFixtures: true, emptyInbox: true, withoutBaseline: true })
  for (const state of emptyStates) {
    await page.goto(state.path)
    await expect(page.locator('#main-content .content').getByRole('heading', { level: 2, name: state.heading, exact: true })).toBeVisible()
    await settle(page)
    await expectAccessible(page, `empty state on ${state.path}`, `the empty state on ${state.path}`)
  }
})

test('axe audits a job with baseline changes that await confirmation', async ({ page }, testInfo) => {
  test.skip(!auditedProjects.has(testInfo.project.name), 'The page states are audited at desktop, narrow-mobile, and iPhone 13 widths.')

  await expectProjectDevice(page, testInfo)
  await mockConsole(page, 'administrator', { routeAuditFixtures: true, pendingBaselineChanges: true })
  await page.goto('/jobs/job-1')
  const pending = page.getByRole('region', { name: 'Pending confirmations' })
  await expect(pending).toContainText('192.0.2.10')
  await expect(pending).toContainText('1 / 2 scans')
  await settle(page)
  await expectAccessible(page, 'pending baseline changes', 'job-1 with pending baseline changes')
})

test('axe audits the scan-slot demand notice near capacity', async ({ page }, testInfo) => {
  test.skip(!auditedProjects.has(testInfo.project.name), 'The page states are audited at desktop, narrow-mobile, and iPhone 13 widths.')

  await expectProjectDevice(page, testInfo)
  await mockConsole(page, 'administrator', { routeAuditFixtures: true, scanSlotDemand: { estimated_slot_seconds_per_day: 6_120, utilization_percent: 85 } })
  await page.goto('/jobs')
  const demand = page.getByRole('region', { name: 'Scan-slot demand' })
  await expect(demand).toContainText('Scheduled scan demand is near capacity')
  await expect(demand).toContainText('(85% of 2 available slot-hours/day across 2 scan slots)')
  await settle(page)
  await expectAccessible(page, 'scan-slot demand near capacity', '/jobs with scan-slot demand near capacity')
})

test('axe audits each step of a monitor setup that Perimeter prefilled', async ({ page }, testInfo) => {
  test.skip(!auditedProjects.has(testInfo.project.name), 'The page states are audited at desktop, narrow-mobile, and iPhone 13 widths.')

  await expectProjectDevice(page, testInfo)
  await mockConsole(page, 'administrator', { routeAuditFixtures: true })
  await page.goto('/perimeter/ranges/range-1')
  await page.getByRole('region', { name: 'UDP', exact: true }).getByRole('button', { name: 'Create monitor' }).click()
  await expect(page).toHaveURL(/\/jobs\/new$/)
  await expect(page.getByText('Prefilled from Perimeter (203.0.113.0/24).', { exact: false })).toBeVisible()

  const steps = [
    { heading: 'Choose targets', next: 'Continue to coverage' },
    { heading: 'Set scan coverage', next: 'Continue to schedule' },
    { heading: 'Set schedule and alerts', next: 'Continue without alerts' },
    { heading: 'Set schedule and alerts', next: 'Review monitor' },
    { heading: 'Review and create' },
  ]
  for (const [index, step] of steps.entries()) {
    await expect(page.getByRole('heading', { level: 1, name: step.heading, exact: true })).toBeVisible()
    if (step.heading === 'Review and create') await expect(page.locator('.estimate-grid')).toBeVisible()
    await settle(page)
    await expectAccessible(page, `prefilled monitor setup: ${step.heading}`, `step ${index + 1} of the prefilled monitor setup (${step.heading})`)
    if (step.next) await page.getByRole('button', { name: step.next }).click()
  }
})

test('the configured axe 4.13 rule detects visible labels missing from accessible names', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'The explicit rule-activation regression runs once; route audits cover each configured device project.')

  await page.setContent('<!doctype html><html lang="en"><head><title>Rule activation fixture</title></head><body><button aria-label="Action">Delete deployment</button></body></html>')
  const results = await consoleAxe(page).analyze()
  expect(results.violations.filter(violation => violation.id === labelNameMismatchRule)).toHaveLength(1)
})

test('the axe gate fails on structure rules and serious violations unless an allowance names the node', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'The regression of the gate itself runs once; the audits above cover each configured device project.')

  // A skipped heading level, no level-one heading, and no main landmark.
  await page.setContent('<!doctype html><html lang="en"><head><title>Gate fixture</title></head><body><div><h2>Section</h2><h4 id="skipped">Skipped level</h4></div></body></html>')
  const structure = (await consoleAxe(page).analyze()).violations
  expect(gateFindings(structure, 'fixture', []).blocking.sort()).toEqual([
    'heading-order (moderate) at #skipped',
    'landmark-one-main (moderate) at html',
    'page-has-heading-one (moderate) at html',
  ])
  // Content outside every landmark stays a finding of its own, outside the gate.
  expect(structure.map(violation => violation.id)).toContain('region')

  const allowance = { rule: 'heading-order', surface: 'fixture', target: '#skipped', reason: 'Fixture.' }
  const stale = { rule: 'landmark-unique', surface: 'fixture', target: 'nav', reason: 'Fixture.' }
  const elsewhere = { rule: 'page-has-heading-one', surface: 'another page', target: 'html', reason: 'Fixture.' }
  const findings = gateFindings(structure, 'fixture', [allowance, stale, elsewhere])
  expect(findings.blocking.sort()).toEqual(['landmark-one-main (moderate) at html', 'page-has-heading-one (moderate) at html'])
  expect(findings.unused).toEqual(['landmark-unique at nav'])

  // An open modal dialog without an accessible name.
  await page.setContent('<!doctype html><html lang="en"><head><title>Gate fixture</title></head><body><main><h1>Page</h1><div role="dialog" aria-modal="true" id="unnamed"><button type="button">Close</button></div></main></body></html>')
  expect(gateFindings((await consoleAxe(page).analyze()).violations, 'fixture', []).blocking).toEqual(['aria-dialog-name (serious) at #unnamed'])
})

test('legacy scan detail route audit checks successful scan content before axe', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'The focused scan detail regression runs once; the route matrix covers every role and configured device.')

  await expectProjectDevice(page, testInfo)
  await mockConsole(page, 'administrator', { routeAuditFixtures: true })
  await page.goto('/scans/scan-1')

  const content = page.locator('#main-content .content')
  await expect(content.locator('.page').last()).toBeVisible()
  await page.waitForLoadState('networkidle')
  await expect(content.locator('.loading, .skeleton-list')).toHaveCount(0)
  await expectRouteDataReady(page, '/scans/scan-1')

  await expectAccessible(page, '/scans/scan-1', 'administrator on /scans/scan-1')
})

test('activity error text remains in visible row link names (#1629)', async ({ page }, testInfo) => {
  test.skip(!auditedProjects.has(testInfo.project.name), 'The focused accessible-name regression runs at desktop, narrow-mobile, and iPhone 13 widths.')

  await expectProjectDevice(page, testInfo)
  await mockConsole(page, 'administrator', { accessibilityFixtures: true })
  await page.goto('/')
  const failedScan = page.getByRole('link', { name: /Target timed out after 10 seconds/ })
  await expect(failedScan).toBeVisible()
  await page.waitForLoadState('networkidle')
  await expect(page.locator('#main-content .content .loading, #main-content .content .skeleton-list')).toHaveCount(0)
  await expect(failedScan).toHaveAccessibleName(/Target timed out after 10 seconds/)
  const activityAxe = await consoleAxe(page).analyze()
  expect(activityAxe.violations.filter(violation => violation.id === labelNameMismatchRule)).toEqual([])
})

test('disabled unit lifecycle status remains in the visible row link name (#1629)', async ({ page }, testInfo) => {
  test.skip(!auditedProjects.has(testInfo.project.name), 'The focused accessible-name regression runs at desktop, narrow-mobile, and iPhone 13 widths.')

  await expectProjectDevice(page, testInfo)
  await mockConsole(page, 'platform_admin', { accessibilityFixtures: true })
  await page.goto('/platform/units')
  const disabledUnit = page.getByRole('link', { name: /Retail.*Disabled/ })
  await expect(disabledUnit).toBeVisible()
  await page.waitForLoadState('networkidle')
  await expect(page.locator('#main-content .content .loading, #main-content .content .skeleton-list')).toHaveCount(0)
  await expect(disabledUnit).toHaveAccessibleName(/Retail.*Disabled/)
  const platformAxe = await consoleAxe(page).analyze()
  expect(platformAxe.violations.filter(violation => violation.id === labelNameMismatchRule)).toEqual([])
})
