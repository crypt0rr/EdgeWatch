import AxeBuilder from '@axe-core/playwright'
import { expect, test, type Page, type TestInfo } from '@playwright/test'
import { allConsoleRoutes, expectedConsolePath } from './console-routes'
import { mockConsole, rolePermissions, type ConsoleRole } from './mock-console'

const roles: ConsoleRole[] = ['administrator', 'operator', 'viewer', 'platform_admin']
const auditedProjects = new Set(['desktop', 'mobile-narrow', 'iphone-13'])
const labelNameMismatchRule = 'label-content-name-mismatch'
const routeBatchSize = 6
const routeBatches = Array.from(
  { length: Math.ceil(allConsoleRoutes.length / routeBatchSize) },
  (_, index) => allConsoleRoutes.slice(index * routeBatchSize, (index + 1) * routeBatchSize),
)

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

        const results = await consoleAxe(page).analyze()
        const labelMismatches = results.violations.filter(violation => violation.id === labelNameMismatchRule)
        const blocking = results.violations.filter(violation => violation.impact === 'serious' || violation.impact === 'critical')
        expect(labelMismatches, `${role} on ${route.path} has visible link or button text missing from its accessible name`).toEqual([])
        expect(blocking, `${role} on ${route.path}: ${blocking.map(violation => `${violation.id} (${violation.impact})`).join(', ')}`).toEqual([])
      }
    })
  }
}

test('the configured axe 4.13 rule detects visible labels missing from accessible names', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'The explicit rule-activation regression runs once; route audits cover each configured device project.')

  await page.setContent('<!doctype html><html lang="en"><head><title>Rule activation fixture</title></head><body><button aria-label="Action">Delete deployment</button></body></html>')
  const results = await consoleAxe(page).analyze()
  expect(results.violations.filter(violation => violation.id === labelNameMismatchRule)).toHaveLength(1)
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
