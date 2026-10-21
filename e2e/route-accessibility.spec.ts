import AxeBuilder from '@axe-core/playwright'
import { expect, test, type Page, type TestInfo } from '@playwright/test'
import { allConsoleRoutes, expectedConsolePath } from './console-routes'
import { mockConsole, rolePermissions, type ConsoleRole } from './mock-console'

const roles: ConsoleRole[] = ['administrator', 'operator', 'viewer', 'platform_admin']
const auditedProjects = new Set(['desktop', 'mobile-narrow', 'iphone-13'])

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
  test(`axe audits every rendered console route for ${role}`, async ({ page }, testInfo) => {
    test.skip(!auditedProjects.has(testInfo.project.name), 'The complete route matrix runs at desktop, narrow-mobile, and iPhone 13 widths; Pixel 7 covers additional phone regressions.')
    test.setTimeout(180_000)

    await expectProjectDevice(page, testInfo)
    await mockConsole(page, role)

    for (const route of allConsoleRoutes) {
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

      const results = await new AxeBuilder({ page }).analyze()
      const labelMismatches = results.violations.filter(violation => violation.id === 'label-content-name-mismatch')
      const blocking = results.violations.filter(violation => violation.impact === 'serious' || violation.impact === 'critical')
      expect(labelMismatches, `${role} on ${route.path} has visible link or button text missing from its accessible name`).toEqual([])
      expect(blocking, `${role} on ${route.path}: ${blocking.map(violation => `${violation.id} (${violation.impact})`).join(', ')}`).toEqual([])
    }
  })
}

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
  const activityAxe = await new AxeBuilder({ page }).analyze()
  expect(activityAxe.violations.filter(violation => violation.id === 'label-content-name-mismatch')).toEqual([])
})

test('disabled unit lifecycle status remains in the visible row link name (#1629)', async ({ page }, testInfo) => {
  test.skip(!auditedProjects.has(testInfo.project.name), 'The focused accessible-name regression runs at desktop, narrow-mobile, and iPhone 13 widths.')

  await expectProjectDevice(page, testInfo)
  await mockConsole(page, 'platform_admin', { accessibilityFixtures: true })
  await page.goto('/platform/units')
  const disabledUnit = page.getByRole('link', { name: /Disabled Retail/ })
  await expect(disabledUnit).toBeVisible()
  await page.waitForLoadState('networkidle')
  await expect(page.locator('#main-content .content .loading, #main-content .content .skeleton-list')).toHaveCount(0)
  await expect(disabledUnit).toHaveAccessibleName(/Disabled/)
  const platformAxe = await new AxeBuilder({ page }).analyze()
  expect(platformAxe.violations.filter(violation => violation.id === 'label-content-name-mismatch')).toEqual([])
})
