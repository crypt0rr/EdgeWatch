import AxeBuilder from '@axe-core/playwright'
import { expect, test } from '@playwright/test'
import { allConsoleRoutes, expectedConsolePath } from './console-routes'
import { mockConsole, rolePermissions, type ConsoleRole } from './mock-console'

const roles: ConsoleRole[] = ['administrator', 'operator', 'viewer', 'platform_admin']
const auditedProjects = new Set(['desktop', 'iphone-13'])

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
  test(`axe audits every rendered console route for ${role}`, async ({ browser, baseURL }, testInfo) => {
    test.skip(!auditedProjects.has(testInfo.project.name), 'The complete route matrix runs at desktop and iPhone 13 widths; the other projects cover additional phone and tablet regressions.')
    test.setTimeout(180_000)

    const context = await browser.newContext({ baseURL })
    const page = await context.newPage()
    try {
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
        await expect(content.locator('.loading')).toHaveCount(0)

        const results = await new AxeBuilder({ page }).analyze()
        const labelMismatches = results.violations.filter(violation => violation.id === 'label-content-name-mismatch')
        const blocking = results.violations.filter(violation => violation.impact === 'serious' || violation.impact === 'critical')
        expect(labelMismatches, `${role} on ${route.path} has visible link or button text missing from its accessible name`).toEqual([])
        expect(blocking, `${role} on ${route.path}: ${blocking.map(violation => `${violation.id} (${violation.impact})`).join(', ')}`).toEqual([])
      }
    } finally {
      await context.close()
    }
  })
}

test('activity errors and unit lifecycle states remain in visible row link names (#1629)', async ({ browser, baseURL }, testInfo) => {
  test.skip(!auditedProjects.has(testInfo.project.name), 'The focused accessible-name regression runs at desktop and iPhone 13 widths.')

  const activityContext = await browser.newContext({ baseURL })
  try {
    const activity = await activityContext.newPage()
    await mockConsole(activity, 'administrator', { accessibilityFixtures: true })
    await activity.goto('/')
    const failedScan = activity.getByRole('link', { name: /Target timed out after 10 seconds/ })
    await expect(failedScan).toBeVisible()
    await expect(failedScan).toHaveAccessibleName(/Target timed out after 10 seconds/)
    const activityAxe = await new AxeBuilder({ page: activity }).analyze()
    expect(activityAxe.violations.filter(violation => violation.id === 'label-content-name-mismatch')).toEqual([])
  } finally {
    await activityContext.close()
  }

  const platformContext = await browser.newContext({ baseURL })
  try {
    const platform = await platformContext.newPage()
    await mockConsole(platform, 'platform_admin', { accessibilityFixtures: true })
    await platform.goto('/platform/units')
    const disabledUnit = platform.getByRole('link', { name: /Disabled Retail/ })
    await expect(disabledUnit).toBeVisible()
    await expect(disabledUnit).toHaveAccessibleName(/Disabled/)
    const platformAxe = await new AxeBuilder({ page: platform }).analyze()
    expect(platformAxe.violations.filter(violation => violation.id === 'label-content-name-mismatch')).toEqual([])
  } finally {
    await platformContext.close()
  }
})
