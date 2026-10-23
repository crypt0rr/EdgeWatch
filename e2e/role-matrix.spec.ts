import { expect, test } from '@playwright/test'
import { mockConsole, rolePermissions, type UnitConsoleRole } from './mock-console'
import { allConsoleRoutes, expectedConsolePath } from './console-routes'

const navigationLabels = [
  'Overview', 'Jobs', 'Hosts', 'Perimeter', 'Incidents', 'Notifications', 'Users',
  'Public status', 'Scanner profiles', 'Audit', 'Security',
]

const expectedNavigation: Record<UnitConsoleRole, string[]> = {
  administrator: navigationLabels,
  operator: ['Overview', 'Jobs', 'Hosts', 'Perimeter', 'Incidents', 'Scanner profiles', 'Security'],
  viewer: ['Jobs', 'Security'],
}

const routeBatchSize = 8
const routeBatches = Array.from(
  { length: Math.ceil(allConsoleRoutes.length / routeBatchSize) },
  (_, index) => allConsoleRoutes.slice(index * routeBatchSize, (index + 1) * routeBatchSize),
)

// Keep the role-level navigation contract separate from route navigation.
// The route inventory runs in fixed-size batches so every role still checks
// every path without one long test approaching Playwright's 30-second limit.
for (const role of Object.keys(expectedNavigation) as UnitConsoleRole[]) {
  test(`role navigation matrix matches the authorization contract for ${role}`, async ({ browser, baseURL }, testInfo) => {
    test.skip(testInfo.project.name !== 'desktop', 'The permission matrix runs once on desktop; mobile navigation is covered separately.')

    // Use the configured preview origin so PLAYWRIGHT_PORT is honored.
    const context = await browser.newContext({ baseURL })
    const page = await context.newPage()
    try {
      await mockConsole(page, role)
      await page.goto('/jobs')
      await expect(page.getByRole('heading', { name: 'Jobs', exact: true })).toBeVisible()

      const navigation = page.locator('#primary-navigation nav')
      for (const label of navigationLabels) {
        const link = label === 'Incidents'
          ? navigation.getByRole('link', { name: /^Incidents(?:\s|$)/ })
          : navigation.getByRole('link', { name: label, exact: true })
        if (expectedNavigation[role].includes(label)) await expect(link).toHaveCount(1)
        else await expect(link).toHaveCount(0)
      }

      // The controls are part of the role contract, not merely hidden by CSS.
      if (role === 'administrator') {
        await page.goto('/users')
        await expect(page.getByRole('heading', { name: 'Users', exact: true })).toBeVisible()
        await expect(page.getByRole('button', { name: 'Create activation link' })).toBeVisible()
        await page.goto('/notifications')
        await expect(page.getByRole('heading', { name: 'Notifications', exact: true })).toBeVisible()
        await expect(page.getByRole('checkbox', { name: 'Disable update alerts for Operations' })).toBeVisible()
        await page.goto('/public-dashboard')
        await expect(page.getByRole('heading', { name: 'Public status', exact: true })).toBeVisible()
        await expect(page.getByRole('button', { name: 'Save public view' })).toBeVisible()
        await page.goto('/scanner-profiles')
        await expect(page.getByRole('button', { name: 'New profile' })).toBeVisible()
        await expect(page.getByRole('button', { name: 'Validate & preview' })).toBeVisible()
        await page.goto('/perimeter')
        await expect(page.getByRole('heading', { name: 'Declare ranges', exact: true })).toBeVisible()
        await expect(page.getByRole('button', { name: 'Remove 203.0.113.0/24' })).toBeVisible()
      } else if (role === 'operator') {
        await page.goto('/scanner-profiles')
        await expect(page.getByRole('heading', { name: 'Scanner profiles', exact: true })).toBeVisible()
        await expect(page.getByText('Only administrators can create, validate, or revise scanner profiles.')).toBeVisible()
        await expect(page.getByRole('button', { name: 'New profile' })).toHaveCount(0)
        await expect(page.getByRole('button', { name: 'Validate & preview' })).toHaveCount(0)
        await expect(page.getByRole('button', { name: 'Create profile' })).toHaveCount(0)
        // Operators read the perimeter but neither declare nor remove ranges.
        await page.goto('/perimeter')
        await expect(page.getByRole('heading', { name: 'Declared ranges', exact: true })).toBeVisible()
        await expect(page.getByRole('heading', { name: 'Declare ranges', exact: true })).toHaveCount(0)
        await expect(page.getByRole('textbox', { name: 'Ranges, one per line' })).toHaveCount(0)
        await expect(page.getByRole('button', { name: /^Remove / })).toHaveCount(0)
      } else {
        await expect(page.getByRole('button', { name: 'New job' })).toHaveCount(0)
      }
    } finally {
      await context.close()
    }
  })

  for (const [batchIndex, routes] of routeBatches.entries()) {
    test(`role route matrix batch ${batchIndex + 1}/${routeBatches.length} matches the authorization contract for ${role}`, async ({ browser, baseURL }, testInfo) => {
      test.skip(testInfo.project.name !== 'desktop', 'The permission matrix runs once on desktop; mobile navigation is covered separately.')
      const context = await browser.newContext({ baseURL })
      const page = await context.newPage()
      try {
        await mockConsole(page, role)
        for (const route of routes) {
          await page.goto(route.path)
          const expectedPath = expectedConsolePath(role, route)
          await expect.poll(() => new URL(page.url()).pathname).toBe(expectedPath)
        }
      } finally {
        await context.close()
      }
    })
  }
}

// The platform administrator's console: its own navigation, never a unit's,
// and every unit route leads to the platform's home without a request for a
// unit's data.
const platformNavigation = ['Units', 'Platform admins', 'Notifications', 'Audit', 'Status', 'Security']

test('platform administrator navigation keeps unit pages out of the platform console', async ({ browser, baseURL }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'The permission matrix runs once on desktop; mobile navigation is covered separately.')
  const context = await browser.newContext({ baseURL })
  const page = await context.newPage()
  try {
    const controls = await mockConsole(page, 'platform_admin')
    await page.goto('/platform/units')
    await expect(page.getByRole('heading', { name: 'Business units', exact: true })).toBeVisible()
    const navigation = page.locator('#primary-navigation nav')
    for (const label of [...navigationLabels, ...platformNavigation]) {
      const link = label === 'Incidents'
        ? navigation.getByRole('link', { name: /^Incidents(?:\s|$)/ })
        : navigation.getByRole('link', { name: label, exact: true })
      if (platformNavigation.includes(label)) await expect(link).toHaveCount(1)
      else await expect(link).toHaveCount(0)
    }
    await expect(page.getByText('All business units')).toBeVisible()

    expect(controls.calls['unit-data'] ?? 0).toBe(0)
  } finally {
    await context.close()
  }
})

for (const [batchIndex, routes] of routeBatches.entries()) {
  test(`platform administrator route matrix batch ${batchIndex + 1}/${routeBatches.length} keeps unit pages out of the platform console`, async ({ browser, baseURL }, testInfo) => {
    test.skip(testInfo.project.name !== 'desktop', 'The permission matrix runs once on desktop; mobile navigation is covered separately.')
    const context = await browser.newContext({ baseURL })
    const page = await context.newPage()
    try {
      const controls = await mockConsole(page, 'platform_admin')
      for (const route of routes) {
        if (route.scope === 'platform' && route.permission) expect(rolePermissions.platform_admin).toContain(route.permission)
        await page.goto(route.path)
        await expect.poll(() => new URL(page.url()).pathname).toBe(expectedConsolePath('platform_admin', route))
      }
      expect(controls.calls['unit-data'] ?? 0).toBe(0)
    } finally {
      await context.close()
    }
  })
}
