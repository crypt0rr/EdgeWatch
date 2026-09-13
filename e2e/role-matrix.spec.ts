import { expect, test } from '@playwright/test'
import { mockConsole, rolePermissions, type ConsoleRole } from './mock-console'

const navigationLabels = [
  'Overview', 'Jobs', 'Hosts', 'Incidents', 'Notifications', 'Users',
  'Public status', 'Scanner profiles', 'Security',
]

const expectedNavigation: Record<ConsoleRole, string[]> = {
  administrator: navigationLabels,
  operator: ['Overview', 'Jobs', 'Hosts', 'Incidents', 'Scanner profiles', 'Security'],
  viewer: ['Jobs', 'Security'],
}

const routePermissions: Array<{ path: string; permission?: string }> = [
  { path: '/', permission: 'overview.read' },
  { path: '/jobs', permission: 'jobs.read' },
  { path: '/jobs/new', permission: 'jobs.write' },
  { path: '/jobs/job-1', permission: 'jobs.read' },
  { path: '/jobs/job-1/edit', permission: 'jobs.write' },
  { path: '/jobs/job-1/baseline', permission: 'baselines.read' },
  { path: '/jobs/job-1/scans/scan-1', permission: 'scans.read' },
  { path: '/jobs/job-1/scans/scan-1/hosts/192.0.2.10', permission: 'scans.read' },
  { path: '/hosts', permission: 'hosts.read' },
  { path: '/scans/scan-1', permission: 'scans.read' },
  { path: '/incidents', permission: 'incidents.read' },
  { path: '/notifications', permission: 'notifications.manage' },
  { path: '/users', permission: 'users.manage' },
  { path: '/public-dashboard', permission: 'public_dashboard.manage' },
  { path: '/scanner-profiles', permission: 'scanner_profiles.read' },
  { path: '/security', permission: 'account.self' },
]

test('role route and navigation matrix matches the authorization contract', async ({ browser }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'The permission matrix runs once on desktop; mobile navigation is covered separately.')

  for (const role of Object.keys(expectedNavigation) as ConsoleRole[]) {
    const context = await browser.newContext({ baseURL: 'http://127.0.0.1:4173' })
    const page = await context.newPage()
    try {
      await mockConsole(page, role)
      await page.goto('/jobs')
      await expect(page.getByRole('heading', { name: 'Jobs', exact: true })).toBeVisible()

      const navigation = page.locator('#primary-navigation nav')
      for (const label of navigationLabels) {
        const link = navigation.getByRole('link', { name: label, exact: true })
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
        await expect(page.getByRole('button', { name: 'Save update routing' })).toBeVisible()
        await page.goto('/public-dashboard')
        await expect(page.getByRole('heading', { name: 'Public status', exact: true })).toBeVisible()
        await expect(page.getByRole('button', { name: 'Save public view' })).toBeVisible()
        await page.goto('/scanner-profiles')
        await expect(page.getByRole('button', { name: 'New profile' })).toBeVisible()
        await expect(page.getByRole('button', { name: 'Validate & preview' })).toBeVisible()
      } else if (role === 'operator') {
        await page.goto('/scanner-profiles')
        await expect(page.getByRole('heading', { name: 'Scanner profiles', exact: true })).toBeVisible()
        await expect(page.getByText('Only administrators can create, validate, or revise scanner profiles.')).toBeVisible()
        await expect(page.getByRole('button', { name: 'New profile' })).toHaveCount(0)
        await expect(page.getByRole('button', { name: 'Validate & preview' })).toHaveCount(0)
        await expect(page.getByRole('button', { name: 'Create profile' })).toHaveCount(0)
      } else {
        await expect(page.getByRole('button', { name: 'New job' })).toHaveCount(0)
      }

      for (const route of routePermissions) {
        await page.goto(route.path)
        const allowed = route.permission === undefined || rolePermissions[role].includes(route.permission)
        const expectedPath = allowed ? new URL(route.path, 'http://127.0.0.1:4173').pathname : '/jobs'
        await expect.poll(() => new URL(page.url()).pathname).toBe(expectedPath)
      }
    } finally {
      await context.close()
    }
  }
})

