import { expect, test } from '@playwright/test'
import { mockConsole } from './mock-console'

test.describe('load and save error recovery (#982)', () => {
  test.beforeEach(async ({}, testInfo) => {
    test.skip(testInfo.project.name !== 'desktop', 'These checks control their own viewport sizes.')
  })

  test('the hosts load error appears quickly, is styled, and can be retried', async ({ page }) => {
    await mockConsole(page)
    let requests = 0
    await page.route('**/api/v1/hosts**', async route => {
      if (route.request().method() !== 'GET') return route.fallback()
      requests += 1
      if (requests === 1) {
        await route.fulfill({ status: 503, json: { error: { code: 'unavailable', message: 'temporarily unavailable' } } })
        return
      }
      await route.fulfill({ json: { hosts: [], pagination: { limit: 50, offset: 0, total: 0, has_more: false, next_offset: null } } })
    })

    await page.goto('/hosts')
    const alert = page.getByRole('alert')
    await expect(alert).toContainText('Could not load scanned hosts.')
    expect(requests).toBe(1)
    await expect(alert).toHaveCSS('border-top-width', '1px')
    await expect(alert).not.toHaveCSS('background-color', 'rgba(0, 0, 0, 0)')
    await alert.getByRole('button', { name: 'Retry' }).click()
    await expect(page.getByRole('heading', { name: 'Scanned hosts' })).toBeVisible()
    expect(requests).toBe(2)
  })

  test('save failures remain visible by the scanner-profile controls', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 800 })
    const mock = await mockConsole(page)
    mock.failNext('profile-create')
    await page.goto('/scanner-profiles')
    await page.getByLabel('Name').fill('review-feedback-profile')
    await page.getByLabel('Password confirmation').fill('fixture-password')
    await page.getByRole('button', { name: 'Create profile' }).click()
    const alert = page.getByRole('alert').filter({ hasText: 'fixture profile-create failed' })
    await expect(alert).toBeVisible()
    await expect(alert).toBeInViewport()
  })

  test('save failures remain visible by the scanner-profile controls on a phone', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 812 })
    const mock = await mockConsole(page)
    mock.failNext('profile-create')
    await page.goto('/scanner-profiles')
    await page.getByLabel('Name').fill('review-feedback-profile')
    await page.getByLabel('Password confirmation').fill('fixture-password')
    await page.getByRole('button', { name: 'Create profile' }).click()
    const alert = page.getByRole('alert').filter({ hasText: 'fixture profile-create failed' })
    await expect(alert).toBeVisible()
    await expect(alert).toBeInViewport()
  })

  test('public-status save feedback is visible next to its action', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 812 })
    const mock = await mockConsole(page)
    mock.failNext('public-dashboard')
    await page.goto('/public-dashboard')
    await page.getByRole('button', { name: 'Save public view' }).click()
    const alert = page.getByRole('alert').filter({ hasText: 'fixture public-dashboard failed' })
    await expect(alert).toBeVisible()
    await expect(alert).toBeInViewport()
  })

  test('public-status save feedback is visible next to its action on desktop', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 800 })
    const mock = await mockConsole(page)
    mock.failNext('public-dashboard')
    await page.goto('/public-dashboard')
    await page.getByRole('button', { name: 'Save public view' }).click()
    const alert = page.getByRole('alert').filter({ hasText: 'fixture public-dashboard failed' })
    await expect(alert).toBeVisible()
    await expect(alert).toBeInViewport()
  })

  test('the startup connection screen retries automatically when service status returns', async ({ page }) => {
    await mockConsole(page)
    let statusRequests = 0
    await page.route('**/api/v1/setup/status', async route => {
      statusRequests += 1
      if (statusRequests === 1) {
        await route.fulfill({ status: 503, json: { error: { code: 'unavailable', message: 'temporarily unavailable' } } })
        return
      }
      await route.fallback()
    })

    await page.goto('/login')
    await expect(page.getByRole('heading', { name: 'EdgeWatch is not responding' })).toBeVisible()
    await expect(page.getByRole('button', { name: 'Reload status' })).toBeVisible()
    await expect(page.getByRole('heading', { name: 'Good day, administrator' })).toBeVisible({ timeout: 10_000 })
    expect(statusRequests).toBeGreaterThanOrEqual(2)
  })
})
