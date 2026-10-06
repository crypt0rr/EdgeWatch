import { expect, test, type Page } from '@playwright/test'
import { mockConsole, rolePermissions } from './mock-console'

/**
 * Serves the mocked console to a signed-out browser until it signs in: every
 * request except the setup status is refused with 401, as the server refuses
 * a request without a valid session. The routes are registered after the
 * fixture, so they take precedence over it. Returns a function that ends the
 * session again.
 */
async function requireSignIn(page: Page) {
  let signedIn = false
  await page.route('**/api/v1/**', async route => {
    const path = new URL(route.request().url()).pathname
    if (path === '/api/v1/auth/login' && route.request().method() === 'POST') {
      signedIn = true
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ username: 'admin', display_name: 'administrator', role: 'administrator', permissions: rolePermissions.administrator, csrf_token: 'fixture-csrf', totp_required: false }) })
      return
    }
    if (signedIn || path === '/api/v1/setup/status' || path === '/api/v1/stream') { await route.fallback(); return }
    await route.fulfill({ status: 401, contentType: 'application/json', body: JSON.stringify({ error: { code: 'unauthorized', message: 'authentication required' } }) })
  })
  return () => { signedIn = false }
}

async function signIn(page: Page) {
  await expect(page.getByRole('heading', { name: 'Sign in to EdgeWatch' })).toBeVisible()
  await expect(page).toHaveURL(/\/login$/)
  await page.getByLabel('Password').fill('correct horse battery staple')
  await page.getByRole('button', { name: 'Sign in' }).click()
}

test('signing in opens the page that was requested while signed out', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'The sign-in journey runs once on desktop; it has no layout of its own.')
  await mockConsole(page, 'administrator')
  await requireSignIn(page)

  await page.goto('/jobs/job-1?view=scans')
  await expect(page.getByRole('heading', { name: 'Sign in to EdgeWatch' })).toBeVisible()
  const entries = await page.evaluate(() => history.length)
  await signIn(page)

  await expect(page.getByRole('heading', { name: 'fixture-job', level: 1 })).toBeVisible()
  await expect(page).toHaveURL(/\/jobs\/job-1\?view=scans$/)
  // The page replaces the sign-in page in the history instead of following it.
  expect(await page.evaluate(() => history.length)).toBe(entries)
})

test('signing in again after the session ends returns to the page that was open', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'The sign-in journey runs once on desktop; it has no layout of its own.')
  await mockConsole(page, 'administrator')
  const endSession = await requireSignIn(page)

  await page.goto('/')
  await signIn(page)
  await expect(page.getByRole('heading', { name: /Good day, administrator/ })).toBeVisible()
  await page.getByRole('link', { name: 'Hosts', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Hosts', level: 1 })).toBeVisible()

  // The session ends while Hosts is open. Open a protected route while the
  // expired session is active and verify that signing in returns to it.
  endSession()
  await page.goto('/incidents')
  await signIn(page)

  await expect(page.getByRole('heading', { name: 'Incidents', level: 1 })).toBeVisible()
  await expect(page).toHaveURL(/\/incidents$/)
})
