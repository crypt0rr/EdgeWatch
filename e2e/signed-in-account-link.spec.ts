import { expect, test } from '@playwright/test'
import { mockConsole } from './mock-console'

test('an activation link opened in a signed-in browser waits for sign-out and then opens with its token', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'The link journey runs once on desktop; it has no layout of its own.')
  await mockConsole(page, 'administrator')
  // The browser holds the administrator's session until it signs out; from
  // then on every request except the setup status is refused with 401, as
  // the server refuses a request without a valid session. The routes are
  // registered after the fixture, so they take precedence over it.
  let signedIn = true
  const redeemed: unknown[] = []
  await page.route('**/api/v1/**', async route => {
    const request = route.request()
    const path = new URL(request.url()).pathname
    if (path === '/api/v1/auth/logout' && request.method() === 'POST') {
      signedIn = false
      await route.fulfill({ status: 204 })
      return
    }
    if (path === '/api/v1/auth/activate' && request.method() === 'POST') {
      redeemed.push(request.postDataJSON())
      await route.fulfill({ status: 204 })
      return
    }
    if (signedIn || path === '/api/v1/setup/status' || path === '/api/v1/stream') { await route.fallback(); return }
    await route.fulfill({ status: 401, contentType: 'application/json', body: JSON.stringify({ error: { code: 'unauthorized', message: 'authentication required' } }) })
  })

  await page.goto('/activate#token=FIXTURE-LINK')
  await expect(page.getByRole('heading', { name: 'You are already signed in' })).toBeVisible()
  await expect(page.getByText('administrator (admin)')).toBeVisible()
  // The link is kept, unused, and the signed-in console does not open.
  await expect(page).toHaveURL(/\/activate#token=FIXTURE-LINK$/)
  await expect(page.getByRole('navigation', { name: /Breadcrumb/ })).toHaveCount(0)
  expect(redeemed).toEqual([])

  await page.getByRole('button', { name: 'Sign out and continue' }).click()
  await expect(page.getByRole('heading', { name: 'Choose your password' })).toBeVisible()
  await expect(page.getByLabel('Activation token')).toHaveValue('FIXTURE-LINK')
  // The activation page removes the token from the address bar.
  await expect(page).toHaveURL(/\/activate$/)

  await page.getByLabel(/^Password/).fill('correct horse battery staple')
  await page.getByLabel('Confirm password').fill('correct horse battery staple')
  await page.getByRole('button', { name: 'Activate account' }).click()
  await expect(page.getByRole('status').filter({ hasText: 'Account activated.' })).toBeVisible()
  expect(redeemed).toEqual([{ token: 'FIXTURE-LINK', password: 'correct horse battery staple' }])
})
