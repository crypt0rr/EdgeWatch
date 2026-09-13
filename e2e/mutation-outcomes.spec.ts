import { expect, test } from '@playwright/test'
import { mockConsole } from './mock-console'

function desktopOnly(testInfo: { project: { name: string } }) {
  return testInfo.project.name === 'desktop'
}

test('public status save exposes failure and success outcomes', async ({ page }, testInfo) => {
  test.skip(!desktopOnly(testInfo), 'Mutation journeys run once on desktop; responsive behavior is covered separately.')
  const controls = await mockConsole(page)
  await page.goto('/public-dashboard')

  await page.getByRole('checkbox', { name: 'Enable public status page' }).check()
  await page.getByRole('checkbox', { name: /192\.0\.2\.10/ }).check()
  controls.failNext('public-dashboard')
  await page.getByRole('button', { name: 'Save public view' }).click()
  await expect(page.getByRole('alert')).toContainText('fixture public-dashboard failed')

  await page.getByRole('button', { name: 'Save public view' }).click()
  await expect(page.getByRole('status')).toContainText('Public view saved')
  expect(controls.payloads['public-dashboard']).toHaveLength(2)
})

test('incident acceptance exposes failure and success outcomes', async ({ page }, testInfo) => {
  test.skip(!desktopOnly(testInfo), 'Mutation journeys run once on desktop; responsive behavior is covered separately.')
  const controls = await mockConsole(page)
  await page.goto('/incidents')
  await expect(page.getByRole('button', { name: 'Accept change' }).first()).toBeVisible()

  controls.failNext('incident-accept')
  await page.getByRole('button', { name: 'Accept change' }).first().click()
  const dialog = page.getByRole('dialog', { name: 'Accept this change?' })
  await dialog.getByRole('button', { name: 'Accept change' }).click()
  await expect(dialog.getByRole('alert')).toContainText('fixture incident-accept failed')

  await dialog.getByRole('button', { name: 'Accept change' }).click()
  await expect(page.getByRole('button', { name: 'Accept change' })).toHaveCount(0)
  expect(controls.calls['incident-accept']).toBe(2)
})

test('inline update notification toggles expose failure and success outcomes', async ({ page }, testInfo) => {
  test.skip(!desktopOnly(testInfo), 'Mutation journeys run once on desktop; responsive behavior is covered separately.')
  const controls = await mockConsole(page)
  await page.goto('/notifications')
  const toggle = page.getByRole('checkbox', { name: 'Disable update alerts for Operations' })
  await expect(toggle).toBeChecked()

  controls.failNext('update-routing')
  await toggle.click()
  const dialog = page.getByRole('dialog', { name: 'Confirm update alerts for Operations' })
  await dialog.getByLabel('Account password').fill('fixture-password')
  await dialog.getByRole('button', { name: 'Disable update alerts' }).click()
  await expect(page.getByRole('alert')).toContainText('fixture update-routing failed')
  await expect(page.getByRole('checkbox', { name: 'Disable update alerts for Operations' })).toBeChecked()

  await page.getByRole('checkbox', { name: 'Disable update alerts for Operations' }).click()
  const retryDialog = page.getByRole('dialog', { name: 'Confirm update alerts for Operations' })
  await retryDialog.getByLabel('Account password').fill('fixture-password')
  await retryDialog.getByRole('button', { name: 'Disable update alerts' }).click()
  await expect(page.getByRole('status')).toContainText('Application update alerts disabled for Operations')
  expect(controls.payloads['update-routing']).toHaveLength(2)
})

test('scanner profile validation exposes failure and success outcomes', async ({ page }, testInfo) => {
  test.skip(!desktopOnly(testInfo), 'Mutation journeys run once on desktop; responsive behavior is covered separately.')
  const controls = await mockConsole(page)
  await page.goto('/scanner-profiles')
  const validate = page.getByRole('button', { name: 'Validate & preview' })
  await expect(validate).toBeVisible()

  controls.failNext('profile-validate')
  await validate.click()
  await expect(page.getByRole('alert')).toContainText('fixture profile-validate failed')

  await validate.click()
  await expect(page.getByRole('status')).toContainText('Profile is valid')
  expect(controls.calls['profile-validate']).toBe(2)
})

test('user invitation exposes failure and success outcomes', async ({ page }, testInfo) => {
  test.skip(!desktopOnly(testInfo), 'Mutation journeys run once on desktop; responsive behavior is covered separately.')
  const controls = await mockConsole(page)
  await page.goto('/users')
  await page.getByLabel('Username').fill('new-user')
  await page.getByLabel('Display name').fill('New User')

  controls.failNext('user-create')
  await page.getByRole('button', { name: 'Create activation link' }).click()
  await expect(page.getByRole('alert')).toContainText('fixture user-create failed')

  await page.getByRole('button', { name: 'Create activation link' }).click()
  await expect(page.getByRole('status')).toContainText('Created new-user')
  await expect(page.getByText('FIXTURE-TOKEN')).toBeVisible()
  expect(controls.payloads['user-create']).toHaveLength(2)
})

test('job creation exposes failure and success outcomes', async ({ page }, testInfo) => {
  test.skip(!desktopOnly(testInfo), 'Mutation journeys run once on desktop; responsive behavior is covered separately.')
  const controls = await mockConsole(page)
  await page.goto('/jobs/new')
  await page.getByLabel('Job name').fill('created-from-browser')
  await page.getByLabel('Target 1').fill('192.0.2.10')
  // Keep this journey independent of Naabu availability: the job builder must
  // still submit a valid Nmap-only configuration when the operator chooses it.
  await page.getByLabel('TCP engine').selectOption('nmap')

  controls.failNext('job-create')
  await page.getByRole('button', { name: 'Create job' }).click()
  await expect(page.getByRole('alert')).toContainText('fixture job-create failed')

  await page.getByRole('button', { name: 'Create job' }).click()
  await expect(page).toHaveURL(/\/jobs$/)
  expect(controls.payloads['job-create']).toHaveLength(2)
})

test('account profile save exposes failure and success outcomes', async ({ page }, testInfo) => {
  test.skip(!desktopOnly(testInfo), 'Mutation journeys run once on desktop; responsive behavior is covered separately.')
  const controls = await mockConsole(page)
  await page.goto('/security')
  const displayName = page.getByLabel('Display name')
  await expect(displayName).toHaveValue('administrator')
  await displayName.fill('Renamed admin')

  controls.failNext('display-name')
  await page.getByRole('button', { name: 'Save display name' }).click()
  await expect(page.getByRole('alert')).toContainText('fixture display-name failed')

  await page.getByRole('button', { name: 'Save display name' }).click()
  await expect(page.getByText('Display name updated.')).toBeVisible()
  expect(controls.payloads['display-name']).toHaveLength(2)
})
