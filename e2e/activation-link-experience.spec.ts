import { expect, test } from '@playwright/test'
import { mockConsole } from './mock-console'

test('unit user invitations show the full link, report copies, and can be dismissed', async ({ page }) => {
  await mockConsole(page, 'administrator')
  await page.context().grantPermissions(['clipboard-read', 'clipboard-write'])
  await page.goto('/users')
  await page.getByLabel('Username').fill('new-user')
  await page.getByLabel('Display name').fill('New User')
  await page.getByLabel('Administrator password').fill('fixture-password')
  await page.getByRole('button', { name: 'Create activation link' }).click()

  const link = page.getByLabel('Activation link for new-user')
  const expectedURL = `${new URL(page.url()).origin}/activate#token=FIXTURE-TOKEN`
  await expect(link).toHaveText(expectedURL)
  await page.getByRole('button', { name: 'Copy link' }).click()
  await expect(page.getByRole('button', { name: 'Copied' })).toBeVisible()
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(expectedURL)

  await page.getByRole('button', { name: 'Done' }).click()
  await expect(page.getByLabel('Activation link for new-user')).toHaveCount(0)
})
