import { expect, test, type Page } from '@playwright/test'
import { mockConsole } from './mock-console'

async function expectNoHorizontalScroll(page: Page) {
  const viewport = await page.evaluate(() => ({ clientWidth: document.documentElement.clientWidth, scrollWidth: document.documentElement.scrollWidth }))
  expect(viewport.scrollWidth).toBeLessThanOrEqual(viewport.clientWidth)
}

test('a platform administrator creates a unit, invites its administrator, recovers an account, and deletes a unit', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'The platform journey runs once on desktop; phone widths are covered separately.')
  const controls = await mockConsole(page, 'platform_admin')
  await page.goto('/platform/units')

  // The unit list shows counts only.
  const retail = page.getByRole('link', { name: 'Open Retail' })
  await expect(retail).toContainText('3 accounts · 1 admin')
  await expect(retail).toContainText('2 jobs')
  await expect(retail).toContainText('1,480 scans')
  await expect(retail).toContainText('1 in use · 0 queued · cap 2')

  // A new unit opens on its accounts, where only an administrator can be invited.
  await page.getByRole('button', { name: 'New unit' }).click()
  const create = page.getByRole('dialog', { name: 'New business unit' })
  await create.getByLabel('Unit name').fill('Logistics')
  controls.failNext('unit-create')
  await create.getByRole('button', { name: 'Create unit' }).click()
  await expect(create.getByRole('alert')).toContainText('fixture unit-create failed')
  await create.getByRole('button', { name: 'Create unit' }).click()
  await expect(page).toHaveURL(/\/platform\/units\/unit-3\/accounts$/)
  await expect(page.getByRole('heading', { name: 'Invite an administrator' })).toBeVisible()
  await expect(page.getByRole('combobox')).toHaveCount(0)
  await page.getByLabel('Username').fill('dana')
  await page.getByLabel('Your password').fill('fixture-password')
  await page.getByRole('button', { name: 'Create activation link' }).click()
  await expect(page.getByLabel('Activation link for dana')).toContainText('/activate#token=FIXTURE-INVITE')
  expect(controls.payloads['unit-admin-invite']).toEqual([{ username: 'dana', display_name: '', password: 'fixture-password', role: 'administrator' }])

  // Resets exist only on administrator rows, and warn when the account has no TOTP.
  await page.goto('/platform/units/unit-retail/accounts')
  await expect(page.getByTestId('account-casey').getByRole('button', { name: /Reset password/ })).toHaveCount(0)
  await expect(page.getByTestId('account-taylor').getByRole('button', { name: /Reset password/ })).toHaveCount(0)
  await page.getByTestId('account-riley').getByRole('button', { name: /Reset password/ }).click()
  const reset = page.getByRole('dialog', { name: 'Reset the password of riley?' })
  await expect(reset.getByRole('alert')).toContainText('You will be able to sign in as this user with this link.')
  await reset.getByLabel('Your password').fill('fixture-password')
  await reset.getByRole('button', { name: 'Create reset link' }).click()
  await expect(page.getByLabel('Password reset link for riley')).toContainText('/activate#token=FIXTURE-RESET')
  await expect(page.getByRole('alert')).toContainText('You will be able to sign in as this user with this link.')
  await page.getByTestId('account-casey').getByRole('button', { name: /Revoke sessions/ }).click()
  const revoke = page.getByRole('dialog', { name: 'Revoke all sessions of casey?' })
  await revoke.getByLabel('Your password').fill('fixture-password')
  await revoke.getByRole('button', { name: 'Revoke sessions' }).click()
  await expect(page.getByRole('status').filter({ hasText: 'casey was signed out of every session.' })).toBeVisible()

  // Changing the slug warns that the public link changes.
  await page.getByRole('link', { name: 'Overview' }).click()
  await page.getByLabel('Slug').fill('stores')
  await expect(page.getByText(/stops working\. Share .*\/public\/stores instead\./)).toBeVisible()
  await page.getByRole('button', { name: 'Save changes' }).click()
  await expect(page.getByText('Saved. The public page is now at /public/stores.')).toBeVisible()

  // Deleting needs a disabled unit, its typed name, and the password.
  await page.getByRole('link', { name: 'Danger zone' }).click()
  await expect(page.getByRole('button', { name: 'Delete unit…' })).toBeDisabled()
  await page.getByRole('button', { name: 'Disable unit' }).click()
  const disable = page.getByRole('dialog', { name: 'Disable Retail?' })
  await disable.getByLabel('Your password').fill('fixture-password')
  await disable.getByRole('button', { name: 'Disable unit' }).click()
  await expect(page.getByRole('button', { name: 'Delete unit…' })).toBeEnabled()
  await page.getByRole('button', { name: 'Delete unit…' }).click()
  const remove = page.getByRole('dialog', { name: 'Delete Retail permanently?' })
  await expect(remove.getByRole('button', { name: 'Delete unit' })).toBeDisabled()
  await remove.getByLabel('Type “Retail” to confirm').fill('Retail')
  await remove.getByLabel('Your password').fill('fixture-password')
  await remove.getByRole('button', { name: 'Delete unit' }).click()
  await expect(page.getByRole('heading', { name: 'Deleting Retail…' })).toBeVisible()
  expect(controls.payloads['unit-delete']).toEqual([{ confirm_name: 'Retail', password: 'fixture-password' }])

  // The platform's own notifications route update alerts to none until chosen.
  await page.getByRole('link', { name: 'Notifications' }).click()
  const pager = page.getByRole('checkbox', { name: 'Enable update alerts for Platform pager' })
  await expect(pager).not.toBeChecked()
  await pager.click()
  const routing = page.getByRole('dialog', { name: 'Confirm update alerts for Platform pager' })
  await routing.getByLabel('Account password').fill('fixture-password')
  await routing.getByRole('button', { name: 'Enable update alerts' }).click()
  await expect(page.getByRole('checkbox', { name: 'Disable update alerts for Platform pager' })).toBeChecked()
  expect(controls.payloads['platform-update-routing']).toEqual([{ destination_id: 'platform-1', enabled: true, password: 'fixture-password' }])

  await page.getByRole('link', { name: 'Audit' }).click()
  await expect(page.getByText('business unit Retail created')).toBeVisible()
  await page.getByRole('link', { name: 'Status' }).click()
  await expect(page.getByText('Accounts in units')).toBeVisible()
  expect(controls.calls['unit-data'] ?? 0).toBe(0)
})

test('a platform administrator without TOTP gets the forced enrolment as soon as it creates the second unit', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'The platform journey runs once on desktop; phone widths are covered separately.')
  const controls = await mockConsole(page, 'platform_admin', { platformTOTP: false })
  await page.goto('/platform/units')
  await expect(page.getByRole('heading', { name: '1 unit', exact: true })).toBeVisible()

  await page.getByRole('button', { name: 'New unit' }).click()
  const create = page.getByRole('dialog', { name: 'New business unit' })
  await create.getByLabel('Unit name').fill('Logistics')
  await create.getByRole('button', { name: 'Create unit' }).click()

  // The second unit restricts the session to its own account. The console
  // shows the enrolment right away, without first trying the unit list or
  // the new unit, which the session may no longer read.
  await expect(page.getByRole('heading', { name: 'Set up an authenticator' })).toBeVisible({ timeout: 2_000 })
  await expect(page).toHaveURL(/\/security$/)
  await expect(page.getByRole('status').filter({ hasText: 'Set up TOTP to continue.' })).toBeVisible()
  await expect(page.getByRole('link')).toHaveCount(0)
  await page.setViewportSize({ width: 320, height: 760 })
  const signOut = page.getByRole('button', { name: /Sign out/ })
  await expect(signOut).toBeVisible()
  expect(await signOut.evaluate(element => getComputedStyle(element).whiteSpace)).toBe('nowrap')
  expect((await signOut.boundingBox())!.height).toBeLessThanOrEqual(44)
  await expectNoHorizontalScroll(page)
  await expect(page.getByText('This business unit could not be loaded.')).toHaveCount(0)
  expect(controls.payloads['unit-create']).toEqual([{ name: 'Logistics' }])
  expect(controls.calls['platform-refused'] ?? 0).toBe(0)
  expect(controls.calls['unit-data'] ?? 0).toBe(0)
})

test('a platform administrator revokes the invitation of another that has not redeemed it', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'The platform journey runs once on desktop; phone widths are covered separately.')
  const controls = await mockConsole(page, 'platform_admin')
  await page.goto('/platform/admins')
  await expect(page.getByTestId('admin-platform').getByRole('button')).toHaveCount(0)
  await page.getByLabel('Username').fill('avery')
  await page.getByLabel('Your password').fill('fixture-password')
  await page.getByRole('button', { name: 'Create activation link' }).click()
  await expect(page.getByLabel('Activation link for avery')).toContainText('/activate#token=FIXTURE-ADMIN')

  // A pending administrator is neither enabled nor disabled: its row offers
  // to renew or revoke the invitation, or to remove the account.
  const avery = page.getByTestId('admin-avery')
  await expect(avery.getByText('Pending activation')).toBeVisible()
  await expect(avery.getByRole('button')).toHaveText(['Renew invitation', 'Revoke invitation', 'Remove'])
  await avery.getByRole('button', { name: 'Revoke invitation' }).click()
  const revoke = page.getByRole('dialog', { name: 'Revoke the invitation of avery?' })
  await revoke.getByLabel('Your password').fill('fixture-password')
  await revoke.getByRole('button', { name: 'Revoke invitation' }).click()
  await expect(page.getByRole('status').filter({ hasText: 'The invitation of avery was revoked; its activation link no longer works.' })).toBeVisible()
  await expect(page.getByLabel('Activation link for avery')).toHaveCount(0)
  expect(controls.payloads['platform-admin-revoke']).toEqual([{ account: 'user-avery', password: 'fixture-password' }])
})

test('a platform administrator renews a lapsed invitation, or removes the pending account to free its username', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'The platform journey runs once on desktop; phone widths are covered separately.')
  const controls = await mockConsole(page, 'platform_admin')
  await page.goto('/platform/admins')
  await page.getByLabel('Username').fill('avery')
  await page.getByLabel('Your password').fill('fixture-password')
  await page.getByRole('button', { name: 'Create activation link' }).click()
  await expect(page.getByLabel('Activation link for avery')).toContainText('/activate#token=FIXTURE-ADMIN')
  await page.getByRole('button', { name: 'Done' }).click()
  await expect(page.getByLabel('Activation link for avery')).toHaveCount(0)

  // The link was not redeemed in time: a new one is shown once.
  const avery = page.getByTestId('admin-avery')
  await avery.getByRole('button', { name: 'Renew invitation' }).click()
  const renew = page.getByRole('dialog', { name: 'Renew the invitation of avery?' })
  await renew.getByLabel('Your password').fill('fixture-password')
  await renew.getByRole('button', { name: 'Renew invitation' }).click()
  await expect(page.getByRole('status').filter({ hasText: 'A new activation link for avery was created; any earlier link no longer works.' })).toBeVisible()
  await expect(page.getByLabel('Activation link for avery')).toContainText('/activate#token=FIXTURE-RENEWED')
  await expect(avery.getByText('Pending activation')).toBeVisible()

  // Removing the pending account stops its link and frees its username.
  await avery.getByRole('button', { name: 'Remove' }).click()
  const remove = page.getByRole('dialog', { name: 'Remove avery?' })
  await remove.getByLabel('Your password').fill('fixture-password')
  await remove.getByRole('button', { name: 'Remove' }).click()
  await expect(page.getByRole('status').filter({ hasText: 'avery was removed; its username can be invited again.' })).toBeVisible()
  await expect(page.getByTestId('admin-avery')).toHaveCount(0)
  await expect(page.getByLabel('Activation link for avery')).toHaveCount(0)
  await page.getByLabel('Username').fill('avery')
  await page.getByLabel('Your password').fill('fixture-password')
  await page.getByRole('button', { name: 'Create activation link' }).click()
  await expect(page.getByTestId('admin-avery').getByText('Pending activation')).toBeVisible()
  expect(controls.payloads['platform-admin-renew']).toEqual([{ account: 'user-avery', password: 'fixture-password' }])
  expect(controls.payloads['platform-admin-remove']).toEqual([{ account: 'user-avery', password: 'fixture-password' }])
  expect(controls.payloads['platform-admin-invite']).toHaveLength(2)
})

test('a unit without a high-cost grant stays without one when its capacity is saved', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'The capacity form runs once on desktop; phone widths are covered separately.')
  const controls = await mockConsole(page, 'platform_admin')
  await page.goto('/platform/units/unit-retail/capacity')
  await expect(page.getByLabel('Not granted')).toBeChecked()
  await expect(page.getByLabel('High-cost ceiling', { exact: true })).toHaveCount(0)
  await page.getByLabel('Scan slot cap', { exact: true }).fill('1')
  await page.getByRole('button', { name: 'Save capacity' }).click()
  await expect(page.getByText('Capacity saved. It applies to the next scan this unit queues.')).toBeVisible()
  // Only the edited setting is sent, with the revision the capacity was read at.
  expect(controls.payloads['unit-capacity']).toEqual([{ max_concurrent_scans: 1, revision: 1 }])
  await expect(page.getByLabel('Not granted')).toBeChecked()
})

test('the platform console fits a phone', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name === 'desktop', 'The responsive smoke runs in the mobile projects.')
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await mockConsole(page, 'platform_admin')
  for (const path of ['/platform/units', '/platform/units/unit-retail', '/platform/units/unit-retail/accounts', '/platform/units/unit-retail/capacity', '/platform/admins', '/platform/notifications', '/platform/audit', '/platform/status']) {
    await page.goto(path)
    await expect(page.locator('.page h1')).toBeVisible()
    await expectNoHorizontalScroll(page)
  }
  await page.getByRole('button', { name: 'Open navigation' }).click()
  const drawer = page.getByRole('dialog', { name: 'Primary navigation' })
  await expect(drawer.getByRole('link', { name: 'Platform admins' })).toBeVisible()
  await drawer.getByRole('link', { name: 'Units' }).click()
  await expect(page).toHaveURL(/\/platform\/units$/)
  await expect(page.getByRole('dialog', { name: 'Primary navigation' })).toHaveCount(0)
})

test('a one-time link for a long username fits a phone', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name === 'desktop', 'The responsive smoke runs in the mobile projects.')
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await page.setViewportSize({ width: 320, height: 720 })
  await mockConsole(page, 'platform_admin')
  const username = 'morgan.reyes@corp.example.com'
  for (const path of ['/platform/admins', '/platform/units/unit-retail/accounts']) {
    await page.goto(path)
    await page.getByLabel('Username').fill(username)
    await page.getByLabel('Your password').fill('fixture-password')
    await page.getByRole('button', { name: 'Create activation link' }).click()
    await expect(page.getByLabel(`Activation link for ${username}`)).toContainText('/activate#token=')
    await expect(page.getByText(`Activation link for ${username}`, { exact: true })).toBeVisible()
    const link = page.locator('.one-time-link')
    const code = await link.locator('code').boundingBox()
    const actions = await link.locator('.one-time-link-actions').boundingBox()
    const buttons = link.locator('.one-time-link-actions .button')
    const copyButton = await buttons.nth(0).boundingBox()
    const doneButton = await buttons.nth(1).boundingBox()
    expect(code).not.toBeNull()
    expect(actions).not.toBeNull()
    expect(copyButton).not.toBeNull()
    expect(doneButton).not.toBeNull()
    expect(actions!.y - (code!.y + code!.height)).toBeLessThanOrEqual(16)
    expect(Math.abs(copyButton!.height - doneButton!.height)).toBeLessThanOrEqual(1)
    expect(await buttons.nth(0).evaluate(element => getComputedStyle(element).whiteSpace)).toBe('nowrap')
    expect(await buttons.nth(0).evaluate(element => element.scrollWidth <= element.clientWidth)).toBe(true)
    await expectNoHorizontalScroll(page)
  }
})

test('one-time link actions stay below the link on wide screens', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'The desktop layout check runs once on the desktop project.')
  await mockConsole(page, 'platform_admin')
  await page.goto('/platform/admins')
  await page.getByLabel('Username').fill('avery')
  await page.getByLabel('Your password').fill('fixture-password')
  await page.getByRole('button', { name: 'Create activation link' }).click()
  await expect(page.getByLabel('Activation link for avery')).toContainText('/activate#token=FIXTURE-ADMIN')

  for (const width of [1280, 1920]) {
    await page.setViewportSize({ width, height: 900 })
    const link = page.locator('.one-time-link')
    const code = await link.locator('code').boundingBox()
    const actions = await link.locator('.one-time-link-actions').boundingBox()
    expect(code).not.toBeNull()
    expect(actions).not.toBeNull()
    expect(actions!.y - (code!.y + code!.height)).toBeLessThanOrEqual(16)
    expect(Math.abs(actions!.x - code!.x)).toBeLessThanOrEqual(1)
    await expectNoHorizontalScroll(page)
  }
})
