import { expect, test, type Locator, type Page } from '@playwright/test'
import { mockConsole } from './mock-console'

async function focusWithKeyboard(page: Page, locator: Locator) {
  await locator.focus()
  await page.keyboard.press('Shift+Tab')
  await page.keyboard.press('Tab')
  await expect(locator).toBeFocused()
}

test('the dark scheme and form controls remain legible under either system preference (#983, #984)', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'The shared form appearance is verified once on desktop.')
  await mockConsole(page)
  await page.emulateMedia({ colorScheme: 'light' })
  await page.goto('/scanner-profiles')

  await expect.poll(() => page.evaluate(() => getComputedStyle(document.documentElement).colorScheme)).toBe('dark')
  await expect(page.locator('meta[name="color-scheme"]')).toHaveAttribute('content', 'dark')
  const textarea = page.getByLabel('Nmap argument array')
  await expect(textarea).toHaveAttribute('rows', '6')
  const textareaStyle = await textarea.evaluate(element => ({
    background: getComputedStyle(element).backgroundColor,
    border: getComputedStyle(element).borderTopWidth,
    weight: getComputedStyle(element).fontWeight,
  }))
  expect(textareaStyle.background).not.toBe('rgba(0, 0, 0, 0)')
  expect(textareaStyle.border).toBe('1px')
  expect(textareaStyle.weight).toBe('400')

  await page.emulateMedia({ colorScheme: 'dark' })
  await expect.poll(() => page.evaluate(() => getComputedStyle(document.documentElement).colorScheme)).toBe('dark')
})

test('keyboard focus is visible on switches, host filters, unit rows and tabs (#985)', async ({ page, browser, baseURL }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'Keyboard focus states are verified once on desktop.')
  await mockConsole(page)
  await page.goto('/jobs/new/advanced')
  const checkbox = page.locator('.switch-row input[type="checkbox"]').first()
  await focusWithKeyboard(page, checkbox)
  await expect.poll(() => checkbox.evaluate(element => getComputedStyle(element).outlineStyle)).toBe('solid')

  await page.goto('/hosts')
  const protocol = page.locator('.host-toolbar select').first()
  await focusWithKeyboard(page, protocol)
  const protocolFocus = await protocol.evaluate(element => ({ outline: getComputedStyle(element).outlineStyle, border: getComputedStyle(element).borderColor }))
  expect(protocolFocus.outline).toBe('solid')
  expect(protocolFocus.border).not.toBe('rgb(40, 65, 94)')

  const platformContext = await browser.newContext({ baseURL })
  try {
    const platformPage = await platformContext.newPage()
    await mockConsole(platformPage, 'platform_admin')
    await platformPage.goto('/platform/units')
    const row = platformPage.locator('.unit-row').first()
    await focusWithKeyboard(platformPage, row)
    await expect.poll(() => row.evaluate(element => getComputedStyle(element).outlineStyle)).toBe('solid')

    await platformPage.goto('/platform/units/unit-retail/accounts')
    const tab = platformPage.getByRole('link', { name: 'Capacity' })
    await focusWithKeyboard(platformPage, tab)
    await expect.poll(() => tab.evaluate(element => getComputedStyle(element).outlineStyle)).toBe('solid')
  } finally {
    await platformContext.close()
  }
})

test('disabled actions have a disabled appearance and no hover effect (#984)', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'The shared disabled action style is verified once on desktop.')
  await mockConsole(page, 'platform_admin')
  await page.goto('/platform/units/unit-retail/danger')
  const remove = page.getByRole('button', { name: 'Delete unit…' })
  await expect(remove).toBeDisabled()
  const box = await remove.boundingBox()
  if (!box) throw new Error('Disabled action has no visible box')
  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2)
  const styles = await remove.evaluate(element => ({
    opacity: Number(getComputedStyle(element).opacity),
    cursor: getComputedStyle(element).cursor,
    filter: getComputedStyle(element).filter,
  }))
  expect(styles.opacity).toBeLessThanOrEqual(.5)
  expect(styles.cursor).toBe('not-allowed')
  expect(styles.filter).toBe('none')
})

test('long confirmation dialogs scroll the focused field into the visible area (#985)', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'The dialog is checked at several viewport sizes in one browser.')
  await mockConsole(page, 'platform_admin')
  await page.route('**/api/v1/platform/units/unit-retail', route => route.request().method() === 'GET'
    ? route.fulfill({ json: { id: 'unit-retail', name: 'Retail', slug: 'retail', status: 'disabled', is_default: false, revision: 2, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z', state_changed_at: '2026-01-01T00:00:00Z', accounts: 0, administrators: 0, jobs: 0, stored_scans: 0, slots: { in_use: 0, queued: 0 } } })
    : route.fallback())
  await page.setViewportSize({ width: 844, height: 390 })
  await page.goto('/platform/units/unit-retail/danger')
  await page.getByRole('button', { name: 'Delete unit…' }).click()
  const dialog = page.getByRole('dialog', { name: 'Delete Retail permanently?' })
  const confirmation = dialog.getByLabel('Type “Retail” to confirm')
  const confirmAction = dialog.getByRole('button', { name: 'Delete unit' })
  await expect(dialog).toBeVisible()

  for (const viewport of [{ width: 320, height: 568 }, { width: 375, height: 667 }, { width: 844, height: 390 }, { width: 640, height: 400 }]) {
    await page.setViewportSize(viewport)
    await confirmation.focus()
    const bounds = await page.evaluate(() => {
      const field = document.activeElement!.getBoundingClientRect()
      const panel = document.querySelector<HTMLElement>('.action-dialog')!.getBoundingClientRect()
      const action = document.querySelector<HTMLElement>('.action-dialog-actions button[type="submit"]')!.getBoundingClientRect()
      return { fieldTop: field.top, fieldBottom: field.bottom, actionTop: action.top, actionBottom: action.bottom, panelTop: panel.top, panelBottom: panel.bottom }
    })
    expect(bounds.fieldTop).toBeGreaterThanOrEqual(bounds.panelTop)
    expect(bounds.fieldBottom).toBeLessThanOrEqual(bounds.panelBottom)
    expect(bounds.actionTop).toBeGreaterThanOrEqual(bounds.panelTop)
    expect(bounds.actionBottom).toBeLessThanOrEqual(bounds.panelBottom)
    await expect(confirmAction).toBeInViewport()
  }
})

test('coarse pointers retain 44px controls on tablets and landscape phones (#986)', async ({ browser, baseURL }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'One touch-enabled context covers the tablet and landscape widths.')
  const context = await browser.newContext({ baseURL, viewport: { width: 820, height: 1180 }, deviceScaleFactor: 1, hasTouch: true, isMobile: true })
  try {
    const page = await context.newPage()
    await mockConsole(page)
    await page.goto('/jobs/job-1/baseline/hosts/192.0.2.10')
    for (const viewport of [{ width: 768, height: 1024 }, { width: 820, height: 1180 }, { width: 844, height: 390 }, { width: 1024, height: 768 }]) {
      await page.setViewportSize(viewport)
      await expect(page.getByRole('heading', { name: 'Identity and coverage' })).toBeVisible()
      await expect(page.locator('.back-link').first()).toBeVisible()
      const measurements = await page.locator('.back-link, .sort-button, details.scope-details > summary').evaluateAll(elements => elements.map(element => ({ label: element.textContent?.trim(), height: element.getBoundingClientRect().height })))
      const visible = measurements.filter(item => item.height > 0)
      expect(visible.some(item => item.label?.startsWith('TCP'))).toBe(true)
      expect(visible.every(item => item.height >= 44), `${viewport.width}x${viewport.height} hit heights: ${JSON.stringify(measurements)}`).toBe(true)
    }
  } finally {
    await context.close()
  }
})
