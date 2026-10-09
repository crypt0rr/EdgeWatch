import { expect, test } from '@playwright/test'
import { mockConsole } from './mock-console'

const desktopOnly = (project: string) => project === 'desktop'

async function expectNoHorizontalOverflow(page: import('@playwright/test').Page) {
  await expect.poll(async () => {
    const layout = await page.evaluate(() => {
    const viewport = document.documentElement.clientWidth
    const offenders = Array.from(document.body.querySelectorAll<HTMLElement>('*')).map(element => {
      const rect = element.getBoundingClientRect()
      const style = getComputedStyle(element)
      return {
        tag: element.tagName.toLowerCase(),
        className: typeof element.className === 'string' ? element.className : '',
        id: element.id,
        text: (element.innerText || element.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 120),
        left: Math.round(rect.left),
        right: Math.round(rect.right),
        width: Math.round(rect.width),
        scrollWidth: element.scrollWidth,
        clientWidth: element.clientWidth,
        position: style.position,
        overflowX: style.overflowX,
        visible: style.visibility !== 'hidden' && style.display !== 'none',
      }
    }).filter(element => element.visible && element.right > viewport + 1 && element.left < viewport)
      .sort((left, right) => right.right - left.right)
      .slice(0, 12)
    const chain: HTMLElement[] = []
    let ancestor = document.querySelector<HTMLElement>('.monitor-setup .panel')
    while (ancestor) {
      chain.push(ancestor)
      ancestor = ancestor.parentElement
    }
    const ancestors = chain.map(element => {
      const rect = element.getBoundingClientRect()
      const style = getComputedStyle(element)
      return { tag: element.tagName.toLowerCase(), className: typeof element.className === 'string' ? element.className : '', left: Math.round(rect.left), right: Math.round(rect.right), width: Math.round(rect.width), scrollWidth: element.scrollWidth, clientWidth: element.clientWidth, boxSizing: style.boxSizing, display: style.display, minWidth: style.minWidth, paddingLeft: style.paddingLeft, paddingRight: style.paddingRight }
    })
    return {
      fits: document.documentElement.scrollWidth <= viewport,
      viewport,
      documentScrollWidth: document.documentElement.scrollWidth,
      offenders,
      ancestors,
    }
    })
    return layout.fits ? 'fits' : JSON.stringify(layout)
  }).toBe('fits')
}

async function openReview(page: import('@playwright/test').Page, name = 'guided-edge') {
  await page.goto('/jobs/new')
  await page.getByLabel('Monitor name').fill(name)
  await page.getByLabel('Target 1').fill('192.0.2.10')
  await page.getByRole('button', { name: 'Continue to coverage' }).click()
  await page.getByRole('radio', { name: /Selected TCP ports/ }).check()
  await page.getByRole('textbox', { name: /TCP ports/ }).fill('22,443')
  await page.getByRole('button', { name: 'Continue to schedule' }).click()
  await page.getByRole('button', { name: 'Continue without alerts' }).click()
  await page.getByRole('button', { name: 'Review monitor' }).click()
  await expect(page.getByRole('heading', { name: 'Coverage and scan cost' })).toBeVisible()
  await expect(page.locator('.estimate-grid')).toBeVisible()
}

test('guided create failure preserves the draft; create without starting never dispatches a scan', async ({ page }, testInfo) => {
  test.skip(!desktopOnly(testInfo.project.name), 'The guided mutation journey runs once on desktop.')
  const controls = await mockConsole(page)
  await openReview(page, 'saved-without-scan')

  controls.failNext('job-create')
  await page.getByRole('button', { name: 'Create without starting' }).click()
  await expect(page.getByRole('alert')).toContainText('fixture job-create failed')
  await expect(page.getByText('saved-without-scan', { exact: true })).toBeVisible()
  expect(controls.calls['job-create']).toBe(1)
  expect(controls.calls['job-run'] ?? 0).toBe(0)

  await page.getByRole('button', { name: 'Create without starting' }).click()
  await expect(page).toHaveURL(/\/jobs\/job-created$/)
  await expect(page.getByRole('heading', { name: 'saved-without-scan' })).toBeVisible()
  expect(controls.calls['job-create']).toBe(2)
  expect(controls.calls['job-run'] ?? 0).toBe(0)

  await page.reload()
  await expect(page.getByRole('heading', { name: 'saved-without-scan' })).toBeVisible()
  expect(controls.calls['job-create']).toBe(2)
  expect(controls.calls['job-run'] ?? 0).toBe(0)
})

test('create-and-start creates once, retries only the failed run, and refresh does not dispatch again', async ({ page }, testInfo) => {
  test.skip(!desktopOnly(testInfo.project.name), 'The guided mutation journey runs once on desktop.')
  const controls = await mockConsole(page)
  await openReview(page, 'guided-first-scan')
  controls.failNext('job-run')

  await page.getByRole('button', { name: 'Create and start first scan' }).click()
  await expect(page).toHaveURL(/\/jobs\/job-created$/)
  await expect(page.getByRole('heading', { name: 'guided-first-scan' })).toBeVisible()
  await expect(page.getByRole('alert')).toContainText('fixture job-run failed')
  expect(controls.calls['job-create']).toBe(1)
  expect(controls.calls['job-run']).toBe(1)

  await page.getByRole('button', { name: 'Scan now' }).click()
  await expect(page.getByRole('heading', { name: 'Scan queued' })).toBeVisible()
  expect(controls.calls['job-create']).toBe(1)
  expect(controls.calls['job-run']).toBe(2)

  await page.reload()
  await expect(page.getByRole('heading', { name: 'guided-first-scan' })).toBeVisible()
  await page.waitForTimeout(300)
  expect(controls.calls['job-create']).toBe(1)
  expect(controls.calls['job-run']).toBe(2)
})

test('an over-budget preview allows saving the monitor but blocks its first scan', async ({ page }, testInfo) => {
  test.skip(!desktopOnly(testInfo.project.name), 'The guided budget journey runs once on desktop.')
  const controls = await mockConsole(page)
  controls.setPreviewResponse({
    scan_estimate: { hosts: 1, tcp_ports: 65_535, udp_ports: 0, probes: 65_535, nmap_invocations: 1, naabu_invocations: 0, unknown_dns: 0 },
    scan_budget: { exceeded: true, estimated_probes: 65_535, limit: 10_000, approval_would_fit: true },
    warnings: [],
  })
  await openReview(page, 'over-budget-monitor')

  await expect(page.getByRole('button', { name: 'Create and start first scan' })).toBeDisabled()
  await expect(page.getByText(/Create without starting remains available/)).toBeVisible()
  await page.getByRole('button', { name: 'Create without starting' }).click()
  await expect(page.getByRole('heading', { name: 'over-budget-monitor' })).toBeVisible()
  expect(controls.calls['job-create']).toBe(1)
  expect(controls.calls['job-run'] ?? 0).toBe(0)
})

test('an out-of-order preview cannot replace the current draft estimate', async ({ page }, testInfo) => {
  test.skip(!desktopOnly(testInfo.project.name), 'The preview race journey runs once on desktop.')
  const controls = await mockConsole(page)
  const stale = controls.deferNextPreview()

  await page.goto('/jobs/new')
  await page.getByLabel('Monitor name').fill('preview-race')
  await page.getByLabel('Target 1').fill('192.0.2.10')
  await page.getByRole('button', { name: 'Continue to coverage' }).click()
  await page.getByRole('radio', { name: /Selected TCP ports/ }).check()
  await page.getByRole('textbox', { name: /TCP ports/ }).fill('22')
  await page.getByRole('button', { name: 'Continue to schedule' }).click()
  await page.getByRole('button', { name: 'Continue without alerts' }).click()
  await page.getByRole('button', { name: 'Review monitor' }).click()
  await stale.started

  await page.getByRole('button', { name: 'Previous step' }).click()
  await page.getByLabel('Five-field cron').fill('5 */6 * * *')
  const currentPreview = page.waitForRequest(request => request.method() === 'POST'
    && new URL(request.url()).pathname === '/api/v1/jobs/preview'
    && JSON.parse(request.postData() ?? '{}').schedule === '5 */6 * * *')
  await page.getByRole('button', { name: 'Review monitor' }).click()
  await currentPreview
  await expect(page.locator('.estimate-grid')).toBeVisible()

  stale.resolve({
    job: { name: 'preview-race', schedule: '0 */6 * * *', timezone: 'UTC' },
    scan_estimate: { hosts: 1, tcp_ports: 65_535, udp_ports: 0, probes: 999_999, nmap_invocations: 50, naabu_invocations: 0, unknown_dns: 0 },
    scan_budget: { exceeded: false },
    warnings: [],
  })
  await page.waitForTimeout(100)
  await expect(page.getByText('999,999', { exact: true })).toHaveCount(0)
  await page.getByRole('button', { name: 'Create without starting' }).click()
  await expect(page.getByRole('heading', { name: 'preview-race' })).toBeVisible()
  expect(controls.payloads['job-create']?.[0]).toMatchObject({ schedule: '5 */6 * * *', tcp: { ports: '22' } })
})

test('guided and advanced creation share the same draft and guard leaving with unsaved work', async ({ page }, testInfo) => {
  test.skip(!desktopOnly(testInfo.project.name), 'The guided mode transfer runs once on desktop.')
  await mockConsole(page)
  await page.goto('/jobs/new')
  await page.getByLabel('Monitor name').fill('transferred-monitor')
  await page.getByLabel('Target 1').fill('192.0.2.10')
  await page.getByRole('link', { name: 'Open full editor' }).click()
  await expect(page.getByRole('heading', { name: 'Create a monitoring job' })).toBeVisible()
  await expect(page.getByLabel('Job name')).toHaveValue('transferred-monitor')
  await page.getByRole('link', { name: 'Back to guided setup' }).click()
  await expect(page.getByRole('heading', { name: 'Choose targets' })).toBeVisible()
  await expect(page.getByLabel('Monitor name')).toHaveValue('transferred-monitor')

  await page.getByRole('link', { name: 'Back to jobs' }).click()
  const dialog = page.getByRole('dialog', { name: /Discard/ })
  await expect(dialog).toBeVisible()
  await expect(dialog).toContainText('has not been saved')
})

test('keyboard users receive step focus and announced validation feedback', async ({ page }, testInfo) => {
  test.skip(!desktopOnly(testInfo.project.name), 'The keyboard setup journey runs once on desktop.')
  await mockConsole(page)
  await page.goto('/jobs/new')
  const targetsHeading = page.getByRole('heading', { name: 'Choose targets' })
  await expect(targetsHeading).toBeFocused()

  const next = page.getByRole('button', { name: 'Continue to coverage' })
  await next.focus()
  await page.keyboard.press('Enter')
  await expect(page.getByRole('alert')).toContainText('A monitor name is required.')
  await page.getByLabel('Monitor name').fill('keyboard-monitor')
  await page.getByLabel('Target 1').fill('192.0.2.10')
  await next.focus()
  await page.keyboard.press('Enter')
  await expect(page.getByRole('heading', { name: 'Set scan coverage' })).toBeFocused()

  await page.getByRole('radio', { name: /Selected TCP ports/ }).focus()
  await page.keyboard.press('Space')
  await page.getByRole('textbox', { name: /TCP ports/ }).fill('')
  const coverageNext = page.getByRole('button', { name: 'Continue to schedule' })
  await coverageNext.focus()
  await page.keyboard.press('Enter')
  await expect(page.getByRole('alert')).toContainText('Choose TCP ports for Nmap.')
  await page.getByRole('textbox', { name: /TCP ports/ }).fill('22')
  await coverageNext.focus()
  await page.keyboard.press('Enter')
  await expect(page.getByRole('heading', { name: 'Set schedule and alerts' })).toBeFocused()
})

test('guided setup fits narrow mobile viewports without horizontal scrolling', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name === 'desktop', 'The narrow viewport acceptance runs in mobile projects.')
  await mockConsole(page)
  await page.goto('/jobs/new')
  await expect(page.getByRole('heading', { name: 'Choose targets' })).toBeVisible()
  await expectNoHorizontalOverflow(page)
  const continueButton = page.getByRole('button', { name: 'Continue to coverage' })
  const bounds = await continueButton.boundingBox()
  const viewport = await page.evaluate(() => ({ width: document.documentElement.clientWidth, height: document.documentElement.clientHeight }))
  expect(bounds).not.toBeNull()
  expect(bounds!.x).toBeGreaterThanOrEqual(0)
  expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(viewport.width)
  expect(bounds!.height).toBeGreaterThanOrEqual(40)

  await page.getByLabel('Monitor name').fill('phone-monitor')
  await page.getByLabel('Target 1').fill('192.0.2.10')
  await continueButton.click()
  await expect(page.getByRole('heading', { name: 'Set scan coverage' })).toBeVisible()
  await expectNoHorizontalOverflow(page)
})

test('operators can select a saved destination but cannot manage destinations or high-cost approval', async ({ page }, testInfo) => {
  test.skip(!desktopOnly(testInfo.project.name), 'The operator guided access check runs once on desktop.')
  await mockConsole(page, 'operator')
  await page.goto('/jobs/new')
  await page.getByLabel('Monitor name').fill('operator-monitor')
  await page.getByLabel('Target 1').fill('192.0.2.10')
  await page.getByRole('button', { name: 'Continue to coverage' }).click()
  await page.getByRole('button', { name: 'Continue to schedule' }).click()
  await expect(page.getByRole('checkbox', { name: /Operations/ })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Add destination' })).toHaveCount(0)
  await expect(page.getByText(/high-cost approval/i)).toHaveCount(0)
  await expect(page.getByText(/administrator can add destinations/i)).toBeVisible()
})

test('viewers and platform administrators are redirected away from unit monitor setup', async ({ page }, testInfo) => {
  test.skip(!desktopOnly(testInfo.project.name), 'The role boundary check runs once on desktop.')
  const viewer = await mockConsole(page, 'viewer')
  await page.goto('/jobs/new')
  await expect(page).toHaveURL(/\/jobs$/)
  await expect(page.getByRole('heading', { name: 'Jobs' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Choose targets' })).toHaveCount(0)
  expect(viewer.calls['job-create'] ?? 0).toBe(0)
  expect(viewer.calls['job-run'] ?? 0).toBe(0)

  const platformPage = await page.context().newPage()
  try {
    const platform = await mockConsole(platformPage, 'platform_admin')
    await platformPage.goto('/jobs/new')
    await expect(platformPage).toHaveURL(/\/platform\/units$/)
    await expect(platformPage.getByRole('heading', { name: 'Business units' })).toBeVisible()
    await expect(platformPage.getByRole('heading', { name: 'Choose targets' })).toHaveCount(0)
    expect(platform.calls['job-create'] ?? 0).toBe(0)
    expect(platform.calls['job-run'] ?? 0).toBe(0)
    expect(platform.calls['unit-data'] ?? 0).toBe(0)
  } finally {
    await platformPage.close()
  }
})
