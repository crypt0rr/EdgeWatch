import { expect, test } from '@playwright/test'
import { mockConsole } from './mock-console'

const viewportWidths = [320, 375, 768, 1280, 1920]

test.beforeEach(async ({}, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'This suite controls its own viewport sizes.')
})

test('action labels stay on one line and activity ghost actions align to panel edges (#1130)', async ({ page }) => {
  await mockConsole(page, 'administrator')
  await page.route(url => new URL(url).pathname === '/api/v1/jobs', route => route.request().method() === 'GET' ? route.fulfill({ json: { jobs: [{
    id: 'job-1', revision: 1, enabled: true, archived: false, security_hash: 'fixture-security-hash',
    created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z',
    job: { name: 'fixture-job', schedule: '0 * * * *', timezone: 'UTC', targets: ['192.0.2.10'], max_expanded_hosts: 16, tcp: { ports: '22,443', mode: 'connect', service_detection: false }, baseline_samples: 1, change_confirmations: 1 },
    baseline: { status: 'complete', samples: 1, attempts: 1, host_count: 1, pending: 1 },
  }] } }) : route.fallback())
  await page.route(url => new URL(url).pathname === '/api/v1/events', route => route.fulfill({ json: { events: [], pagination: { limit: 20, offset: 0, total: 0, has_more: false, next_offset: null } } }))

  const paths = ['/', '/jobs/job-1', '/scanner-profiles', '/users', '/activity']
  for (const width of viewportWidths) {
    await page.setViewportSize({ width, height: 1000 })
    for (const path of paths) {
      await page.goto(path)
      await expect(page.locator('#main-content')).toBeVisible()
      const wrappedLabels = await page.locator('#main-content .button:visible').evaluateAll(buttons => buttons.flatMap(button => {
        const walker = document.createTreeWalker(button, NodeFilter.SHOW_TEXT)
        const wrapped: string[] = []
        let node: Node | null
        while ((node = walker.nextNode())) {
          if (!node.textContent?.trim()) continue
          const range = document.createRange()
          range.selectNodeContents(node)
          const lines = [...range.getClientRects()].filter(rect => rect.width > 0 && rect.height > 0)
          if (lines.length > 1) wrapped.push((button as HTMLElement).innerText.trim())
        }
        return wrapped
      }))
      expect(wrappedLabels, `wrapped button labels on ${path} at ${width}px`).toEqual([])
    }

    await page.goto('/activity')
    const edges = await page.locator('.activity-state-grid').evaluate(grid => {
      const panels = [...grid.children] as HTMLElement[]
      const first = panels[0]
      const second = panels[1]
      const incidentLink = first.querySelector<HTMLAnchorElement>(':scope > a.button.ghost')!
      const pendingLink = second.querySelector<HTMLAnchorElement>('.pending-job-heading > a.button.ghost')!
      const textBounds = (element: HTMLElement) => {
        const range = document.createRange()
        range.selectNodeContents(element)
        return range.getBoundingClientRect()
      }
      const contentEdges = (element: HTMLElement) => {
        const rect = element.getBoundingClientRect()
        const style = getComputedStyle(element)
        return {
          left: rect.left + parseFloat(style.borderLeftWidth) + parseFloat(style.paddingLeft),
          right: rect.right - parseFloat(style.borderRightWidth) - parseFloat(style.paddingRight),
        }
      }
      return {
        incidentLeft: textBounds(incidentLink).left - contentEdges(first).left,
        pendingRight: contentEdges(second).right - textBounds(pendingLink).right,
      }
    })
    expect(Math.abs(edges.incidentLeft), `incident action left edge at ${width}px`).toBeLessThanOrEqual(1)
    expect(Math.abs(edges.pendingRight), `pending action right edge at ${width}px`).toBeLessThanOrEqual(1)
  }
})

test('filter, reminder, profile, and empty-search controls remain readable (#1131)', async ({ page }) => {
  const controls = await mockConsole(page, 'administrator')

  for (const path of ['/hosts', '/jobs/job-1/baseline']) {
    await page.goto(path)
    const controls = page.locator('.host-toolbar input, .host-toolbar select')
    await expect(controls).toHaveCount(3)
    expect(await controls.evaluateAll(elements => elements.map(element => getComputedStyle(element).fontWeight))).toEqual(['400', '400', '400'])
  }

  await page.goto('/notifications')
  const reminderToggle = page.getByRole('checkbox', { name: 'Send reminders for incidents that remain open' })
  for (const width of [320, 1280]) {
    await page.setViewportSize({ width, height: 900 })
    const layout = await reminderToggle.evaluate(input => {
      const label = input.closest('label')!
      const inputBox = input.getBoundingClientRect()
      const titleBox = label.querySelector('strong')!.getBoundingClientRect()
      return {
        width: inputBox.width,
        height: inputBox.height,
        centerDifference: Math.abs((inputBox.top + inputBox.height / 2) - (titleBox.top + titleBox.height / 2)),
      }
    })
    expect(layout.width, `reminder checkbox width at ${width}px`).toBe(15)
    expect(layout.height, `reminder checkbox height at ${width}px`).toBe(15)
    expect(layout.centerDifference, `reminder checkbox alignment at ${width}px`).toBeLessThanOrEqual(4)
  }

  await page.setViewportSize({ width: 320, height: 900 })
  controls.failNext('incident-reminders')
  await page.goto('/notifications')
  await page.getByRole('checkbox', { name: 'Send reminders for incidents that remain open' }).click()
  const dialog = page.getByRole('dialog', { name: 'Confirm incident reminders' })
  await dialog.getByLabel('Account password').fill('fixture-password')
  await dialog.getByRole('button', { name: 'Disable reminders' }).click()
  const alert = page.getByRole('alert').filter({ hasText: 'fixture incident-reminders failed' })
  await expect(alert).toBeVisible()
  const reminderErrorLayout = await alert.evaluate(element => {
    const icon = element.querySelector('svg')!.getBoundingClientRect()
    const range = document.createRange()
    range.selectNodeContents(element)
    const firstText = range.getClientRects()[0]
    const help = document.querySelector('.notification-reminder-cadence small')!.getBoundingClientRect()
    const banner = element.getBoundingClientRect()
    return {
      iconTextCenterDifference: Math.abs((icon.top + icon.height / 2) - (firstText.top + firstText.height / 2)),
      gapAboveBanner: banner.top - help.bottom,
    }
  })
  expect(reminderErrorLayout.iconTextCenterDifference).toBeLessThanOrEqual(4)
  expect(reminderErrorLayout.gapAboveBanner).toBeGreaterThanOrEqual(8)

  await page.goto('/scanner-profiles')
  await page.getByRole('button', { name: 'New profile' }).click()
  const legend = page.getByText('Operator-adjustable fields', { exact: true })
  await expect(legend).toBeVisible()
  await expect(legend).toHaveCSS('font-size', '13px')
  await expect(legend).toHaveCSS('font-weight', '600')
  const fieldsetGap = await legend.evaluate(element => {
    const fieldset = element.closest('fieldset')!
    const rows = fieldset.querySelector('.two-fields')!.getBoundingClientRect()
    const helper = fieldset.querySelector('.helper')!.getBoundingClientRect()
    return helper.top - rows.bottom
  })
  expect(fieldsetGap).toBeGreaterThanOrEqual(8)

  await page.route(url => {
    const parsed = new URL(url)
    return parsed.pathname === '/api/v1/hosts' && (parsed.searchParams.has('q') || parsed.searchParams.has('protocol'))
  }, route => route.fulfill({ json: { hosts: [], pagination: { limit: 50, offset: 0, total: 0, has_more: false, next_offset: null } } }))
  await page.goto('/hosts')
  const search = page.getByRole('searchbox', { name: 'Search hosts' })
  await search.fill('missing.example')
  const empty = page.getByRole('status').filter({ hasText: 'No hosts match' })
  await expect(empty).toContainText('missing.example')
  await expect(empty.getByRole('button', { name: 'Clear search' })).toBeVisible()
  await page.getByLabel('Protocol').selectOption('tcp')
  await expect(empty.getByRole('button', { name: 'Reset filters' })).toBeVisible()
  await page.getByRole('button', { name: 'Clear search' }).click()
  await expect(search).toHaveValue('')
  await page.getByRole('button', { name: 'Reset filters' }).click()
  await expect(page.getByLabel('Protocol')).toHaveValue('')
  await expect(page.getByLabel('Open ports filter')).toHaveValue('')

  const platform = await page.context().newPage()
  await mockConsole(platform, 'platform_admin')
  await platform.goto('/platform/audit')
  const auditControls = platform.locator('.host-toolbar.audit-filters input, .host-toolbar.audit-filters select')
  await expect(auditControls).toHaveCount(4)
  expect(await auditControls.evaluateAll(elements => elements.map(element => getComputedStyle(element).fontWeight))).toEqual(['400', '400', '400', '400'])
  await platform.close()
})

test('scan failures are red, anomalies are warnings, and cancellation copy is consistent (#1132)', async ({ page }) => {
  await mockConsole(page, 'administrator')
  const failedScan = { id: 'failed-scan', job_id: 'job-1', job: 'fixture-job', started_at: '2026-01-01T00:00:00Z', finished_at: '2026-01-01T00:00:01Z', status: 'failed', error: 'Nmap exited with status 1.', config_hash: 'fixture-security-hash' }
  await page.route(url => new URL(url).pathname === '/api/v1/events', route => route.fulfill({ json: { events: [
    { id: 1, type: 'scan-failure', job_id: 'job-1', job: 'fixture-job', scan_id: 'failed-scan', message: 'Nmap exited with status 1.', created_at: '2026-01-01T00:00:01Z' },
    { id: 2, type: 'scan-anomaly', job_id: 'job-1', job: 'fixture-job', message: 'A scan result needs review.', created_at: '2026-01-01T00:00:02Z' },
    { id: 3, type: 'scan-canceled', job_id: 'job-1', job: 'fixture-job', message: 'The scan was canceled.', created_at: '2026-01-01T00:00:03Z' },
  ], pagination: { limit: 20, offset: 0, total: 3, has_more: false, next_offset: null } } }))
  await page.route(url => new URL(url).pathname === '/api/v1/scans', route => route.fulfill({ json: { scans: [failedScan], pagination: { limit: 20, offset: 0, total: 1, has_more: false, next_offset: null } } }))
  await page.route(url => new URL(url).pathname === '/api/v1/jobs/job-1/scans', route => route.fulfill({ json: { scans: [failedScan], pagination: { limit: 20, offset: 0, total: 1, has_more: false, next_offset: null } } }))

  await page.goto('/activity')
  await expect(page.getByText('Scan canceled', { exact: true })).toBeVisible()
  const activityFailure = page.locator('.activity-event.failure .activity-event-marker').first()
  const activityWarning = page.locator('.activity-event.warning .activity-event-marker').first()
  await expect(activityFailure).toBeVisible()
  await expect(activityWarning).toBeVisible()
  const [failureColor, warningColor] = await Promise.all([
    activityFailure.evaluate(element => getComputedStyle(element).backgroundColor),
    activityWarning.evaluate(element => getComputedStyle(element).backgroundColor),
  ])
  expect(failureColor).toBe('rgb(243, 125, 131)')
  expect(warningColor).toBe('rgb(241, 189, 106)')

  await page.goto('/')
  const dashboardFailure = page.locator('.activity-row .activity-dot.fail').first()
  await expect(dashboardFailure).toBeVisible()
  await expect(dashboardFailure).toHaveCSS('background-color', failureColor)

  await page.route(url => new URL(url).pathname === '/api/v1/scans/active', route => route.fulfill({ json: { scans: [], queued_runs: [
    { job_id: 'job-1', job: 'fixture-job', queued_at: '2026-01-01T00:00:02Z', trigger: 'manual' },
  ] } }))
  await page.goto('/jobs/job-1')
  const jobFailure = page.locator('.scan-row .activity-dot.fail').first()
  await expect(jobFailure).toBeVisible()
  await expect(jobFailure).toHaveCSS('background-color', failureColor)
  const queuedPill = page.locator('.job-scan-status > .pill')
  await expect(page.getByRole('heading', { name: 'Scan queued' })).toBeVisible()
  for (const width of [320, 414, 620]) {
    await page.setViewportSize({ width, height: 900 })
    await expect(queuedPill).toHaveCSS('align-self', 'flex-start')
    expect((await queuedPill.boundingBox())!.width, `Queued pill width at ${width}px`).toBeLessThan(100)
  }
})

test('user-link actions are clear and keep a newly issued link beside its account (#1127)', async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 812 })
  await mockConsole(page, 'administrator')
  const timestamp = '2026-01-01T00:00:00Z'
  const accounts = [
    { id: 'user-administrator', username: 'admin', display_name: 'Administrator', role: 'administrator', enabled: true, pending: false, has_active_link: false, totp_enabled: false, created_at: timestamp, updated_at: timestamp, revision: 1 },
    ...Array.from({ length: 30 }, (_, index) => ({ id: `user-${index + 1}`, username: `operator-${String(index + 1).padStart(2, '0')}`, display_name: `Operator ${String(index + 1).padStart(2, '0')}`, role: 'operator', enabled: true, pending: false, has_active_link: false, totp_enabled: false, created_at: timestamp, updated_at: timestamp, revision: 1 })),
  ]
  await page.route(url => new URL(url).pathname === '/api/v1/users', route => route.request().method() === 'GET' ? route.fulfill({ json: { users: accounts } }) : route.fallback())
  await page.route(url => new URL(url).pathname === '/api/v1/users/user-30/password-reset', route => route.fulfill({ json: { activation_token: 'RESET-30', activation_path: '/activate#token=RESET-30', expires_at: '2026-01-01T00:30:00Z' } }))

  await page.goto('/users')
  const target = page.locator('.user-row').filter({ hasText: 'operator-30' })
  const disable = target.getByRole('button', { name: 'Disable' })
  await expect(disable).toHaveCSS('color', 'rgb(255, 156, 162)')
  await expect(disable).not.toHaveCSS('border-color', 'rgba(0, 0, 0, 0)')
  await expect(target.getByRole('button', { name: 'Revoke password reset link' })).toHaveCount(0)
  await expect(target.getByText('No outstanding activation or password reset link.')).toBeVisible()

  const issueLink = target.getByRole('button', { name: 'Create password reset link' })
  await expect(issueLink).toHaveCSS('white-space', 'nowrap')
  await issueLink.scrollIntoViewIfNeeded()
  await issueLink.click()
  const dialog = page.getByRole('dialog')
  await dialog.getByLabel('Administrator password').fill('fixture-password')
  await dialog.getByRole('button', { name: 'Confirm' }).click()

  const linkPanel = target.getByRole('region', { name: 'One-time link details' })
  await expect(linkPanel).toBeInViewport()
  await expect(linkPanel).toBeFocused()
  await expect(target.getByLabel('Password reset link for operator-30', { exact: true })).toContainText('/activate#token=RESET-30')
})
