import { expect, test, type Page } from '@playwright/test'
import { mockConsole } from './mock-console'

const timestamp = '2026-09-29T10:00:00Z'
const longValue = `gateway-${'customer-facing-api-cluster-'.repeat(7)}example.internal`

async function expectNoHorizontalScroll(page: Page, context = '') {
  const widths = await page.evaluate(() => ({ client: document.documentElement.clientWidth, scroll: document.documentElement.scrollWidth }))
  const location = context ? ` on ${context}` : ''
  expect(widths.scroll, `page scroll width ${widths.scroll} exceeds viewport ${widths.client}${location}`).toBeLessThanOrEqual(widths.client)
}

test.describe('responsive issue regressions', () => {
  test.beforeEach(async ({}, testInfo) => {
    test.skip(testInfo.project.name !== 'desktop', 'This suite controls its own viewport sizes.')
  })

  test('sidebar and mobile drawer scroll to sign out on short screens (#970)', async ({ page }) => {
    await page.setViewportSize({ width: 844, height: 390 })
    await mockConsole(page, 'administrator')
    await page.goto('/jobs')
    const sidebar = page.locator('#primary-navigation')
    expect(await sidebar.evaluate(element => getComputedStyle(element).overflowY)).toBe('auto')
    const signOut = page.getByRole('button', { name: 'Sign out' })
    const sourceLink = sidebar.getByRole('link', { name: 'Source code' })
    await sourceLink.scrollIntoViewIfNeeded()
    await expect(sourceLink).toBeVisible()
    await expect(sourceLink).toHaveAttribute('href', '/source')
    await signOut.scrollIntoViewIfNeeded()
    let box = (await signOut.boundingBox())!
    expect(box.y).toBeGreaterThanOrEqual(0)
    expect(box.y + box.height).toBeLessThanOrEqual(390)

    await page.setViewportSize({ width: 390, height: 664 })
    await page.getByRole('button', { name: 'Open navigation' }).click()
    await expect(sidebar).toHaveAttribute('aria-hidden', 'false')
    expect(await sidebar.evaluate(element => getComputedStyle(element).backgroundColor)).toBe('rgb(6, 17, 31)')
    await signOut.scrollIntoViewIfNeeded()
    box = (await signOut.boundingBox())!
    expect(box.y + box.height).toBeLessThanOrEqual(664)
  })

  test('sign-in setup link is actionable, secondary links align, and throttling explains its wait (#991)', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 900 })
    await page.route('**/api/v1/**', async route => {
      const path = new URL(route.request().url()).pathname
      if (path === '/api/v1/setup/status') {
        await route.fulfill({ json: { configured: true, platform_setup_available: true, public_dashboard_enabled: true, password_requirements: { minimum_length: 12 } } })
        return
      }
      if (path === '/api/v1/auth/session') {
        await route.fulfill({ status: 401, json: { error: { code: 'unauthorized', message: 'authentication required' } } })
        return
      }
      if (path === '/api/v1/auth/login') {
        await route.fulfill({ status: 429, headers: { 'Retry-After': '60' }, json: { error: { code: 'rate_limited', message: 'too many login attempts; try again later' } } })
        return
      }
      await route.fulfill({ status: 401, json: { error: { code: 'unauthorized', message: 'authentication required' } } })
    })

    await page.goto('/login')
    await expect(page.getByRole('link', { name: 'Source code' })).toHaveCount(0)
    const setupLink = page.getByRole('link', { name: 'Create the platform administrator' })
    const setupLinkAppearance = await setupLink.evaluate(element => ({
      decoration: getComputedStyle(element).textDecorationLine,
      height: element.getBoundingClientRect().height,
    }))
    expect(setupLinkAppearance.decoration).toContain('underline')
    expect(setupLinkAppearance.height).toBeGreaterThanOrEqual(24)

    const secondaryActions = [
      page.getByRole('button', { name: 'Use a recovery code' }),
      page.getByRole('link', { name: 'Activate an account' }),
      page.getByRole('link', { name: 'View read-only highlights' }),
    ]
    const xPositions = await Promise.all(secondaryActions.map(async action => (await action.boundingBox())!.x))
    expect(Math.max(...xPositions) - Math.min(...xPositions)).toBeLessThanOrEqual(1)

    await page.getByLabel('Password').fill('wrong password')
    await page.getByRole('button', { name: 'Sign in' }).click()
    await expect(page.getByRole('alert')).toHaveText('Too many sign-in attempts. Try again in about 1 minute.')
    await page.getByRole('button', { name: 'Use a recovery code' }).click()
    await expect(page.getByRole('alert')).toHaveCount(0)
  })

  test('live status, breadcrumbs, skip link and route focus stay useful (#989, #990)', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 800 })
    await mockConsole(page, 'administrator')
    await page.goto('/scanner-profiles')

    const reconnecting = page.getByRole('status', { name: 'Reconnecting…' })
    await expect(reconnecting).toBeVisible()
    await expect(reconnecting).toHaveClass(/reconnecting/)
    expect(await reconnecting.locator('i').evaluate(element => getComputedStyle(element).backgroundColor)).toBe('rgb(243, 125, 131)')
    await expect(page.locator('.breadcrumb')).toHaveText('Scanner profiles')
    await expect(page.locator('.nav-link.active')).toHaveAttribute('aria-current', 'page')
    await expect(page).toHaveTitle('Scanner profiles · EdgeWatch')

    await page.keyboard.press('Tab')
    const skip = page.getByRole('link', { name: 'Skip to content' })
    await expect(skip).toBeFocused()
    expect((await skip.boundingBox())!.x).toBeGreaterThanOrEqual(0)

    await page.getByRole('link', { name: 'Jobs' }).click()
    await expect(page).toHaveURL(/\/jobs$/)
    await expect(page.locator('#main-content')).toBeFocused()
    await expect(page).toHaveTitle('Jobs · EdgeWatch')

    await page.setViewportSize({ width: 375, height: 812 })
    const mobileStatus = page.getByRole('status', { name: 'Reconnecting…' })
    await expect(mobileStatus).toBeVisible()
    expect(await mobileStatus.evaluate(element => getComputedStyle(element).display)).not.toBe('none')
    await page.getByRole('button', { name: 'Open navigation' }).click()
    await page.getByRole('dialog', { name: 'Primary navigation' }).getByRole('link', { name: 'Hosts' }).click()
    await expect(page).toHaveURL(/\/hosts$/)
    await expect(page.locator('#main-content')).toBeFocused()
    await expectNoHorizontalScroll(page)
  })

  test('viewer is not left with a permanent connecting message (#989)', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 812 })
    await mockConsole(page, 'viewer')
    await page.goto('/jobs')
    const status = page.getByRole('status', { name: 'Live updates unavailable' })
    await expect(status).toBeVisible()
    await expect(status).toHaveClass(/unavailable/)
    expect(await status.locator('i').evaluate(element => getComputedStyle(element).backgroundColor)).toBe('rgb(130, 150, 174)')
    await expectNoHorizontalScroll(page)
  })

  test('platform update indicator and status notice are visible on a phone (#989, #990)', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 760 })
    await mockConsole(page, 'platform_admin')
    await page.route('**/api/v1/platform/status', async route => {
      if (route.request().method() !== 'GET') return route.fallback()
      await route.fulfill({ json: {
        version: 'v0.20.13', version_release_url: 'https://example.test/releases/v0.20.13',
        updates: { enabled: true, status: 'update_available', available: true, current_version: 'v0.20.13', latest_version: 'v0.21.0', release_url: 'https://example.test/releases/v0.21.0' },
        units: { total: 2, active: 2, disabled: 0, deleting: 0 }, accounts: 5, jobs: 3, stored_scans: 12,
        platform_admins: { total: 1, enabled: 1 }, capacity: { limits: { max_concurrent_scans: 4, max_probe_count: 5000000, max_naabu_probe_count: 20000000, max_probe_count_limit: 100000000 }, slots: { capacity: 4, in_use: 1, queued: 0 } },
      } })
    })
    await page.goto('/platform/status')
    await expect(page).toHaveTitle('Status · EdgeWatch')
    await page.keyboard.press('Tab')
    await expect(page.getByRole('link', { name: 'Skip to content' })).toBeFocused()
    await page.keyboard.press('Tab')
    const menu = page.getByRole('button', { name: 'Open navigation' })
    await expect(menu).toBeFocused()
    await page.keyboard.press('Enter')
    const indicator = page.getByRole('link', { name: 'Update available: v0.20.13 to v0.21.0' })
    await expect(indicator).toBeVisible()
    await expect(indicator).toHaveAttribute('href', 'https://example.test/releases/v0.21.0')
    await page.getByRole('dialog', { name: 'Primary navigation' }).getByRole('button', { name: 'Close navigation' }).click()
    await expect(page.getByRole('status')).toContainText('Version v0.21.0 is available.')
    await expect(page.getByRole('link', { name: 'Release notes' })).toBeVisible()
    expect(await page.locator('.breadcrumb').evaluate(element => element.innerText)).toBe('Status')
    await expectNoHorizontalScroll(page)
  })

  test('platform unit tabs, capacity ceiling and unit list remain usable on phones (#992)', async ({ page }) => {
    await mockConsole(page, 'platform_admin')
    await page.setViewportSize({ width: 320, height: 760 })
    await page.goto('/platform/units/unit-retail/overview')

    const tabs = page.getByRole('navigation', { name: 'Retail sections' }).getByRole('link')
    await expect(tabs).toHaveCount(4)
    for (const tab of await tabs.all()) {
      await expect(tab).toBeVisible()
      const box = (await tab.boundingBox())!
      expect(box.x).toBeGreaterThanOrEqual(0)
      expect(box.x + box.width).toBeLessThanOrEqual(320)
    }
    await expectNoHorizontalScroll(page)

    await page.goto('/platform/units/unit-retail/capacity')
    const grant = page.getByRole('radio', { name: 'Grant a ceiling' })
    await grant.check()
    const grantOption = page.locator('.ceiling-option').filter({ has: grant })
    const ceiling = grantOption.getByLabel('High-cost ceiling')
    await expect(ceiling).toBeVisible()
    await ceiling.fill('5000000')
    await expect(grantOption).toContainText('Granted ceiling: 5,000,000 probes per run. Maximum 100,000,000.')
    await expectNoHorizontalScroll(page)

    await page.setViewportSize({ width: 1280, height: 900 })
    await page.goto('/platform/units')
    const accountLabels = page.locator('.unit-row .unit-facts > div:first-child dt')
    await expect(accountLabels).toHaveCount(2)
    const labelPositions = await accountLabels.evaluateAll(elements => elements.map(element => element.getBoundingClientRect().x))
    expect(Math.abs(labelPositions[0] - labelPositions[1])).toBeLessThanOrEqual(1)

    await page.setViewportSize({ width: 320, height: 760 })
    const search = page.getByRole('searchbox', { name: 'Search by name or public slug' })
    await search.fill('retail')
    await expect(page.getByRole('link', { name: 'Open Retail' })).toBeVisible()
    await expect(page.getByRole('link', { name: 'Open Default' })).toHaveCount(0)
    await expectNoHorizontalScroll(page)
  })

  test('audit actors cannot squeeze the event column at tablet widths (#1123)', async ({ page }) => {
    await mockConsole(page, 'administrator')
    const actor = 'alexandra.konstantinopoulou.security-operations@international-services.example.com'
    await page.route('**/api/v1/audit**', async route => {
      if (route.request().method() !== 'GET' || new URL(route.request().url()).pathname !== '/api/v1/audit') return route.fallback()
      await route.fulfill({ json: { entries: [{
        id: 9001,
        created_at: timestamp,
        action: 'user.login',
        category: 'account',
        actor: { kind: 'user', user_id: 'user-long', username: actor },
        detail: 'signed in successfully',
        source_ip: '192.0.2.30',
      }], next_before: null } })
    })

    await page.goto('/audit')
    await expect(page.getByText(actor, { exact: true })).toBeVisible()
    for (const width of [761, 768, 844, 900, 1024, 1100]) {
      await page.setViewportSize({ width, height: 900 })
      const row = page.locator('.audit-row')
      const widths = await row.evaluate(element => ({
        main: element.querySelector('.audit-main')!.getBoundingClientRect().width,
        height: element.getBoundingClientRect().height,
        actor: element.querySelector('.audit-actor')!.getBoundingClientRect().width,
      }))
      expect(widths.main, `audit event column at ${width}px`).toBeGreaterThanOrEqual(200)
      expect(widths.actor, `actor column at ${width}px`).toBeLessThanOrEqual(240)
      expect(widths.height, `audit row at ${width}px`).toBeLessThanOrEqual(250)
      await expectNoHorizontalScroll(page, `audit at ${width}px`)
    }

    const platformPage = await page.context().newPage()
    await mockConsole(platformPage, 'platform_admin')
    await platformPage.route('**/api/v1/platform/audit**', async route => {
      if (route.request().method() !== 'GET' || new URL(route.request().url()).pathname !== '/api/v1/platform/audit') return route.fallback()
      await route.fulfill({ json: { entries: [{
        id: 9002,
        created_at: timestamp,
        action: 'unit.admin_invited',
        category: 'account',
        actor: { kind: 'user', user_id: 'user-long', username: actor },
        unit: { id: 'unit-retail', name: 'Retail' },
        detail: 'invited an administrator',
        source_ip: '192.0.2.30',
      }], next_before: null } })
    })
    await platformPage.goto('/platform/audit')
    await expect(platformPage.getByText(actor, { exact: true })).toBeVisible()
    for (const width of [761, 768, 844, 900, 1024, 1100]) {
      await platformPage.setViewportSize({ width, height: 900 })
      const row = platformPage.locator('.audit-row')
      const layout = await row.evaluate(element => ({
        main: element.querySelector('.audit-main')!.getBoundingClientRect().width,
        height: element.getBoundingClientRect().height,
      }))
      expect(layout.main, `platform audit event column at ${width}px`).toBeGreaterThanOrEqual(200)
      expect(layout.height, `platform audit row at ${width}px`).toBeLessThanOrEqual(250)
      await expectNoHorizontalScroll(platformPage, `platform audit at ${width}px`)
    }
    await platformPage.close()
  })

  test('activity panels stack and keep their own height across tablet widths (#1123)', async ({ page }) => {
    await mockConsole(page, 'administrator')
    await page.route('**/api/v1/jobs**', async route => {
      if (route.request().method() !== 'GET' || new URL(route.request().url()).pathname !== '/api/v1/jobs') return route.fallback()
      await route.fulfill({ json: { jobs: [{
        id: 'job-1', revision: 1, enabled: true, archived: false, security_hash: 'fixture-security-hash', created_at: timestamp, updated_at: timestamp,
        job: { name: 'Long-running edge scanning maintenance job', schedule: '0 * * * *', timezone: 'UTC', targets: ['192.0.2.10'], max_expanded_hosts: 16, tcp: { ports: '22,443', mode: 'connect', service_detection: false }, timing: 'balanced', timeout: '1h', baseline_samples: 1, change_confirmations: 3 },
        baseline: { status: 'complete', samples: 1, attempts: 1, host_count: 1, pending: 8 },
      }] } })
    })
    await page.route('**/api/v1/jobs/job-1/pending-changes**', async route => {
      if (route.request().method() !== 'GET') return route.fallback()
      const changes = Array.from({ length: 8 }, (_, index) => ({ key: `port-${index + 1}`, change: { kind: 'port', target: '192.0.2.10', protocol: 'tcp', port: 4000 + index, severity: 'info' }, count: 1 }))
      await route.fulfill({ json: { job_id: 'job-1', job: 'Long-running edge scanning maintenance job', pending_changes: changes, pagination: { limit: 10, offset: 0, total: changes.length, has_more: false, next_offset: null } } })
    })

    await page.goto('/activity')
    await page.getByRole('button', { name: 'Show 8 pending changes' }).click()
    await expect(page.getByText('TCP:4000', { exact: false })).toBeVisible()
    for (const width of [768, 844, 900, 1024, 1100]) {
      await page.setViewportSize({ width, height: 900 })
      const grid = page.locator('.activity-state-grid')
      const layout = await grid.evaluate(element => ({
        columns: getComputedStyle(element).gridTemplateColumns.trim().split(/\s+/).length,
        alignItems: getComputedStyle(element).alignItems,
        incidentHeight: element.children[0].getBoundingClientRect().height,
        pendingHeight: element.children[1].getBoundingClientRect().height,
      }))
      expect(layout.columns, `activity panel columns at ${width}px`).toBe(1)
      expect(layout.alignItems).toBe('start')
      expect(layout.pendingHeight - layout.incidentHeight, `independent panel heights at ${width}px`).toBeGreaterThan(80)
      expect(await page.locator('.pending-job-heading strong').evaluate(element => getComputedStyle(element).overflowWrap)).not.toBe('anywhere')
      await expectNoHorizontalScroll(page, `activity at ${width}px`)
    }
  })

  test('platform unit facts stay wide on tablets and compact on a 320px phone (#1123)', async ({ page }) => {
    await mockConsole(page, 'platform_admin')
    await page.goto('/platform/units')
    for (const width of [768, 900]) {
      await page.setViewportSize({ width, height: 900 })
      const facts = page.locator('.unit-facts').first()
      await expect(facts).toBeVisible()
      expect(await facts.evaluate(element => element.getBoundingClientRect().width), `unit facts at ${width}px`).toBeGreaterThanOrEqual(300)
      await expectNoHorizontalScroll(page, `units at ${width}px`)
    }

    await page.setViewportSize({ width: 320, height: 760 })
    const row = page.locator('.unit-row').first()
    const rowHeight = await row.evaluate(element => element.getBoundingClientRect().height)
    expect(rowHeight, 'compact business-unit row at 320px').toBeLessThanOrEqual(140)
    await expectNoHorizontalScroll(page, 'units at 320px')

  })

  test('decorative heading icons stay with tablet layouts on all affected pages (#1123)', async ({ page }) => {
    const unitPages = ['/activity', '/notifications', '/users', '/audit', '/public-dashboard']
    const platformPages = ['/platform/admins', '/platform/status', '/platform/notifications', '/platform/audit']
    await mockConsole(page, 'administrator')
    for (const width of [768, 1024, 1100]) {
      await page.setViewportSize({ width, height: 900 })
      for (const path of unitPages) {
        await page.goto(path)
        const icon = page.locator('.page-heading > svg.muted-icon')
        await expect(icon, `${path} has its heading icon`).toHaveCount(1)
        await expect(icon, `${path} hides its orphaned heading icon at ${width}px`).toHaveCSS('display', 'none')
      }
    }

    const platformPage = await page.context().newPage()
    await mockConsole(platformPage, 'platform_admin')
    for (const width of [768, 1024, 1100]) {
      await platformPage.setViewportSize({ width, height: 900 })
      for (const path of platformPages) {
        await platformPage.goto(path)
        const icon = platformPage.locator('.page-heading > svg.muted-icon')
        await expect(icon, `${path} has its heading icon`).toHaveCount(1)
        await expect(icon, `${path} hides its orphaned heading icon at ${width}px`).toHaveCSS('display', 'none')
      }
    }
    await platformPage.close()
  })

  test('dashboard baseline pills never cover job names at phone widths (#1124)', async ({ page }) => {
    await mockConsole(page, 'operator')
    await page.route('**/api/v1/jobs**', async route => {
      if (route.request().method() !== 'GET' || new URL(route.request().url()).pathname !== '/api/v1/jobs') return route.fallback()
      const jobs = [
        { id: 'vpn', name: 'VPN gateways', status: 'complete' },
        { id: 'office', name: 'Office perimeter', status: 'updating' },
        { id: 'mail', name: 'Mail relays', status: 'complete' },
        { id: 'web', name: 'Public web', status: 'complete' },
      ].map(({ id, name, status }) => ({
        id, revision: 1, enabled: true, archived: false, security_hash: 'hash', created_at: timestamp, updated_at: timestamp,
        job: { name, schedule: '0 * * * *', timezone: 'UTC', targets: ['192.0.2.10'], max_expanded_hosts: 16, tcp: { ports: '22,443', mode: 'connect', service_detection: false }, timing: 'balanced', timeout: '1h', baseline_samples: 1, change_confirmations: 1 },
        baseline: { status, samples: 1, attempts: 1, host_count: 1 },
      }))
      await route.fulfill({ json: { jobs } })
    })

    for (const width of [320, 375, 414]) {
      await page.setViewportSize({ width, height: 900 })
      await page.goto('/')
      const row = page.locator('.dashboard-job').filter({ hasText: 'Office perimeter' })
      await expect(row).toBeVisible()
      const layout = await row.evaluate(element => {
        const name = element.querySelector('.dashboard-job-info strong')!
        const pill = element.querySelector('.pill')!
        const range = document.createRange()
        range.selectNodeContents(name)
        const textRects = [...range.getClientRects()].map(rect => ({ left: rect.left, right: rect.right, top: rect.top, bottom: rect.bottom }))
        const pillRect = pill.getBoundingClientRect()
        const overlaps = textRects.some(rect => rect.left < pillRect.right && rect.right > pillRect.left && rect.top < pillRect.bottom && rect.bottom > pillRect.top)
        return { nameWidth: name.getBoundingClientRect().width, nameBottom: Math.max(...textRects.map(rect => rect.bottom)), pillTop: pillRect.top, overlaps }
      })
      expect(layout.overlaps, `baseline pill overlap at ${width}px`).toBe(false)
      expect(layout.nameWidth >= 128 || layout.pillTop >= layout.nameBottom, `job name has room or wraps away from its pill at ${width}px`).toBe(true)
      await expectNoHorizontalScroll(page, `dashboard at ${width}px`)
    }
  })

  test('latest activity stacks its timestamp and keeps outcome copy readable (#1124)', async ({ page }) => {
    await mockConsole(page, 'operator')
    await page.route('**/api/v1/scans**', async route => {
      if (route.request().method() !== 'GET' || new URL(route.request().url()).pathname !== '/api/v1/scans') return route.fallback()
      await route.fulfill({ json: { scans: [
        { id: 'failed-scan', job_id: 'job-1', job: 'Public web', status: 'failed', error: 'nmap exited with status 1: Failed to resolve "customer-facing-api-gateway-perimeter-monitoring.eu-west-1.production.example.com"; QUITTING! The scan could not complete because the target list contained an unresolvable hostname and the scanner refused to continue.', started_at: '2026-09-29T09:00:00Z', finished_at: '2026-09-29T10:00:00Z', config_hash: 'hash' },
        { id: 'successful-scan', job_id: 'job-2', job: 'VPN gateways', status: 'success', started_at: '2026-09-29T08:00:00Z', finished_at: '2026-09-29T08:30:00Z', config_hash: 'hash' },
      ], pagination: { limit: 20, offset: 0, total: 2, has_more: false, next_offset: null } } })
    })

    for (const width of [375, 1280]) {
      await page.setViewportSize({ width, height: 900 })
      await page.goto('/')
      const failedRow = page.locator('.activity-row').filter({ hasText: 'Public web' })
      const outcome = failedRow.locator(':scope > div')
      await expect(outcome).toBeVisible()
      expect(await outcome.boundingBox().then(box => box!.width), `activity outcome at ${width}px`).toBeGreaterThanOrEqual(200)
      const successfulRow = page.getByRole('link', { name: 'Open scan details for VPN gateways' })
      await expect(successfulRow).toBeVisible()
      await expect(successfulRow).toHaveAttribute('href', '/jobs/job-2/scans/successful-scan')
      await expectNoHorizontalScroll(page, `dashboard at ${width}px`)
    }
  })

  test('stagger suggestion copy stays readable and its button follows it (#1124)', async ({ page }) => {
    await mockConsole(page, 'operator')
    await page.route('**/api/v1/jobs/schedule-suggestion**', async route => {
      if (route.request().method() !== 'GET' || new URL(route.request().url()).pathname !== '/api/v1/jobs/schedule-suggestion') return route.fallback()
      await route.fulfill({ json: { suggested: true, suggested_schedule: '30 */6 * * *', offset_minutes: 30, gap_minutes: 0, nearest: { id: 'job-2', name: 'Customer-facing API gateway perimeter monitoring for the EU West production estate weekly', schedule: '0 */6 * * *', timezone: 'America/Argentina/ComodRivadavia', next_run: '2026-09-29T18:00:00Z' } } })
    })

    for (const width of [320, 1280]) {
      await page.setViewportSize({ width, height: 900 })
      await page.goto('/jobs/new')
      const suggestion = page.locator('.schedule-suggestion')
      await expect(suggestion).toBeVisible({ timeout: 5_000 })
      const copy = suggestion.locator('.schedule-suggestion-copy')
      const button = suggestion.getByRole('button', { name: 'Use later time' })
      await expect(copy).toBeVisible()
      const [copyBox, buttonBox] = await Promise.all([copy.boundingBox(), button.boundingBox()])
      expect(copyBox!.width, `stagger copy at ${width}px`).toBeGreaterThanOrEqual(180)
      expect(buttonBox!.y, `stagger button below copy at ${width}px`).toBeGreaterThanOrEqual(copyBox!.y + copyBox!.height - 1)
      expect(await copy.evaluate(element => getComputedStyle(element).overflowWrap)).toBe('break-word')
      await expectNoHorizontalScroll(page, `job editor at ${width}px`)
    }

    await expect(page.locator('.editor-side .panel-heading .muted-icon')).toHaveCount(0)
  })

  test('scan work estimate lead-in remains part of the sentence at narrow and wide widths (#1124)', async ({ page }) => {
    await mockConsole(page, 'operator')
    await page.route('**/api/v1/jobs/job-1**', async route => {
      if (route.request().method() !== 'GET' || new URL(route.request().url()).pathname !== '/api/v1/jobs/job-1') return route.fallback()
      await route.fulfill({ json: {
        id: 'job-1', revision: 1, enabled: true, archived: false, security_hash: 'hash', created_at: timestamp, updated_at: timestamp,
        job: { name: 'fixture-job', schedule: '0 * * * *', timezone: 'UTC', targets: ['192.0.2.10'], max_expanded_hosts: 16, tcp: { ports: '1-65535', mode: 'connect', service_detection: false }, timing: 'balanced', timeout: '1h', resume_window: '8d', baseline_samples: 1, change_confirmations: 1, run_on_start: false, assume_alive: true, allow_high_cost: false },
        baseline: { status: 'complete', samples: 1, attempts: 1, host_count: 1 },
        scan_estimate: { hosts: 4096, tcp_ports: 65535, udp_ports: 0, probes: 268505088, nmap_invocations: 4096, unknown_dns: 0 },
      } })
    })

    for (const width of [320, 1280]) {
      await page.setViewportSize({ width, height: 900 })
      await page.goto('/jobs/job-1')
      const notice = page.locator('.notice').filter({ hasText: 'Scan work per run:' })
      await expect(notice).toBeVisible()
      await expect(notice.locator(':scope > span')).toHaveCount(1)
      await expect(notice.locator(':scope > strong')).toHaveCount(0)
      expect((await notice.locator('strong').boundingBox())!.height, `estimate lead-in at ${width}px`).toBeLessThan(25)
      await expectNoHorizontalScroll(page, `job detail at ${width}px`)
    }
  })

  test('status labels stay readable and archived host badges stay compact (#994)', async ({ page }) => {
    await mockConsole(page, 'administrator')
    await page.route('**/api/v1/hosts**', async route => {
      if (route.request().method() !== 'GET') return route.fallback()
      await route.fulfill({ json: { hosts: [{
        address: '198.51.100.20', job_id: 'job-archived', job: 'retired job', scan_id: 'scan-archived',
        scanned_at: timestamp, data_quality: 'detailed', open_ports: 0, open_filtered_ports: 0,
        has_open_ports: false, archived: true,
      }], pagination: { limit: 100, offset: 0, total: 1, has_more: false, next_offset: null } } })
    })

    await page.goto('/scanner-profiles')
    const builtIn = page.getByText('Built-in', { exact: true })
    await expect(builtIn).toBeVisible()
    expect(await builtIn.evaluate(element => getComputedStyle(element).textTransform)).toBe('none')

    await page.goto('/public-dashboard')
    const archived = page.locator('.public-picker-archived')
    await expect(archived).toHaveText('Archived')
    expect(await archived.evaluate(element => getComputedStyle(element).justifySelf)).toBe('start')
  })

  test('long dashboard values stay in shrinkable cards (#971)', async ({ page }) => {
    await mockConsole(page, 'operator')
    await page.route('**/api/v1/jobs**', async route => {
      if (route.request().method() !== 'GET' || new URL(route.request().url()).pathname !== '/api/v1/jobs') return route.fallback()
      await route.fulfill({ json: { jobs: [{
        id: 'job-1', revision: 1, enabled: true, archived: false, security_hash: 'hash', created_at: timestamp, updated_at: timestamp,
        job: { name: longValue, schedule: '0 * * * *', timezone: 'UTC', targets: [longValue], max_expanded_hosts: 32, tcp: { ports: '443', mode: 'connect', service_detection: false }, baseline_samples: 1, change_confirmations: 1 },
        baseline: { status: 'complete', samples: 1, attempts: 1, host_count: 1 },
      }] } })
    })
    await page.route('**/api/v1/scans**', async route => {
      if (route.request().method() !== 'GET' || new URL(route.request().url()).pathname !== '/api/v1/scans') return route.fallback()
      await route.fulfill({ json: { scans: [{ id: 'scan-long', job_id: 'job-1', job: longValue, started_at: timestamp, finished_at: timestamp, status: 'failed', error: longValue, config_hash: 'hash' }], pagination: { limit: 20, offset: 0, total: 1, has_more: false, next_offset: null } } })
    })

    for (const width of [320, 768]) {
      await page.setViewportSize({ width, height: 900 })
      await page.goto('/')
      await expect(page.getByText(longValue, { exact: false }).first()).toBeVisible()
      await expectNoHorizontalScroll(page)
    }
  })

  test('long values stay inside notification, profile, picker and host result rows (#971)', async ({ page }) => {
    // This intentionally visits six pages at seven viewport widths; allow the
    // full matrix to complete on slower CI workers instead of failing halfway.
    test.setTimeout(90_000)
    await mockConsole(page, 'administrator')
    const longIPv6 = '2a01:4f8:c17:b8f2:9c2b:4bff:fe12:3456'
    const longProfile = 'perimeter_naabu_full_tcp_nmap_confirmed_v2_customer_edge'

    await page.route('**/api/v1/notifications/destinations', async route => {
      if (route.request().method() !== 'GET') return route.fallback()
      await route.fulfill({ json: {
        destinations: [{ id: 'dest-long', name: longValue, provider: 'generic', source: 'web', enabled: true, locked: false, read_only: false, revision: 1 }],
        status: { deployment: 0, managed: 1, active: 1, locked: 0, key_state: 'ready' },
        update_routing: { configured: true, destinations: ['dest-long'] },
      } })
    })
    await page.route('**/api/v1/scanner-profiles*', async route => {
      if (route.request().method() !== 'GET' || new URL(route.request().url()).pathname !== '/api/v1/scanner-profiles') return route.fallback()
      await route.fulfill({ json: { profiles: [{
        id: 'profile-long', name: longProfile, built_in: false, archived: false, revision: 1,
        definition: { engine: 'nmap', naabu: {}, nmap_args: [], naabu_args: [], enrichment_args: [] },
      }] } })
    })
    await page.route('**/api/v1/hosts**', async route => {
      if (route.request().method() !== 'GET') return route.fallback()
      await route.fulfill({ json: { hosts: [{
        address: longIPv6, address_family: 'IPv6', source_targets: [longValue], dns_names: [],
        job_id: 'job-1', job: longValue, scan_id: 'scan-1', scanned_at: timestamp,
        open_ports: 1, open_filtered_ports: 0, has_open_ports: true, data_quality: 'detailed', protocols: [],
      }], pagination: { limit: 100, offset: 0, total: 1, has_more: false, next_offset: null } } })
    })
    await page.route('**/api/v1/scans/scan-1/hosts**', async route => {
      if (route.request().method() !== 'GET') return route.fallback()
      await route.fulfill({ json: {
        job_id: 'job-1', job: longValue, scan: { id: 'scan-1', job_id: 'job-1', job: longValue, started_at: timestamp, finished_at: timestamp, status: 'success', config_hash: 'hash' },
        hosts: [{ address: longIPv6, address_family: 'IPv6', protocols: [], open_ports: 1, open_filtered_ports: 0 }],
        pagination: { limit: 50, offset: 0, total: 1, has_more: false, next_offset: null },
      } })
    })
    await page.route('**/api/v1/scans/scan-1/summary', async route => {
      if (route.request().method() !== 'GET') return route.fallback()
      await route.fulfill({ json: { scan: { id: 'scan-1', job_id: 'job-1', job: longValue, started_at: timestamp, finished_at: timestamp, status: 'success', config_hash: 'hash' } } })
    })
    await page.route('**/api/v1/jobs/job-1', async route => {
      if (route.request().method() !== 'GET') return route.fallback()
      await route.fulfill({ json: {
        id: 'job-1', revision: 1, enabled: true, archived: false, security_hash: 'hash', created_at: timestamp, updated_at: timestamp,
        job: { name: longValue, schedule: '0 * * * *', timezone: 'UTC', targets: [longValue], max_expanded_hosts: 32, tcp: { ports: '443', mode: 'connect', service_detection: false }, baseline_samples: 1, change_confirmations: 1 },
        baseline: { status: 'complete', samples: 1, attempts: 1, host_count: 1 },
      } })
    })
    await page.route('**/api/v1/public-dashboard', async route => {
      if (route.request().method() !== 'GET') return route.fallback()
      await route.fulfill({ json: { enabled: false, title: 'Fixture public status', introduction: '', updated_at: timestamp, hosts: [] } })
    })

    for (const path of ['/notifications', '/scanner-profiles', '/public-dashboard', '/hosts', '/jobs/job-1', '/scans/scan-1']) {
      for (const width of [320, 375, 414, 768, 844, 1280, 1920]) {
        await page.setViewportSize({ width, height: 1024 })
        await page.goto(path)
        await expectNoHorizontalScroll(page, `${path} at ${width}px`)
      }
    }

    for (const width of [320, 768, 1280]) {
      await page.setViewportSize({ width, height: 1024 })
      await page.goto('/notifications')
      const updateAlertState = page.locator('.notification-update-toggle small').first()
      await expect(updateAlertState).toHaveAttribute('title', /^Release and upgrade alerts (on|off)$/)
      const updateAlertDimensions = await updateAlertState.evaluate(element => ({ client: element.clientWidth, scroll: element.scrollWidth }))
      expect(updateAlertDimensions.scroll).toBeLessThanOrEqual(updateAlertDimensions.client)
      const notificationPanel = page.locator('.notification-list-panel')
      const notificationEdit = notificationPanel.getByRole('button', { name: 'Edit' })
      await expect(notificationEdit).toBeVisible()
      const [notificationPanelBox, notificationEditBox] = await Promise.all([notificationPanel.boundingBox(), notificationEdit.boundingBox()])
      expect(notificationEditBox!.x + notificationEditBox!.width).toBeLessThanOrEqual(notificationPanelBox!.x + notificationPanelBox!.width)
      for (const button of await notificationPanel.locator('.notification-actions button').all()) {
        const [panelBox, buttonBox] = await Promise.all([notificationPanel.boundingBox(), button.boundingBox()])
        expect(buttonBox!.x + buttonBox!.width).toBeLessThanOrEqual(panelBox!.x + panelBox!.width)
      }

      await page.goto('/scanner-profiles')
      const profileEdit = page.getByRole('button', { name: `Edit ${longProfile}` })
      const profileArchive = page.getByRole('button', { name: `Archive ${longProfile}` })
      await expect(profileEdit).toBeVisible()
      await expect(profileArchive).toBeVisible()
      for (const action of [profileEdit, profileArchive]) {
        const actionBox = (await action.boundingBox())!
        expect(actionBox.x + actionBox.width).toBeLessThanOrEqual(width)
      }
      const profileHit = await profileEdit.evaluate(button => {
        const box = button.getBoundingClientRect()
        const hit = document.elementFromPoint(box.x + box.width / 2, box.y + box.height / 2)
        return hit instanceof Node && (button === hit || button.contains(hit))
      })
      expect(profileHit).toBe(true)

      await page.goto('/public-dashboard')
      await expect(page.locator('.public-picker-row strong')).toContainText(longIPv6)
      const pickerRow = page.locator('.public-picker-row').filter({ hasText: longIPv6 }).first()
      const pickerAddressLayout = await pickerRow.locator('strong').evaluate(element => {
        const range = document.createRange()
        range.selectNodeContents(element)
        const textRects = [...range.getClientRects()].map(rect => ({ left: rect.left, right: rect.right }))
        const picker = element.closest('.public-picker')!.getBoundingClientRect()
        return { textRects, left: picker.left, right: picker.right }
      })
      expect(pickerAddressLayout.textRects.length).toBeGreaterThan(0)
      expect(pickerAddressLayout.textRects.every(rect => rect.left >= pickerAddressLayout.left && rect.right <= pickerAddressLayout.right)).toBe(true)
      await page.goto('/scans/scan-1')
      await expect(page.locator('.result-row strong')).toContainText(longIPv6)
      await page.goto('/jobs/job-1')
      await expect(page.locator('.detail-summary')).toContainText(longValue)
      await expect(page.locator('.scan-row-copy > span').first()).toHaveAttribute('title', 'Completed successfully · Open results to inspect the snapshot')
      await expectNoHorizontalScroll(page)
    }

    for (const width of [320, 375, 414, 1280]) {
      await page.setViewportSize({ width, height: 1024 })
      await page.goto('/')
      const latestOutcome = page.locator('.activity-row').first().locator('div > span').first()
      await expect(latestOutcome).toHaveAttribute('title', 'Completed successfully · Open scan details')
      await expectNoHorizontalScroll(page, `latest activity at ${width}px`)
    }
  })

  test('user and audit copy keep useful width at tablet sizes (#972)', async ({ page }) => {
    await mockConsole(page, 'administrator')
    for (const width of [768, 844, 900, 1024, 1100, 1280, 1920]) {
      await page.setViewportSize({ width, height: 1024 })
      await page.goto('/users')
      const name = page.locator('.user-row > div:first-child').first()
      await expect(name).toBeVisible()
      expect((await name.boundingBox())!.width).toBeGreaterThan(120)
      await expectNoHorizontalScroll(page)

      await page.goto('/audit')
      const main = page.locator('.audit-main').first()
      await expect(main).toBeVisible()
      expect((await main.boundingBox())!.width).toBeGreaterThan(200)
      await expectNoHorizontalScroll(page)
    }

    await mockConsole(page, 'platform_admin')
    await page.route('**/api/v1/platform/units/unit-retail/accounts', async route => {
      if (route.request().method() !== 'GET') return route.fallback()
      await route.fulfill({ json: { accounts: [{
        id: 'acct-pending', username: 'pending.admin@corp.example.com', display_name: 'Pending Administrator',
        role: 'administrator', enabled: false, pending: true, totp_enabled: false,
        created_at: timestamp, updated_at: timestamp, revision: 1,
      }] } })
    })
    await page.setViewportSize({ width: 320, height: 720 })
    await page.goto('/platform/units/unit-retail/accounts')
    const accountName = page.locator('.account-row > div:first-child').first()
    await expect(accountName).toContainText('pending.admin@corp.example.com')
    expect((await accountName.boundingBox())!.width).toBeGreaterThan(120)
    await expectNoHorizontalScroll(page)
  })

  test('incident actions and host evidence remain within their cards (#973)', async ({ page }) => {
    await page.setViewportSize({ width: 820, height: 900 })
    await mockConsole(page, 'administrator')
    await page.goto('/incidents')
    await expect(page.locator('.desktop-incident-table')).toBeHidden()
    await expect(page.locator('.mobile-incident-list')).toBeVisible()
    const incidentCard = page.locator('.mobile-incident-list article').first()
    const action = incidentCard.getByRole('button', { name: 'Accept change' })
    await expect(action).toBeVisible()
    const [cardBox, actionBox] = await Promise.all([incidentCard.boundingBox(), action.boundingBox()])
    expect(actionBox!.x + actionBox!.width).toBeLessThanOrEqual(cardBox!.x + cardBox!.width)

    const address = '2001:db8:85a3::8a2e:370:7334'
    const fingerprint = `${'Apache httpd OpenSSL mod_wsgi Python mod_perl '.repeat(5)}2.4.62`
    const host = {
      address, address_family: 'IPv6', source_targets: [longValue], status: 'up',
      protocols: [{ protocol: 'tcp', scanned_ports: '443', scanned_port_count: 1, service_detection: true, ports: [{ port: 443, state: 'open', service: { name: 'https', product: fingerprint, version: '2.4.62', extra_info: fingerprint } }], state_summaries: [], nse_output: ['http-title: <img src=x onerror=alert(1)>', `ssl-cert: ${longValue}\nIssuer: Example CA`] }],
    }
    await page.route('**/api/v1/scans/scan-1/hosts/**', async route => {
      const pathname = new URL(route.request().url()).pathname
      if (pathname.endsWith('/rdap')) return route.fulfill({ json: { rdap: { status: 'private', address } } })
      await route.fulfill({ json: { job_id: 'job-1', job: 'fixture-job', data_quality: 'detailed', scan: { id: 'scan-1', job_id: 'job-1', job: 'fixture-job', started_at: timestamp, finished_at: timestamp, status: 'success', config_hash: 'hash' }, host } })
    })
    await page.setViewportSize({ width: 768, height: 1024 })
    await page.goto(`/scans/scan-1/hosts/${encodeURIComponent(address)}`)
    await expect(page.getByRole('heading', { name: address })).toBeVisible()
    await expectNoHorizontalScroll(page)
    const protocol = page.locator('.protocol-card').first()
    const protocolBox = (await protocol.boundingBox())!
    expect(protocolBox.x + protocolBox.width).toBeLessThanOrEqual(768)
    expect(await page.locator('.port-table-wrap').evaluate(element => getComputedStyle(element).overflowX)).toBe('auto')
    const nseResults = page.getByRole('region', { name: 'TCP Nmap script results' })
    await expect(nseResults).toContainText('http-title')
    await expect(nseResults).toContainText('<img src=x onerror=alert(1)>')
    await expect(nseResults.locator('img')).toHaveCount(0)
    await expect(nseResults.locator('pre').nth(1)).toContainText('Issuer: Example CA')
    await expectNoHorizontalScroll(page)
  })

  test('incident table keeps every column and action inside the card on desktop widths (#1122)', async ({ page }) => {
    await mockConsole(page, 'administrator')
    const rows = Array.from({ length: 8 }, (_, i) => ({
      job_id: 'job-1',
      job: 'Customer-facing API gateway perimeter monitoring for the EU West production estate (weekly)',
      incident: {
        change: {
          key: `svc-${i}`,
          kind: 'service',
          target: i % 2 ? 'api-gateway.eu-west-1.example.com' : '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
          protocol: 'tcp',
          port: 443 + i,
          old: 'nginx 1.18.0 (Ubuntu)',
          new: 'Apache httpd 2.4.62 ((Debian) OpenSSL/3.0.15)',
          severity: 'warning',
        },
        opened_at: timestamp,
        last_seen_at: timestamp,
      },
    }))
    await page.route(url => new URL(url).pathname === '/api/v1/incidents', async route => {
      if (route.request().method() !== 'GET') return route.fallback()
      await route.fulfill({ json: { incidents: rows, pagination: { limit: 50, offset: 0, total: rows.length, has_more: false, next_offset: null } } })
    })

    for (const width of [1101, 1180, 1280, 1920]) {
      await page.setViewportSize({ width, height: 900 })
      await page.goto('/incidents')
      const card = page.locator('.incident-table-card')
      const cardBox = (await card.boundingBox())!
      if (width <= 1400) {
        await expect(page.locator('.desktop-incident-table')).toBeHidden()
        const cards = page.locator('.mobile-incident-list .incident-card')
        await expect(cards).toHaveCount(rows.length)
        for (const incidentCard of await cards.all()) {
          await expect(incidentCard.locator('.pill')).toBeVisible()
          await expect(incidentCard.locator('.incident-facts')).toContainText('Last seen')
          const incidentBox = (await incidentCard.boundingBox())!
          for (const button of await incidentCard.locator('.incident-actions button').all()) {
            const buttonBox = await button.boundingBox()
            expect(buttonBox, `incident action is missing at ${width}px`).not.toBeNull()
            expect(buttonBox!.x).toBeGreaterThanOrEqual(incidentBox.x)
            expect(buttonBox!.x + buttonBox!.width).toBeLessThanOrEqual(incidentBox.x + incidentBox.width)
          }
        }
      } else {
        await expect(page.locator('.desktop-incident-table')).toBeVisible()
        const dimensions = await card.evaluate(element => ({ client: element.clientWidth, scroll: element.scrollWidth }))
        expect(dimensions.scroll, `incident table overflows its card at ${width}px`).toBeLessThanOrEqual(dimensions.client)

        const importantCells = page.locator('.desktop-incident-table tbody tr td:nth-child(4), .desktop-incident-table tbody tr td:nth-child(5), .desktop-incident-table .incident-actions button')
        for (const element of await importantCells.all()) {
          const box = await element.boundingBox()
          expect(box, `incident action or detail is missing at ${width}px`).not.toBeNull()
          expect(box!.x, `incident content starts outside the card at ${width}px`).toBeGreaterThanOrEqual(cardBox.x)
          expect(box!.x + box!.width, `incident content ends outside the card at ${width}px`).toBeLessThanOrEqual(cardBox.x + cardBox.width)
        }
      }
      await expectNoHorizontalScroll(page, `/incidents at ${width}px`)
    }
  })

  test('stale incident actions focus their explanation where the user can see it (#1122)', async ({ page }) => {
    await mockConsole(page, 'administrator')
    const rows = Array.from({ length: 12 }, (_, i) => ({
      job_id: 'job-1',
      job: 'Public web',
      incident: {
        change: {
          key: `port|192.0.2.${i + 1}|tcp|443`,
          kind: 'port',
          target: `192.0.2.${i + 1}`,
          protocol: 'tcp',
          port: 443,
          old: 'closed',
          new: 'open',
          severity: 'warning',
        },
        opened_at: timestamp,
        last_seen_at: timestamp,
      },
    }))
    const staleScenarios = [
      { viewport: { width: 375, height: 812 }, status: 409, code: 'incident_conflict', message: 'This incident changed while it was open. The incident list was refreshed; review the new evidence before retrying.' },
      { viewport: { width: 1280, height: 800 }, status: 409, code: 'incident_conflict', message: 'This incident changed while it was open. The incident list was refreshed; review the new evidence before retrying.' },
      { viewport: { width: 375, height: 812 }, status: 404, code: 'incident_not_found', message: 'This incident is no longer active. The incident list was refreshed.' },
      { viewport: { width: 1280, height: 800 }, status: 404, code: 'incident_not_found', message: 'This incident is no longer active. The incident list was refreshed.' },
    ] as const
    let activeScenario: typeof staleScenarios[number] = staleScenarios[0]
    await page.route(url => new URL(url).pathname === '/api/v1/incidents', async route => {
      if (route.request().method() !== 'GET') return route.fallback()
      await route.fulfill({ json: { incidents: rows, pagination: { limit: 50, offset: 0, total: rows.length, has_more: false, next_offset: null } } })
    })
    await page.route('**/api/v1/jobs/job-1/incidents/accept', async route => {
      await route.fulfill({ status: activeScenario.status, json: { error: { code: activeScenario.code, message: 'incident changed' } } })
    })

    for (const scenario of staleScenarios) {
      activeScenario = scenario
      await page.setViewportSize(scenario.viewport)
      await page.goto('/incidents')
      await expect(page.locator('.mobile-incident-list .incident-card')).toHaveCount(rows.length)
      const accept = page.getByRole('button', { name: 'Accept change' }).last()
      await accept.scrollIntoViewIfNeeded()
      await accept.click()
      const dialog = page.getByRole('dialog', { name: 'Accept this change?' })
      await dialog.getByRole('button', { name: 'Accept change' }).click()

      const alert = page.getByRole('alert')
      await expect(alert).toHaveText(scenario.message)
      await expect(alert).toBeInViewport()
      await expect(alert).toBeFocused()
    }
  })

  test('scan diff wraps changes and shows the complete failure reason (#974)', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 900 })
    await mockConsole(page, 'administrator')
    const error = `Nmap failed to resolve ${longValue}; ${'coverage incomplete after retries. '.repeat(5)}`
    const scan = { id: 'scan-1', job_id: 'job-1', job: 'fixture-job', started_at: timestamp, finished_at: timestamp, status: 'failed', error, config_hash: 'fixture-security-hash' }
    const change = { kind: 'service', target: '2001:0db8:85a3:0000:0000:8a2e:0370:7334', protocol: 'tcp', port: 444, old: `${'nginx 1.18 Ubuntu reverse proxy '.repeat(4)}`, new: `${'Apache httpd Debian OpenSSL mod_wsgi '.repeat(4)}`, severity: 'warning' }
    await page.route('**/api/v1/jobs/job-1/scans**', async route => {
      const pathname = new URL(route.request().url()).pathname
      if (pathname === '/api/v1/jobs/job-1/scans') return route.fulfill({ json: { scans: [scan], pagination: { limit: 20, offset: 0, total: 1, has_more: false, next_offset: null } } })
      if (pathname === '/api/v1/jobs/job-1/scans/scan-1') return route.fulfill({ json: { scan, changes: [change], changes_pagination: { limit: 50, offset: 0, total: 1, has_more: false, next_offset: null }, current_security_hash: 'fixture-security-hash', comparison_state: 'not_compared' } })
      return route.fallback()
    })
    await page.goto('/jobs/job-1/scans/scan-1')
    const detail = page.locator('.scan-detail-inline')
    await expect(detail).toContainText(error)
    const clipCount = await page.evaluate(() => {
      const entry = document.querySelector('.scan-entry.expanded')
      if (!entry) return -1
      const right = entry.getBoundingClientRect().right
      return [...entry.querySelectorAll('.change-row > *')].filter(element => element.getBoundingClientRect().right > right + 1).length
    })
    expect(clipCount).toBe(0)
    await expectNoHorizontalScroll(page)

    await page.route('**/api/v1/scans/scan-1/summary', route => route.fulfill({ json: { scan } }))
    await page.goto('/scans/scan-1')
    await expect(page.locator('.scan-error')).toContainText(error)
  })

  test('job editor actions follow the form and tablet headings/settings fit (#975, #977)', async ({ page }) => {
    await mockConsole(page, 'administrator')
    await page.route('**/api/v1/jobs/schedule-suggestion**', route => route.fulfill({ json: {
      suggested: true,
      suggested_schedule: '30 */6 * * *',
      offset_minutes: 30,
      gap_minutes: 0,
      nearest: { id: 'job-2', name: longValue, schedule: '0 */6 * * *', timezone: 'America/Argentina/ComodRivadavia', next_run: timestamp },
    } }))
    for (const width of [375, 768, 834, 1024]) {
      await page.setViewportSize({ width, height: 900 })
      await page.goto('/jobs/new')
      const main = (await page.locator('.editor-main').boundingBox())!
      const side = (await page.locator('.editor-side').boundingBox())!
      const actions = (await page.locator('.editor-actions').boundingBox())!
      expect(main.y + main.height).toBeLessThanOrEqual(side.y + 1)
      expect(actions.y).toBeGreaterThanOrEqual(Math.max(main.y + main.height, side.y + side.height) - 1)
      const create = (await page.getByRole('button', { name: 'Create job' }).boundingBox())!
      expect(create.x + create.width).toBeLessThanOrEqual(width)
      if (width === 375) {
        const suggestion = page.locator('.schedule-suggestion')
        await expect(suggestion).toContainText('Stagger scheduled scans')
        const title = (await suggestion.locator('strong').boundingBox())!
        const useTime = (await suggestion.getByRole('button').boundingBox())!
        expect(title.x + title.width <= useTime.x || useTime.x + useTime.width <= title.x || title.y + title.height <= useTime.y || useTime.y + useTime.height <= title.y).toBe(true)
      }
      await expectNoHorizontalScroll(page)
    }

    await page.setViewportSize({ width: 834, height: 900 })
    await page.goto('/jobs/job-1')
    const headingActions = page.locator('.page-heading .heading-actions')
    await expect(headingActions).toBeVisible()
    const lastAction = (await headingActions.locator('button, a').last().boundingBox())!
    expect(lastAction.x + lastAction.width).toBeLessThanOrEqual(834)
    await expectNoHorizontalScroll(page)

    await mockConsole(page, 'platform_admin')
    await page.setViewportSize({ width: 768, height: 1024 })
    await page.goto('/platform/units/unit-retail')
    const grid = page.locator('.settings-grid').first()
    await expect(grid).toBeVisible()
    expect((await grid.evaluate(element => getComputedStyle(element).gridTemplateColumns)).trim().split(/\s+/)).toHaveLength(1)
    await expectNoHorizontalScroll(page)
  })

  test('stalled scan banners and reconnect notices wrap within the viewport (#976)', async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 720 })
    await mockConsole(page, 'administrator')
    await page.route('**/api/v1/jobs/job-1/scan-cycle', route => route.fulfill({ json: { cycle: {
      id: 'cycle-1', job_id: 'job-1', job_revision: 1, status: 'stalled', attempt_count: 4, no_progress_attempts: 3,
      total_units: 4096, completed_units: 1234, total_probes: 268505088, completed_probes: 81234567,
      started_at: timestamp, updated_at: timestamp, expires_at: '2026-10-07T10:00:00Z', last_error: longValue,
    } } }))
    await page.goto('/jobs/job-1')
    const banner = page.locator('.cycle-banner')
    const discard = page.getByRole('button', { name: 'Discard saved progress' })
    await expect(banner).toContainText(longValue)
    const box = (await discard.boundingBox())!
    expect(box.x + box.width).toBeLessThanOrEqual(320)
    await expectNoHorizontalScroll(page)

    await page.evaluate(() => {
      const notice = document.createElement('div')
      notice.className = 'connection-notice'
      notice.textContent = 'Unable to contact EdgeWatch. Retry when the service is available.'
      document.body.append(notice)
    })
    const notice = page.locator('.connection-notice')
    const noticeBox = (await notice.boundingBox())!
    expect(noticeBox.x).toBeGreaterThanOrEqual(0)
    expect(noticeBox.x + noticeBox.width).toBeLessThanOrEqual(320)
    expect(await page.locator('.content').evaluate(element => parseFloat(getComputedStyle(element).paddingBottom))).toBeGreaterThanOrEqual(110)
    await expectNoHorizontalScroll(page)
  })

  test('TOTP setup uses its own password prompt and keeps recovery acknowledgement inline (#988)', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 812 })
    await page.addInitScript(() => {
      Object.defineProperty(navigator, 'clipboard', {
        configurable: true,
        value: { writeText: async (value: string) => { document.documentElement.dataset.copiedSecret = value } },
      })
    })
    await mockConsole(page, 'administrator')
    let setupAttempts = 0
    await page.route('**/api/v1/auth/totp/setup', async route => {
      setupAttempts += 1
      if (setupAttempts === 1) {
        await route.fulfill({ status: 401, json: { error: { code: 'invalid_credentials', message: 'The password is incorrect.' } } })
        return
      }
      await route.fulfill({ json: { secret: 'JBSWY3DPEHPK3PXP', otpauth: 'otpauth://totp/EdgeWatch:admin' } })
    })
    await page.route('**/api/v1/auth/totp/enable', async route => {
      await route.fulfill({ json: { recovery_codes: ['AAAA-1111', 'BBBB-2222'] } })
    })
    await page.goto('/security')

    const passwordPanel = page.getByLabel('Current password', { exact: true })
    await passwordPanel.fill('password-from-password-panel')
    await page.getByRole('button', { name: 'Set up authenticator' }).click()
    const setupDialog = page.getByRole('dialog', { name: 'Set up authenticator?' })
    await expect(setupDialog).toBeVisible()
    await expect(passwordPanel).toHaveValue('')
    await setupDialog.getByLabel('Account password').fill('incorrect-password')
    await setupDialog.getByRole('button', { name: 'Start setup' }).click()
    await expect(setupDialog.getByRole('alert')).toContainText('The password is incorrect.')
    await expect(setupDialog.getByRole('alert')).toBeInViewport()
    await setupDialog.getByLabel('Account password').fill('account-password')
    await setupDialog.getByRole('button', { name: 'Start setup' }).click()
    await expect(page.getByRole('link', { name: 'Open authenticator app' })).toHaveAttribute('href', 'otpauth://totp/EdgeWatch:admin')
    await expect(page.getByLabel('Authenticator secret')).toHaveText('JBSW Y3DP EHPK 3PXP')
    await page.getByRole('button', { name: 'Copy secret' }).click()
    await expect(page.locator('.helper[role="status"]')).toContainText('Authenticator secret copied.')
    expect(await page.evaluate(() => document.documentElement.dataset.copiedSecret)).toBe('JBSWY3DPEHPK3PXP')
    await expectNoHorizontalScroll(page)

    await page.getByLabel('Verification code').fill('123456')
    await page.getByRole('button', { name: 'Enable TOTP' }).click()
    const acknowledgement = page.getByRole('checkbox', { name: 'I saved these recovery codes in a secure place.' })
    const label = page.locator('label.recovery-ack')
    await expect(label).toBeVisible()
    for (const width of [320, 1280, 1920]) {
      await page.setViewportSize({ width, height: 844 })
      await expectNoHorizontalScroll(page)
      const layout = await acknowledgement.evaluate(input => {
        const parent = input.closest('label')!
        const inputBox = input.getBoundingClientRect()
        const textBox = parent.querySelector('span')!.getBoundingClientRect()
        const style = getComputedStyle(parent)
        return {
          width: inputBox.width,
          height: inputBox.height,
          display: style.display,
          alignItems: style.alignItems,
          gap: style.gap,
          marginTop: style.marginTop,
          marginBottom: style.marginBottom,
          centersAligned: Math.abs((inputBox.top + inputBox.bottom) / 2 - (textBox.top + textBox.bottom) / 2) < 3,
        }
      })
      expect(layout.width).toBe(16)
      expect(layout.height).toBe(16)
      expect(layout.display).toBe('flex')
      expect(layout.alignItems).toBe('center')
      expect(layout.centersAligned).toBe(true)
      expect(layout.marginTop).toBe('4px')
      expect(layout.marginBottom).toBe('14px')
    }
  })
})
