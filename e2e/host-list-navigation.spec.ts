import { expect, test } from '@playwright/test'
import { mockConsole, type UnitConsoleRole } from './mock-console'

const returnQuery = '?q=router&protocol=tcp&has_open_ports=true&offset=50'

const host = {
  address: '192.0.2.10',
  address_family: 'IPv4',
  visibility: 'non_public',
  source_targets: ['router.example'],
  protocols: [{ protocol: 'tcp', scanned_ports: '22,443', scanned_port_count: 2, service_detection: false, open_ports: 1, open_filtered_ports: 0 }],
  open_ports: 1,
  open_filtered_ports: 0,
  has_open_ports: true,
  job_id: 'job-1',
  job: 'fixture-job',
  scan_id: 'scan-1',
  scanned_at: '2026-01-01T00:00:00Z',
  data_quality: 'detailed',
  archived: false,
}

async function expectNoHorizontalOverflow(page: import('@playwright/test').Page) {
  const width = await page.evaluate(() => ({ viewport: document.documentElement.clientWidth, page: document.documentElement.scrollWidth }))
  expect(width.page, `page overflow at ${width.viewport}px`).toBeLessThanOrEqual(width.viewport)
}

test('global and baseline host lists restore their URL state through detail links and browser Back (#1698)', async ({ browser, baseURL }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'The host list navigation regression controls its own narrow viewport.')

  for (const role of ['administrator', 'operator'] satisfies UnitConsoleRole[]) {
    const context = await browser.newContext({ baseURL, viewport: { width: 320, height: 720 } })
    try {
      const page = await context.newPage()
      await mockConsole(page, role)
      await page.route(url => new URL(url).pathname === '/api/v1/hosts' && url.searchParams.has('offset'), route => route.fulfill({
        json: { hosts: [host], pagination: { limit: 50, offset: 50, total: 100, has_more: false, next_offset: null } },
      }))
      await page.route(url => new URL(url).pathname === '/api/v1/jobs/job-1/baseline/hosts', route => route.fulfill({
        json: { job_id: 'job-1', job: 'fixture-job', data_quality: 'detailed', hosts: [host], pagination: { limit: 50, offset: 50, total: 100, has_more: false, next_offset: null } },
      }))

      for (const listPath of ['/hosts', '/jobs/job-1/baseline']) {
        const returnTo = `${listPath}${returnQuery}`
        await page.goto(returnTo)
        const search = page.getByRole('searchbox', { name: 'Search hosts' })
        await expect(search).toHaveValue('router')
        await expect(page.getByLabel('Protocol')).toHaveValue('tcp')
        await expect(page.getByLabel('Open ports filter')).toHaveValue('true')
        await expect(page.getByRole('navigation', { name: 'Pagination' })).toContainText('51–100 of 100')
        await expectNoHorizontalOverflow(page)

        const row = page.locator('.host-row').first()
        await row.focus()
        await expect(row).toBeFocused()
        await page.keyboard.press('Enter')
        await expect(page.locator('.back-link').first()).toBeVisible()
        await page.locator('.back-link').first().click()
        await expect(page).toHaveURL(new RegExp(`${listPath.replaceAll('/', '\\/')}${returnQuery.replaceAll('?', '\\?')}$`))
        await expect(search).toHaveValue('router')
        await expectNoHorizontalOverflow(page)

        await row.focus()
        await page.keyboard.press('Enter')
        await expect(page.locator('.back-link').first()).toBeVisible()
        await page.goBack()
        await expect(page).toHaveURL(new RegExp(`${listPath.replaceAll('/', '\\/')}${returnQuery.replaceAll('?', '\\?')}$`))
        await expect(page.getByRole('searchbox', { name: 'Search hosts' })).toHaveValue('router')
        await expect(page.getByLabel('Protocol')).toHaveValue('tcp')
        await expect(page.getByLabel('Open ports filter')).toHaveValue('true')
        await expect(page.getByRole('navigation', { name: 'Pagination' })).toContainText('51–100 of 100')
        await expectNoHorizontalOverflow(page)

        await page.goForward()
        await expect(page).toHaveURL(/\/hosts\/192\.0\.2\.10$/)
        await expect(page.locator('.back-link').first()).toBeVisible()
        await page.goBack()
        await expect(page).toHaveURL(new RegExp(`${listPath.replaceAll('/', '\\/')}${returnQuery.replaceAll('?', '\\?')}$`))
        await expect(page.getByRole('searchbox', { name: 'Search hosts' })).toHaveValue('router')
        await expect(page.getByLabel('Protocol')).toHaveValue('tcp')
        await expect(page.getByLabel('Open ports filter')).toHaveValue('true')
      }
    } finally {
      await context.close()
    }
  }
})

test('rapid typing keeps host search, URL, results, and focus synchronized on both lists', async ({ browser, baseURL }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'The rapid typing regression runs once on desktop.')

  const context = await browser.newContext({ baseURL })
  try {
    const page = await context.newPage()
    await mockConsole(page, 'administrator')
    const query = 'router.example'
    await page.route(url => {
      const parsed = new URL(url)
      return parsed.pathname === '/api/v1/hosts' || parsed.pathname === '/api/v1/jobs/job-1/baseline/hosts'
    }, route => {
      const request = new URL(route.request().url())
      const matches = request.searchParams.get('q') === query
      const hosts = matches ? [host] : []
      const pagination = { limit: 50, offset: 0, total: hosts.length, has_more: false, next_offset: null }
      return route.fulfill({
        json: request.pathname === '/api/v1/hosts'
          ? { hosts, pagination }
          : { job_id: 'job-1', job: 'fixture-job', data_quality: 'detailed', hosts, pagination },
      })
    })

    for (const listPath of ['/hosts', '/jobs/job-1/baseline']) {
      await page.goto(listPath)
      const search = page.getByRole('searchbox', { name: 'Search hosts' })
      await search.focus()
      await page.keyboard.type(query)

      await expect(search).toHaveValue(query)
      await expect(search).toBeFocused()
      await expect(page).toHaveURL(new RegExp(`${listPath.replaceAll('/', '\\/')}\\?q=${query}$`))
      await expect(page.locator('.host-row')).toHaveCount(1)
      await expect(page.locator('.host-row').first()).toContainText(host.address)
    }
  } finally {
    await context.close()
  }
})

test('host explorers recover restored pages past the inventory end and clamp invalid large offsets', async ({ page }) => {
  await mockConsole(page, 'administrator')
  const offsets: Array<{ path: string; offset: number }> = []
  await page.route(url => {
    const pathname = new URL(url).pathname
    return pathname === '/api/v1/hosts' || pathname === '/api/v1/jobs/job-1/baseline/hosts'
  }, route => {
    const request = new URL(route.request().url())
    const offset = Number(request.searchParams.get('offset') ?? 0)
    offsets.push({ path: request.pathname, offset })
    const outOfRange = offset === 500
    const hosts = outOfRange ? [] : [host]
    const pagination = { limit: 50, offset, total: 30, has_more: false, next_offset: null }
    return route.fulfill({ json: request.pathname === '/api/v1/hosts'
      ? { hosts, pagination }
      : { job_id: 'job-1', job: 'fixture-job', data_quality: 'detailed', hosts, pagination } })
  })

  for (const listPath of ['/hosts', '/jobs/job-1/baseline']) {
    await page.goto(`${listPath}?offset=500`)
    await expect(page.getByText('No hosts on this page.')).toBeVisible()
    await expect(page.getByText(/No completed scans have produced effective hosts yet\.|No hosts are in this baseline\./)).toHaveCount(0)
    await page.getByRole('button', { name: 'Go to first page' }).click()
    await expect(page).toHaveURL(new RegExp(`${listPath.replaceAll('/', '\\/')}$`))
    await expect(page.locator('.host-row').first()).toContainText(host.address)
  }

  await page.goto('/hosts?offset=20000000')
  await expect(page.locator('.host-row').first()).toContainText(host.address)
  expect(offsets).toContainEqual({ path: '/api/v1/hosts', offset: 0 })
  expect(offsets.every(({ offset }) => offset <= 10_000_000)).toBe(true)
})
