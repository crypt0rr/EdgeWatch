import { expect, test, type Page } from '@playwright/test'
import type { Job } from '../src/types'
import { mockConsole, type UnitConsoleRole } from './mock-console'

const monitoringJob = (id: string, name: string, targets: string[], options: { archived?: boolean; attentionReason?: string } = {}): Job => ({
  id,
  revision: 1,
  enabled: !options.archived,
  archived: options.archived ?? false,
  security_hash: `fixture-${id}`,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
  job: {
    name,
    schedule: '0 * * * *',
    timezone: 'UTC',
    targets,
    max_expanded_hosts: 256,
    timing: 'balanced',
    timeout: '1h',
    baseline_samples: 1,
    change_confirmations: 1,
  },
  baseline: { status: 'complete', samples: 1 },
  monitoring: {
    availability: 'available',
    history_available: true,
    activity: 'none',
    schedule_state: options.archived ? 'archived' : 'scheduled',
    next_run_at: null,
    timezone: 'UTC',
    latest_attempt: null,
    latest_successful_scan: null,
    cycle_in_progress: false,
    cycle_completed_units: 0,
    cycle_total_units: 0,
    attention_reason: options.attentionReason ?? 'none',
  },
})

const jobs: Job[] = [
  monitoringJob('gateway', 'Gateway monitor', ['192.0.2.10']),
  monitoringJob('database', 'Database monitor', ['API.EXAMPLE.NET', 'db.internal'], { attentionReason: 'failed' }),
  monitoringJob('retired', 'Retired router', ['legacy-gateway.internal'], { archived: true }),
  monitoringJob('heartbeat', 'Heartbeat', ['203.0.113.20']),
]

async function expectNoHorizontalScroll(page: Page) {
  const widths = await page.evaluate(() => ({ client: document.documentElement.clientWidth, scroll: document.documentElement.scrollWidth }))
  expect(widths.scroll, `page scroll width ${widths.scroll} exceeds viewport ${widths.client}`).toBeLessThanOrEqual(widths.client)
}

async function getJobSearchLayout(page: Page) {
  return page.evaluate(() => {
    const search = document.querySelector<HTMLInputElement>('#jobs-search')!
    const filter = document.querySelector<HTMLSelectElement>('#jobs-filter')!
    const searchBounds = search.getBoundingClientRect()
    const filterBounds = filter.getBoundingClientRect()
    return {
      inputWidth: searchBounds.width,
      stacked: filterBounds.top > searchBounds.bottom + 1,
    }
  })
}

test('jobs search matches names and targets for every reader and keeps the selected filter', async ({ browser, baseURL }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'This test covers all roles and controls its own desktop and phone viewports.')

  const roles: UnitConsoleRole[] = ['administrator', 'operator', 'viewer']
  for (const role of roles) {
    const context = await browser.newContext({
      baseURL,
      viewport: role === 'viewer' ? { width: 320, height: 720 } : { width: 1280, height: 800 },
    })
    const page = await context.newPage()
    const nonGetJobRequests: string[] = []
    page.on('request', request => {
      const url = new URL(request.url())
      if (url.pathname === '/api/v1/jobs' && request.method() !== 'GET') nonGetJobRequests.push(`${request.method()} ${url.pathname}`)
    })

    try {
      await mockConsole(page, role)
      await page.route('**/api/v1/jobs**', async route => {
        const request = route.request()
        if (request.method() !== 'GET' || new URL(request.url()).pathname !== '/api/v1/jobs') return route.fallback()
        await route.fulfill({ json: { jobs } })
      })
      await page.goto('/jobs')

      const search = page.getByRole('searchbox', { name: 'Search jobs by name or target' })
      await expect(search).toBeVisible()
      await expect(page.getByRole('status').filter({ hasText: 'Showing 4 of 4 jobs' })).toBeVisible()
      await expect(page.getByRole('link', { name: 'Gateway monitor' })).toHaveAttribute('href', '/jobs/gateway')
      if (role === 'viewer') {
        for (const width of [428, 430, 761, 1012]) {
          await page.setViewportSize({ width, height: 720 })
          const layout = await getJobSearchLayout(page)
          expect(layout.inputWidth, `search input width at ${width}px: ${JSON.stringify(layout)}`).toBeGreaterThanOrEqual(240)
          expect(layout.stacked, `search controls should stack at ${width}px`).toBe(true)
          await expectNoHorizontalScroll(page)
        }
        await page.setViewportSize({ width: 1013, height: 720 })
        const transitionLayout = await getJobSearchLayout(page)
        expect(transitionLayout.inputWidth, 'search input width just above the 700px controls threshold').toBeGreaterThanOrEqual(240)
        expect(transitionLayout.stacked, 'search controls should fit side by side just above the container threshold').toBe(false)
        await expectNoHorizontalScroll(page)
        await page.setViewportSize({ width: 320, height: 720 })
      }
      if (role === 'viewer') await expect(page.getByRole('button', { name: /New job/ })).toHaveCount(0)
      else await expect(page.getByRole('button', { name: /New job/ })).toBeVisible()

      await search.focus()
      await search.pressSequentially('gAtEwAy')
      await expect(page.getByRole('heading', { name: 'Gateway monitor' })).toBeVisible()
      await expect(page.getByRole('heading', { name: 'Retired router' })).toBeVisible()
      await expect(page.getByRole('status').filter({ hasText: 'Showing 2 of 4 jobs' })).toBeVisible()

      await search.fill('api.example.net')
      await expect(page.getByRole('heading', { name: 'Database monitor' })).toBeVisible()
      await expect(page.getByRole('heading', { name: 'Gateway monitor' })).toHaveCount(0)
      await expect(page.getByRole('status').filter({ hasText: 'Showing 1 of 4 jobs' })).toBeVisible()

      const filter = page.getByRole('combobox', { name: 'Filter jobs' })
      await filter.selectOption('attention')
      await expect(page.getByRole('heading', { name: 'Database monitor' })).toBeVisible()
      await search.fill('gateway')
      await expect(page.getByRole('heading', { name: 'No jobs match your search' })).toBeVisible()
      await expect(page.getByRole('status').filter({ hasText: 'Showing 0 of 4 jobs' })).toBeVisible()

      const clear = page.getByRole('button', { name: 'Clear' })
      await clear.focus()
      await expect(clear).toBeFocused()
      await page.keyboard.press('Enter')
      await expect(search).toHaveValue('')
      await expect(search).toBeFocused()
      await expect(filter).toHaveValue('attention')
      await expect(page.getByRole('heading', { name: 'Database monitor' })).toBeVisible()
      await expect(page.getByRole('heading', { name: 'No jobs match your search' })).toHaveCount(0)
      await expect(page.getByRole('status').filter({ hasText: 'Showing 1 of 4 jobs' })).toBeVisible()
      expect(nonGetJobRequests).toEqual([])
      if (role === 'viewer') await expectNoHorizontalScroll(page)
    } finally {
      await context.close()
    }
  }
})
