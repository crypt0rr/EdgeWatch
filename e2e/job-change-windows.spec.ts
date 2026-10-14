import { expect, test, type Page } from '@playwright/test'
import { mockConsole } from './mock-console'

type WindowFixture = {
  id: string
  job_id: string
  start_at: string
  end_at: string
  timezone: string
  reason: string
  actor_label: string
  created_at: string
  status: 'scheduled' | 'active' | 'closed' | 'cancelled'
  end_reason?: string
  closed_at: string | null
  effective_end: string | null
  new_count: number
  recovered_count: number
  still_open_count: number
  suppressed_event_count: number
  in_flight_event_count: number
  unknown_outcome_event_count: number
  incomplete_event_count: number
  review_state: 'none' | 'due' | 'reviewed'
  reviewed_at: string | null
  reviewer_label: string
  revision: number
  summary: {
    known_changes: Array<{ key: string; kind: string; severity: string; target: string; protocol: string; port: number; old: string; new: string }>
    still_open: []
    known_change_details_truncated: boolean
    still_open_details_truncated: boolean
    incomplete_event_count: number
    incomplete_reported_change_count: number
  } | null
}

const job = {
  id: 'job-1',
  revision: 1,
  enabled: true,
  archived: false,
  security_hash: 'fixture-security-hash',
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
  job: {
    name: 'fixture-job',
    schedule: '0 * * * *',
    timezone: 'Europe/Amsterdam',
    targets: ['192.0.2.10'],
    max_expanded_hosts: 256,
    tcp: { ports: '22,443', mode: 'connect', service_detection: false, engine: 'nmap' },
    timing: 'balanced',
    timeout: '1h',
    resume_window: '8d',
    baseline_samples: 1,
    change_confirmations: 1,
    run_on_start: false,
    assume_alive: true,
    allow_high_cost: false,
  },
  baseline: { status: 'complete', samples: 1, attempts: 1, host_count: 1, scan_id: 'scan-1' },
}

function makeWindow(id: string, body: Record<string, unknown>): WindowFixture {
  const startNow = body.start_now === true
  return {
    id,
    job_id: 'job-1',
    start_at: startNow ? '2026-10-01T12:00:00Z' : new Date(String(body.start_at)).toISOString(),
    end_at: new Date(String(body.end_at)).toISOString(),
    timezone: 'Europe/Amsterdam',
    reason: String(body.reason),
    actor_label: 'Test operator',
    created_at: '2026-10-01T12:00:00Z',
    status: startNow ? 'active' : 'scheduled',
    closed_at: null,
    effective_end: null,
    new_count: 0,
    recovered_count: 0,
    still_open_count: 0,
    suppressed_event_count: 0,
    in_flight_event_count: 0,
    unknown_outcome_event_count: 0,
    incomplete_event_count: 0,
    review_state: 'none',
    reviewed_at: null,
    reviewer_label: '',
    revision: 1,
    summary: null,
  }
}

async function installJobAndWindowRoutes(page: Page, options: { archived?: boolean; windows?: WindowFixture[] } = {}) {
  let windows = [...(options.windows ?? [])]
  let nextCreateFailure: { status: number; message: string } | null = null
  const createPayloads: Record<string, unknown>[] = []
  await page.route(url => {
    const parsed = new URL(url)
    return parsed.pathname === '/api/v1/jobs/job-1' && parsed.search === ''
  }, route => route.request().method() === 'GET'
    ? route.fulfill({ json: { ...job, archived: options.archived ?? false } })
    : route.fallback())
  await page.route(url => new URL(url).pathname.startsWith('/api/v1/jobs/job-1/change-windows'), async route => {
    const request = route.request()
    const path = new URL(request.url()).pathname
    const json = (body: unknown, status = 200) => route.fulfill({ status, json: body })
    const body = () => JSON.parse(request.postData() ?? '{}') as Record<string, unknown>
    if (path === '/api/v1/jobs/job-1/change-windows' && request.method() === 'GET') {
      await json({ windows })
      return
    }
    if (path === '/api/v1/jobs/job-1/change-windows' && request.method() === 'POST') {
      const value = body()
      createPayloads.push(value)
      if (nextCreateFailure) {
        const failure = nextCreateFailure
        nextCreateFailure = null
        await json({ error: { code: failure.status === 409 ? 'change_window_conflict' : 'validation_failed', message: failure.message } }, failure.status)
        return
      }
      const window = makeWindow(`window-${windows.length + 1}`, value)
      windows = [window, ...windows]
      await json({ window })
      return
    }
    if (path === '/api/v1/jobs/job-1/change-windows' && request.method() === 'DELETE') {
      const value = body()
      const index = windows.findIndex(window => window.id === value.window_id)
      if (index < 0) { await json({ error: { code: 'not_found', message: 'window not found' } }, 404); return }
      const current = windows[index]
      const active = current.status === 'active'
      const window: WindowFixture = {
        ...current,
        status: active ? 'closed' : 'cancelled',
        end_reason: 'cancelled',
        closed_at: '2026-10-01T13:00:00Z',
        effective_end: '2026-10-01T13:00:00Z',
        new_count: active ? 1 : 0,
        suppressed_event_count: active ? 1 : 0,
        review_state: active ? 'due' : 'none',
        revision: current.revision + 1,
        summary: active ? {
          known_changes: [{ key: 'port|192.0.2.10|tcp|443', kind: 'port', severity: 'high', target: '192.0.2.10', protocol: 'tcp', port: 443, old: 'closed', new: 'open' }],
          still_open: [],
          known_change_details_truncated: false,
          still_open_details_truncated: false,
          incomplete_event_count: 0,
          incomplete_reported_change_count: 0,
        } : null,
      }
      windows[index] = window
      await json({ window })
      return
    }
    if (path === '/api/v1/jobs/job-1/change-windows/review' && request.method() === 'PUT') {
      const value = body()
      const index = windows.findIndex(window => window.id === value.window_id)
      if (index < 0) { await json({ error: { code: 'not_found', message: 'window not found' } }, 404); return }
      const window = { ...windows[index], review_state: 'reviewed' as const, reviewed_at: '2026-10-01T13:01:00Z', reviewer_label: 'Test operator', revision: windows[index].revision + 1 }
      windows[index] = window
      await json({ window })
      return
    }
    const detail = windows.find(window => path === `/api/v1/jobs/job-1/change-windows/${window.id}`)
    if (detail && request.method() === 'GET') { await json({ window: detail }); return }
    await route.fallback()
  })
  return {
    createPayloads,
    failNextCreate(status: number, message: string) { nextCreateFailure = { status, message } },
  }
}

test.describe('planned change window browser journeys', () => {
  test.beforeEach(async ({}, testInfo) => {
    test.skip(!['desktop', 'mobile-narrow'].includes(testInfo.project.name), 'The create and lifecycle journeys run on desktop and the 320px mobile project.')
  })

  test('starts now, ends early, reviews the close, and opens its summary', async ({ page }) => {
    await page.clock.install({ time: new Date('2026-10-01T12:00:00Z') })
    await mockConsole(page, 'administrator')
    await installJobAndWindowRoutes(page)
    await page.goto('/jobs/job-1')

    const form = page.getByRole('form', { name: 'Plan a change window' })
    await form.getByLabel(/End time/).fill('2026-10-01T16:00')
    await form.getByLabel('Reason').fill('Router replacement')
    await form.getByRole('button', { name: 'Start change window' }).click()
    await expect(page.getByText('Change window started.')).toBeVisible()
    await expect(page.getByText('Active', { exact: true })).toBeVisible()

    await page.getByRole('button', { name: 'Cancel window' }).click()
    const dialog = page.getByRole('dialog', { name: 'End this change window early?' })
    await dialog.getByRole('button', { name: 'End window now' }).click()
    await expect(page.getByText('Review due', { exact: true })).toBeVisible()
    await page.getByRole('button', { name: 'Mark review complete' }).click()
    await expect(page.locator('.change-window-card .pill.green').filter({ hasText: 'Reviewed' })).toBeVisible()
    await page.getByRole('button', { name: 'View closing summary' }).click()
    await expect(page.getByRole('region', { name: 'Changes observed during the window' })).toContainText('192.0.2.10')
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true)
  })

  test('schedules the second DST-fold instant, cancels it, and reports overlap conflicts', async ({ page }) => {
    await page.clock.install({ time: new Date('2026-10-01T12:00:00Z') })
    await mockConsole(page, 'administrator')
    const controls = await installJobAndWindowRoutes(page)
    await page.goto('/jobs/job-1')

    const form = page.getByRole('form', { name: 'Plan a change window' })
    await form.getByLabel('Schedule for later').check()
    await form.getByLabel(/Start time/).fill('2026-10-25T02:30')
    await form.getByRole('combobox', { name: /Choose the UTC offset for start time/ }).selectOption('2026-10-25T02:30:00+01:00')
    await form.getByLabel(/End time/).fill('2026-10-25T04:00')
    await form.getByLabel('Reason').fill('Router replacement')
    await form.getByRole('button', { name: 'Schedule change window' }).click()
    await expect(page.getByText('Change window scheduled.')).toBeVisible()
    expect(controls.createPayloads[0]).toMatchObject({
      start_now: false,
      start_at: '2026-10-25T02:30:00+01:00',
      end_at: '2026-10-25T04:00:00+01:00',
      reason: 'Router replacement',
    })

    await page.getByRole('button', { name: 'Cancel window' }).click()
    const cancelDialog = page.getByRole('dialog', { name: 'Cancel this scheduled change window?' })
    await cancelDialog.getByRole('button', { name: 'Cancel scheduled window' }).click()
    await expect(page.getByText('Cancelled', { exact: true })).toBeVisible()

    controls.failNextCreate(409, 'A change window overlaps this time.')
    await form.getByLabel(/Start time/).fill('2026-10-26T10:00')
    await form.getByLabel(/End time/).fill('2026-10-26T11:00')
    await form.getByLabel('Reason').fill('Maintenance overlap test')
    await form.getByRole('button', { name: 'Schedule change window' }).click()
    await expect(form.getByRole('alert')).toHaveText('A change window overlaps this time.')
  })
})
