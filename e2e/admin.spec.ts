import { expect, test } from '@playwright/test'

test('setup, login, and build a TCP/UDP job in the console', async ({ page }) => {
  let configured = false
  let loggedIn = false
  let csrf = ''
  let createdJob: Record<string, unknown> | null = null
  const scan = {
    id: 'scan-1', job_id: 'job-1', job: 'edge-router', job_revision: 1,
    started_at: '2026-01-01T00:00:00Z', finished_at: '2026-01-01T00:00:01Z',
    status: 'success', config_hash: 'hash', snapshot: { units: [], scopes: [] },
  }

  await page.route('**/api/v1/**', async (route) => {
    const request = route.request()
    const path = new URL(request.url()).pathname.replace('/api/v1', '')
    const method = request.method()
    const json = (body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })

    if (path === '/stream') {
      await route.abort()
      return
    }
    if (path === '/setup/status' && method === 'GET') {
      await json({ configured, setup_available: !configured, password_requirements: { minimum_length: 12 } })
      return
    }
    if (path === '/auth/session' && method === 'GET') {
      if (!loggedIn) { await json({ error: { code: 'unauthorized', message: 'authentication required' } }, 401); return }
      await json({ username: 'admin', csrf_token: csrf, totp_enabled: false })
      return
    }
    if (path === '/setup' && method === 'POST') {
      configured = true
      await json({ configured: true }, 201)
      return
    }
    if (path === '/auth/login' && method === 'POST') {
      loggedIn = true
      csrf = 'test-csrf'
      await json({ username: 'admin', csrf_token: csrf, totp_required: false })
      return
    }
    if (path === '/jobs' && method === 'GET') {
      await json({ jobs: createdJob ? [createdJob] : [] })
      return
    }
    if (path === '/jobs' && method === 'POST') {
      const payload = JSON.parse(request.postData() ?? '{}') as Record<string, unknown>
      createdJob = {
        id: 'job-1', revision: 1, enabled: true, archived: false, security_hash: 'hash',
        created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z',
        job: payload, baseline: { status: 'collecting', samples: 0, attempts: 0 },
      }
      await json(createdJob, 201)
      return
    }
    if (path === '/notifications/destinations' && method === 'GET') {
      await json({ destinations: [{ id: 'dest-1', name: 'Operations', provider: 'generic', source: 'web', enabled: true, locked: false, read_only: false, revision: 1 }], status: { deployment: 0, managed: 1, active: 1, locked: 0, key_state: 'ready' } })
      return
    }
    if (path === '/jobs/job-1' && method === 'GET') { await json(createdJob); return }
    if (path === '/jobs/job-1/scans' && method === 'GET') {
      await json({ scans: [scan], pagination: { limit: 20, offset: 0, total: 1, has_more: false, next_offset: null } })
      return
    }
    if (path === '/jobs/job-1/scans/scan-1' && method === 'GET') {
      await json({ scan, changes: [], changes_pagination: { limit: 50, offset: 0, total: 0, has_more: false, next_offset: null }, current_security_hash: 'hash' })
      return
    }
    if (path === '/jobs/job-1/run' && method === 'POST') { await json({ status: 'accepted', job_id: 'job-1' }, 202); return }
    await json({ error: { code: 'not_found', message: `${method} ${path}` } }, 404)
  })

  await page.goto('/')
  await expect(page.getByRole('heading', { name: 'Create your administrator' })).toBeVisible()
  await page.getByLabel('Setup token').fill('setup-token')
  await page.locator('input[autocomplete="new-password"]').first().fill('correct horse battery staple')
  await page.locator('input[autocomplete="new-password"]').nth(1).fill('correct horse battery staple')
  await page.getByRole('button', { name: 'Create administrator' }).click()
  await expect(page.getByRole('heading', { name: 'Sign in to EdgeWatch' })).toBeVisible()

  await page.locator('input[autocomplete="current-password"]').fill('correct horse battery staple')
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('heading', { name: 'Good afternoon, admin' })).toBeVisible()
  await page.getByRole('link', { name: 'Jobs' }).click()
  await page.getByRole('button', { name: 'New job' }).click()
  await expect(page.getByRole('heading', { name: 'Create a monitoring job' })).toBeVisible()

  await page.getByLabel('Job name').fill('edge-router')
  await page.getByLabel('Target 1').fill('router.example.com')
  await page.getByRole('button', { name: 'Add target' }).click()
  await page.getByLabel('Target 2').fill('192.0.2.1/32')
  await page.getByRole('checkbox', { name: 'UDP scan' }).check()
  await page.getByRole('textbox', { name: /Ports Ranges/ }).nth(1).fill('53,123')
  await page.getByRole('checkbox', { name: 'Assume targets are alive' }).uncheck()
  await page.getByLabel('Five-field cron').fill('*/15 * * * *')
  await page.getByRole('button', { name: 'Create job' }).click()

  await expect(page).toHaveURL(/\/jobs$/)
  await expect(page.getByRole('heading', { name: 'edge-router' })).toBeVisible()
  expect(createdJob?.job && (createdJob.job as Record<string, unknown>).targets).toEqual(['router.example.com', '192.0.2.1/32'])
  expect(createdJob?.job && (createdJob.job as Record<string, unknown>).udp).toMatchObject({ ports: '53,123' })
  expect(createdJob?.job && (createdJob.job as Record<string, unknown>).assume_alive).toBe(false)
  expect(createdJob?.job && (createdJob.job as Record<string, unknown>).schedule).toBe('*/15 * * * *')
  await page.getByRole('link', { name: 'Notifications' }).click()
  await expect(page.getByRole('heading', { name: 'Notifications' })).toBeVisible()
  await expect(page.getByText('Operations')).toBeVisible()
  await expect(page.locator('.notifications-page')).not.toContainText('generic://')
})
