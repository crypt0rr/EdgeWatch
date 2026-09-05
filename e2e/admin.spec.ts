import { expect, test } from '@playwright/test'

test('setup, login, and build a TCP/UDP job in the console', async ({ page }) => {
  let configured = false
  let loggedIn = false
  let csrf = ''
  let createdJob: Record<string, unknown> | null = null
  const existingJob = {
    id: 'job-existing', revision: 1, enabled: true, archived: false, security_hash: 'existing-hash',
    created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z',
    job: { name: 'nightly', schedule: '0 */6 * * *', timezone: 'Europe/Amsterdam', targets: ['192.0.2.2'], max_expanded_hosts: 256, tcp: { ports: '22', mode: 'connect', service_detection: false }, timing: 'balanced', timeout: '1h', baseline_samples: 1, change_confirmations: 1 },
    baseline: { status: 'collecting', samples: 0, attempts: 0 },
  }
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
      await json({ configured, setup_available: !configured, version: 'v0.7.0', password_requirements: { minimum_length: 12 } })
      return
    }
    if (path === '/auth/session' && method === 'GET') {
      if (!loggedIn) { await json({ error: { code: 'unauthorized', message: 'authentication required' } }, 401); return }
      await json({ username: 'admin', csrf_token: csrf, totp_enabled: false })
      return
    }
    if (path === '/status' && method === 'GET') {
      await json({ configured: true, username: 'admin', notification_destinations: 0, notifications: { deployment: 0, managed: 0, active: 0, locked: 0, key_state: 'not_required' }, retention: '90d', max_concurrent_scans: 1 })
      return
    }
    if (path === '/scans/active' && method === 'GET') {
      await json({ scans: [] })
      return
    }
    if (path === '/incidents' && method === 'GET') {
      await json({ incidents: [{ job_id: 'job-existing', job: 'nightly', incident: { change: { key: 'port|192.0.2.2|tcp|443', kind: 'port', target: '192.0.2.2', protocol: 'tcp', port: 443, severity: 'high' }, opened_at: '2026-01-01T00:00:00Z', last_seen_at: '2026-01-01T00:00:00Z' } }], pagination: { limit: 1, offset: 0, total: 1, has_more: false, next_offset: null } })
      return
    }
    if (path === '/hosts' && method === 'GET') {
      await json({ hosts: [{ address: '192.0.2.1', address_family: 'IPv4', source_targets: ['router.example.com'], protocols: [{ protocol: 'tcp', scanned_ports: '22', scanned_port_count: 1, service_detection: false, open_ports: 1, open_filtered_ports: 0 }], open_ports: 1, open_filtered_ports: 0, has_open_ports: true, job_id: 'job-1', job: 'edge-router', scan_id: 'scan-1', scanned_at: '2026-01-01T00:00:01Z', data_quality: 'detailed' }], pagination: { limit: 50, offset: 0, total: 1, has_more: false, next_offset: null } })
      return
    }
    if (path === '/scans/scan-1/hosts/192.0.2.1/rdap' && method === 'GET') {
      await json({ rdap: { status: 'private', address: '192.0.2.1' } })
      return
    }
    if (path === '/scans/scan-1/hosts/192.0.2.1' && method === 'GET') {
      await json({ job_id: 'job-1', job: 'edge-router', scan, data_quality: 'detailed', host: { address: '192.0.2.1', address_family: 'IPv4', source_targets: ['router.example.com'], status: 'up', protocols: [{ protocol: 'tcp', scanned_ports: '22', scanned_port_count: 1, service_detection: false, ports: [{ port: 22, state: 'open', reason: 'syn-ack' }], state_summaries: [{ state: 'open', count: 1 }] }] } })
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
    if (path === '/auth/logout' && method === 'POST') {
      loggedIn = false
      csrf = ''
      await route.fulfill({ status: 204 })
      return
    }
    if (path === '/jobs' && method === 'GET') {
      await json({ jobs: [existingJob, ...(createdJob ? [createdJob] : [])] })
      return
    }
    if (path === '/jobs/schedule-suggestion' && method === 'GET') {
      const schedule = new URL(request.url()).searchParams.get('schedule')
      await json(schedule === '0 */6 * * *' ? { suggested: true, suggested_schedule: '30 */6 * * *', offset_minutes: 30, nearest: { id: 'job-existing', name: 'nightly', schedule: '0 */6 * * *', timezone: 'Europe/Amsterdam', next_run: '2026-09-05T12:00:00Z' }, draft_next_run: '2026-09-05T12:00:00Z', gap_minutes: 0 } : { suggested: false, gap_minutes: 45 })
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
  await expect(page.getByText('EdgeWatch v0.7.0')).toBeVisible()
  await expect(page.getByRole('link', { name: 'Incidents' })).toHaveClass(/nav-link-alert/)
  await expect(page.locator('#active-incident-count')).toHaveText('1')
  await page.getByRole('link', { name: 'Incidents' }).click()
  await expect(page.getByRole('button', { name: 'Accept change' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Suppress 1 scan' })).toBeVisible()
  await page.getByRole('link', { name: 'Hosts' }).click()
  await expect(page.getByRole('heading', { name: 'Hosts', exact: true })).toBeVisible()
  await expect(page.getByText('192.0.2.1')).toBeVisible()
  await page.getByRole('link', { name: /192\.0\.2\.1/ }).click()
  await expect(page.getByRole('heading', { name: '192.0.2.1' })).toBeVisible()
  await page.getByRole('link', { name: 'Jobs' }).click()
  await page.getByRole('button', { name: 'New job' }).click()
  await expect(page.getByRole('heading', { name: 'Create a monitoring job' })).toBeVisible()
  await expect(page.getByText('Stagger scheduled scans')).toBeVisible()
  await page.getByRole('button', { name: 'Use later time' }).click()
  await expect(page.getByLabel('Five-field cron')).toHaveValue('30 */6 * * *')

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
  await page.getByRole('button', { name: 'Edit' }).click()
  await page.getByRole('button', { name: 'Save changes' }).click()
  const passwordDialog = page.getByRole('dialog', { name: 'Confirm destination changes' })
  await expect(passwordDialog).toBeVisible()
  await expect(passwordDialog.locator('input[type="password"]')).toBeVisible()
  await passwordDialog.getByRole('button', { name: 'Cancel' }).click()
  await page.getByRole('button', { name: 'Sign out' }).click()
  await expect(page.getByRole('heading', { name: 'Sign in to EdgeWatch' })).toBeVisible()
})
