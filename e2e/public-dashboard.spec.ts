import { expect, test } from '@playwright/test'

const adminPermissions = [
  'overview.read', 'jobs.read', 'jobs.write', 'jobs.run', 'jobs.delete',
  'hosts.read', 'scans.read', 'baselines.read', 'baselines.manage',
  'incidents.read', 'incidents.manage', 'notification_options.read',
  'notifications.manage', 'users.manage',
  'public_dashboard.manage', 'stream.read', 'scanner_profiles.read',
  'scanner_profiles.manage',
]

test('public status controls remain interactive and navigation leaves the page', async ({ page }) => {
  let dashboard = {
    enabled: false,
    title: 'EdgeWatch public status',
    introduction: '',
    updated_at: '2026-01-01T00:00:00Z',
    hosts: [] as Array<{ job_id: string; address: string; created_at: string }>,
  }
  let saved: Record<string, unknown> | undefined
  const hostRequests: Array<{ q: string | null; offset: number }> = []
  const laterHost = { job_id: 'job-later', address: '198.51.100.99', job: 'later-job', scan_id: 'scan-later', scanned_at: '2026-01-01T00:00:00Z', data_quality: 'detailed', open_ports: 1, open_filtered_ports: 0, has_open_ports: true, archived: false }

  await page.route('**/api/v1/**', async route => {
    const request = route.request()
    const url = new URL(request.url())
    const path = url.pathname.replace('/api/v1', '')
    const method = request.method()
    const json = (body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })

    if (path === '/stream') return route.abort()
    if (path === '/setup/status') return json({ configured: true, public_dashboard_enabled: false })
    if (path === '/auth/session') return json({ username: 'admin', display_name: 'admin', role: 'administrator', permissions: adminPermissions, csrf_token: 'public-csrf', totp_enabled: false })
    if (path === '/status') return json({ configured: true, version: 'v0.11.2', updates: {} })
    if (path === '/incidents') return json({ incidents: [], pagination: { limit: 1, offset: 0, total: 0, has_more: false, next_offset: null }, truncated: false, active_count: 0, server_now: new Date().toISOString(), next_follow_up_at: null })
    if (path === '/incidents/summary') return json({ active_count: 0 })
    if (path === '/public-dashboard' && method === 'GET') return json(dashboard)
    if (path === '/public-dashboard' && method === 'PUT') {
      saved = JSON.parse(request.postData() ?? '{}') as Record<string, unknown>
      dashboard = { ...dashboard, ...saved, updated_at: '2026-01-01T00:00:01Z' } as typeof dashboard
      return json(dashboard)
    }
    if (path === '/hosts') {
      const q = url.searchParams.get('q')
      const offset = Number(url.searchParams.get('offset') ?? 0)
      hostRequests.push({ q, offset })
      const hosts = q
        ? (q === 'later-job' || q === laterHost.address ? [laterHost] : [])
        : offset >= 100
          ? [laterHost]
          : Array.from({ length: 100 }, (_, index) => ({ job_id: `job-${index + 1}`, address: `192.0.2.${index + 1}`, job: `router-${index + 1}`, open_ports: 1, scanned_at: '2026-01-01T00:00:00Z' }))
      const total = q ? hosts.length : 221
      return json({ hosts, pagination: { limit: 100, offset, total, has_more: offset + hosts.length < total, next_offset: offset + hosts.length < total ? offset + 100 : null } })
    }
    if (path === '/jobs') return json({ jobs: [] })
    return json({ error: { code: 'not_found', message: `${method} ${path}` } }, 404)
  })

  await page.setViewportSize({ width: 320, height: 720 })
  await page.goto('/public-dashboard')
  await expect(page.getByRole('heading', { name: 'Public status' })).toBeVisible()

  const enabled = page.getByRole('checkbox', { name: 'Enable public status page' })
  await expect(enabled).not.toBeChecked()
  await enabled.check()
  await expect(enabled).toBeChecked()

  const search = page.getByRole('searchbox', { name: 'Search hosts by address or job' })
  await search.focus()
  await page.keyboard.type('later-job')
  await expect(page.getByText('1 host matches “later-job” · 0 selected for publication.')).toBeVisible()
  expect(hostRequests).toContainEqual({ q: 'later-job', offset: 0 })
  const host = page.getByRole('checkbox', { name: /198\.51\.100\.99/ })
  await expect(host).not.toBeChecked()
  expect(saved).toBeUndefined()
  await host.focus()
  await page.keyboard.press('Space')
  await expect(host).toBeChecked()
  expect(saved).toBeUndefined()

  await search.focus()
  await page.keyboard.press('Control+A')
  await page.keyboard.type('198.51.100.99')
  await expect(page.getByText('1 host matches “198.51.100.99” · 1 selected for publication.')).toBeVisible()
  expect(hostRequests).toContainEqual({ q: '198.51.100.99', offset: 0 })
  await expect(host).toBeChecked()

  const clear = page.getByRole('button', { name: 'Clear search' }).first()
  await clear.focus()
  await page.keyboard.press('Enter')
  await expect(search).toHaveValue('')
  await expect(page.getByText('221 hosts in the inventory · 1 selected for publication.')).toBeVisible()
  await expect(host).toHaveCount(0)
  expect(saved).toBeUndefined()

  const pagination = page.getByRole('navigation', { name: 'Host search results pagination' })
  await pagination.getByRole('button', { name: 'Next' }).focus()
  await page.keyboard.press('Enter')
  await expect(page.getByRole('checkbox', { name: /198\.51\.100\.99/ })).toBeChecked()
  expect(hostRequests).toContainEqual({ q: null, offset: 100 })
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320)

  await page.getByRole('button', { name: 'Save public view' }).click()
  await expect(page.locator('.save-feedback[role="status"]')).toContainText('Public view saved.')
  expect(saved).toMatchObject({ enabled: true, hosts: [{ job_id: 'job-later', address: '198.51.100.99' }] })

  const openNavigation = page.getByRole('button', { name: 'Open navigation' })
  if (await openNavigation.isVisible()) await openNavigation.click()
  await page.getByRole('link', { name: 'Jobs', exact: true }).click()
  await expect(page).toHaveURL(/\/jobs$/)
  await expect(page.getByRole('heading', { name: 'Jobs', exact: true })).toBeVisible()
})

test('a business unit public page loads by its slug without signing in', async ({ page }) => {
  const consoleRequests: string[] = []
  const publicRequests: string[] = []
  await page.route('**/api/v1/**', async route => {
    consoleRequests.push(new URL(route.request().url()).pathname)
    return route.fulfill({ status: 401, contentType: 'application/json', body: JSON.stringify({ error: { code: 'unauthorized', message: 'authentication required' } }) })
  })
  await page.route('**/api/public/v1/**', async route => {
    const path = new URL(route.request().url()).pathname
    publicRequests.push(path)
    const json = (body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })
    if (path === '/api/public/v1/dashboard/other') {
      return json({ title: 'Other unit status', introduction: 'Services of the other unit', updated_at: '2026-01-01T00:00:00Z', hosts: [{ job: 'edge', address: '198.51.100.10', public: false, private: true, open_ports: [{ protocol: 'tcp', port: 22, service: 'ssh' }] }] })
    }
    if (path === '/api/public/v1/dashboard') return json({ title: 'Default unit status', updated_at: '2026-01-01T00:00:00Z', hosts: [] })
    return json({ error: { code: 'public_disabled', message: 'public status is not enabled' } }, 404)
  })

  await page.goto('/public/other')
  await expect(page.getByRole('heading', { name: 'Other unit status' })).toBeVisible()
  await expect(page.getByText('Services of the other unit')).toBeVisible()
  await expect(page.getByText('198.51.100.10')).toBeVisible()
  await expect(page.getByRole('link', { name: 'Source code' })).toHaveCount(0)

  await page.goto('/public/nobody')
  await expect(page.getByRole('heading', { name: 'Public status unavailable' })).toBeVisible()
  await expect(page.getByText('This status page is not enabled by the administrator.')).toBeVisible()
  await expect(page.getByRole('link', { name: 'Source code' })).toHaveCount(0)

  await page.goto('/public')
  await expect(page.getByRole('heading', { name: 'Default unit status' })).toBeVisible()
  await expect(page.getByRole('link', { name: 'Source code' })).toHaveCount(0)

  expect(publicRequests).toEqual(['/api/public/v1/dashboard/other', '/api/public/v1/dashboard/nobody', '/api/public/v1/dashboard'])
  expect(consoleRequests).toEqual([])
})
