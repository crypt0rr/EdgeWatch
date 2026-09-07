import { expect, test } from '@playwright/test'

test('public status controls remain interactive and navigation leaves the page', async ({ page }) => {
  let dashboard = {
    enabled: false,
    title: 'EdgeWatch public status',
    introduction: '',
    updated_at: '2026-01-01T00:00:00Z',
    hosts: [] as Array<{ job_id: string; address: string; created_at: string }>,
  }
  let saved: Record<string, unknown> | undefined

  await page.route('**/api/v1/**', async route => {
    const request = route.request()
    const path = new URL(request.url()).pathname.replace('/api/v1', '')
    const method = request.method()
    const json = (body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })

    if (path === '/stream') return route.abort()
    if (path === '/setup/status') return json({ configured: true, version: 'v0.11.2', public_dashboard_enabled: false })
    if (path === '/auth/session') return json({ username: 'admin', display_name: 'admin', role: 'administrator', permissions: [], csrf_token: 'public-csrf', totp_enabled: false })
    if (path === '/status') return json({ configured: true, version: 'v0.11.2', updates: {} })
    if (path === '/incidents') return json({ incidents: [], pagination: { limit: 1, offset: 0, total: 0, has_more: false, next_offset: null } })
    if (path === '/public-dashboard' && method === 'GET') return json(dashboard)
    if (path === '/public-dashboard' && method === 'PUT') {
      saved = JSON.parse(request.postData() ?? '{}') as Record<string, unknown>
      dashboard = { ...dashboard, ...saved, updated_at: '2026-01-01T00:00:01Z' } as typeof dashboard
      return json(dashboard)
    }
    if (path === '/hosts') return json({
      hosts: [{ job_id: 'job-1', address: '192.0.2.1', job: 'router', open_ports: 1, scanned_at: '2026-01-01T00:00:00Z' }],
      pagination: { limit: 100, offset: 0, total: 1, has_more: false, next_offset: null },
    })
    if (path === '/jobs') return json({ jobs: [] })
    return json({ error: { code: 'not_found', message: `${method} ${path}` } }, 404)
  })

  await page.goto('/public-dashboard')
  await expect(page.getByRole('heading', { name: 'Public status' })).toBeVisible()

  const enabled = page.getByRole('checkbox', { name: 'Enable public status page' })
  await expect(enabled).not.toBeChecked()
  await enabled.check()
  await expect(enabled).toBeChecked()

  const host = page.getByRole('checkbox', { name: /192\.0\.2\.1/ })
  await host.check()
  await expect(host).toBeChecked()
  await page.getByRole('button', { name: 'Save public view' }).click()
  await expect(page.getByRole('status')).toContainText('Public view saved')
  expect(saved).toMatchObject({ enabled: true, hosts: [{ job_id: 'job-1', address: '192.0.2.1' }] })

  const openNavigation = page.getByRole('button', { name: 'Open navigation' })
  if (await openNavigation.isVisible()) await openNavigation.click()
  await page.getByRole('link', { name: 'Jobs', exact: true }).click()
  await expect(page).toHaveURL(/\/jobs$/)
  await expect(page.getByRole('heading', { name: 'Jobs', exact: true })).toBeVisible()
})
