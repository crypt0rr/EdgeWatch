import { expect, test } from '@playwright/test'
import { mockConsole } from './mock-console'

const widths = [320, 375, 414, 768, 844, 1280, 1920]
const longIPv6 = '2a01:4f8:c17:b8f2:9c2b:4bff:fe12:3456'
const longJobName = 'Weekly perimeter security monitoring for production infrastructure'
const longName = 'Konzernsicherheitsinfrastrukturueberwachungsabteilungsleitungsstelle'

async function noHorizontalPageOverflow(page: import('@playwright/test').Page) {
  const dimensions = await page.evaluate(() => ({
    viewport: document.documentElement.clientWidth,
    document: document.documentElement.scrollWidth,
    offenders: Array.from(document.querySelectorAll<HTMLElement>('body *')).map(element => {
      const rect = element.getBoundingClientRect()
      return { tag: element.tagName, className: typeof element.className === 'string' ? element.className : '', left: Math.round(rect.left), right: Math.round(rect.right), width: Math.round(rect.width), overflow: element.scrollWidth - element.clientWidth, text: element.textContent?.trim().replace(/\s+/g, ' ').slice(0, 70) }
    }).filter(element => element.right > document.documentElement.clientWidth + 1 || element.overflow > 1).sort((left, right) => right.overflow - left.overflow).slice(0, 12),
  }))
  expect(dimensions.document, `page overflow at ${dimensions.viewport}px: ${JSON.stringify(dimensions.offenders)}`).toBeLessThanOrEqual(dimensions.viewport)
}

test('host rows and filter controls stay readable from phone through desktop widths', async ({ page }) => {
  await mockConsole(page)
  const hosts = [{
    address: longIPv6,
    address_family: 'IPv6',
    source_targets: ['www.example.com', 'mail.example.com', 'vpn.example.com'],
    dns_names: [],
    job_id: 'job-1',
    job: longJobName,
    scan_id: 'scan-1',
    scanned_at: '2026-01-01T00:00:00Z',
    data_quality: 'detailed',
    open_ports: 3,
    open_filtered_ports: 0,
    has_open_ports: true,
    archived: false,
    protocols: [{ protocol: 'tcp', scanned_ports: '1-1024', scanned_port_count: 1024, service_detection: true, open_ports: 3, open_filtered_ports: 0 }],
  }]
  await page.route('**/api/v1/hosts*', route => route.fulfill({ json: { hosts, pagination: { limit: 50, offset: 0, total: 1, has_more: false, next_offset: null } } }))
  await page.goto('/hosts')
  const address = page.locator('.host-address strong')
  const row = page.locator('.host-row').first()
  await expect(address).toContainText(longIPv6)
  await expect(page.locator('.host-source strong')).toContainText(longJobName)

  for (const width of widths) {
    await page.setViewportSize({ width, height: 900 })
    await noHorizontalPageOverflow(page)
    const addressSize = await address.evaluate(element => ({ client: element.clientWidth, scroll: element.scrollWidth }))
    expect(addressSize.scroll).toBeLessThanOrEqual(addressSize.client)
  }

  await page.setViewportSize({ width: 768, height: 900 })
  const tabletColumns = await row.evaluate(element => getComputedStyle(element).gridTemplateColumns.split(' ').length)
  expect(tabletColumns).toBe(2)

  await page.setViewportSize({ width: 320, height: 900 })
  const filterBounds = await page.locator('.host-toolbar input, .host-toolbar select').evaluateAll(elements => elements.map(element => {
    const rect = element.getBoundingClientRect()
    return { x: rect.x, height: rect.height }
  }))
  expect(filterBounds).toHaveLength(3)
  expect(new Set(filterBounds.map(bounds => bounds.x)).size).toBe(1)
  expect(filterBounds.every(bounds => bounds.height === filterBounds[0].height)).toBe(true)
})

test('public IPv6 cards keep their address badges inside and size to their own content', async ({ page }) => {
  const address2 = '2001:db8:4f2e:91a7:c3d1:77b0:1e5f:9a20'
  const address3 = '2001:4860:4860:0000:0000:0000:0000:8888'
  const hosts = [longIPv6, address2, address3].map((address, index) => ({
    job: longJobName,
    address,
    public: true,
    private: false,
    last_successful_scan: '2026-01-01T00:00:00Z',
    open_ports: Array.from({ length: index === 1 ? 25 : 1 }, (_, port) => ({ protocol: 'tcp', port: 400 + port, service: `service-${port}` })),
    open_filtered_ports: [],
  }))
  await page.route('**/api/public/v1/dashboard*', route => route.fulfill({ json: { title: 'Production status', introduction: 'A public view of monitored infrastructure and its latest successful scan results.', updated_at: '2026-01-01T00:00:00Z', hosts } }))
  await page.goto('/public')
  await expect(page.locator('.public-host-card')).toHaveCount(3)

  for (const width of widths) {
    await page.setViewportSize({ width, height: 900 })
    await noHorizontalPageOverflow(page)
    const cards = page.locator('.public-host-card')
    for (let index = 0; index < await cards.count(); index += 1) {
      const card = cards.nth(index)
      const bounds = await card.evaluate(element => {
        const cardRect = element.getBoundingClientRect()
        const pillRect = element.querySelector('.public-host-heading .pill')!.getBoundingClientRect()
        const heading = element.querySelector('.public-host-heading h2')!
        return { card: cardRect.toJSON(), pill: pillRect.toJSON(), addressClient: heading.clientWidth, addressScroll: heading.scrollWidth }
      })
      expect(bounds.pill.x).toBeGreaterThanOrEqual(bounds.card.x)
      expect(bounds.pill.x + bounds.pill.width).toBeLessThanOrEqual(bounds.card.x + bounds.card.width)
      expect(bounds.addressScroll).toBeLessThanOrEqual(bounds.addressClient)
    }
    const cardHeights = await cards.evaluateAll(elements => elements.map(element => element.getBoundingClientRect().height))
    expect(cardHeights[0]).toBeLessThan(cardHeights[1])
    expect(cardHeights[2]).toBeLessThan(cardHeights[1])
  }
})

test('job targets and scan host addresses remain available in full', async ({ page }) => {
  await mockConsole(page)
  const targets = [
    'edgewatch-inventory-monitoring-target-with-a-very-long-dns-label.example.test',
    'second-target.example.test',
    'third-target.example.test',
  ]
  await page.route('**/api/v1/jobs/job-1', route => route.request().method() === 'GET'
    ? route.fulfill({ json: {
      id: 'job-1', revision: 1, enabled: true, archived: false, security_hash: 'scope',
      created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z',
      job: { name: 'Target inventory', schedule: '0 * * * *', timezone: 'UTC', targets, max_expanded_hosts: 256, tcp: { ports: '22,443', mode: 'connect', service_detection: false, engine: 'nmap' }, timing: 'balanced', timeout: '1h', resume_window: '8d', baseline_samples: 1, change_confirmations: 1, run_on_start: false, assume_alive: true, allow_high_cost: false },
      baseline: { status: 'complete', samples: 1, attempts: 1, host_count: 1, scan_id: 'scan-1' },
    } })
    : route.fallback())
  await page.goto('/jobs/job-1')
  const targetDisclosure = page.locator('.targets-summary details')
  await expect(targetDisclosure.locator('summary')).toHaveText('View all 3 targets')
  await targetDisclosure.locator('summary').click()
  await expect(targetDisclosure).toContainText(targets[2])

  const scan = { id: 'scan-1', job_id: 'job-1', job: 'Target inventory', started_at: '2026-01-01T00:00:00Z', finished_at: '2026-01-01T00:00:01Z', status: 'success', config_hash: 'scope' }
  const scanHosts = [0, 2, 4].map(suffix => ({ address: `2001:db8:85a3:1234:5678:8a2e:370:${7000 + suffix}`, open_ports: 13, open_filtered_ports: 0, has_open_ports: true, protocols: [{ protocol: 'tcp', scanned_ports: '1-1024', scanned_port_count: 1024, service_detection: true, open_ports: 13, open_filtered_ports: 0 }] }))
  await page.route('**/api/v1/scans/scan-1/**', route => {
    const path = new URL(route.request().url()).pathname
    if (path.endsWith('/summary')) return route.fulfill({ json: { scan } })
    if (path.endsWith('/hosts')) return route.fulfill({ json: { job_id: 'job-1', job: 'Target inventory', scan, data_quality: 'detailed', hosts: scanHosts, pagination: { limit: 50, offset: 0, total: scanHosts.length, has_more: false, next_offset: null } } })
    return route.fallback()
  })
  await page.goto('/scans/scan-1')
  await expect(page.locator('.result-row > strong')).toHaveCount(3)
  for (const width of widths) {
    await page.setViewportSize({ width, height: 900 })
    await noHorizontalPageOverflow(page)
    const address = page.locator('.result-row > strong').first()
    await expect(address).toHaveAttribute('title', scanHosts[0].address)
    const size = await address.evaluate(element => ({ client: element.clientWidth, scroll: element.scrollWidth }))
    expect(size.scroll).toBeLessThanOrEqual(size.client)
  }
})

test('long unit headings and confirmation dialogs wrap without clipping', async ({ page }) => {
  await mockConsole(page, 'platform_admin')
  await page.route('**/api/v1/platform/units/unit-retail', route => route.request().method() === 'GET'
    ? route.fulfill({ json: { id: 'unit-retail', name: longName, slug: 'retail', status: 'active', is_default: false, revision: 1, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z', state_changed_at: '2026-01-01T00:00:00Z', accounts: 3, administrators: 1, jobs: 2, stored_scans: 1480, slots: { in_use: 0, queued: 0 } } })
    : route.fallback())
  await page.goto('/platform/units/unit-retail/danger')
  await expect(page.getByRole('heading', { name: longName, level: 1 })).toBeVisible()
  for (const width of widths) {
    await page.setViewportSize({ width, height: 900 })
    await noHorizontalPageOverflow(page)
  }

  await page.getByRole('button', { name: 'Disable unit' }).click()
  const dialog = page.getByRole('dialog', { name: `Disable ${longName}?` })
  await expect(dialog).toBeVisible()
  for (const width of widths) {
    await page.setViewportSize({ width, height: 900 })
    const bounds = await dialog.evaluate(element => ({ client: element.clientWidth, scroll: element.scrollWidth }))
    expect(bounds.scroll).toBeLessThanOrEqual(bounds.client)
    const title = dialog.locator('h2')
    const titleBounds = await title.evaluate(element => ({ client: element.clientWidth, scroll: element.scrollWidth }))
    expect(titleBounds.scroll).toBeLessThanOrEqual(titleBounds.client)
  }
})

test('notification destination names stay distinguishable in settings and job routing', async ({ page }) => {
  await mockConsole(page)
  const destinationName = 'Security operations center on-call pager rotation primary escalation duty'
  const response = {
    destinations: [{ id: 'dest-long', name: destinationName, provider: 'mattermost', source: 'web', enabled: true, locked: false, read_only: false, revision: 1 }],
    status: { deployment: 0, managed: 1, active: 1, locked: 0, key_state: 'ready' },
    update_routing: { configured: true, destinations: ['dest-long'] },
  }
  await page.route('**/api/v1/notifications/destinations', route => route.request().method() === 'GET' ? route.fulfill({ json: response }) : route.fallback())

  await page.goto('/notifications')
  await expect(page.locator('.notification-meta strong')).toHaveText(destinationName)
  for (const width of [320, 375, 414, 768, 844]) {
    await page.setViewportSize({ width, height: 900 })
    await noHorizontalPageOverflow(page)
  }

  await page.goto('/jobs/job-1/edit')
  const editorName = page.locator('.job-notification-option strong')
  await expect(editorName).toHaveText(destinationName)
  await expect(editorName).toHaveAttribute('title', destinationName)
  for (const width of [320, 375, 414, 768, 844]) {
    await page.setViewportSize({ width, height: 900 })
    await noHorizontalPageOverflow(page)
    const size = await editorName.evaluate(element => ({ client: element.clientWidth, scroll: element.scrollWidth }))
    expect(size.scroll).toBeLessThanOrEqual(size.client)
  }
})

test('platform status cards and audit filters wrap at narrow and landscape widths', async ({ page }) => {
  await mockConsole(page, 'platform_admin')
  await page.route('**/api/v1/platform/status', route => route.fulfill({ json: {
    version: 'v0.20.8',
    units: { total: 12345, active: 12300, disabled: 25, deleting: 20 },
    accounts: 98765,
    jobs: 98765,
    stored_scans: 123456,
    platform_admins: { total: 16, enabled: 14 },
    capacity: { limits: { max_concurrent_scans: 4, max_probe_count: 5000000, max_naabu_probe_count: 20000000, max_probe_count_limit: 100000000 }, slots: { capacity: 4, in_use: 2, queued: 12345 } },
    updates: { enabled: true, status: 'up_to_date', current_version: 'v0.20.8' },
  } }))

  await page.goto('/platform/status')
  for (const width of widths) {
    await page.setViewportSize({ width, height: 900 })
    await noHorizontalPageOverflow(page)
    const cards = page.locator('.platform-status .summary-card')
    for (let index = 0; index < await cards.count(); index += 1) {
      const card = cards.nth(index)
      const overflow = await card.locator('.summary-label, .muted').evaluateAll(elements => elements.map(element => element.scrollWidth - element.clientWidth))
      expect(overflow.every(value => value <= 0)).toBe(true)
    }
  }

  await page.goto('/platform/audit')
  for (const width of [320, 375, 414, 768, 844, 1280]) {
    await page.setViewportSize({ width, height: 900 })
    await noHorizontalPageOverflow(page)
    const controls = await page.locator('.audit-filters input, .audit-filters select').evaluateAll(elements => elements.map(element => {
      const rect = element.getBoundingClientRect()
      return { x: rect.x, height: rect.height }
    }))
    expect(controls).toHaveLength(4)
    if (width <= 520) expect(new Set(controls.map(control => control.x)).size).toBe(1)
    if (width === 1280) {
      const labels = await page.locator('.audit-filters label').evaluateAll(elements => elements.map(element => element.getBoundingClientRect().height))
      expect(labels.every(height => height <= 64)).toBe(true)
    }
  }
})
