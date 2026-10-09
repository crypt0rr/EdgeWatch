import { expect, test } from '@playwright/test'
import { mockConsole } from './mock-console'

const operatorPages = [
  '/jobs',
  '/jobs/new',
  '/jobs/new/advanced',
  '/jobs/job-1',
  '/incidents',
  '/activity',
  '/notifications',
  '/hosts',
  '/scans/scan-1/hosts/192.0.2.10',
  '/security',
]

async function expectNoTinyVisibleText(page: import('@playwright/test').Page, path: string) {
  const tiny = await page.evaluate(() => [...document.querySelectorAll<HTMLElement>('body *')]
    .filter(element => [...element.childNodes].some(node => node.nodeType === Node.TEXT_NODE && !!node.textContent?.trim()))
    .filter(element => {
      const style = getComputedStyle(element)
      const bounds = element.getBoundingClientRect()
      return style.display !== 'none' && style.visibility !== 'hidden' && bounds.width > 0 && bounds.height > 0 && Number.parseFloat(style.fontSize) < 11
    })
    .map(element => `${element.tagName.toLowerCase()}.${typeof element.className === 'string' ? element.className : ''} ${getComputedStyle(element).fontSize}: ${element.textContent?.trim().slice(0, 40)}`))
  expect(tiny, `visible text smaller than 11px on ${path}`).toEqual([])
}

async function installIssue1128Fixtures(page: import('@playwright/test').Page) {
  await mockConsole(page)
  const job = {
    id: 'job-1', revision: 1, enabled: true, archived: false, security_hash: 'fixture-security-hash',
    created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z',
    job: { name: 'fixture-job', schedule: '0 * * * *', timezone: 'UTC', targets: ['192.0.2.10'], tcp: { ports: '1-65535', mode: 'connect', service_detection: true, engine: 'nmap' }, baseline_samples: 1, change_confirmations: 3, run_on_start: false, assume_alive: true, timeout: '1h', resume_window: '8d' },
    baseline: { status: 'complete', samples: 1, attempts: 1, host_count: 1, scan_id: 'scan-1', pending: 3 },
  }
  const address = '192.0.2.10'
  const truncatedSummary = `ssl-cert: Subject: CN=${'x'.repeat(487)}…`
  const host = {
    address, address_family: 'IPv4', status: 'up', status_reason: 'syn-ack', source_targets: [address],
    protocols: [{
      protocol: 'tcp', scanned_ports: '1-65535', scanned_port_count: 65535, service_detection: true,
      ports: [{ port: 443, state: 'open', reason: 'syn-ack', service: { name: 'https', product: 'nginx' } }],
      state_summaries: [{ state: 'open', count: 1 }, { state: 'closed', count: 65534 }],
      nse_output: [truncatedSummary, ...Array.from({ length: 31 }, (_, index) => `http-title-${index}: ${'Example result and captured metadata '.repeat(12)}\nIssuer: Example test CA`) ],
    }],
  }
  const timestamp = (second: number) => `2026-09-29T10:00:${String(second).padStart(2, '0')}Z`
  const incidents = Array.from({ length: 5 }, (_, index) => ({
    job_id: 'job-1', job: 'fixture-job',
    incident: { change: { key: `port-${index}`, kind: 'port', target: address, protocol: 'tcp', port: 443 + index, severity: 'critical' }, opened_at: timestamp(index), last_seen_at: timestamp(index) },
  }))
  const events = Array.from({ length: 20 }, (_, index) => ({
    type: 'scan-failure', job_id: 'job-1', job: 'fixture-job', scan_id: 'scan-1',
    message: `Scan failure history entry ${index + 1}.`, created_at: timestamp(index),
  }))

  await page.route(url => {
    const path = new URL(url).pathname
    return path === '/api/v1/jobs' || path === '/api/v1/jobs/job-1' || path === '/api/v1/jobs/job-1/pending-changes' ||
      path === '/api/v1/events' || path === '/api/v1/incidents' || path === `/api/v1/scans/scan-1/hosts/${address}` || path === `/api/v1/scans/scan-1/hosts/${address}/rdap`
  }, async route => {
    const path = new URL(route.request().url()).pathname
    if (path === '/api/v1/jobs' || path === '/api/v1/jobs/job-1') {
      await route.fulfill({ json: path === '/api/v1/jobs' ? { jobs: [job] } : job })
      return
    }
    if (path === '/api/v1/jobs/job-1/pending-changes') {
      await route.fulfill({ json: { job_id: 'job-1', job: 'fixture-job', pending_changes: [{ key: 'port|192.0.2.10|tcp|443', count: 1, change: { key: 'port|192.0.2.10|tcp|443', kind: 'port', target: address, protocol: 'tcp', port: 443, severity: 'critical' } }], pagination: { limit: 10, offset: 0, total: 1, has_more: false, next_offset: null } } })
      return
    }
    if (path === '/api/v1/events') {
      await route.fulfill({ json: { events, pagination: { limit: 20, offset: 0, total: events.length, has_more: false, next_offset: null } } })
      return
    }
    if (path === '/api/v1/incidents') {
      await route.fulfill({ json: { incidents, pagination: { limit: 5, offset: 0, total: incidents.length, has_more: false, next_offset: null } } })
      return
    }
    if (path.endsWith('/rdap')) {
      await route.fulfill({ json: { rdap: { status: 'private', address } } })
      return
    }
    await route.fulfill({ json: { job_id: 'job-1', job: 'fixture-job', data_quality: 'detailed', scan: { id: 'scan-1', job_id: 'job-1', job: 'fixture-job', status: 'success', started_at: timestamp(0), finished_at: timestamp(1), config_hash: 'fixture-security-hash' }, host } })
  })
}

test('operational text stays at least 11px on narrow screens', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'mobile-narrow', 'The mobile typography floor is checked once at 375px.')
  await installIssue1128Fixtures(page)
  await page.setViewportSize({ width: 375, height: 812 })

  for (const path of operatorPages) {
    await page.goto(path)
    const pageTitle = path.startsWith('/scans/') ? page.locator('.host-identity h2') : page.locator('h1').first()
    await expect(pageTitle).toBeVisible()
    if (path === '/activity') await expect(page.locator('.activity-event-heading time').first()).toBeVisible()
    if (path === '/jobs/job-1') await expect(page.locator('.pending-detail-heading')).toBeVisible()
    if (path.startsWith('/scans/')) await expect(page.locator('.nse-output-panel')).toBeVisible()
    await expectNoTinyVisibleText(page, path)
    const width = await page.evaluate(() => ({ document: document.documentElement.scrollWidth, viewport: window.innerWidth }))
    expect(width.document, `horizontal overflow on ${path}`).toBeLessThanOrEqual(width.viewport)
  }
})

test('Activity, pending confirmations, and host evidence stay readable on desktop', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'The desktop typography floor is checked once at 1280px.')
  await installIssue1128Fixtures(page)
  await page.setViewportSize({ width: 1280, height: 900 })

  for (const path of ['/activity', '/jobs/job-1', '/scans/scan-1/hosts/192.0.2.10']) {
    await page.goto(path)
    const pageTitle = path.startsWith('/scans/') ? page.locator('.host-identity h2') : page.locator('h1').first()
    await expect(pageTitle).toBeVisible()
    if (path === '/activity') await expect(page.locator('.activity-event-heading time').first()).toBeVisible()
    if (path === '/jobs/job-1') await expect(page.locator('.pending-detail-heading')).toBeVisible()
    if (path.startsWith('/scans/')) await expect(page.locator('.nse-output-panel')).toBeVisible()
    await expectNoTinyVisibleText(page, path)
  }
})

test('primary port evidence stays ahead of a long NSE list on phones and desktop', async ({ page }, testInfo) => {
  test.skip(!['desktop', 'mobile-narrow'].includes(testInfo.project.name), 'The long NSE layout is checked once per coarse and fine pointer layout.')
  const mobile = testInfo.project.name === 'mobile-narrow'
  await installIssue1128Fixtures(page)
  await page.setViewportSize(mobile ? { width: 375, height: 812 } : { width: 1280, height: 900 })
  await page.goto('/scans/scan-1/hosts/192.0.2.10')
  const primaryPorts = mobile ? page.locator('.mobile-port-list') : page.locator('.port-table-wrap')
  const nsePanel = page.locator('.nse-output-panel')
  await expect(primaryPorts).toBeVisible()
  await expect(nsePanel).toBeVisible()
  const position = await page.evaluate(({ portsSelector, panelSelector }) => {
    const host = document.querySelector('.host-identity')
    const ports = document.querySelector(portsSelector)
    const panel = document.querySelector(panelSelector)
    if (!host || !ports || !panel) throw new Error('Expected host summary, port evidence, and NSE results')
    return {
      distance: ports.getBoundingClientRect().top - host.getBoundingClientRect().top,
      height: window.innerHeight,
      portsBeforeNSE: !!(ports.compareDocumentPosition(panel) & Node.DOCUMENT_POSITION_FOLLOWING),
    }
  }, { portsSelector: mobile ? '.mobile-port-list' : '.port-table-wrap', panelSelector: '.nse-output-panel' })
  expect(position.portsBeforeNSE).toBe(true)
  expect(position.distance).toBeLessThan(position.height)
})

test('Activity and pending-confirmation controls meet the touch target floor (#1128)', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'mobile-narrow', 'Touch target checks use a single coarse-pointer browser at issue-specific viewports.')
  await installIssue1128Fixtures(page)

  for (const viewport of [{ width: 375, height: 812 }, { width: 768, height: 1024 }, { width: 844, height: 390 }]) {
    await page.setViewportSize(viewport)
    for (const path of ['/activity', '/jobs/job-1']) {
      await page.goto(path)
      const region = path === '/activity' ? page.locator('.activity-page') : page.locator('.pending-detail')
      if (path === '/activity') await expect(region.locator('.activity-event-heading time').first()).toBeVisible()
      else await expect(region.locator('a')).toBeVisible()
      const undersized = await region.locator('a, button').evaluateAll(elements => elements
        .filter(element => {
          const style = getComputedStyle(element)
          const rect = element.getBoundingClientRect()
          return style.display !== 'none' && style.visibility !== 'hidden' && rect.width > 0 && rect.height > 0 && (rect.width < 24 || rect.height < 24)
        })
        .map(element => `${element.tagName.toLowerCase()}.${(element as HTMLElement).className} ${Math.round(element.getBoundingClientRect().width)}×${Math.round(element.getBoundingClientRect().height)}`))
      expect(undersized, `undersized controls on ${path} at ${viewport.width}×${viewport.height}`).toEqual([])
    }
  }
})

test('platform console keeps operational text readable on a phone', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'mobile-narrow', 'The platform typography floor is checked once at 375px.')
  await mockConsole(page, 'platform_admin')
  await page.setViewportSize({ width: 375, height: 812 })

  for (const path of ['/platform/units', '/platform/units/unit-retail/accounts', '/platform/units/unit-retail/capacity', '/platform/admins', '/platform/notifications', '/platform/status']) {
    await page.goto(path)
    await expect(page.locator('h1').first()).toBeVisible()
    await expectNoTinyVisibleText(page, path)
    const width = await page.evaluate(() => ({ document: document.documentElement.scrollWidth, viewport: window.innerWidth }))
    expect(width.document, `horizontal overflow on ${path}`).toBeLessThanOrEqual(width.viewport)
  }
})

test('headings and primary actions meet contrast expectations and archived jobs stay legible', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'Shared typography and contrast are checked once on desktop.')
  await mockConsole(page)
  await page.route('**/api/v1/jobs*', async route => {
    if (new URL(route.request().url()).searchParams.get('include_archived') !== 'true') return route.fallback()
    await route.fulfill({ json: { jobs: [{
      id: 'archived-job', revision: 1, enabled: false, archived: true, security_hash: 'scope',
      created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z',
      job: { name: 'Archived target', schedule: '0 * * * *', timezone: 'UTC', targets: ['192.0.2.10'], tcp: { ports: '443', mode: 'connect', service_detection: false, engine: 'nmap' }, baseline_samples: 1 },
      baseline: { status: 'complete', samples: 1, attempts: 1 },
    }] } })
  })
  await page.goto('/jobs')
  await expect(page.getByRole('heading', { name: 'Jobs' })).toBeVisible()
  await expect(page.getByRole('link', { name: /Archived target/ })).toBeVisible()

  const styles = await page.evaluate(() => {
    const primary = document.querySelector<HTMLElement>('.button.primary')
    const archived = document.querySelector<HTMLElement>('.job-card')
    const heading = document.querySelector<HTMLElement>('.page-heading h1')
    if (!primary || !archived || !heading) throw new Error(`Missing typography elements: primary=${!!primary}, archived=${!!archived}, heading=${!!heading}`)
    const rgb = (value: string) => value.match(/[\d.]+/g)?.slice(0, 3).map(Number) ?? [0, 0, 0]
    const luminance = (value: string) => rgb(value).map(component => {
      const channel = component / 255
      return channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4
    }).reduce((sum, channel, index) => sum + channel * [0.2126, 0.7152, 0.0722][index], 0)
    const foreground = luminance(getComputedStyle(primary).color)
    const background = luminance(getComputedStyle(primary).backgroundColor)
    const contrast = (Math.max(foreground, background) + 0.05) / (Math.min(foreground, background) + 0.05)
    const archivedBackground = getComputedStyle(archived).backgroundColor
    const archivedOpacity = getComputedStyle(archived).opacity
    const revision = archived.querySelector<HTMLElement>('.revision')
    const footer = archived.querySelector<HTMLElement>('.job-card-bottom')
    if (!revision || !footer) throw new Error('Expected archived job metadata to render')
    const cardLuminance = luminance(archivedBackground)
    const textContrast = (element: HTMLElement) => {
      const textLuminance = luminance(getComputedStyle(element).color)
      return (Math.max(textLuminance, cardLuminance) + 0.05) / (Math.min(textLuminance, cardLuminance) + 0.05)
    }
    return {
      contrast,
      archivedOpacity,
      archivedClass: archived.className,
      archivedBorderStyle: getComputedStyle(archived).borderTopStyle,
      archivedBackground,
      revisionContrast: textContrast(revision),
      footerContrast: textContrast(footer),
      headingWeight: Number.parseInt(getComputedStyle(heading).fontWeight, 10),
    }
  })

  expect(styles.contrast).toBeGreaterThanOrEqual(4.5)
  expect(styles.archivedOpacity).toBe('1')
  expect(styles.archivedClass).toContain('archived')
  expect(styles.archivedBorderStyle).toBe('dashed')
  expect(styles.archivedBackground).toBe('rgb(11, 22, 36)')
  expect(styles.revisionContrast).toBeGreaterThanOrEqual(4.5)
  expect(styles.footerContrast).toBeGreaterThanOrEqual(4.5)
  expect(styles.headingWeight).toBeGreaterThanOrEqual(600)

  await page.goto('/jobs/new/advanced')
  const panelHeading = page.locator('.panel h2').first()
  await expect(panelHeading).toBeVisible()
  expect(Number.parseInt(await panelHeading.evaluate(element => getComputedStyle(element).fontWeight), 10)).toBeGreaterThanOrEqual(600)
})
