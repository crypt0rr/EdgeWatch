import { expect, test } from '@playwright/test'
import { mockConsole } from './mock-console'

const operatorPages = [
  '/jobs',
  '/jobs/new',
  '/jobs/job-1',
  '/incidents',
  '/notifications',
  '/hosts',
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

test('operational text stays at least 11px on narrow screens', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'mobile-narrow', 'The mobile typography floor is checked once at 375px.')
  await mockConsole(page)
  await page.setViewportSize({ width: 375, height: 812 })

  for (const path of operatorPages) {
    await page.goto(path)
    await expect(page.locator('h1').first()).toBeVisible()
    await expectNoTinyVisibleText(page, path)
    const width = await page.evaluate(() => ({ document: document.documentElement.scrollWidth, viewport: window.innerWidth }))
    expect(width.document, `horizontal overflow on ${path}`).toBeLessThanOrEqual(width.viewport)
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

  await page.goto('/jobs/new')
  const panelHeading = page.locator('.panel h2').first()
  await expect(panelHeading).toBeVisible()
  expect(Number.parseInt(await panelHeading.evaluate(element => getComputedStyle(element).fontWeight), 10)).toBeGreaterThanOrEqual(600)
})
