import { expect, test, type Locator, type Page } from '@playwright/test'
import { mockConsole } from './mock-console'

// The Perimeter page and its range detail against the mock console's
// perimeter: four declared ranges, monitors in every list of the page, and
// targets outside the perimeter. Every test runs at each of the suite's
// viewports, where the ranges table becomes cards on phones.

const docsURL = 'https://edgewatch.offsec.nl/user-guide/perimeter/#seed-the-perimeter-from-an-asn'
const coverageDocsURL = 'https://edgewatch.offsec.nl/user-guide/perimeter/#how-coverage-is-computed'

async function noHorizontalPageOverflow(page: Page) {
  await expect.poll(() => page.evaluate(() => {
    const viewport = document.documentElement.clientWidth
    if (document.documentElement.scrollWidth <= viewport) return 'fits'
    const offenders = Array.from(document.querySelectorAll<HTMLElement>('body *')).map(element => {
      const rect = element.getBoundingClientRect()
      return { tag: element.tagName, className: typeof element.className === 'string' ? element.className : '', right: Math.round(rect.right), text: element.textContent?.trim().replace(/\s+/g, ' ').slice(0, 70) }
    }).filter(element => element.right > viewport + 1).sort((left, right) => right.right - left.right).slice(0, 8)
    return `page overflow at ${viewport}px: ${JSON.stringify(offenders)}`
  })).toBe('fits')
}

/** Whether the page shows the ranges as cards, as the console does at 760px and below. */
function showsCards(page: Page) {
  return (page.viewportSize()?.width ?? 1280) <= 760
}

/** A declared range's table row on desktop, or its card on a phone. */
function rangeEntry(page: Page, value: string): Locator {
  const link = page.getByRole('link', { name: value, exact: true })
  return showsCards(page)
    ? page.getByRole('list', { name: 'Declared ranges' }).locator(':scope > li').filter({ has: link })
    : page.getByRole('region', { name: 'Declared ranges table' }).getByRole('row').filter({ has: link })
}

function summaryCard(page: Page, label: string): Locator {
  return page.getByRole('region', { name: 'Perimeter summary' }).locator('.summary-card').filter({ hasText: label })
}

async function openNavigation(page: Page) {
  const trigger = page.getByRole('button', { name: 'Open navigation' })
  if (await trigger.isVisible()) await trigger.click()
}

test('the report shows its summary, every declared range, and each monitor list', async ({ page }) => {
  await mockConsole(page)
  await page.goto('/perimeter')
  await expect(page.getByRole('heading', { level: 1, name: 'Perimeter' })).toBeVisible()

  // 65,796 declared IPv4 addresses, 4 of them excluded: the shares use the
  // 65,792 scannable ones.
  await expect(summaryCard(page, 'Declared IPv4')).toContainText('65,796')
  await expect(summaryCard(page, 'Declared IPv4')).toContainText('4 excluded · plus 1 IPv6 range')
  await expect(summaryCard(page, 'Full TCP covered')).toContainText('0.1%')
  await expect(summaryCard(page, 'Full TCP covered')).toContainText('128 of 65,792 addresses')
  await expect(summaryCard(page, 'Any TCP covered')).toContainText('0.5%')
  await expect(summaryCard(page, 'Any TCP covered')).toContainText('384 of 65,792 addresses')
  await expect(summaryCard(page, 'UDP covered')).toContainText('0%')
  await expect(summaryCard(page, 'Cannot scan').locator('strong')).toHaveText('2')
  await expect(summaryCard(page, 'Coverage not proven').locator('strong')).toHaveText('2')
  await expect(summaryCard(page, 'Outside the perimeter').locator('strong')).toHaveText('2')
  await expect(page.getByText('1 covering monitor scans only hosts that answer host discovery:')).toBeVisible()

  // The ranges come in the store's order, IPv4 first, by address, and a
  // visible legend says what fills each bucket at every width.
  const rangesPanel = page.getByRole('region', { name: 'Declared ranges', exact: true })
  await expect(rangesPanel.locator('.perimeter-range-name a')).toHaveText(['192.0.2.128/30', '198.18.0.0/16', '203.0.113.0/24', '2001:db8:100::/48'])
  const legend = rangesPanel.locator('.perimeter-bucket-legend > div')
  await expect(legend).toHaveText([
    /^Full TCP\s*TCP with Naabu discovery and Nmap confirmation, or Nmap only over ports 1–65535\.$/,
    /^Any TCP\s*TCP with any engine and any ports, full TCP included\.$/,
    /^UDP\s*UDP with any ports\.$/,
  ])
  for (const item of await legend.all()) await expect(item).toBeVisible()

  // Each range shows its kind, label, a share per bucket and the states of
  // its monitors; an IPv6 range shows counts, and an excluded one no share.
  const owned = rangeEntry(page, '203.0.113.0/24')
  await expect(owned).toContainText('Owned')
  await expect(owned).toContainText('DC1 edge')
  const ownedCoverage = owned.locator('.perimeter-coverage')
  await expect(ownedCoverage).toHaveCount(3)
  await expect(ownedCoverage.nth(0)).toContainText('50%')
  await expect(ownedCoverage.nth(0)).toContainText('128 of 256 addresses')
  await expect(ownedCoverage.nth(1)).toContainText('100%')
  await expect(ownedCoverage.nth(2)).toContainText('0%')
  await expect(owned.getByRole('list', { name: 'Monitors of 203.0.113.0/24' }).getByRole('listitem')).toHaveText(['Paused 1', 'Covering 2', 'Not proven 1'])
  const partner = rangeEntry(page, '198.18.0.0/16')
  await expect(partner).toContainText('Authorized')
  await expect(partner.locator('.perimeter-coverage').nth(1)).toContainText('128 of 65,536 addresses')
  await expect(partner.getByRole('list', { name: 'Monitors of 198.18.0.0/16' }).getByRole('listitem')).toHaveText(['Covering 1', 'Over probe budget 1', 'Not proven 1'])
  const ipv6 = rangeEntry(page, '2001:db8:100::/48').locator('.perimeter-coverage')
  await expect(ipv6.nth(1)).toContainText('256 addresses monitored', { useInnerText: true })
  await expect(ipv6.nth(0)).toContainText('0 addresses monitored', { useInnerText: true })
  await expect(rangeEntry(page, '2001:db8:100::/48')).not.toContainText('%')
  await expect(rangeEntry(page, '192.0.2.128/30').locator('.perimeter-coverage')).toHaveText(Array(3).fill(/All addresses excluded/))
  await expect(page.getByRole('note').filter({ hasText: 'One monitor scans at most 65,536 addresses (scanner.max_job_hosts), a /112' })).toBeVisible()

  // Only the monitors that touch a declared range are listed: fixture-job is
  // stale but is listed only for its target outside the perimeter.
  const cannotScan = page.getByRole('region', { name: 'Monitors that cannot scan' }).locator('.perimeter-monitor-list > li')
  await expect(cannotScan).toHaveCount(2)
  await expect(cannotScan.nth(0)).toContainText('Edge DNS UDP')
  await expect(cannotScan.nth(0)).toContainText('Paused: scheduled runs do not start it.')
  await expect(cannotScan.nth(1)).toContainText('Partner sweep')
  await expect(cannotScan.nth(1)).toContainText('Over probe budget: ')
  await expect(cannotScan.nth(1)).toContainText('Over expansion limit: ')
  await expect(cannotScan.nth(0).getByRole('link', { name: 'Edge DNS UDP' })).toHaveAttribute('href', '/jobs/job-dns')
  const unproven = page.getByRole('region', { name: 'Coverage not proven' }).locator('.perimeter-monitor-list > li')
  await expect(unproven).toHaveCount(2)
  await expect(unproven.nth(0)).toContainText('Edge web ports')
  await expect(unproven.nth(0)).toContainText(/No successful scan since \S/)
  await expect(unproven.nth(0)).toContainText('Scans only hosts that answer host discovery')
  await expect(unproven.nth(1)).toContainText('Partner TCP')
  await expect(unproven.nth(1)).toContainText('Scan cycle stalled')
  await expect(unproven.nth(1)).toContainText('Last attempt failed')
  await expect(page.getByRole('region', { name: 'Coverage not proven' })).not.toContainText('fixture-job')

  const outsideRegion = page.getByRole('region', { name: 'Outside the perimeter' })
  const outside = outsideRegion.locator('.perimeter-outside-list > li')
  await expect(outside).toHaveCount(2)
  await expect(outside.nth(0)).toContainText('198.18.0.0/15')
  await expect(outside.nth(0)).toContainText('Partly outside')
  await expect(outside.nth(0)).toContainText('65,536 addresses outside')
  await expect(outside.nth(0)).toContainText('Partner sweep · Over probe budget')
  await expect(outside.nth(1)).toContainText('192.0.2.10')
  await expect(outside.nth(1)).toContainText('Fully outside')
  await expect(outside.nth(1)).toContainText('1 address outside')
  await expect(outside.nth(1)).toContainText('fixture-job · Covering')
  await expect(outsideRegion.getByText(/^Showing /)).toHaveCount(0)

  // The report links how coverage is computed; the ASN recipe belongs to
  // the empty page and the declare form.
  const guide = page.getByRole('link', { name: /How coverage is computed/ })
  await expect(guide).toHaveAttribute('href', coverageDocsURL)
  await expect(guide).toHaveAttribute('target', '_blank')
  await expect(guide).toHaveAttribute('rel', 'noopener noreferrer')
  await expect(page.getByRole('heading', { name: 'Declare ranges', exact: true })).toBeVisible()
  await noHorizontalPageOverflow(page)
})

test('a truncated outside list says how many targets it shows', async ({ page }) => {
  const controls = await mockConsole(page)
  controls.transformPerimeterOverview(overview => ({ ...overview, outside_truncated: true, totals: { ...overview.totals, outside_targets: 250 } }))
  await page.goto('/perimeter')
  const outside = page.getByRole('region', { name: 'Outside the perimeter' })
  await expect(outside.getByRole('status')).toHaveText('Showing 2 of 250 targets outside the perimeter.')
  await expect(summaryCard(page, 'Outside the perimeter').locator('strong')).toHaveText('250')
  await noHorizontalPageOverflow(page)
})

test('a range opens from its row and from the keyboard, and its detail keeps Perimeter active', async ({ page }) => {
  await mockConsole(page)
  await page.goto('/perimeter')

  // A pointer selects the range anywhere on its row or card.
  await rangeEntry(page, '203.0.113.0/24').locator('.perimeter-coverage').first().click()
  await expect(page).toHaveURL(/\/perimeter\/ranges\/range-1$/)
  await expect(page.getByRole('heading', { level: 1, name: '203.0.113.0/24' })).toBeVisible()
  await expect(page.locator('#primary-navigation a[href="/perimeter"]')).toHaveAttribute('aria-current', 'page')
  await expect(page.getByRole('navigation', { name: /^Breadcrumb/ })).toHaveText('Perimeter / Range')

  // The range's link is the keyboard's way there; on desktop it follows the
  // focusable table region. The ranges are in address order, IPv4 first, so
  // the first link is the lowest range.
  await page.getByRole('link', { name: '← Perimeter' }).click()
  await expect(page).toHaveURL(/\/perimeter$/)
  const link = page.getByRole('link', { name: '192.0.2.128/30', exact: true })
  if (showsCards(page)) {
    await link.focus()
  } else {
    const table = page.getByRole('region', { name: 'Declared ranges table' })
    await table.focus()
    await expect(table).toBeFocused()
    await page.keyboard.press('Tab')
  }
  await expect(link).toBeFocused()
  await page.keyboard.press('Enter')
  await expect(page).toHaveURL(/\/perimeter\/ranges\/range-4$/)
})

test('the range detail shows its monitors, uncovered blocks, and a Create monitor button per suggestion', async ({ page }) => {
  await mockConsole(page)
  await page.goto('/perimeter/ranges/range-1')
  await expect(page.getByRole('heading', { level: 1, name: '203.0.113.0/24' })).toBeVisible()
  await expect(page.getByText('DC1 edge', { exact: true })).toBeVisible()
  const coverage = page.getByRole('region', { name: 'Range coverage' })
  await expect(coverage.locator('.summary-card').filter({ hasText: 'Full TCP covered' })).toContainText('50%')
  await expect(coverage.locator('.summary-card').filter({ hasText: 'Any TCP covered' })).toContainText('100%')
  await expect(coverage.locator('.summary-card').filter({ hasText: 'UDP covered' })).toContainText('0%')

  const monitors = page.getByRole('region', { name: 'Monitors touching this range' }).locator('.perimeter-monitor-list > li')
  await expect(monitors).toHaveCount(3)
  const web = monitors.filter({ hasText: 'Edge web ports' })
  await expect(web).toContainText(/No successful scan since \S/)
  await expect(web).toContainText('Scans only hosts that answer host discovery')
  await expect(web).toContainText('1 DNS-name target, which never counts as coverage')
  await expect(monitors.filter({ hasText: 'Edge DNS UDP' })).toContainText('Paused')

  await expect(page.getByRole('region', { name: 'Full TCP uncovered blocks' })).toContainText('203.0.113.128/25')
  await expect(page.getByRole('region', { name: 'Any TCP uncovered blocks' })).toContainText('No uncovered addresses.')
  await expect(page.getByRole('region', { name: 'UDP uncovered blocks' })).toContainText('203.0.113.0/24')

  const suggestions = page.getByRole('region', { name: 'Suggested monitors' })
  await expect(suggestions.getByRole('note')).toContainText('A declared range is not an authorization: confirm you may scan these addresses')
  const fullTCP = page.getByRole('region', { name: 'Full TCP', exact: true })
  await expect(fullTCP).toContainText('Up to 305 addresses per monitor')
  await expect(fullTCP).toContainText('Monitor 1 of 1')
  await expect(fullTCP).toContainText('128 addresses · 8,388,480 estimated probes · TCP ports 1-65535')
  await expect(fullTCP.getByRole('button', { name: 'Create monitor' })).toHaveCount(1)
  const selected = page.getByRole('region', { name: 'Selected TCP ports', exact: true })
  await expect(selected).toContainText('No gaps to fill in this mode.')
  await expect(selected.getByRole('button', { name: 'Create monitor' })).toHaveCount(0)
  const udp = page.getByRole('region', { name: 'UDP', exact: true })
  // Six UDP ports with service detection cost 12 probes per address.
  await expect(udp).toContainText('256 addresses · 3,072 estimated probes · UDP ports 53,123,161,500,1194,4500')
  await expect(udp.getByRole('button', { name: 'Create monitor' })).toHaveCount(1)
  await noHorizontalPageOverflow(page)
})

test('a range that needs more than 16 monitors in a mode states the count instead of listing them', async ({ page }) => {
  await mockConsole(page)
  await page.goto('/perimeter/ranges/range-2')
  await expect(page.getByRole('heading', { level: 1, name: '198.18.0.0/16' })).toBeVisible()
  await expect(page.getByText('Authorized', { exact: true })).toBeVisible()

  const fullTCP = page.getByRole('region', { name: 'Full TCP', exact: true })
  await expect(fullTCP).toContainText('Needs 256 monitors')
  await expect(fullTCP.getByRole('button', { name: 'Create monitor' })).toHaveCount(0)
  const udp = page.getByRole('region', { name: 'UDP', exact: true })
  await expect(udp).toContainText('Needs 64 monitors')
  await expect(udp.getByRole('button', { name: 'Create monitor' })).toHaveCount(0)
  // Exactly 16 monitors are still listed, each with its own button.
  const selected = page.getByRole('region', { name: 'Selected TCP ports', exact: true })
  await expect(selected.getByRole('button', { name: 'Create monitor' })).toHaveCount(16)
  // As the report packs them, the blocks of at least 4,096 addresses come
  // first, a monitor each, and the smaller ones share the last monitor.
  const listed = selected.locator('.perimeter-suggestion-list > li')
  await expect(listed.first()).toContainText('Monitor 1 of 16')
  await expect(listed.first().locator('code')).toHaveText(['198.18.16.0/20'])
  await expect(listed.first()).toContainText('4,096 addresses')
  await expect(listed.last()).toContainText('Monitor 16 of 16')
  await expect(listed.last().locator('code')).toHaveText(['198.18.0.128/25', '198.18.1.0/24', '198.18.2.0/23', '198.18.4.0/22', '198.18.8.0/21'])
  await expect(listed.last()).toContainText('3,968 addresses')
  await expect(page.getByRole('region', { name: 'Any TCP uncovered blocks' })).toContainText('9 uncovered blocks')
  await noHorizontalPageOverflow(page)
})

test('an IPv6 range shows monitored counts and no suggestions, and an excluded range suggests nothing', async ({ page }) => {
  await mockConsole(page)
  await page.goto('/perimeter/ranges/range-3')
  await expect(page.getByRole('heading', { level: 1, name: '2001:db8:100::/48' })).toBeVisible()
  const coverage = page.getByRole('region', { name: 'Range coverage' })
  await expect(coverage.locator('.summary-card').filter({ hasText: 'Family' })).toContainText('IPv6')
  await expect(coverage.locator('.summary-card').filter({ hasText: 'Any TCP monitored' })).toContainText('256')
  await expect(coverage).not.toContainText('%')
  await expect(page.getByRole('note').filter({ hasText: 'a /112, so EdgeWatch cannot sweep an IPv6 prefix' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Suggested monitors' })).toHaveCount(0)
  await expect(page.getByRole('button', { name: 'Create monitor' })).toHaveCount(0)
  const anyTCP = page.getByRole('region', { name: 'Any TCP uncovered blocks' })
  await expect(anyTCP).toContainText('72 uncovered blocks')
  await expect(anyTCP.locator('code').first()).toHaveText('2001:db8:100::100/120')
  await expect(anyTCP.locator('code')).toHaveCount(24)
  await anyTCP.getByRole('button', { name: 'Show all 72 blocks' }).click()
  await expect(anyTCP.locator('code')).toHaveCount(72)
  await expect(anyTCP.locator('code').last()).toHaveText('2001:db8:100:8000::/49')
  await noHorizontalPageOverflow(page)

  await page.goto('/perimeter/ranges/range-4')
  await expect(page.getByRole('heading', { level: 1, name: '192.0.2.128/30' })).toBeVisible()
  await expect(page.getByRole('region', { name: 'Range coverage' }).locator('.summary-card').first()).toContainText('4 in scanner.target_exclusions')
  await expect(page.getByText('All addresses excluded: there is nothing to suggest.')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Create monitor' })).toHaveCount(0)
  await noHorizontalPageOverflow(page)

  await page.goto('/perimeter/ranges/range-unknown')
  await expect(page.getByText('This range could not be found. It may have been removed.')).toBeVisible()
  await expect(page.getByRole('button', { name: /Retry/ })).toHaveCount(0)
})

test('an administrator declares ranges: refused lines are reported on their lines and nothing is saved', async ({ page }) => {
  const controls = await mockConsole(page, 'administrator', { emptyPerimeter: true })
  await page.goto('/perimeter')
  await expect(page.getByRole('heading', { name: 'Declare the perimeter' })).toBeVisible()
  await expect(page.getByText('No ranges are declared for this business unit yet.')).toBeVisible()
  await expect(page.getByRole('region', { name: 'Perimeter summary' })).toHaveCount(0)
  const recipe = page.getByRole('link', { name: /Seed the perimeter from an ASN/ }).first()
  await expect(recipe).toHaveAttribute('href', docsURL)
  await expect(recipe).toHaveAttribute('target', '_blank')
  await noHorizontalPageOverflow(page)

  const ranges = page.getByRole('textbox', { name: 'Ranges, one per line' })
  await ranges.fill('203.0.113.0/24   DC1 edge\n\nexample.com\n10.0.0.0/7\n198.51.100.7')
  await expect(page.getByText('4 of at most 256 entries')).toBeVisible()
  await page.getByRole('button', { name: 'Declare owned ranges' }).click()
  await expect(page.getByRole('alert').filter({ hasText: 'Nothing was saved' })).toHaveText('Nothing was saved: 2 lines were refused. Fix them and declare again.')
  // The server numbers the entries it was sent; the page maps them back to
  // their textarea lines, past the blank one.
  await expect(page.getByRole('list', { name: 'Refused lines' }).getByRole('listitem')).toHaveText([
    'Line 3 example.com: not an IP address or CIDR prefix',
    'Line 4 10.0.0.0/7: IPv4 prefixes must be /8 or longer',
  ])
  await expect(ranges).toHaveAttribute('aria-invalid', 'true')
  expect(controls.payloads['perimeter-declare']).toEqual([{ entries: [
    { kind: 'prefix', value: '203.0.113.0/24', label: 'DC1 edge' },
    { kind: 'prefix', value: 'example.com' },
    { kind: 'prefix', value: '10.0.0.0/7' },
    { kind: 'prefix', value: '198.51.100.7' },
  ] }])
  await expect(page.getByRole('heading', { name: 'Declare the perimeter' })).toBeVisible()
  await expect(ranges).toHaveValue(/example\.com/)
  await noHorizontalPageOverflow(page)

  // A repeat under the same kind is skipped, not refused.
  await ranges.fill('203.0.113.0/24 DC1 edge\n198.51.100.7\n203.0.113.0/24')
  await page.getByRole('button', { name: 'Declare owned ranges' }).click()
  await expect(page.getByRole('status').filter({ hasText: 'Declared 2 new ranges.' })).toHaveText('Declared 2 new ranges. 1 already declared entry was skipped.')
  await expect(ranges).toHaveValue('')
  await expect(page.getByRole('heading', { name: 'Declared ranges', exact: true })).toBeVisible()
  await expect(rangeEntry(page, '203.0.113.0/24')).toContainText('DC1 edge')
  await expect(rangeEntry(page, '198.51.100.7/32').locator('.perimeter-coverage').nth(1)).toContainText('0 of 1 address')
  await expect(summaryCard(page, 'Declared IPv4')).toContainText('257')

  // A value already declared under the other kind is refused.
  await page.getByRole('radio', { name: /Authorized/ }).check()
  await ranges.fill('203.0.113.0/24')
  await page.getByRole('button', { name: 'Declare authorized ranges' }).click()
  await expect(page.getByRole('list', { name: 'Refused lines' }).getByRole('listitem')).toHaveText(['Line 1 203.0.113.0/24: already declared as owned'])
  expect(controls.payloads['perimeter-declare']?.at(-1)).toEqual({ entries: [{ kind: 'authorized', value: '203.0.113.0/24' }] })
  await expect(rangeEntry(page, '203.0.113.0/24')).toContainText('Owned')
  await noHorizontalPageOverflow(page)
})

test('removing a range asks for confirmation and keeps the range when the removal fails', async ({ page }) => {
  const controls = await mockConsole(page)
  await page.goto('/perimeter')
  const lab = rangeEntry(page, '192.0.2.128/30')
  await expect(lab).toBeVisible()

  const removeLab = page.getByRole('button', { name: 'Remove 192.0.2.128/30' })
  await removeLab.click()
  const dialog = page.getByRole('dialog', { name: 'Remove this range?' })
  await expect(dialog).toContainText('Remove owned range 192.0.2.128/30 (Lab) from the perimeter?')
  await noHorizontalPageOverflow(page)
  await dialog.getByRole('button', { name: 'Cancel' }).click()
  await expect(dialog).toHaveCount(0)
  expect(controls.calls['perimeter-remove'] ?? 0).toBe(0)
  // Cancel returns focus to the button that opened the dialog.
  await expect(removeLab).toBeFocused()

  // The dialog stays open with the reason, and the range is kept.
  controls.failNext('perimeter-remove')
  await page.getByRole('button', { name: 'Remove 192.0.2.128/30' }).click()
  await dialog.getByRole('button', { name: 'Remove range' }).click()
  await expect(dialog).toContainText('The range was kept because the audit record could not be written. Try again later.')
  expect(controls.calls['perimeter-remove']).toBe(1)
  await dialog.getByRole('button', { name: 'Cancel' }).click()
  await expect(dialog).toHaveCount(0)
  await expect(lab).toBeVisible()

  await page.getByRole('button', { name: 'Remove 192.0.2.128/30' }).click()
  await expect(dialog).not.toContainText('audit record')
  await dialog.getByRole('button', { name: 'Remove range' }).click()
  await expect(dialog).toHaveCount(0)
  const removed = page.getByRole('status').filter({ hasText: 'Removed 192.0.2.128/30 from the perimeter.' })
  await expect(removed).toBeVisible()
  await expect(lab).toHaveCount(0)
  // The removed range's row and its button are gone; focus stays on the
  // notice instead of falling to the document body.
  await expect(removed).toBeFocused()
  expect(await page.evaluate(() => document.activeElement?.tagName)).not.toBe('BODY')
  await expect(summaryCard(page, 'Declared IPv4')).toContainText('65,792')
  await expect(summaryCard(page, 'Declared IPv4')).not.toContainText('excluded')
  expect(controls.payloads['perimeter-remove']).toEqual(['range-4', 'range-4'])
})

test('Create monitor opens the guided setup with a one-time prefill and creates nothing by itself', async ({ page }) => {
  const controls = await mockConsole(page)
  await page.goto('/perimeter/ranges/range-1')
  await page.getByRole('region', { name: 'UDP', exact: true }).getByRole('button', { name: 'Create monitor' }).click()

  await expect(page).toHaveURL(/\/jobs\/new$/)
  await expect(page.getByRole('heading', { name: 'Choose targets' })).toBeVisible()
  await expect(page.getByText('Prefilled from Perimeter (203.0.113.0/24). A declared range is not an authorization: confirm you may scan these addresses.')).toBeVisible()
  await expect(page.getByText('Only add targets that you are authorized to scan.')).toBeVisible()
  await expect(page.getByLabel('Monitor name')).toHaveValue('Perimeter 203.0.113.0/24 · UDP')
  await expect(page.getByRole('textbox', { name: 'Target 1', exact: true })).toHaveValue('203.0.113.0/24')
  await expect(page.getByRole('textbox', { name: 'Target 2', exact: true })).toHaveCount(0)
  await expect(page.getByRole('spinbutton', { name: /Maximum expanded hosts/ })).toHaveValue('256')
  // The router state is cleared once the prefill is applied.
  await expect.poll(() => page.evaluate(() => (window.history.state as { usr?: unknown } | null)?.usr ?? null)).toBeNull()
  await noHorizontalPageOverflow(page)

  // The protocol settings are the suggestion's: UDP only, its ports as sent.
  await page.getByRole('button', { name: 'Continue to coverage' }).click()
  await expect(page.getByRole('checkbox', { name: /Include TCP/ })).not.toBeChecked()
  await expect(page.getByRole('checkbox', { name: /Include UDP/ })).toBeChecked()
  await expect(page.getByRole('textbox', { name: /UDP ports/ })).toHaveValue('53,123,161,500,1194,4500')
  await page.getByRole('button', { name: 'Continue to schedule' }).click()
  await page.getByRole('button', { name: 'Use no alerts' }).click()
  await page.getByRole('button', { name: 'Review monitor' }).click()
  await expect(page.locator('.estimate-grid')).toBeVisible()
  expect(controls.calls['job-create'] ?? 0).toBe(0)
  const preview = controls.payloads['job-preview']?.at(-1) as Record<string, unknown>
  expect(preview).toMatchObject({ name: 'Perimeter 203.0.113.0/24 · UDP', targets: ['203.0.113.0/24'], max_expanded_hosts: 256, allow_high_cost: false })
  expect(preview).not.toHaveProperty('tcp')
  expect(preview.udp).toEqual({ engine: 'nmap', ports: '53,123,161,500,1194,4500', service_detection: true })

  // A person saves the monitor through the job API; nothing starts.
  await page.getByRole('button', { name: 'Create without starting' }).click()
  await expect(page).toHaveURL(/\/jobs\/job-created$/)
  expect(controls.calls['job-create']).toBe(1)
  expect(controls.calls['job-run'] ?? 0).toBe(0)
  const created = controls.payloads['job-create']?.[0] as Record<string, unknown>
  expect(created).toMatchObject({ name: 'Perimeter 203.0.113.0/24 · UDP', targets: ['203.0.113.0/24'], allow_high_cost: false, udp: { engine: 'nmap', ports: '53,123,161,500,1194,4500', service_detection: true } })
  expect(created).not.toHaveProperty('tcp')
})

test('a prefilled monitor is guarded like any draft, and a reload does not apply the prefill again', async ({ page }) => {
  const controls = await mockConsole(page)
  await page.goto('/perimeter/ranges/range-2')
  await page.getByRole('region', { name: 'Selected TCP ports', exact: true }).getByRole('button', { name: 'Create monitor' }).last().click()
  await expect(page).toHaveURL(/\/jobs\/new$/)
  await expect(page.getByText('Prefilled from Perimeter (198.18.0.0/16).', { exact: false })).toBeVisible()
  await expect(page.getByLabel('Monitor name')).toHaveValue('Perimeter 198.18.0.128/25 +4 more · selected TCP ports')
  const targets = ['198.18.0.128/25', '198.18.1.0/24', '198.18.2.0/23', '198.18.4.0/22', '198.18.8.0/21']
  for (const [index, target] of targets.entries()) await expect(page.getByRole('textbox', { name: `Target ${index + 1}`, exact: true })).toHaveValue(target)
  await expect(page.getByRole('textbox', { name: `Target ${targets.length + 1}`, exact: true })).toHaveCount(0)
  await expect(page.getByRole('spinbutton', { name: /Maximum expanded hosts/ })).toHaveValue('3968')

  // The prefill marked the draft dirty, so leaving asks first.
  await openNavigation(page)
  await page.locator('#primary-navigation').getByRole('link', { name: 'Jobs', exact: true }).click()
  const discard = page.getByRole('dialog', { name: 'Discard monitor changes?' })
  await expect(discard).toBeVisible()
  await discard.getByRole('button', { name: 'Cancel' }).click()
  await expect(page).toHaveURL(/\/jobs\/new$/)
  await expect(page.getByLabel('Monitor name')).toHaveValue('Perimeter 198.18.0.128/25 +4 more · selected TCP ports')

  // The draft lives in memory, and the cleared router state cannot apply
  // the prefill again.
  page.once('dialog', dialog => void dialog.accept())
  await page.reload()
  await expect(page.getByRole('heading', { name: 'Choose targets' })).toBeVisible()
  await expect(page.getByLabel('Monitor name')).toHaveValue('')
  await expect(page.getByText(/Prefilled from Perimeter/)).toHaveCount(0)
  expect(controls.calls['job-create'] ?? 0).toBe(0)
  expect(controls.calls['job-preview'] ?? 0).toBe(0)
})
