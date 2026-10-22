import { expect, test, type Page } from '@playwright/test'
import { bootstrapAdministrator, callAPI, createHarness, navigateFromShell } from './real-stack-harness'

// The Perimeter page against the real daemon. The harness provides only a
// fake Nmap, and no scan runs here: the monitor is saved without starting,
// on a schedule that cannot fire during the test, so its coverage comes from
// its configuration alone.

const range = '192.0.2.0/24'
const monitorName = `Perimeter ${range} · selected TCP ports`

function summaryCard(page: Page, label: string) {
  return page.getByRole('region', { name: 'Perimeter summary' }).locator('.summary-card').filter({ hasText: label })
}

function rangeRow(page: Page) {
  return page.getByRole('region', { name: 'Declared ranges table' }).getByRole('row').filter({ has: page.getByRole('link', { name: range, exact: true }) })
}

/** Expects the summary's covered share and count of each bucket: none or all of the range's 256 addresses. */
async function expectSummary(page: Page, covered: { full: 0 | 256; any: 0 | 256; udp: 0 | 256 }) {
  for (const [label, count] of [['Full TCP covered', covered.full], ['Any TCP covered', covered.any], ['UDP covered', covered.udp]] as const) {
    await expect(summaryCard(page, label).locator('.perimeter-coverage-value')).toHaveText(count === 256 ? '100%' : '0%')
    await expect(summaryCard(page, label).locator('.perimeter-coverage-count')).toHaveText(`${count} of 256 addresses`)
  }
}

test('a monitor created from a perimeter suggestion covers the range until it is paused', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'The controlled real-stack lifecycle runs once on desktop.')
  test.setTimeout(180_000)
  const harness = await createHarness({ scannerMode: 'stable' })
  try {
    const csrf = await bootstrapAdministrator(page, harness)

    // Declare the range as owned: no monitor covers any of it yet.
    await navigateFromShell(page, 'Perimeter')
    await expect(page.getByRole('heading', { name: 'Declare the perimeter' })).toBeVisible()
    await page.getByRole('textbox', { name: 'Ranges, one per line' }).fill(`${range} Documentation edge`)
    await expect(page.getByRole('radio', { name: /Owned/ })).toBeChecked()
    await page.getByRole('button', { name: 'Declare owned ranges' }).click()
    await expect(page.getByRole('status').filter({ hasText: 'Declared 1 new range.' })).toBeVisible()
    await expectSummary(page, { full: 0, any: 0, udp: 0 })
    await expect(rangeRow(page).locator('.perimeter-coverage-value')).toHaveText(['0%', '0%', '0%'])
    await expect(rangeRow(page)).toContainText('No monitors')
    const declared = await callAPI(page, '/perimeter', 'GET', csrf)
    expect(declared.status).toBe(200)
    expect(declared.body.ranges).toHaveLength(1)
    expect(declared.body.ranges[0]).toMatchObject({ kind: 'prefix', value: range, label: 'Documentation edge', family: 4, addresses: 256, excluded: 0, coverage: { full_tcp: 0, any_tcp: 0, udp: 0 } })
    expect(declared.body.monitors).toEqual([])

    // The range's suggestions are sized to the unit's default probe budget.
    await page.getByRole('link', { name: range, exact: true }).click()
    await expect(page.getByRole('heading', { level: 1, name: range })).toBeVisible()
    await expect(page.getByRole('region', { name: 'Full TCP', exact: true })).toContainText('Up to 305 addresses per monitor')
    await expect(page.getByRole('region', { name: 'UDP', exact: true })).toContainText('Up to 1,024 addresses per monitor')
    const selected = page.getByRole('region', { name: 'Selected TCP ports', exact: true })
    await expect(selected).toContainText('Up to 4,096 addresses per monitor')
    await expect(selected).toContainText('Monitor 1 of 1')
    await selected.getByRole('button', { name: 'Create monitor' }).click()

    // The guided setup holds the suggestion; a person reviews and saves it.
    await expect(page).toHaveURL(/\/jobs\/new$/)
    await expect(page.getByText(`Prefilled from Perimeter (${range}). A declared range is not an authorization: confirm you may scan these addresses.`)).toBeVisible()
    await expect(page.getByLabel('Monitor name')).toHaveValue(monitorName)
    await expect(page.getByRole('textbox', { name: 'Target 1', exact: true })).toHaveValue(range)
    await page.getByRole('button', { name: 'Continue to coverage' }).click()
    await expect(page.getByRole('radio', { name: /Selected TCP ports/ })).toBeChecked()
    await expect(page.getByRole('textbox', { name: /TCP ports/ })).toHaveValue('22,443')
    await page.getByRole('button', { name: 'Continue to schedule' }).click()
    // Keep the schedule enabled, since a monitor saved without one is
    // paused, on a cron that cannot fire during this test.
    await page.getByLabel('Five-field cron').fill('0 3 1 1 *')
    await expect(page.getByRole('checkbox', { name: /Schedule enabled/ })).toBeChecked()
    await page.getByRole('button', { name: 'Continue without alerts' }).click()
    await page.getByRole('button', { name: 'Review monitor' }).click()
    await expect(page.getByRole('heading', { name: 'Coverage and scan cost' })).toBeVisible()
    await expect(page.locator('.estimate-grid')).toBeVisible()
    const create = page.getByRole('button', { name: 'Create without starting' })
    await expect(create).toBeEnabled()
    await create.click()
    await expect(page).toHaveURL(/\/jobs\/[0-9a-f-]+$/i)
    await expect(page.getByRole('heading', { level: 1, name: monitorName })).toBeVisible()
    const jobID = new URL(page.url()).pathname.split('/').pop()!

    const saved = await callAPI(page, `/jobs/${jobID}`, 'GET', csrf)
    expect(saved.status).toBe(200)
    expect(saved.body.enabled).toBe(true)
    expect(saved.body.job).toMatchObject({ name: monitorName, schedule: '0 3 1 1 *', targets: [range], max_expanded_hosts: 256, allow_high_cost: false, tcp: { engine: 'nmap', ports: '22,443', mode: 'connect', service_detection: false } })
    expect(saved.body.job.udp ?? null).toBeNull()

    // Its configuration covers every address on any TCP port. A new monitor
    // is unproven until its first successful scan, but not stale before its
    // first scheduled run is due.
    await navigateFromShell(page, 'Perimeter')
    await expectSummary(page, { full: 0, any: 256, udp: 0 })
    await expect(rangeRow(page).locator('.perimeter-coverage-value')).toHaveText(['0%', '100%', '0%'])
    await expect(rangeRow(page).getByRole('list', { name: `Monitors of ${range}` }).getByRole('listitem')).toHaveText(['Covering 1', 'Not proven 1'])
    await expect(page.getByRole('region', { name: 'Monitors that cannot scan' })).toContainText('Every monitor that touches the perimeter can scan.')
    const covering = await callAPI(page, '/perimeter', 'GET', csrf)
    expect(covering.body.monitors).toEqual([expect.objectContaining({ job_id: jobID, name: monitorName, state: 'covering', reasons: [], stale: false, stalled_cycle: false, last_attempt_status: '', last_success_at: null, protocols: ['any_tcp'] })])
    expect(covering.body.totals).toMatchObject({ covered_full_tcp: 0, covered_any_tcp: 256, covered_udp: 0, cannot_scan_monitors: 0, unproven_monitors: 1, outside_targets: 0 })
    await expect(page.getByRole('region', { name: 'Coverage not proven' })).toContainText(monitorName)
    await expect(summaryCard(page, 'Coverage not proven').locator('strong')).toHaveText('1')

    // Pause the monitor from its job page.
    await page.getByRole('link', { name: range, exact: true }).click()
    const monitors = page.getByRole('region', { name: 'Monitors touching this range' })
    await expect(monitors).toContainText('Covering')
    await expect(page.getByRole('region', { name: 'Selected TCP ports', exact: true })).toContainText('No gaps to fill in this mode.')
    await monitors.getByRole('link', { name: monitorName }).click()
    await expect(page).toHaveURL(new RegExp(`/jobs/${jobID}$`))
    await page.getByRole('button', { name: 'Pause schedule' }).click()
    await expect(page.getByRole('button', { name: 'Resume schedule' })).toBeVisible()
    expect((await callAPI(page, `/jobs/${jobID}`, 'GET', csrf)).body.enabled).toBe(false)

    // A paused monitor cannot scan and covers nothing.
    await navigateFromShell(page, 'Perimeter')
    const cannotScan = page.getByRole('region', { name: 'Monitors that cannot scan' }).locator('.perimeter-monitor-list > li')
    await expect(cannotScan).toHaveCount(1)
    await expect(cannotScan).toContainText(monitorName)
    await expect(cannotScan).toContainText('Paused: scheduled runs do not start it.')
    await expect(summaryCard(page, 'Cannot scan').locator('strong')).toHaveText('1')
    await expectSummary(page, { full: 0, any: 0, udp: 0 })
    await expect(rangeRow(page).locator('.perimeter-coverage-value')).toHaveText(['0%', '0%', '0%'])
    await expect(rangeRow(page).getByRole('list', { name: `Monitors of ${range}` }).getByRole('listitem')).toHaveText(['Paused 1'])
    const paused = await callAPI(page, '/perimeter', 'GET', csrf)
    expect(paused.body.monitors).toEqual([expect.objectContaining({ job_id: jobID, state: 'paused', reasons: ['paused'], stale: false, stalled_cycle: false })])
    expect(paused.body.totals).toMatchObject({ covered_any_tcp: 0, cannot_scan_monitors: 1, unproven_monitors: 0 })

    // Nothing in this journey started a scan.
    const scans = await callAPI(page, `/jobs/${jobID}/scans?limit=10`, 'GET', csrf)
    expect(scans.status).toBe(200)
    expect(scans.body.scans).toEqual([])
  } finally {
    await harness.close()
  }
})
