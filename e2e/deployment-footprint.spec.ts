import { expect, test, type Page } from '@playwright/test'
import { mockConsole } from './mock-console'

// The footprint lays its counters out with container queries, which jsdom
// cannot check: render it with deployment-sized counts at phone, tablet and
// desktop widths and require every counter, label and status to stay inside
// its own cell.
const widths = [320, 390, 1000, 1280, 1440]

const largeTelemetry = { collected_at: '2026-10-08T18:03:00Z', database_bytes: 1.2 * 1024 ** 4, jobs: 120, scans: 987_654, host_observations: 12_345_678, effective_hosts: 1_234_567, events: 99_999_999, scan_cycles: 4000, outbox_pending: 12_345, outbox_retrying: 0, outbox_failed: 0 }

const degradedSandboxes = {
  scanner_sandbox: { mode: 'auto', state: 'unavailable', process_uid: 0, reason: 'the container does not grant SETUID, SETGID, KILL, which EdgeWatch needs to start and stop scanner processes as UID 65532; add them to cap_add', landlock: { mode: 'auto', state: 'enforced', abi: 6 }, seccomp: { state: 'unavailable', reason: 'nmap could not start with the seccomp filter: signal: bad system call' } },
  notification_sandbox: { mode: 'auto', state: 'unavailable', process_uid: 0, reason: 'a test notification process could not start as UID 65531: read SSL_CERT_FILE: permission denied', landlock: { mode: 'auto', state: 'unavailable', reason: 'the kernel does not provide Landlock' }, seccomp: { state: 'unavailable', reason: 'the seccomp filter applies only with Landlock' } },
}

const healthySandboxes = {
  scanner_sandbox: { mode: 'auto', state: 'enforced', uid: 65532, gid: 65532, process_uid: 65532, capabilities: ['NET_RAW', 'NET_ADMIN'], no_new_privileges: true, landlock: { mode: 'auto', state: 'enforced', abi: 6 }, seccomp: { state: 'enforced' } },
  notification_sandbox: { mode: 'auto', state: 'enforced', uid: 65531, gid: 65531, process_uid: 65531, no_new_privileges: true, landlock: { mode: 'auto', state: 'enforced', abi: 6 }, seccomp: { state: 'enforced' } },
}

async function showFootprint(page: Page, status: Record<string, unknown>) {
  await mockConsole(page, 'administrator')
  await page.route('**/api/v1/status', route => route.fulfill({ json: { configured: true, username: 'administrator', display_name: 'administrator', role: 'administrator', version: 'v0.30.1', notification_destinations: 1, notifications: { deployment: 0, managed: 1, active: 1, locked: 0, key_state: 'ready' }, retention: '2160h0m0s', max_concurrent_scans: 2, ...status } }))
  await page.goto('/')
  await expect(page.locator('.deployment-telemetry')).toBeVisible()
}

// Lists every footprint element whose text or box leaves the cell, strip, or
// element it belongs to, with enough detail to see which one at which width.
async function footprintOverflow(page: Page) {
  return page.locator('.deployment-telemetry').evaluate(panel => {
    const problems: string[] = []
    const strip = panel.querySelector('.telemetry-strip')!.getBoundingClientRect()
    for (const cell of panel.querySelectorAll<HTMLElement>('.telemetry-metric')) {
      const bounds = cell.getBoundingClientRect()
      for (const part of cell.querySelectorAll<HTMLElement>('dt, dd')) {
        const range = document.createRange()
        range.selectNodeContents(part)
        const text = range.getBoundingClientRect()
        if (text.right > bounds.right - 1 || text.left < bounds.left) problems.push(`${part.tagName} "${part.textContent}" leaves its cell (${Math.round(text.left)}-${Math.round(text.right)} in ${Math.round(bounds.left)}-${Math.round(bounds.right)})`)
      }
      const label = cell.querySelector('dt')!
      if (label.scrollWidth > label.clientWidth) problems.push(`label "${label.textContent}" is truncated`)
    }
    for (const element of panel.querySelectorAll<HTMLElement>('.isolation-name, .isolation-state, .isolation-layer, .isolation-capabilities, .isolation-reasons li')) {
      const box = element.getBoundingClientRect()
      if (box.right > strip.right + 0.5 || box.left < strip.left - 0.5) problems.push(`"${element.textContent}" leaves the strip`)
      if (element.scrollWidth > element.clientWidth + 1) problems.push(`"${element.textContent}" overflows itself`)
    }
    if (document.documentElement.scrollWidth > document.documentElement.clientWidth) problems.push('the page scrolls horizontally')
    return problems
  })
}

async function metricRows(page: Page) {
  const tops = await page.locator('.telemetry-metric').evaluateAll(cells => cells.map(cell => Math.round(cell.getBoundingClientRect().top)))
  return new Set(tops).size
}

test('the deployment footprint keeps large counters and sandbox details inside their cells', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'One browser renders every width.')
  await showFootprint(page, { telemetry: largeTelemetry, ...degradedSandboxes })
  await expect(page.locator('.telemetry-metric dd')).toHaveText(['1.2 TB', '1,234,567', '12,345,678', '987,654', '99,999,999', '12,345'])
  for (const width of widths) {
    await page.setViewportSize({ width, height: 1200 })
    expect(await footprintOverflow(page), `at ${width}px`).toEqual([])
  }
  // Six counters share one row on a desktop panel and two columns on a phone.
  await page.setViewportSize({ width: 1280, height: 1200 })
  expect(await metricRows(page)).toBe(1)
  await page.setViewportSize({ width: 390, height: 1200 })
  expect(await metricRows(page)).toBe(3)
})

test('the deployment footprint of a unit leaves no empty cell without the database size', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'One browser renders every width.')
  const { database_bytes: _database, ...unitTelemetry } = largeTelemetry
  await showFootprint(page, { telemetry: unitTelemetry, ...healthySandboxes })
  await expect(page.locator('.telemetry-metric dt')).toHaveText(['Effective hosts', 'Host observations', 'Retained scans', 'Events', 'Pending delivery'])
  for (const width of widths) {
    await page.setViewportSize({ width, height: 1200 })
    expect(await footprintOverflow(page), `at ${width}px`).toEqual([])
    // The last counter spans what is left of its row, so no cell is empty.
    const lastRow = await page.locator('.telemetry-metrics').evaluate(list => {
      const cells = Array.from(list.children).map(cell => cell.getBoundingClientRect())
      const last = cells[cells.length - 1]
      return { right: Math.round(last.right), listRight: Math.round(list.getBoundingClientRect().right) }
    })
    expect(Math.abs(lastRow.right - lastRow.listRight), `last counter ends at the strip edge at ${width}px`).toBeLessThanOrEqual(1)
  }
})
