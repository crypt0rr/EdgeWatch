import { expect, test, type Page } from '@playwright/test'
import { mockConsole } from './mock-console'

const review0 = { status: 'needs_review', reviewer_label: null, reviewed_at: null, note: '', follow_up_at: null, revision: 0 }
const pagination = (offset: number, total: number, count: number) => ({ limit: 20, offset, total, has_more: offset + count < total, next_offset: offset + count < total ? offset + 20 : null })

function incident(index: number, review = review0, occurrenceToken = `occurrence-${index}`) {
  const opened = new Date(Date.UTC(2026, 0, 1, 0, index)).toISOString()
  return {
    job_id: 'job-1', job: 'Production perimeter monitoring', occurrence_token: occurrenceToken,
    opening_time_known: true, view_status: review.status === 'investigating' ? 'investigating' : 'needs_review',
    opening_scan_available: index !== 20,
    incident: {
      change: { key: `port|192.0.2.${index + 1}|tcp|443`, kind: 'port', target: `192.0.2.${index + 1}`, protocol: 'tcp', port: 443, old: 'closed', new: 'open', severity: index % 3 === 0 ? 'critical' : 'warning' },
      scan_id: index === 20 ? 'scan-pruned' : 'scan-1', opened_at: opened, last_seen_at: opened, recovery_count: 0,
    },
    review,
    observation_uncertainty: { status: 'unknown', reason: 'no_newer_observation' },
  }
}

async function installInboxAPI(page: Page, conflict: 'revision-move' | 'occurrence-closed' | 'lookup-error' = 'revision-move', total = 21) {
  let currentReview = review0
  let reviewWrites = 0
  let occurrenceChanged = false
  let replacedOccurrence = ''
  const writes: Record<string, unknown>[] = []
  await page.route(url => new URL(url).pathname === '/api/v1/incidents', async route => {
    const url = new URL(route.request().url())
    const offset = Number(url.searchParams.get('offset')) || 0
    const limit = Number(url.searchParams.get('limit')) || 20
    const token = url.searchParams.get('occurrence_token')
    const all = Array.from({ length: total }, (_, index) => {
      const token = `occurrence-${index}`
      return incident(index, index === 35 ? currentReview : review0, occurrenceChanged && token === replacedOccurrence ? 'occurrence-replacement' : token)
    })
    if (token) {
      if (conflict === 'lookup-error' && token === 'occurrence-35') {
        await route.fulfill({ status: 503, json: { error: { code: 'service_unavailable', message: 'lookup unavailable', details: {} } } })
        return
      }
      const selected = all.filter(row => row.occurrence_token === token).slice(0, limit)
      await route.fulfill({ json: { incidents: selected, pagination: pagination(0, selected.length, selected.length), truncated: false, active_count: total } })
      return
    }
    const view = url.searchParams.get('view') ?? 'all_active'
    const byView = view === 'needs_review' ? all.filter(row => row.review.status === 'needs_review')
      : view === 'investigating' ? all.filter(row => row.review.status === 'investigating')
        : all
    const selected = byView.slice(offset, offset + limit)
    await route.fulfill({ json: { incidents: selected, pagination: pagination(offset, byView.length, selected.length), truncated: false, active_count: total } })
  })
  await page.route('**/api/v1/jobs/job-1/incidents/review', async route => {
    if (route.request().method() !== 'PUT') return route.fallback()
    const payload = route.request().postDataJSON() as Record<string, unknown>
    writes.push(payload)
    if (reviewWrites++ === 0) {
      if (conflict === 'revision-move') {
        currentReview = { status: 'investigating', reviewer_label: 'Another reviewer', reviewed_at: '2026-10-11T12:00:00Z', note: 'Saved by another reviewer', follow_up_at: null, revision: 2 }
        await route.fulfill({ status: 409, json: { error: { code: 'incident_review_revision_conflict', message: 'review changed', details: {} } } })
      } else if (conflict === 'lookup-error') {
        currentReview = { status: 'investigating', reviewer_label: 'Another reviewer', reviewed_at: '2026-10-11T12:00:00Z', note: 'Saved by another reviewer', follow_up_at: null, revision: 2 }
        await route.fulfill({ status: 409, json: { error: { code: 'incident_review_revision_conflict', message: 'review changed', details: {} } } })
      } else {
        occurrenceChanged = true
        replacedOccurrence = String(payload.occurrence_token)
        await route.fulfill({ status: 409, json: { error: { code: 'incident_occurrence_conflict', message: 'occurrence changed', details: {} } } })
      }
      return
    }
    currentReview = { status: payload.status, reviewer_label: 'Administrator', reviewed_at: '2026-10-11T12:05:00Z', note: payload.note, follow_up_at: payload.follow_up_at, revision: 3 }
    await route.fulfill({ json: currentReview })
  })
  return { writes }
}

async function expectNoHorizontalScroll(page: Page) {
  const dimensions = await page.evaluate(() => ({ client: document.documentElement.clientWidth, scroll: document.documentElement.scrollWidth }))
  expect(dimensions.scroll).toBeLessThanOrEqual(dimensions.client)
}

test.describe('investigation inbox browser behavior', () => {
  test('direct URLs, reload, and close preserve filters and page while pruned evidence stays unavailable', async ({ page }, testInfo) => {
    test.skip(testInfo.project.name !== 'desktop', 'Direct URL behavior is checked once in the desktop browser.')
    await mockConsole(page, 'administrator')
    await installInboxAPI(page)
    await page.setViewportSize({ width: 1280, height: 900 })
    const original = '/incidents?view=all_active&job_id=job-1&severity=warning&kind=port&offset=20&occurrence=occurrence-20'
    await page.goto(original)

    const panel = page.getByRole('complementary', { name: 'Evidence and review' })
    await expect(panel).toBeVisible()
    await expect(page.getByText('21–21 of 21')).toBeVisible()
    await expect(panel.getByRole('link', { name: /Open job details/ })).toHaveAttribute('target', '_blank')
    await expect(panel.getByRole('link', { name: /Open baseline evidence/ })).toBeVisible()
    await expect(panel.getByRole('link', { name: /Open source scan/ })).toHaveCount(0)
    await expect(panel.getByText('Opening scan scan-pruned is no longer available.')).toBeVisible()
    await page.screenshot({ path: '/tmp/edgewatch-inbox-desktop.png', fullPage: true })

    await page.reload()
    await expect(page.getByRole('complementary', { name: 'Evidence and review' })).toBeVisible()
    await expect(page).toHaveURL(/view=all_active.*job_id=job-1.*severity=warning.*kind=port.*offset=20.*occurrence=occurrence-20/)
    await page.getByRole('button', { name: 'Close evidence panel' }).click()
    await expect(page.getByRole('complementary', { name: 'Evidence and review' })).toHaveCount(0)
    await expect(page).toHaveURL(/view=all_active.*job_id=job-1.*severity=warning.*kind=port.*offset=20/)
    await expect(page.getByText('21–21 of 21')).toBeVisible()
  })

  test('filters normalize invalid values and an inaccessible job yields no matching data', async ({ page }, testInfo) => {
    test.skip(testInfo.project.name !== 'desktop', 'Filter normalization is checked once in the desktop browser.')
    await mockConsole(page, 'administrator')
    await page.route(url => new URL(url).pathname === '/api/v1/incidents', async route => {
      const url = new URL(route.request().url())
      if (url.searchParams.get('limit') === '1') {
        await route.fulfill({ json: { incidents: [], pagination: { limit: 1, offset: 0, total: 0, has_more: false, next_offset: null }, truncated: false, active_count: 21 } })
        return
      }
      expect(url.searchParams.get('view')).toBe('needs_review')
      expect(url.searchParams.get('severity')).toBeNull()
      expect(url.searchParams.get('kind')).toBeNull()
      expect(url.searchParams.get('occurrence_token')).toBeNull()
      await route.fulfill({ json: { incidents: [], pagination: { limit: 20, offset: 0, total: 0, has_more: false, next_offset: null }, truncated: false, active_count: 21 } })
    })
    await page.goto('/incidents?view=unknown&job_id=foreign-job&severity=urgent&kind=bad&offset=-1&lookup_occurrence=orphan-token')
    await expect(page.getByRole('heading', { name: 'No matching incidents' })).toBeVisible()
    await expect(page.getByRole('combobox', { name: 'Filter by review view' })).toHaveValue('needs_review')
    await expect(page.getByRole('option', { name: 'Unavailable or inaccessible job' })).toBeAttached()
    await expect(page).toHaveURL(/view=needs_review.*job_id=foreign-job.*offset=0/)
    await expect(page).not.toHaveURL(/lookup_occurrence=/)
    await expect(page.locator('.incident-inbox-active-count')).toContainText('21')
  })

  test('keyboard operation and responsive cards keep evidence usable on mobile widths', async ({ page }, testInfo) => {
    test.skip(testInfo.project.name !== 'desktop', 'This test controls both mobile and desktop viewport sizes.')
    await mockConsole(page, 'administrator')
    await installInboxAPI(page)
    for (const width of [390, 820, 1280]) {
      await page.setViewportSize({ width, height: 820 })
      await page.goto('/incidents')
      if (width <= 900) {
        await expect(page.locator('.inbox-desktop-table')).toBeHidden()
        await expect(page.locator('.inbox-mobile-list')).toBeVisible()
      } else {
        await expect(page.locator('.inbox-desktop-table')).toBeVisible()
      }
      await expectNoHorizontalScroll(page)
      const opener = page.locator('.inbox-mobile-list').getByRole('button', { name: 'Review evidence' }).first()
      if (width > 900) await page.getByRole('button', { name: 'Review evidence' }).first().focus()
      else await opener.focus()
      await page.keyboard.press('Enter')
      const panel = page.getByRole('complementary', { name: 'Evidence and review' })
      await expect(panel).toBeVisible()
      await expect(panel).toBeFocused()
      await page.screenshot({ path: `/tmp/edgewatch-inbox-${width}.png`, fullPage: true })
      const close = page.getByRole('button', { name: 'Close evidence panel' })
      await close.focus()
      await page.keyboard.press('Enter')
      await expect(panel).toHaveCount(0)
      if (width <= 900) await expect(opener).toBeFocused()
      await expectNoHorizontalScroll(page)
    }
  })

  test('revision conflicts find a moved occurrence by token and preserve the draft', async ({ page }, testInfo) => {
    test.skip(testInfo.project.name !== 'desktop', 'Conflict refresh is checked once in the desktop browser.')
    await mockConsole(page, 'administrator')
    const { writes } = await installInboxAPI(page, 'revision-move', 41)
    await page.goto('/incidents?view=needs_review&job_id=job-1&offset=20&occurrence=occurrence-35')
    const panel = page.getByRole('complementary', { name: 'Evidence and review' })
    await expect(panel).toBeVisible()
    await panel.getByRole('textbox', { name: 'Shared reviewer note' }).fill('My draft stays here')
    await panel.getByLabel('Review status').selectOption('investigating')
    await panel.getByRole('button', { name: 'Save review' }).click()
    await expect(panel.locator('.incident-review-conflict')).toContainText('Another reviewer')
    await expect(panel.getByRole('textbox', { name: 'Shared reviewer note' })).toHaveValue('My draft stays here')
    await expect(panel.locator('blockquote')).toHaveText('Saved by another reviewer')
    await expect(panel.getByRole('button', { name: 'Show refreshed occurrence' })).toBeVisible()
    await expect(panel.getByRole('button', { name: 'Save draft to latest review' })).toBeDisabled()
    await panel.getByRole('button', { name: 'Show refreshed occurrence' }).click()
    await expect(page).toHaveURL(/view=all_active.*job_id=job-1.*lookup_occurrence=occurrence-35.*occurrence=occurrence-35/)
    await expect(page.getByText('Showing the exact refreshed occurrence')).toBeVisible()
    await expect(panel.getByRole('button', { name: 'Save draft to latest review' })).toBeEnabled()
    await panel.getByRole('button', { name: 'Save draft to latest review' }).click()
    await expect.poll(() => writes.length).toBe(2)
    expect(writes[0]).toMatchObject({ occurrence_token: 'occurrence-35', expected_revision: 0, note: 'My draft stays here' })
    expect(writes[1]).toMatchObject({ occurrence_token: 'occurrence-35', expected_revision: 2, note: 'My draft stays here', status: 'investigating' })
    await expect(panel.getByRole('status')).toContainText('Review saved')
    await page.getByRole('combobox', { name: 'Filter by review view' }).selectOption('needs_review')
    await expect(page.getByRole('complementary', { name: 'Evidence and review' })).toHaveCount(0)
    await expect(page).not.toHaveURL(/lookup_occurrence=/)
    await expect(page).not.toHaveURL(/occurrence=/)
  })

  test('closed or replaced occurrences retain drafts and block stale retries', async ({ page }, testInfo) => {
    test.skip(testInfo.project.name !== 'desktop', 'Occurrence replacement is checked once in the desktop browser.')
    await mockConsole(page, 'administrator')
    const { writes } = await installInboxAPI(page, 'occurrence-closed')
    await page.goto('/incidents?view=needs_review&occurrence=occurrence-0')
    const panel = page.getByRole('complementary', { name: 'Evidence and review' })
    await expect(panel).toBeVisible()
    await panel.getByRole('textbox', { name: 'Shared reviewer note' }).fill('Keep this draft after replacement')
    await panel.getByRole('button', { name: 'Save review' }).click()
    await expect(panel.getByText('This occurrence is no longer active. Your draft is kept for reference, but it cannot be saved because the active occurrence has changed or closed.')).toBeVisible()
    await expect(panel.getByRole('textbox', { name: 'Shared reviewer note' })).toHaveValue('Keep this draft after replacement')
    await expect(panel.getByRole('button', { name: 'Save review' })).toBeDisabled()
    expect(writes).toHaveLength(1)
  })

  test('an exact lookup error remains distinct from an inactive occurrence and retains the draft', async ({ page }, testInfo) => {
    test.skip(testInfo.project.name !== 'desktop', 'Lookup failure is checked once in the desktop browser.')
    await mockConsole(page, 'administrator')
    const { writes } = await installInboxAPI(page, 'lookup-error', 41)
    await page.goto('/incidents?view=needs_review&job_id=job-1&offset=20&occurrence=occurrence-35')
    const panel = page.getByRole('complementary', { name: 'Evidence and review' })
    await expect(panel).toBeVisible()
    await panel.getByRole('textbox', { name: 'Shared reviewer note' }).fill('Keep this draft when lookup fails')
    await panel.getByRole('button', { name: 'Save review' }).click()
    await expect(panel.getByText('Could not verify the latest active occurrence. Your draft is kept, and saving is disabled until the exact lookup succeeds.')).toBeVisible()
    await expect(panel.getByText(/This occurrence is no longer active/)).toHaveCount(0)
    await expect(panel.getByRole('textbox', { name: 'Shared reviewer note' })).toHaveValue('Keep this draft when lookup fails')
    await expect(panel.getByRole('button', { name: 'Save review' })).toBeDisabled()
    expect(writes).toHaveLength(1)
  })
})
