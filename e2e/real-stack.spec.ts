import { expect, test } from '@playwright/test'
import { callAPI, clickScanNow, createHarness, navigateFromShell, password, waitForScan } from './real-stack-harness'

test('real EdgeWatch setup, baseline, change detection, and restart persistence', async ({ page }) => {
  test.setTimeout(150_000)
  const harness = await createHarness()
  try {
    await page.goto(harness.url)
    await expect(page.getByRole('heading', { name: 'Create your administrator' })).toBeVisible()
    const status = await callAPI(page, '/setup/status', 'GET')
    expect(status.status).toBe(200)
    await page.getByLabel('Setup token').fill(harness.setupToken())
    await page.locator('input[autocomplete="new-password"]').first().fill(password)
    await page.locator('input[autocomplete="new-password"]').nth(1).fill(password)
    await page.getByRole('button', { name: 'Create administrator' }).click()
    await expect(page.getByRole('heading', { name: 'Sign in to EdgeWatch' })).toBeVisible()

    await page.locator('input[autocomplete="current-password"]').fill(password)
    await page.getByRole('button', { name: 'Sign in' }).click()
    await expect(page.getByRole('heading', { name: /Good day, admin/ })).toBeVisible()
    const session = await callAPI(page, '/auth/session', 'GET')
    expect(session.status).toBe(200)
    const csrf = session.body.csrf_token as string

    await navigateFromShell(page, 'Jobs')
    await page.getByRole('button', { name: 'New job' }).click()
    await page.getByRole('link', { name: 'Open full editor' }).click()
    await expect(page.getByRole('heading', { name: 'Create a monitoring job' })).toBeVisible()
    await page.getByLabel('Job name').fill('real-stack-fixture')
    await page.getByLabel('Target 1').fill('127.0.0.1')
    // This fixture supplies a deterministic fake Nmap binary but no Naabu
    // binary, so opt into the Nmap-only engine explicitly.
    await page.getByLabel('TCP engine').selectOption('nmap')
    // The TCP engine label contains explanatory text mentioning "ports", so
    // a substring getByLabel('Ports') can resolve the engine <select> before
    // the actual port-range textbox. Target the textbox role explicitly.
    await page.getByRole('textbox', { name: /Ports Ranges/ }).first().fill('22-23')
    await page.getByLabel('Baseline samples').fill('1')
    await page.getByLabel('Five-field cron').fill('0 0 * * *')
    await page.getByLabel('Timezone').fill('UTC')
    await page.getByRole('button', { name: 'Create job' }).click()
    await expect(page).toHaveURL(/\/jobs$/)
    const jobCard = page.getByRole('link', { name: /real-stack-fixture/ }).first()
    const href = await jobCard.getAttribute('href')
    expect(href).toMatch(/^\/jobs\//)
    const jobID = href!.split('/').pop()!

    await jobCard.click()
    await expect(page.getByRole('heading', { name: 'real-stack-fixture' })).toBeVisible()
    await clickScanNow(page, jobID)
    await waitForScan(page, jobID, csrf, 1)
    const learned = await callAPI(page, `/jobs/${jobID}`, 'GET', csrf)
    expect(learned.body.baseline.status).toBe('complete')

    await clickScanNow(page, jobID)
    await waitForScan(page, jobID, csrf, 2)
    const incidents = await callAPI(page, '/incidents', 'GET', csrf)
    expect(incidents.status).toBe(200)
    expect(incidents.body.incidents.length).toBeGreaterThanOrEqual(2)
    expect(incidents.body.incidents.every((incident: any) => incident.job === 'real-stack-fixture')).toBe(true)

    // Runtime updates and concurrent saves must not replace an in-progress
    // editor draft. The real SSE connection invalidates the job query here.
    await page.goto(`${harness.url}/jobs/${jobID}/edit`)
    await expect(page.getByRole('heading', { name: 'Tune your monitoring job' })).toBeVisible()
    await page.getByLabel('Job name').fill('draft-name-that-must-survive')
    const current = await callAPI(page, `/jobs/${jobID}`, 'GET', csrf)
    const concurrent = await callAPI(page, `/jobs/${jobID}`, 'PUT', csrf, {
      ...current.body.job,
      revision: current.body.revision,
      enabled: current.body.enabled,
      schedule: '5 0 * * *',
      confirm_rebaseline: false,
    })
    expect(concurrent.status).toBe(200)
    await expect(page.getByRole('alert')).toContainText('saved elsewhere')
    await expect(page.getByLabel('Job name')).toHaveValue('draft-name-that-must-survive')

    await harness.stop()
    await harness.start()
    const persisted = await callAPI(page, '/jobs', 'GET', csrf)
    expect(persisted.status).toBe(200)
    expect(persisted.body.jobs.map((job: any) => job.job.name)).toContain('real-stack-fixture')
    // Reload after the process restart so the SPA establishes a fresh session
    // and EventSource connection instead of retaining a half-closed stream.
    await page.goto(`${harness.url}/`, { waitUntil: 'domcontentloaded' })
    await expect(page.getByRole('heading', { name: /Good day, admin/ })).toBeVisible({ timeout: 15_000 })
    await navigateFromShell(page, 'Incidents')
    await expect(page.getByRole('heading', { name: 'Incidents' })).toBeVisible()
    await expect(page.getByRole('row', { name: /real-stack-fixture/ }).or(page.getByRole('article', { name: /real-stack-fixture/ })).first()).toBeVisible()
  } finally {
    await harness.stop()
  }
})

test('real public status page is unauthenticated and follows publication state', async ({ page, browser }) => {
  test.setTimeout(150_000)
  const harness = await createHarness()
  const guestContext = await browser.newContext()
  const guest = await guestContext.newPage()
  try {
    // Confirm the anonymous surface is unavailable before an administrator
    // publishes anything. This exercises the real SPA special case and the
    // public API's disabled response, rather than a mocked route.
    await guest.goto(`${harness.url}/public`)
    await expect(guest.getByRole('heading', { name: 'Public status unavailable' })).toBeVisible()

    await page.goto(harness.url)
    await expect(page.getByRole('heading', { name: 'Create your administrator' })).toBeVisible()
    await page.getByLabel('Setup token').fill(harness.setupToken())
    await page.locator('input[autocomplete="new-password"]').first().fill(password)
    await page.locator('input[autocomplete="new-password"]').nth(1).fill(password)
    await page.getByRole('button', { name: 'Create administrator' }).click()
    await expect(page.getByRole('heading', { name: 'Sign in to EdgeWatch' })).toBeVisible()
    await page.locator('input[autocomplete="current-password"]').fill(password)
    await page.getByRole('button', { name: 'Sign in' }).click()
    await expect(page.getByRole('heading', { name: /Good day, admin/ })).toBeVisible()

    const session = await callAPI(page, '/auth/session', 'GET')
    expect(session.status).toBe(200)
    const csrf = session.body.csrf_token as string
    const created = await callAPI(page, '/jobs', 'POST', csrf, {
      name: 'public-real-stack',
      schedule: '0 0 * * *',
      timezone: 'UTC',
      targets: ['127.0.0.1'],
      tcp: { ports: '22', mode: 'connect', engine: 'nmap' },
      timeout: '1m',
      timing: 'balanced',
      baseline_samples: 1,
      change_confirmations: 1,
      max_expanded_hosts: 256,
    })
    expect(created.status).toBe(201)
    const jobID = created.body.id ?? created.body.job?.id
    expect(jobID).toBeTruthy()
    const run = await callAPI(page, `/jobs/${jobID}/run`, 'POST', csrf, {})
    expect(run.status).toBe(202)
    await waitForScan(page, jobID, csrf, 1)

    // Saves carry the loaded updated_at token; a save based on an older
    // token is rejected instead of overwriting a newer publication.
    const loaded = await callAPI(page, '/public-dashboard', 'GET', csrf)
    expect(loaded.status).toBe(200)
    const publish = await callAPI(page, '/public-dashboard', 'PUT', csrf, {
      enabled: true,
      title: 'Public fixture',
      introduction: 'Selected real-stack host',
      hosts: [{ job_id: jobID, address: '127.0.0.1' }],
      updated_at: loaded.body.updated_at,
    })
    expect(publish.status).toBe(200)

    // The guest context has no administrator cookies and can see only the
    // selected host projection. A host that was not selected must not appear.
    await guest.goto(`${harness.url}/public`)
    await expect(guest.getByRole('heading', { name: 'Public fixture' })).toBeVisible()
    await expect(guest.getByRole('heading', { name: '127.0.0.1' })).toBeVisible()
    await expect(guest.getByText('192.0.2.99')).not.toBeVisible()
    expect(await guest.context().cookies()).toEqual([])

    const disable = await callAPI(page, '/public-dashboard', 'PUT', csrf, {
      enabled: false,
      title: 'Public fixture',
      introduction: 'Selected real-stack host',
      hosts: [{ job_id: jobID, address: '127.0.0.1' }],
      updated_at: publish.body.updated_at,
    })
    expect(disable.status).toBe(200)
    const staleRepublish = await callAPI(page, '/public-dashboard', 'PUT', csrf, {
      enabled: true,
      title: 'Public fixture',
      introduction: 'Stale editor',
      hosts: [{ job_id: jobID, address: '127.0.0.1' }],
      updated_at: publish.body.updated_at,
    })
    expect(staleRepublish.status).toBe(409)
    await guest.reload()
    await expect(guest.getByRole('heading', { name: 'Public status unavailable' })).toBeVisible()
  } finally {
    await guestContext.close()
    await harness.stop()
  }
})
