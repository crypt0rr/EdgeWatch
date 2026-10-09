import { expect, test } from '@playwright/test'
import { bootstrapAdministrator, callAPI, createHarness, navigateFromShell, password, waitForScan, waitForScanStatus, type Harness } from './real-stack-harness'

async function openReview(page: import('@playwright/test').Page, harness: Harness, name: string, targets = ['127.0.0.1'], destinationName?: string) {
  await page.goto(`${harness.url}/jobs/new`)
  await page.getByLabel('Monitor name').fill(name)
  await page.getByLabel('Target 1').fill(targets[0])
  for (const [index, target] of targets.slice(1).entries()) {
    await page.getByRole('button', { name: 'Add target' }).click()
    await page.getByRole('textbox', { name: `Target ${index + 2}` }).fill(target)
  }
  await page.getByRole('button', { name: 'Continue to coverage' }).click()
  await page.getByRole('radio', { name: /Selected TCP ports/ }).check()
  await page.getByRole('textbox', { name: /TCP ports/ }).fill('22')
  await page.getByRole('button', { name: 'Continue to schedule' }).click()
  if (destinationName) await page.getByRole('checkbox', { name: new RegExp(destinationName) }).check()
  else await page.getByRole('button', { name: 'Continue without alerts' }).click()
  await page.getByRole('button', { name: 'Review monitor' }).click()
  await expect(page.getByRole('heading', { name: 'Coverage and scan cost' })).toBeVisible()
  await expect(page.locator('.estimate-grid')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Create and start first scan' })).toBeEnabled()
}

async function createAndStart(page: import('@playwright/test').Page, harness: Harness, name: string, targets?: string[], destinationName?: string) {
  await openReview(page, harness, name, targets, destinationName)
  await page.getByRole('button', { name: 'Create and start first scan' }).click()
  await expect(page).toHaveURL(/\/jobs\/[0-9a-f-]+$/i)
  await expect(page.getByRole('heading', { name })).toBeVisible()
  return new URL(page.url()).pathname.split('/').pop()!
}

test('fresh administrator follows guided setup through destination, first scan, restart, and active baseline', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'The controlled real-stack lifecycle runs once on desktop.')
  test.setTimeout(180_000)
  const harness = await createHarness({ scannerMode: 'stable', notificationSink: true })
  try {
    const csrf = await bootstrapAdministrator(page, harness)

    // A destination is a separate saved resource. Create and test it, then
    // discard this monitor draft and confirm that Notifications still owns it.
    await page.goto(`${harness.url}/jobs/new`)
    await page.getByLabel('Monitor name').fill('discarded-draft')
    await page.getByLabel('Target 1').fill('127.0.0.1')
    await page.getByRole('button', { name: 'Continue to coverage' }).click()
    await page.getByRole('radio', { name: /Selected TCP ports/ }).check()
    await page.getByRole('textbox', { name: /TCP ports/ }).fill('22')
    await page.getByRole('button', { name: 'Continue to schedule' }).click()
    await page.getByRole('button', { name: 'Add destination' }).click()
    const destinationForm = page.locator('.notification-inline-create')
    const destinationName = 'Loopback delivery'
    if (!harness.notificationURL) throw new Error('controlled notification sink was not started')
    const secretURL = harness.notificationURL.replace('/edgewatch?', '/secret-transient-marker?')
    const secretPassword = password
    await destinationForm.getByPlaceholder('Production alerts').fill(destinationName)
    await destinationForm.getByLabel('Notification service').selectOption('url')
    await destinationForm.getByLabel('Shoutrrr URL').fill(secretURL)
    await destinationForm.getByLabel('Password confirmation').fill(secretPassword)
    await destinationForm.getByRole('button', { name: 'Save and select destination' }).click()
    await expect(page.getByText(`${destinationName} was created and selected.`)).toBeVisible()
    await expect(destinationForm.getByLabel('Shoutrrr URL')).toHaveCount(0)
    await expect(destinationForm.getByLabel('Password confirmation')).toHaveValue('')
    await expect(destinationForm).not.toContainText(secretURL)
    await expect(destinationForm).not.toContainText(secretPassword)
    await expect(page.locator('body')).not.toContainText(secretURL)
    await expect(page.locator('body')).not.toContainText(secretPassword)
    const browserState = await page.evaluate(() => JSON.stringify({
      url: location.href,
      history: history.state,
      localStorage: Object.values(localStorage),
      sessionStorage: Object.values(sessionStorage),
    }))
    expect(browserState).not.toContain(secretURL)
    expect(browserState).not.toContain(secretPassword)

    await destinationForm.getByRole('button', { name: 'Test destination' }).click()
    await expect(destinationForm.getByRole('status')).toContainText('Test send completed')
    await expect.poll(() => harness.notificationMessages().length, { timeout: 15_000 }).toBeGreaterThan(0)

    await navigateFromShell(page, 'Jobs')
    const discard = page.getByRole('dialog', { name: 'Discard monitor changes?' })
    await expect(discard).toBeVisible()
    await discard.getByRole('button', { name: 'Discard changes' }).click()
    await expect(page).toHaveURL(/\/jobs$/)
    await navigateFromShell(page, 'Notifications')
    await expect(page.getByRole('heading', { name: 'Notifications', exact: true })).toBeVisible()
    await expect(page.getByText(destinationName, { exact: true })).toBeVisible()

    const jobID = await createAndStart(page, harness, 'guided-two-sample-monitor', undefined, destinationName)
    const saved = await callAPI(page, `/jobs/${jobID}`, 'GET', csrf)
    expect(saved.status).toBe(200)
    expect(saved.body.job).toMatchObject({
      name: 'guided-two-sample-monitor',
      targets: ['127.0.0.1'],
      tcp: { engine: 'nmap', ports: '22' },
      baseline_samples: 2,
      notification_destinations: [expect.any(String)],
    })

    await waitForScan(page, jobID, csrf, 1)
    await expect(page.getByRole('heading', { name: 'Next steps' })).toBeVisible()
    await expect(page.getByText('1 of 2 successful samples collected.')).toBeVisible()
    await expect(page.getByRole('button', { name: 'Run another sample' })).toBeEnabled()
    const afterFirst = await callAPI(page, `/jobs/${jobID}`, 'GET', csrf)
    expect(afterFirst.body.baseline).toMatchObject({ status: 'collecting', samples: 1 })

    // A consumed creation intent is gone after a normal refresh and a daemon
    // restart; the saved job still offers an explicit next sample.
    await page.reload()
    await expect(page.getByRole('heading', { name: 'guided-two-sample-monitor' })).toBeVisible()
    await expect.poll(async () => (await callAPI(page, `/jobs/${jobID}/scans?limit=10`, 'GET', csrf)).body.scans.length).toBe(1)
    await harness.stop()
    await harness.start()
    await page.goto(`${harness.url}/jobs/${jobID}`)
    await expect(page.getByRole('button', { name: 'Run another sample' })).toBeEnabled({ timeout: 15_000 })
    await expect.poll(async () => (await callAPI(page, `/jobs/${jobID}/scans?limit=10`, 'GET', csrf)).body.scans.length).toBe(1)

    await page.getByRole('button', { name: 'Run another sample' }).click()
    await waitForScan(page, jobID, csrf, 2)
    await expect(page.getByText('The baseline is active for the configured coverage.')).toBeVisible()
    await expect(page.getByRole('link', { name: 'View baseline evidence' })).toBeVisible()
    const ready = await callAPI(page, `/jobs/${jobID}`, 'GET', csrf)
    expect(ready.body.baseline.status).toBe('complete')
    const scans = await callAPI(page, `/jobs/${jobID}/scans?limit=10`, 'GET', csrf)
    expect(scans.status).toBe(200)
    expect(scans.body.scans).toHaveLength(2)
    expect(scans.body.scans.map((scan: { status: string }) => scan.status)).toEqual(['success', 'success'])
    const evidence = await callAPI(page, `/jobs/${jobID}/baseline?limit=10`, 'GET', csrf)
    expect(evidence.status).toBe(200)
    expect(evidence.body.baseline.status).toBe('complete')
    await page.getByRole('link', { name: 'View baseline evidence →' }).click()
    await expect(page.getByRole('heading', { name: 'Explore baseline' })).toBeVisible()
    const host = page.getByRole('link', { name: /127\.0\.0\.1/ })
    await expect(host).toContainText('1 positive ports')
    await host.click()
    await expect(page.getByRole('heading', { name: '127.0.0.1' })).toBeVisible()
    await expect(page.locator('.port-table code').filter({ hasText: '22/tcp' })).toBeVisible()
  } finally {
    await harness.close()
  }
})

test('a complete baseline with zero positive ports is described as valid', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'The controlled real-stack lifecycle runs once on desktop.')
  test.setTimeout(150_000)
  const harness = await createHarness({ scannerMode: 'empty' })
  try {
    const csrf = await bootstrapAdministrator(page, harness)
    const jobID = await createAndStart(page, harness, 'empty-surface-monitor')
    await waitForScan(page, jobID, csrf, 1)
    await expect(page.getByRole('button', { name: 'Run another sample' })).toBeEnabled()
    await page.getByRole('button', { name: 'Run another sample' }).click()
    await waitForScan(page, jobID, csrf, 2)
    await expect(page.getByText('This is a valid complete baseline with zero positive ports in the configured coverage.')).toBeVisible()
    await expect(page.getByText(/setup failure/i)).toHaveCount(0)
    const job = await callAPI(page, `/jobs/${jobID}`, 'GET', csrf)
    expect(job.body.baseline.status).toBe('complete')
    const scans = await callAPI(page, `/jobs/${jobID}/scans?limit=10`, 'GET', csrf)
    expect(scans.body.scans).toHaveLength(2)
  } finally {
    await harness.close()
  }
})

test('incomplete observations do not count and stalled learning links to scan evidence', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'The controlled real-stack lifecycle runs once on desktop.')
  test.setTimeout(150_000)
  const harness = await createHarness({ scannerMode: 'incomplete' })
  try {
    const csrf = await bootstrapAdministrator(page, harness)
    const jobID = await createAndStart(page, harness, 'incomplete-learning-monitor', ['127.0.0.1', '127.0.0.2'])
    await waitForScanStatus(page, jobID, csrf, 1, 'incomplete')
    await expect(page.getByText('The latest scan was incomplete.')).toBeVisible()
    let job = await callAPI(page, `/jobs/${jobID}`, 'GET', csrf)
    expect(job.body.baseline).toMatchObject({ status: 'collecting', samples: 0, incomplete_attempts: 1 })

    for (const count of [2, 3]) {
      await page.getByRole('button', { name: 'Run first sample' }).click()
      await waitForScanStatus(page, jobID, csrf, count, 'incomplete')
    }
    job = await callAPI(page, `/jobs/${jobID}`, 'GET', csrf)
    expect(job.body.baseline).toMatchObject({ status: 'stalled', samples: 0, incomplete_attempts: 3 })
    await expect(page.getByText('Baseline learning is stalled.')).toBeVisible()
    await expect(page.getByRole('link', { name: 'Review scan evidence' })).toBeVisible()
    await expect(page.getByRole('link', { name: 'Review targets and scanner profile' })).toBeVisible()
  } finally {
    await harness.close()
  }
})
