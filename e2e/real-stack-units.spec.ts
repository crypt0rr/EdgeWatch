import { expect, test, type Page } from '@playwright/test'
import { createHmac } from 'node:crypto'
import { callAPI, clickScanNow, createHarness, delay, navigateFromShell, password, waitForScan, type Harness } from './real-stack-harness'

// Both units name their job the same, so a leak between them shows up as a
// second job or host of that name.
const jobName = 'isolation-fixture'
const unknownID = '00000000-0000-0000-0000-00000000dead'
const platformUsername = 'platform-admin'
const platformPassword = 'platform keeps the units apart'
const unitBUsername = 'bravo-admin'
const unitBPassword = 'bravo keeps its own jobs'

const base32Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
const totpStepMs = 30_000

function base32Decode(value: string): Buffer {
  let bits = 0
  let buffer = 0
  const bytes: number[] = []
  for (const character of value.replace(/=+$/, '').toUpperCase()) {
    const index = base32Alphabet.indexOf(character)
    if (index < 0) throw new Error(`not a base32 secret: ${value}`)
    buffer = ((buffer << 5) | index) & 0xffff
    bits += 5
    if (bits >= 8) {
      bits -= 8
      bytes.push((buffer >> bits) & 0xff)
    }
  }
  return Buffer.from(bytes)
}

/** The RFC 6238 code of a time step, as EdgeWatch computes it: HMAC-SHA1, 30-second steps, six digits. */
function totpAt(secret: string, step: number): string {
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(step))
  const digest = createHmac('sha1', base32Decode(secret)).update(counter).digest()
  const offset = digest[digest.length - 1] & 0x0f
  const value = ((digest[offset] & 0x7f) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3]
  return String(value % 1_000_000).padStart(6, '0')
}

/**
 * The authenticator app of one account. EdgeWatch accepts the code of the
 * current step or a neighbouring one, and each step only once per account, so
 * every sign-in takes the current or the next step that the account has not
 * used, and waits for a new step when both are used. It never takes the
 * previous step, which a step boundary between here and the server could
 * move out of the accepted window.
 */
class Authenticator {
  private lastStep = -1
  constructor(private readonly secret: string) {}
  async nextCode(): Promise<string> {
    for (;;) {
      const now = Math.floor(Date.now() / totpStepMs)
      const step = Math.max(now, this.lastStep + 1)
      if (step <= now + 1) {
        this.lastStep = step
        return totpAt(this.secret, step)
      }
      await delay((now + 1) * totpStepMs - Date.now() + 100)
    }
  }
}

async function rawAPI(page: Page, path: string): Promise<{ status: number; body: string }> {
  return page.evaluate(async path => {
    const response = await fetch(`/api/v1${path}`)
    return { status: response.status, body: await response.text() }
  }, path)
}

async function signIn(page: Page, username: string, accountPassword: string, factor: { code?: string; recoveryCode?: string } = {}) {
  await expect(page.getByRole('heading', { name: 'Sign in to EdgeWatch' })).toBeVisible()
  await page.getByLabel('Username').fill(username)
  await page.locator('input[autocomplete="current-password"]').fill(accountPassword)
  const useCode = page.getByRole('button', { name: 'Use authenticator code' })
  if (factor.recoveryCode) {
    if (!await useCode.isVisible()) await page.getByRole('button', { name: 'Use a recovery code' }).click()
    await page.getByLabel('Recovery code').fill(factor.recoveryCode)
  } else {
    if (await useCode.isVisible()) await useCode.click()
    await page.getByLabel('Authenticator code').fill(factor.code ?? '')
  }
  await page.getByRole('button', { name: 'Sign in' }).click()
}

/**
 * Sets up an authenticator from the security settings, or from the forced
 * enrolment screen of an administrator who must use TOTP, which ends with a
 * sign-out, and returns it with the recovery codes that are shown once.
 */
async function enrolAuthenticator(page: Page, accountPassword: string, { forced }: { forced: boolean }) {
  if (forced) {
    await expect(page.getByRole('heading', { name: 'Set up an authenticator' })).toBeVisible()
    await expect(page.getByRole('status').filter({ hasText: 'Set up TOTP to continue.' })).toBeVisible()
    // The enrolment screen mounts no page with unit or platform data.
    await expect(page.getByRole('link')).toHaveCount(0)
    await page.getByLabel('Account password').fill(accountPassword)
  } else {
    await expect(page.getByRole('heading', { name: 'Security', exact: true })).toBeVisible()
    await page.getByLabel('Current password').fill(accountPassword)
  }
  await page.getByRole('button', { name: 'Set up authenticator' }).click()
  const secret = (await page.locator('code.secret').innerText()).trim()
  // Enabling checks the code without spending its step; only a sign-in does.
  await page.getByLabel('Verification code').fill(totpAt(secret, Math.floor(Date.now() / totpStepMs)))
  await page.getByRole('button', { name: 'Enable TOTP' }).click()
  await expect(page.getByRole('heading', { name: 'Save your recovery codes' })).toBeVisible()
  const recoveryCodes = await page.locator('.code-grid code').allInnerTexts()
  expect(recoveryCodes.length).toBeGreaterThan(0)
  await page.getByLabel('I saved these recovery codes in a secure place.').check()
  await page.getByRole('button', { name: 'Continue to sign in' }).click()
  await expect(page.getByRole('heading', { name: 'Sign in to EdgeWatch' })).toBeVisible()
  return { authenticator: new Authenticator(secret), recoveryCodes }
}

/**
 * Prints a platform setup token with the host command. The token shares the
 * host's setup token record with the first-run token, which the daemon
 * issued at startup, and the host issues at most one a minute, so the command
 * is refused until a minute after startup.
 */
async function issuePlatformSetupToken(harness: Harness): Promise<string> {
  const deadline = Date.now() + 75_000
  for (;;) {
    try {
      const output = await harness.cli(['admin', 'platform-setup-token'])
      const token = output.match(/platform setup token[^:]*:\s*(\S+)/)?.[1]
      if (!token) throw new Error(`no platform setup token in: ${output}`)
      return token
    } catch (error) {
      if (!String(error).includes('issued too recently') || Date.now() > deadline) throw error
      await delay(1_000)
    }
  }
}

/** Creates the fixture job through the console's job editor and returns its ID. */
async function createJob(page: Page): Promise<string> {
  await navigateFromShell(page, 'Jobs')
  await page.getByRole('button', { name: 'New job' }).click()
  await expect(page.getByRole('heading', { name: 'Create a monitoring job' })).toBeVisible()
  await page.getByLabel('Job name').fill(jobName)
  await page.getByLabel('Target 1').fill('127.0.0.1')
  // The fixture has a fake Nmap and no Naabu, as in real-stack.spec.ts.
  await page.getByLabel('TCP engine').selectOption('nmap')
  await page.getByRole('textbox', { name: /Ports Ranges/ }).first().fill('22-23')
  await page.getByLabel('Baseline samples').fill('1')
  await page.getByLabel('Five-field cron').fill('0 0 * * *')
  await page.getByLabel('Timezone').fill('UTC')
  await page.getByRole('button', { name: 'Create job' }).click()
  await expect(page).toHaveURL(/\/jobs$/)
  const card = page.getByRole('link', { name: new RegExp(jobName) })
  await expect(card).toHaveCount(1)
  const href = await card.getAttribute('href')
  expect(href).toMatch(/^\/jobs\/[^/]+$/)
  return href!.split('/').pop()!
}

// One daemon with experimental.business_units on and a browser context per
// person: `page` is the default unit's administrator, then the platform
// administrator, Unit B's administrator, and an anonymous visitor each get
// their own cookies.
test('two business units stay apart through the real console, TOTP enrolment, public pages, and disabling', async ({ page, browser }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop', 'The business units journey runs once on desktop; the mocked platform console covers phone widths.')
  test.setTimeout(180_000)
  // RFC 6238 appendix B: the SHA-1 test secret gives 94287082 at T=59 (step 1).
  expect(totpAt('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 1)).toBe('287082')
  const harness = await createHarness({ businessUnits: true })
  const platformContext = await browser.newContext()
  const unitBContext = await browser.newContext()
  const guestContext = await browser.newContext()
  try {
    const platform = await platformContext.newPage()
    const unitB = await unitBContext.newPage()
    const guest = await guestContext.newPage()

    // The first administrator sets up the deployment and administers the
    // default unit, the only unit so far, without TOTP.
    await page.goto(harness.url)
    await expect(page.getByRole('heading', { name: 'Create your administrator' })).toBeVisible()
    await page.getByLabel('Setup token').fill(harness.setupToken())
    await page.locator('input[autocomplete="new-password"]').first().fill(password)
    await page.locator('input[autocomplete="new-password"]').nth(1).fill(password)
    await page.getByRole('button', { name: 'Create administrator' }).click()
    await signIn(page, 'admin', password)
    await expect(page.getByRole('heading', { name: /Good afternoon, admin/ })).toBeVisible()
    const adminSession = await callAPI(page, '/auth/session', 'GET')
    expect(adminSession.body).toMatchObject({ scope: 'unit', unit: { slug: 'default' }, multi_unit: false })
    expect(adminSession.body.totp_enrollment_required).toBeUndefined()

    // The default unit's job, scanned once against the fake Nmap target.
    const defaultJobID = await createJob(page)
    await page.getByRole('link', { name: new RegExp(jobName) }).click()
    await expect(page.getByRole('heading', { name: jobName })).toBeVisible()
    await clickScanNow(page, defaultJobID)
    const [defaultScan] = await waitForScan(page, defaultJobID, adminSession.body.csrf_token, 1)

    // The host prints a platform setup token, and the sign-in page offers
    // the platform setup while it is valid.
    const platformToken = await issuePlatformSetupToken(harness)
    await platform.goto(`${harness.url}/login`)
    await platform.getByRole('link', { name: 'Create the platform administrator' }).click()
    await expect(platform.getByRole('heading', { name: 'Create the platform administrator' })).toBeVisible()
    await platform.getByLabel('Platform setup token').fill(platformToken)
    await platform.getByLabel('Username').fill(platformUsername)
    await platform.locator('input[autocomplete="new-password"]').first().fill(platformPassword)
    await platform.locator('input[autocomplete="new-password"]').nth(1).fill(platformPassword)
    await platform.getByRole('button', { name: 'Create platform administrator' }).click()
    await expect(platform.getByRole('status').filter({ hasText: 'Platform administrator created.' })).toBeVisible()
    await signIn(platform, platformUsername, platformPassword)

    // The platform console shows the default unit as counts, never its job.
    await expect(platform.getByRole('heading', { name: 'Business units' })).toBeVisible()
    await expect(platform.getByRole('heading', { name: '1 unit', exact: true })).toBeVisible()
    await expect(platform.getByRole('link', { name: 'Open Default' })).toContainText('1 job')
    expect(await platform.locator('main').innerText()).not.toContain(jobName)
    expect((await callAPI(platform, '/jobs', 'GET')).status).toBe(403)

    // As the README asks, the platform administrator enrols TOTP from
    // Security before creating the second unit.
    await navigateFromShell(platform, 'Security')
    const platformFactor = await enrolAuthenticator(platform, platformPassword, { forced: false })
    await signIn(platform, platformUsername, platformPassword, { code: await platformFactor.authenticator.nextCode() })
    await expect(platform.getByRole('heading', { name: '1 unit', exact: true })).toBeVisible()

    // A second unit makes TOTP mandatory for every administrator. The
    // platform administrator keeps its console and opens the new unit's
    // accounts; the session of the default unit's administrator, who has no
    // TOTP, keeps only its own account.
    await platform.getByRole('button', { name: 'New unit' }).click()
    const createUnit = platform.getByRole('dialog', { name: 'New business unit' })
    await createUnit.getByLabel('Unit name').fill('Unit B')
    await createUnit.getByRole('button', { name: 'Create unit' }).click()
    await expect(platform).toHaveURL(/\/platform\/units\/[^/]+\/accounts$/)
    await expect(platform.getByRole('heading', { name: 'Unit B', exact: true })).toBeVisible()
    const unitBID = decodeURIComponent(new URL(platform.url()).pathname.split('/')[3])
    const platformSession = await callAPI(platform, '/auth/session', 'GET')
    expect(platformSession.body).toMatchObject({ scope: 'platform', multi_unit: true, totp_enabled: true })
    expect(platformSession.body.totp_enrollment_required).toBeUndefined()
    const restricted = await callAPI(page, '/auth/session', 'GET')
    expect(restricted.body).toMatchObject({ multi_unit: true, totp_enrollment_required: true, permissions: ['account.self'] })
    expect((await callAPI(page, '/jobs', 'GET')).status).toBe(403)

    // The platform administrator invites Unit B's administrator, who
    // activates the account from the one-time link in another browser.
    await expect(platform.getByRole('heading', { name: 'Invite an administrator' })).toBeVisible()
    await platform.getByLabel('Username').fill(unitBUsername)
    await platform.getByLabel('Display name').fill('Bravo Admin')
    await platform.getByLabel('Your password').fill(platformPassword)
    await platform.getByRole('button', { name: 'Create activation link' }).click()
    const activationLink = (await platform.getByLabel(`Activation link for ${unitBUsername}`).innerText()).trim()
    expect(activationLink).toMatch(new RegExp(`^${harness.url}/activate#token=`))

    await unitB.goto(activationLink)
    await expect(unitB.getByRole('heading', { name: 'Choose your password' })).toBeVisible()
    await unitB.locator('input[autocomplete="new-password"]').first().fill(unitBPassword)
    await unitB.locator('input[autocomplete="new-password"]').nth(1).fill(unitBPassword)
    await unitB.getByRole('button', { name: 'Activate account' }).click()
    await expect(unitB.getByRole('status').filter({ hasText: 'Account activated.' })).toBeVisible()

    // A new administrator of a deployment with two units enrols at its first
    // sign-in, before it sees anything of its unit.
    await signIn(unitB, unitBUsername, unitBPassword)
    const unitBFactor = await enrolAuthenticator(unitB, unitBPassword, { forced: true })
    await signIn(unitB, unitBUsername, unitBPassword, { code: await unitBFactor.authenticator.nextCode() })
    await expect(unitB.getByRole('heading', { name: 'Good afternoon, Bravo Admin' })).toBeVisible()
    await expect(unitB.getByTitle('Business unit: Unit B')).toBeVisible()
    const unitBSession = await callAPI(unitB, '/auth/session', 'GET')
    expect(unitBSession.body).toMatchObject({ scope: 'unit', unit: { id: unitBID, name: 'Unit B', slug: 'unit-b' }, multi_unit: true })

    // Unit B sees none of the default unit's jobs or scans, and the default
    // unit's IDs get exactly the answer of an unknown ID.
    await navigateFromShell(unitB, 'Jobs')
    await expect(unitB.getByRole('heading', { name: 'No jobs yet' })).toBeVisible()
    await expect(unitB.getByRole('link', { name: new RegExp(jobName) })).toHaveCount(0)
    const unitBJobs = await callAPI(unitB, '/jobs', 'GET')
    expect(unitBJobs.status).toBe(200)
    expect(unitBJobs.body.jobs ?? []).toEqual([])
    for (const [foreignPath, unknownPath] of [
      [`/jobs/${defaultJobID}`, `/jobs/${unknownID}`],
      [`/jobs/${defaultJobID}/scans?limit=10`, `/jobs/${unknownID}/scans?limit=10`],
      [`/scans/${defaultScan.id}`, `/scans/${unknownID}`],
    ]) {
      const foreign = await rawAPI(unitB, foreignPath)
      expect(foreign.status, foreignPath).toBe(404)
      expect(foreign, foreignPath).toEqual(await rawAPI(unitB, unknownPath))
    }

    // Unit B may use the same job name, and scans its own job.
    const unitBJobID = await createJob(unitB)
    expect(unitBJobID).not.toBe(defaultJobID)
    const unitBRun = await callAPI(unitB, `/jobs/${unitBJobID}/run`, 'POST', unitBSession.body.csrf_token, {})
    expect(unitBRun.status).toBe(202)
    await waitForScan(unitB, unitBJobID, unitBSession.body.csrf_token, 1)

    // The default unit's administrator, who has no TOTP yet, gets the forced
    // enrolment when the console loads again, and then sees only its own
    // job of that name.
    await page.reload()
    const adminFactor = await enrolAuthenticator(page, password, { forced: true })
    await signIn(page, 'admin', password, { code: await adminFactor.authenticator.nextCode() })
    await expect(page.getByRole('heading', { name: /Good afternoon, admin/ })).toBeVisible()
    await expect(page.getByTitle('Business unit: Default')).toBeVisible()
    await navigateFromShell(page, 'Jobs')
    const defaultCards = page.getByRole('link', { name: new RegExp(jobName) })
    await expect(defaultCards).toHaveCount(1)
    await expect(defaultCards).toHaveAttribute('href', `/jobs/${defaultJobID}`)
    expect(await rawAPI(page, `/jobs/${unitBJobID}`)).toEqual(await rawAPI(page, `/jobs/${unknownID}`))

    // Unit B publishes its page with its own host; the host picker offers
    // only Unit B's observation of the shared address.
    await navigateFromShell(unitB, 'Public status')
    await expect(unitB.getByRole('heading', { name: 'Public status' })).toBeVisible()
    await unitB.getByLabel('Enable public status page').check()
    await unitB.getByLabel('Title', { exact: true }).fill('Unit B status')
    const hostChoices = unitB.getByRole('checkbox', { name: /127\.0\.0\.1/ })
    await expect(hostChoices).toHaveCount(1)
    await hostChoices.check()
    await unitB.getByRole('button', { name: 'Save public view' }).click()
    await expect(unitB.getByRole('status').filter({ hasText: 'Public view saved.' })).toBeVisible()
    await expect(unitB.getByRole('link', { name: 'Preview public page ↗' })).toHaveAttribute('href', '/public/unit-b')

    // /public/unit-b serves Unit B's page. An unknown slug and the default
    // unit's unpublished page, at its slug and at the legacy /public, answer
    // alike: not enabled.
    await guest.goto(`${harness.url}/public/unit-b`)
    await expect(guest.getByRole('heading', { name: 'Unit B status' })).toBeVisible()
    await expect(guest.getByRole('heading', { name: '127.0.0.1' })).toBeVisible()
    for (const path of ['/public/no-such-unit', '/public/default', '/public']) {
      await guest.goto(`${harness.url}${path}`)
      await expect(guest.getByRole('heading', { name: 'Public status unavailable' })).toBeVisible()
      await expect(guest.getByText('This status page is not enabled by the administrator.')).toBeVisible()
    }
    const unknownSlug = await guestContext.request.get(`${harness.url}/api/public/v1/dashboard/no-such-unit`)
    const unpublished = await guestContext.request.get(`${harness.url}/api/public/v1/dashboard/default`)
    expect(unknownSlug.status()).toBe(404)
    expect({ status: unpublished.status(), body: await unpublished.text() }).toEqual({ status: unknownSlug.status(), body: await unknownSlug.text() })
    expect(await guestContext.cookies()).toEqual([])

    // The platform console counts both units' jobs and accounts, and neither
    // the console nor its API names a job.
    await navigateFromShell(platform, 'Units')
    const unitBRow = platform.getByRole('link', { name: 'Open Unit B' })
    await expect(unitBRow).toContainText('1 account · 1 admin')
    await expect(unitBRow).toContainText('1 job')
    await expect(platform.getByRole('link', { name: 'Open Default' })).toContainText('1 job')
    expect(await platform.locator('main').innerText()).not.toContain(jobName)
    for (const path of ['/platform/units', `/platform/units/${unitBID}`, `/platform/units/${unitBID}/accounts`, '/platform/status']) {
      const response = await rawAPI(platform, path)
      expect(response.status, path).toBe(200)
      expect(response.body, path).not.toContain(jobName)
    }
    expect((await callAPI(platform, '/jobs', 'GET')).status).toBe(403)

    // Disabling Unit B, with the platform administrator's password, ends its
    // administrator's session, fails its sign-in as a wrong password does
    // even with a valid second factor, and takes its public page offline.
    await unitBRow.click()
    await platform.getByRole('link', { name: 'Danger zone' }).click()
    await platform.getByRole('button', { name: 'Disable unit' }).click()
    const disable = platform.getByRole('dialog', { name: 'Disable Unit B?' })
    await disable.getByLabel('Your password').fill(platformPassword)
    await disable.getByRole('button', { name: 'Disable unit' }).click()
    await expect(platform.getByText('This unit is disabled.')).toBeVisible()

    expect((await callAPI(unitB, '/auth/session', 'GET')).status).toBe(401)
    await unitB.reload()
    await signIn(unitB, unitBUsername, unitBPassword, { recoveryCode: unitBFactor.recoveryCodes[0] })
    await expect(unitB.getByRole('alert')).toHaveText('invalid credentials')
    await guest.goto(`${harness.url}/public/unit-b`)
    await expect(guest.getByRole('heading', { name: 'Public status unavailable' })).toBeVisible()

    // Enabling it again restores sign-in and the public page.
    await platform.getByRole('button', { name: 'Enable unit' }).click()
    const enable = platform.getByRole('dialog', { name: 'Enable Unit B?' })
    await enable.getByLabel('Your password').fill(platformPassword)
    await enable.getByRole('button', { name: 'Enable unit' }).click()
    await expect(platform.getByText('This unit is disabled.')).toHaveCount(0)

    await signIn(unitB, unitBUsername, unitBPassword, { code: await unitBFactor.authenticator.nextCode() })
    await expect(unitB.getByTitle('Business unit: Unit B')).toBeVisible()
    const restored = await callAPI(unitB, '/jobs', 'GET')
    expect(restored.status).toBe(200)
    expect(restored.body.jobs.map((job: any) => job.id)).toEqual([unitBJobID])
    await guest.goto(`${harness.url}/public/unit-b`)
    await expect(guest.getByRole('heading', { name: 'Unit B status' })).toBeVisible()
  } finally {
    await guestContext.close()
    await unitBContext.close()
    await platformContext.close()
    await harness.stop()
  }
})
