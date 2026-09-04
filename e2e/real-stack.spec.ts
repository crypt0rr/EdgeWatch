import { expect, test } from '@playwright/test'
import { chmod, mkdtemp, writeFile } from 'node:fs/promises'
import { once } from 'node:events'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { spawn, type ChildProcess } from 'node:child_process'
import net from 'node:net'

const password = 'correct horse battery staple'

type Harness = {
  url: string
  setupToken: () => string
  start: () => Promise<void>
  stop: () => Promise<void>
}

async function availablePort(): Promise<number> {
  const server = net.createServer()
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => resolve())
  })
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('could not allocate a test port')
  const port = address.port
  await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()))
  return port
}

async function delay(ms: number): Promise<void> {
  await new Promise(resolve => setTimeout(resolve, ms))
}

async function createHarness(): Promise<Harness> {
  const directory = await mkdtemp(join(tmpdir(), 'edgewatch-real-stack-'))
  const port = await availablePort()
  const counter = join(directory, 'nmap-count')
  const nmap = join(directory, 'fake-nmap.sh')
  await writeFile(nmap, `#!/bin/sh
if [ "\${1:-}" = "--version" ]; then
  printf '%s\\n' 'Nmap 7.99 (https://nmap.org)'
  exit 0
fi
count=0
if [ -f '${counter}' ]; then count=$(cat '${counter}'); fi
count=$((count + 1))
printf '%s' "$count" > '${counter}'
port=22
if [ "$count" -ge 2 ]; then port=23; fi
cat <<EOF
<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="$port"><state state="open"/></port>
    </ports>
  </host>
  <runstats><finished exit="success"/></runstats>
</nmaprun>
EOF
`)
  await chmod(nmap, 0o755)
  const config = join(directory, 'config.yaml')
  await writeFile(config, `database: ${join(directory, 'edgewatch.db')}
retention: 1d
scheduler:
  max_concurrent_scans: 1
web:
  listen: 127.0.0.1:${port}
notifications:
  urls: []
`)

  let child: ChildProcess | undefined
  let output = ''
  let setupToken = ''
  let firstStart = true
  const url = `http://127.0.0.1:${port}`

  const start = async () => {
    child = spawn('go', ['run', './cmd/edgewatch', 'daemon', '--config', config, '--nmap', nmap], {
      cwd: process.cwd(),
      detached: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    output = ''
    const needsToken = firstStart
    child.stdout?.on('data', chunk => { output += chunk.toString() })
    child.stderr?.on('data', chunk => { output += chunk.toString() })
    const deadline = Date.now() + 90_000
    while (Date.now() < deadline) {
      if (child.exitCode !== null) throw new Error(`EdgeWatch exited during startup: ${output}`)
      const tokenMatch = output.match(/"setup_token"\s*:\s*"([A-Z2-7]+)"/)
      if (tokenMatch) setupToken = tokenMatch[1]
      try {
        const response = await fetch(`${url}/api/v1/setup/status`)
        if (response.ok && (!needsToken || setupToken)) {
          firstStart = false
          return
        }
      } catch {
        // The Go process may still be compiling or binding its listener.
      }
      await delay(200)
    }
    throw new Error(`EdgeWatch did not become ready: ${output}`)
  }

  const stop = async () => {
    if (!child || child.exitCode !== null || !child.pid) return
    try { process.kill(-child.pid, 'SIGTERM') } catch { /* already stopped */ }
    await Promise.race([once(child, 'exit'), delay(10_000)])
    if (child.exitCode === null) {
      try { process.kill(-child.pid, 'SIGKILL') } catch { /* already stopped */ }
    }
    child = undefined
  }

  await start()
  return { url, setupToken: () => setupToken, start, stop }
}

type APIResult = { status: number; body: any }

async function callAPI(page: import('@playwright/test').Page, path: string, method: string, csrf = '', payload?: unknown): Promise<APIResult> {
  return page.evaluate(async ({ path, method, csrf, payload }) => {
    const headers: Record<string, string> = {}
    if (payload !== undefined) headers['Content-Type'] = 'application/json'
    if (csrf) headers['X-CSRF-Token'] = csrf
    const response = await fetch(`/api/v1${path}`, {
      method,
      headers,
      body: payload === undefined ? undefined : JSON.stringify(payload),
    })
    let body: any = null
    try { body = await response.json() } catch { /* empty response */ }
    return { status: response.status, body }
  }, { path, method, csrf, payload })
}

async function waitForScan(page: import('@playwright/test').Page, jobID: string, csrf: string, count: number): Promise<any[]> {
  for (let attempt = 0; attempt < 100; attempt++) {
    const response = await callAPI(page, `/jobs/${jobID}/scans?limit=10`, 'GET', csrf)
    if (response.status === 200 && response.body.scans?.length >= count && response.body.scans.every((scan: any) => scan.status === 'success')) {
      return response.body.scans
    }
    await delay(200)
  }
  throw new Error(`scan ${count} did not complete`)
}

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
    await expect(page.getByRole('heading', { name: /Good afternoon, admin/ })).toBeVisible()
    const session = await callAPI(page, '/auth/session', 'GET')
    expect(session.status).toBe(200)
    const csrf = session.body.csrf_token as string

    await page.getByRole('link', { name: 'Jobs' }).click()
    await page.getByRole('button', { name: 'New job' }).click()
    await expect(page.getByRole('heading', { name: 'Create a monitoring job' })).toBeVisible()
    await page.getByLabel('Job name').fill('real-stack-fixture')
    await page.getByLabel('Target 1').fill('127.0.0.1')
    await page.getByLabel('Ports').first().fill('22-23')
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
    await page.getByRole('button', { name: 'Scan now' }).click()
    await waitForScan(page, jobID, csrf, 1)
    const learned = await callAPI(page, `/jobs/${jobID}`, 'GET', csrf)
    expect(learned.body.baseline.status).toBe('complete')

    await page.getByRole('button', { name: 'Scan now' }).click()
    await waitForScan(page, jobID, csrf, 2)
    const incidents = await callAPI(page, '/incidents', 'GET', csrf)
    expect(incidents.status).toBe(200)
    expect(incidents.body.incidents.length).toBeGreaterThanOrEqual(2)
    expect(incidents.body.incidents.every((incident: any) => incident.job === 'real-stack-fixture')).toBe(true)

    await harness.stop()
    await harness.start()
    const persisted = await callAPI(page, '/jobs', 'GET', csrf)
    expect(persisted.status).toBe(200)
    expect(persisted.body.jobs.map((job: any) => job.job.name)).toContain('real-stack-fixture')
    // Reload after the process restart so the SPA establishes a fresh session
    // and EventSource connection instead of retaining a half-closed stream.
    await page.goto(`${harness.url}/`, { waitUntil: 'domcontentloaded' })
    await expect(page.getByRole('heading', { name: /Good afternoon, admin/ })).toBeVisible({ timeout: 15_000 })
    await page.getByRole('link', { name: 'Incidents' }).click()
    await expect(page.getByRole('heading', { name: 'Incidents' })).toBeVisible()
    await expect(page.getByRole('row', { name: /real-stack-fixture/ }).first()).toBeVisible()
  } finally {
    await harness.stop()
  }
})
