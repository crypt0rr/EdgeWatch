import type { Page } from '@playwright/test'
import { access, chmod, mkdtemp, writeFile } from 'node:fs/promises'
import { once } from 'node:events'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { execFile, spawn, type ChildProcess } from 'node:child_process'
import net from 'node:net'
import { promisify } from 'node:util'

// The real-stack browser tests run the daemon built once by Playwright global
// setup on a loopback port, with a temporary database and a fake Nmap that
// reports scripted results for 127.0.0.1 and sends no probe.

const run = promisify(execFile)

export const password = 'correct horse battery staple'

export async function navigateFromShell(page: Page, label: string) {
  const trigger = page.getByRole('button', { name: 'Open navigation' })
  if (await trigger.isVisible()) await trigger.click()
  await page.getByRole('link', { name: label, exact: true }).click()
}

export type Harness = {
  url: string
  setupToken: () => string
  start: () => Promise<void>
  stop: () => Promise<void>
  /** Runs a host command of the same binary against the daemon's configuration and returns its standard output. */
  cli: (args: string[]) => Promise<string>
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

export async function delay(ms: number): Promise<void> {
  await new Promise(resolve => setTimeout(resolve, ms))
}

export async function createHarness(): Promise<Harness> {
  const binary = process.env.EDGEWATCH_E2E_BINARY
  if (!binary) throw new Error('EDGEWATCH_E2E_BINARY is unset; Playwright global setup must build the daemon first')
  await access(binary)

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
scanner:
  # The deterministic fixture intentionally scans the local fake Nmap target.
  # Production configurations retain the safe loopback/link-local denylist.
  target_exclusions: []
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
    child = spawn(binary, ['daemon', '--config', config, '--nmap', nmap], {
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
    if (!child || !child.pid) return
    const processGroupID = child.pid
    const processHandle = child
    // `go run` can exit before the compiled daemon child has finished
    // shutting down. Always signal the detached process group, even when the
    // runner already has an exit code, so a restart cannot race its lease.
    try { process.kill(-processGroupID, 'SIGTERM') } catch { /* already stopped */ }
    if (processHandle.exitCode === null) {
      await Promise.race([once(processHandle, 'exit'), delay(10_000)])
    } else {
      await delay(100)
    }
    if (processHandle.exitCode === null) {
      try { process.kill(-processGroupID, 'SIGKILL') } catch { /* already stopped */ }
    }
    const deadline = Date.now() + 5_000
    while (Date.now() < deadline) {
      try {
        process.kill(-processGroupID, 0)
        await delay(50)
      } catch {
        break
      }
    }
    // Allow the daemon's deferred SQLite lease release to complete before a
    // restart in the same fixture. The process-group check above normally
    // makes this unnecessary, but the Go runner can briefly outlive its
    // child after receiving SIGTERM.
    await delay(100)
    child = undefined
  }

  // Host commands open the daemon's database beside the running daemon, as
  // an operator runs them with `docker compose exec`.
  const cli = async (args: string[]) => {
    const { stdout } = await run(binary, [...args, '--config', config], { cwd: process.cwd() })
    return stdout
  }

  const harness: Harness = { url, setupToken: () => setupToken, start, stop, cli }
  // Register cleanup before waiting for readiness. If compilation, binding,
  // or database startup fails, the caller never receives a harness on which it
  // could run its normal finally block.
  try {
    await start()
    return harness
  } catch (error) {
    await stop()
    throw error
  }
}

export type APIResult = { status: number; body: any }

export async function callAPI(page: Page, path: string, method: string, csrf = '', payload?: unknown): Promise<APIResult> {
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

export async function waitForScan(page: Page, jobID: string, csrf: string, count: number): Promise<any[]> {
  for (let attempt = 0; attempt < 100; attempt++) {
    const response = await callAPI(page, `/jobs/${jobID}/scans?limit=10`, 'GET', csrf)
    if (response.status === 200 && response.body.scans?.length >= count && response.body.scans.every((scan: any) => scan.status === 'success')) {
      return response.body.scans
    }
    await delay(200)
  }
  throw new Error(`scan ${count} did not complete`)
}

// The scan row is saved before the run releases its job lease, so a click
// right after waitForScan can briefly get 409 job_active. Retry that case, as
// the API message tells operators to, and fail on any other refusal.
export async function clickScanNow(page: Page, jobID: string): Promise<void> {
  const runPath = `/api/v1/jobs/${jobID}/run`
  for (let attempt = 0; attempt < 20; attempt++) {
    const [response] = await Promise.all([
      page.waitForResponse(response => response.request().method() === 'POST' && new URL(response.url()).pathname === runPath),
      page.getByRole('button', { name: 'Scan now' }).click(),
    ])
    if (response.status() === 202) return
    if (response.status() !== 409) throw new Error(`Scan now returned ${response.status()}: ${await response.text()}`)
    await delay(250)
  }
  throw new Error('Scan now stayed busy after the previous scan completed')
}
