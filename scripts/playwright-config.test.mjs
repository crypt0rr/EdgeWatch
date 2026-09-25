import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const configURL = new URL('../playwright.config.ts', import.meta.url).href
const repositoryRoot = fileURLToPath(new URL('..', import.meta.url))

// Load the Playwright configuration in a child process so each case evaluates
// the module-level environment checks with exactly the variables it sets.
function loadConfig(overrides) {
  const env = { ...process.env }
  for (const name of ['CI', 'PLAYWRIGHT_PORT', 'PLAYWRIGHT_REUSE_SERVER']) delete env[name]
  Object.assign(env, overrides)
  const script = `const { default: config } = await import(${JSON.stringify(configURL)}); console.log(JSON.stringify({ reuse: config.webServer.reuseExistingServer, url: config.webServer.url }))`
  return spawnSync(process.execPath, ['--input-type=module', '--no-warnings', '-e', script], { cwd: repositoryRoot, env, encoding: 'utf8' })
}

function webServer(overrides) {
  const result = loadConfig(overrides)
  assert.equal(result.status, 0, result.stderr)
  return JSON.parse(result.stdout)
}

test('local runs start a fresh server unless reuse is requested', () => {
  assert.deepEqual(webServer({}), { reuse: false, url: 'http://127.0.0.1:4173' })
  assert.equal(webServer({ PLAYWRIGHT_REUSE_SERVER: '0' }).reuse, false)
  assert.equal(webServer({ PLAYWRIGHT_REUSE_SERVER: '1' }).reuse, true)
  assert.deepEqual(webServer({ PLAYWRIGHT_PORT: '4191', PLAYWRIGHT_REUSE_SERVER: '1' }), { reuse: true, url: 'http://127.0.0.1:4191' })
})

test('CI never reuses a running server', () => {
  assert.equal(webServer({ CI: 'true' }).reuse, false)
  assert.equal(webServer({ CI: 'true', PLAYWRIGHT_REUSE_SERVER: '1' }).reuse, false)
})

test('invalid server settings are rejected before any test runs', () => {
  for (const value of ['true', 'yes', '2', ' 1']) {
    const result = loadConfig({ PLAYWRIGHT_REUSE_SERVER: value })
    assert.notEqual(result.status, 0, `PLAYWRIGHT_REUSE_SERVER=${JSON.stringify(value)} was accepted`)
    assert.match(result.stderr, /PLAYWRIGHT_REUSE_SERVER must be 1/)
  }
  const port = loadConfig({ PLAYWRIGHT_PORT: '80' })
  assert.notEqual(port.status, 0)
  assert.match(port.stderr, /PLAYWRIGHT_PORT must be an integer/)
})
