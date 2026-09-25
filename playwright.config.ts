import { defineConfig, devices } from '@playwright/test'

const previewPort = Number(process.env.PLAYWRIGHT_PORT ?? 4173)
if (!Number.isInteger(previewPort) || previewPort < 1024 || previewPort > 65535) {
  throw new Error('PLAYWRIGHT_PORT must be an integer between 1024 and 65535')
}
const baseURL = `http://127.0.0.1:${previewPort}`

// Reusing a running server is opt-in. Otherwise a stale preview from another
// checkout on the same port would silently receive every test, and the run
// would report results for a build other than the one under test. With reuse
// off, Playwright stops before any test when the port is already in use. CI
// always starts a fresh server.
const reuseServer = process.env.PLAYWRIGHT_REUSE_SERVER ?? ''
if (reuseServer !== '' && reuseServer !== '0' && reuseServer !== '1') {
  throw new Error('PLAYWRIGHT_REUSE_SERVER must be 1 to reuse a running server, or 0 or unset to start a fresh one')
}
const reuseExistingServer = !process.env.CI && reuseServer === '1'

export default defineConfig({
  testDir: './e2e',
  timeout: 30_000,
  expect: { timeout: 5_000 },
  fullyParallel: true,
  reporter: 'list',
  use: {
    baseURL,
    trace: 'retain-on-failure',
  },
  projects: [
    { name: 'desktop', use: { ...devices['Desktop Chrome'] } },
    { name: 'mobile-narrow', use: { viewport: { width: 320, height: 720 }, deviceScaleFactor: 1, hasTouch: true } },
    { name: 'iphone-13', use: { ...devices['iPhone 13'], browserName: 'chromium' } },
    { name: 'pixel-7', use: { ...devices['Pixel 7'] } },
  ],
  webServer: {
    command: `npm run build && npm run preview -- --host 127.0.0.1 --port ${previewPort}`,
    url: baseURL,
    reuseExistingServer,
    timeout: 120_000,
  },
})
