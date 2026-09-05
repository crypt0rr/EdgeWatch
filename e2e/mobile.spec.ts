import { expect, test } from '@playwright/test'

test('mobile navigation is modal and incident cards fit the viewport', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name === 'desktop', 'The responsive smoke runs in the mobile projects.')
  await page.emulateMedia({ reducedMotion: 'reduce' })

  await page.route('**/api/v1/**', async route => {
    const request = route.request()
    const path = new URL(request.url()).pathname.replace('/api/v1', '')
    const json = (body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })
    if (path === '/stream') {
      await route.abort()
      return
    }
    if (path === '/setup/status') {
      await json({ configured: true, setup_available: false, version: 'v0.8.0', password_requirements: { minimum_length: 12 } })
      return
    }
    if (path === '/auth/session') {
      await json({ username: 'admin', csrf_token: 'mobile-csrf', totp_enabled: false })
      return
    }
    if (path === '/incidents') {
      await json({
        incidents: [{
          job_id: 'job-mobile',
          job: 'mobile-production-job',
          incident: {
            change: { key: 'port|203.0.113.10|tcp|443', kind: 'port', target: '203.0.113.10', protocol: 'tcp', port: 443, severity: 'critical' },
            opened_at: '2026-01-01T00:00:00Z',
            last_seen_at: '2026-01-01T00:00:00Z',
          },
        }],
        pagination: { limit: 20, offset: 0, total: 1, has_more: false, next_offset: null },
      })
      return
    }
    if (path === '/jobs') {
      await json({ jobs: [] })
      return
    }
    if (path === '/scans') {
      await json({ scans: [], pagination: { limit: 20, offset: 0, total: 0, has_more: false, next_offset: null } })
      return
    }
    if (path === '/scans/active') {
      await json({ scans: [{ id: 'scan-mobile', job: 'mobile-long-job', phase: 'scanning', protocol: 'tcp', completed_probes: 1024, total_probes: 65535, progress_percent: 1.56, elapsed_seconds: 42, process_alive: true, process_progress_percent: 3, current_invocation: 1, total_batches: 2, last_output: 'SYN Stealth Scan Timing: About 3.1% done' }] })
      return
    }
    if (path === '/status') {
      await json({ configured: true, username: 'admin', notification_destinations: 0, retention: '90d', max_concurrent_scans: 1 })
      return
    }
    await json({ error: { code: 'not_found', message: `GET ${path}` } }, 404)
  })

  await page.goto('/incidents')
  const trigger = page.locator('.menu-button')
  const drawer = page.locator('#primary-navigation')
  await expect(trigger).toBeVisible()
  await expect(trigger).toHaveAttribute('aria-expanded', 'false')
  await expect(drawer).toHaveAttribute('aria-hidden', 'true')
  await expect.poll(() => page.evaluate(() => document.body.style.overflow)).toBe('')

  await trigger.click()
  await expect(trigger).toHaveAttribute('aria-expanded', 'true')
  await expect(drawer).toHaveAttribute('aria-hidden', 'false')
  await expect(drawer).toHaveAttribute('role', 'dialog')
  await expect(page.locator('main.main')).toHaveAttribute('aria-hidden', 'true')
  await expect(page.getByRole('button', { name: 'Close navigation' }).first()).toBeFocused()
  await expect.poll(() => page.evaluate(() => document.body.style.overflow)).toBe('hidden')

  for (let index = 0; index < 12; index += 1) {
    await page.keyboard.press('Tab')
    await expect.poll(() => page.evaluate(() => {
      const active = document.activeElement
      const navigation = document.getElementById('primary-navigation')
      return Boolean(active && navigation?.contains(active))
    })).toBe(true)
  }

  await page.keyboard.press('Escape')
  await expect(trigger).toHaveAttribute('aria-expanded', 'false')
  await expect(trigger).toBeFocused()
  await expect(drawer).toHaveAttribute('aria-hidden', 'true')
  await expect(drawer).not.toHaveAttribute('role', 'dialog')
  await expect(page.locator('main.main')).not.toHaveAttribute('aria-hidden', 'true')
  await expect.poll(() => page.evaluate(() => document.body.style.overflow)).toBe('')

  await expect(page.locator('.desktop-incident-table')).toBeHidden()
  await expect(page.locator('.mobile-incident-list')).toBeVisible()
  await expect(page.getByRole('article', { name: /mobile-production-job/ })).toBeVisible()
  const suppress = page.getByRole('button', { name: 'Suppress 1 scan' })
  await suppress.click()
  const actionDialog = page.getByRole('dialog', { name: /Suppress this incident/ })
  await expect(actionDialog).toBeVisible()
  await expect(actionDialog.getByRole('button', { name: 'Cancel' })).toBeFocused()
  await page.locator('.modal-backdrop').click({ position: { x: 1, y: 1 } })
  await expect(actionDialog).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(actionDialog).toBeHidden()
  await page.goto('/')
  await expect(page.getByRole('heading', { name: 'Scans in progress' })).toBeVisible()
  const scanDetails = page.locator('.active-scan-details')
  await expect(scanDetails).toBeVisible()
  await scanDetails.locator('summary').click()
  await expect(scanDetails).toContainText('SYN Stealth Scan Timing: About 3.1% done')
  await expect(scanDetails).toContainText('Nmap process active')
  const motion = await page.evaluate(() => {
    const probe = document.createElement('span')
    probe.className = 'spinner'
    document.body.append(probe)
    const style = getComputedStyle(probe)
    const drawerStyle = getComputedStyle(document.getElementById('primary-navigation')!)
    const values = { animation: style.animation, animationName: style.animationName, animationDuration: style.animationDuration, transitionDuration: drawerStyle.transitionDuration, reduced: matchMedia('(prefers-reduced-motion: reduce)').matches }
    probe.remove()
    return values
  })
  expect(motion.reduced).toBe(true)
  expect(motion.animationName).toBe('none')
  expect(motion.transitionDuration).toBe('0s')
  const hitTargets = await page.locator('button:visible, a:visible').evaluateAll(elements => elements.map(element => {
    const rect = element.getBoundingClientRect()
    return { tag: element.tagName, width: rect.width, height: rect.height, text: element.textContent?.trim() }
  }))
  expect(hitTargets.every(target => target.width >= 40 && target.height >= 40), JSON.stringify(hitTargets)).toBe(true)
  const viewport = await page.evaluate(() => ({ clientWidth: document.documentElement.clientWidth, scrollWidth: document.documentElement.scrollWidth }))
  expect(viewport.scrollWidth).toBeLessThanOrEqual(viewport.clientWidth)
})
