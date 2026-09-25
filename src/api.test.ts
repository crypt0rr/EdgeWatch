import { afterEach, describe, expect, it, vi } from 'vitest'
import { APIError, acceptIncident, activate, api, baselineHost, baselineHosts, createNotificationDestination, createUser, getPublicDashboard, getScan, getScanSummary, historicalScanHost, issueUserActivation, listHosts, listScans, listUsers, login, recordActivity, revokeUserSessions, scheduleSuggestion, setCSRF, setup, setupStatus, suppressIncident, updateNotificationDestination, updateUser } from './api'
import * as apiRoutes from './api'
import { getDisplayTimeZone, setDisplayTimeZone } from './format'

afterEach(() => {
  vi.restoreAllMocks()
  setCSRF('')
})

describe('API pagination contract', () => {
  it('requests the selected offset and returns pagination metadata', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => new Response(JSON.stringify({
      scans: [],
      pagination: { limit: 10, offset: 20, total: 30, has_more: false, next_offset: null },
    }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)

    const response = await listScans(20, 10)

    expect(response.pagination.offset).toBe(20)
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(String(fetchMock.mock.calls[0][0])).toBe('/api/v1/scans?limit=10&offset=20')
  })

  it('sends the CSRF header for mutating requests while keeping errors structured', async () => {
    setCSRF('csrf-token')
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => new Response(JSON.stringify({ error: { code: 'conflict', message: 'stale', details: { revision: 2 } } }), { status: 409, headers: { 'Content-Type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)

    const request = api('/jobs/example', { method: 'PUT', body: '{}' })
    await expect(request).rejects.toBeInstanceOf(APIError)
    await expect(request).rejects.toMatchObject({ code: 'conflict', details: { revision: 2 } })
    expect(new Headers(fetchMock.mock.calls[0][1]?.headers).get('X-CSRF-Token')).toBe('csrf-token')
  })

  it('signals session expiry for authenticated requests without redirecting login failures', async () => {
    const dispatchEvent = vi.fn()
    vi.stubGlobal('window', { dispatchEvent })
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ error: { code: 'unauthorized', message: 'authentication required' } }), { status: 401, headers: { 'Content-Type': 'application/json' } }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ error: { code: 'login_failed', message: 'invalid credentials' } }), { status: 401, headers: { 'Content-Type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)

    await expect(api('/status')).rejects.toMatchObject({ code: 'unauthorized' })
    await expect(api('/auth/login', { method: 'POST', body: '{}' })).rejects.toMatchObject({ code: 'login_failed' })

    expect(dispatchEvent).toHaveBeenCalledTimes(1)
    expect(dispatchEvent.mock.calls[0][0].type).toBe('edgewatch:unauthorized')
  })

  it('keeps the session when step-up password confirmation is rejected', async () => {
    const dispatchEvent = vi.fn()
    vi.stubGlobal('window', { dispatchEvent })
    const fetchMock = vi.fn(async (_input: RequestInfo | URL) => new Response(JSON.stringify({ error: { code: 'invalid_password', message: 'password confirmation failed' } }), { status: 401, headers: { 'Content-Type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)

    await expect(api('/notifications/destinations/dest-1', { method: 'PUT', body: '{}' })).rejects.toMatchObject({ code: 'invalid_password' })
    expect(dispatchEvent).not.toHaveBeenCalled()
  })

  it('keeps the session when step-up TOTP confirmation is rejected', async () => {
    const dispatchEvent = vi.fn()
    vi.stubGlobal('window', { dispatchEvent })
    const fetchMock = vi.fn(async (_input: RequestInfo | URL) => new Response(JSON.stringify({ error: { code: 'totp_required', message: 'the current authenticator code is required' } }), { status: 401, headers: { 'Content-Type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)

    await expect(api('/auth/security/totp', { method: 'PUT', body: '{}' })).rejects.toMatchObject({ code: 'totp_required' })
    expect(dispatchEvent).not.toHaveBeenCalled()
  })
})

describe('setup status API contract', () => {
  it('loads only the public setup metadata', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL) => new Response(JSON.stringify({ configured: true, password_requirements: { minimum_length: 12 } }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)

    await expect(setupStatus()).resolves.toMatchObject({ configured: true, password_requirements: { minimum_length: 12 } })
    expect(String(fetchMock.mock.calls[0][0])).toBe('/api/v1/setup/status')
  })
})

describe('historical scan API contract', () => {
  it('unwraps the server scan envelope while accepting a bare legacy payload', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ scan: { id: 'scan-1', job: 'legacy', status: 'success' } }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ id: 'scan-2', job: 'legacy', status: 'success' }), { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)

    await expect(getScan('scan-1')).resolves.toMatchObject({ id: 'scan-1', job: 'legacy' })
    await expect(getScan('scan-2')).resolves.toMatchObject({ id: 'scan-2', job: 'legacy' })
    expect(String(fetchMock.mock.calls[0][0])).toBe('/api/v1/scans/scan-1')
    expect(String(fetchMock.mock.calls[1][0])).toBe('/api/v1/scans/scan-2')
  })

  it('loads metadata from the additive summary route', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL) => new Response(JSON.stringify({ scan: { id: 'large-scan', job: 'inventory', status: 'success' } }), { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)

    await expect(getScanSummary('large/scan')).resolves.toMatchObject({ scan: { id: 'large-scan', job: 'inventory' } })
    expect(String(fetchMock.mock.calls[0][0])).toBe('/api/v1/scans/large%2Fscan/summary')
  })
})

describe('notification API contract', () => {
  it('uses write-only named destination payloads and revision updates', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => new Response(JSON.stringify({ id: 'dest-1', name: 'Ops', provider: 'generic', source: 'web', enabled: true, locked: false, read_only: false, revision: 2 }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)
    setCSRF('csrf-token')

    await createNotificationDestination('Ops', 'generic://localhost/ops?disabletls=yes', 'correct horse battery staple')
    const createBody = JSON.parse(String(fetchMock.mock.calls[0][1]?.body)) as Record<string, unknown>
    expect(createBody).toMatchObject({ name: 'Ops', url: 'generic://localhost/ops?disabletls=yes', password: 'correct horse battery staple', enabled: true })
    expect(new Headers(fetchMock.mock.calls[0][1]?.headers).get('X-CSRF-Token')).toBe('csrf-token')

    await updateNotificationDestination('dest-1', 1, 'Ops', 'correct horse battery staple', { enabled: false })
    expect(String(fetchMock.mock.calls[1][0])).toContain('/notifications/destinations/dest-1')
    const updateBody = JSON.parse(String(fetchMock.mock.calls[1][1]?.body)) as Record<string, unknown>
    expect(updateBody).toMatchObject({ revision: 1, name: 'Ops', password: 'correct horse battery staple', enabled: false })
    expect(updateBody.url).toBeUndefined()
  })
})

describe('host explorer API contract', () => {
  it('encodes IPv6 addresses and applies host filters before requesting', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => new Response(JSON.stringify({ hosts: [], data_quality: 'detailed', pagination: { limit: 50, offset: 0, total: 0, has_more: false, next_offset: null } }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)
    await baselineHosts('job-1', { q: 'router', protocol: 'tcp', has_open_ports: true })
    expect(String(fetchMock.mock.calls[0][0])).toBe('/api/v1/jobs/job-1/baseline/hosts?limit=50&offset=0&q=router&protocol=tcp&has_open_ports=true')
    await baselineHost('job-1', '2001:db8::1')
    expect(String(fetchMock.mock.calls[1][0])).toBe('/api/v1/jobs/job-1/baseline/hosts/2001%3Adb8%3A%3A1')
  })

  it('lists global hosts and links historical detail requests by scan', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => new Response(JSON.stringify({ hosts: [], pagination: { limit: 50, offset: 0, total: 0, has_more: false, next_offset: null } }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)
    await listHosts({ q: 'router', protocol: 'udp', has_open_ports: false })
    expect(String(fetchMock.mock.calls[0][0])).toBe('/api/v1/hosts?limit=50&offset=0&q=router&protocol=udp&has_open_ports=false')
    await historicalScanHost('scan-1', '2001:db8::1')
    expect(String(fetchMock.mock.calls[1][0])).toBe('/api/v1/scans/scan-1/hosts/2001%3Adb8%3A%3A1')
  })

  it('forwards query cancellation signals to host requests', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response(JSON.stringify({ hosts: [], pagination: { limit: 50, offset: 0, total: 0, has_more: false, next_offset: null } }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)
    const controller = new AbortController()

    await listHosts({ q: 'router', signal: controller.signal })

    expect(fetchMock.mock.calls[0][1]?.signal).toBe(controller.signal)
  })
})

describe('schedule suggestion API contract', () => {
  it('encodes the proposed cron and timezone', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL) => new Response(JSON.stringify({ suggested: false, gap_minutes: 45 }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)
    await scheduleSuggestion('0 */6 * * *', 'Europe/Amsterdam')
    expect(String(fetchMock.mock.calls[0][0])).toBe('/api/v1/jobs/schedule-suggestion?schedule=0+*%2F6+*+*+*&timezone=Europe%2FAmsterdam')
  })
})

describe('incident action API contract', () => {
  it('posts the incident key with CSRF protection', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response(null, { status: 204 }))
    vi.stubGlobal('fetch', fetchMock)
    setCSRF('csrf-token')

    const expectedChange = { key: 'port|192.0.2.1|tcp|443', kind: 'port', target: '192.0.2.1', protocol: 'tcp', port: 443, old: 'not-open', new: 'open', severity: 'critical' }
    await acceptIncident('job/1', 'port|192.0.2.1|tcp|443', expectedChange)
    await suppressIncident('job/1', 'port|192.0.2.1|tcp|443', expectedChange)

    expect(String(fetchMock.mock.calls[0][0])).toBe('/api/v1/jobs/job%2F1/incidents/accept')
    expect(JSON.parse(String(fetchMock.mock.calls[0][1]?.body))).toEqual({ key: 'port|192.0.2.1|tcp|443', expected_change: expectedChange })
    expect(new Headers(fetchMock.mock.calls[1][1]?.headers).get('X-CSRF-Token')).toBe('csrf-token')
    expect(String(fetchMock.mock.calls[1][0])).toBe('/api/v1/jobs/job%2F1/incidents/suppress')
  })
})

describe('authentication and public API contracts', () => {
  it('handles empty responses, malformed errors, and CSRF only on mutations', async () => {
    const noContent = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response(null, { status: 204 }))
    vi.stubGlobal('fetch', noContent)
    setCSRF('csrf-token')
    await expect(api<void>('/auth/logout', { method: 'POST' })).resolves.toBeUndefined()
    expect(new Headers(noContent.mock.calls[0][1]?.headers).get('X-CSRF-Token')).toBe('csrf-token')

    const malformed = vi.fn(async (_input: RequestInfo | URL) => new Response('not-json', { status: 500 }))
    vi.stubGlobal('fetch', malformed)
    await expect(api('/status')).rejects.toMatchObject({ name: 'APIError', message: 'Request failed' })

    const get = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => new Response(JSON.stringify({ ok: true }), { status: 200 }))
    vi.stubGlobal('fetch', get)
    await api('/status')
    expect(new Headers(get.mock.calls[0][1]?.headers).get('X-CSRF-Token')).toBeNull()
  })

  it('sends the authentication, user, and activation contracts with encoded IDs', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response(JSON.stringify({ user: { id: 'u-1' }, activation_token: 'token', activation_path: '/activate' }), { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)
    setCSRF('csrf-token')
    await login('administrator password', undefined, undefined, 'admin')
    await setup('setup-token', 'administrator password')
    await activate('activation-token', 'operator password')
    await listUsers()
    await createUser('operator', 'Operator', 'operator')
    await updateUser('user/1', { enabled: false })
    await issueUserActivation('user/1')
    await revokeUserSessions('user/1')
    const urls = fetchMock.mock.calls.map(call => String(call[0]))
    expect(urls).toEqual([
      '/api/v1/auth/login',
      '/api/v1/setup',
      '/api/v1/auth/activate',
      '/api/v1/users',
      '/api/v1/users',
      '/api/v1/users/user%2F1',
      '/api/v1/users/user%2F1/activation',
      '/api/v1/users/user%2F1/sessions',
    ])
    expect(new Headers(fetchMock.mock.calls[7][1]?.headers).get('X-CSRF-Token')).toBe('csrf-token')
  })

  it('keeps public requests credential-free and exposes structured errors', async () => {
    const errorFetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      expect(init?.credentials).toBe('omit')
      return new Response(JSON.stringify({ error: { code: 'public_disabled', message: 'disabled' } }), { status: 404 })
    })
    vi.stubGlobal('fetch', errorFetch)
    await expect(getPublicDashboard()).rejects.toMatchObject({ code: 'public_disabled', message: 'disabled' })
    const successFetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      expect(init?.credentials).toBe('omit')
      return new Response(JSON.stringify({ title: 'Status', hosts: [] }), { status: 200 })
    })
    vi.stubGlobal('fetch', successFetch)
    await expect(getPublicDashboard()).resolves.toMatchObject({ title: 'Status', hosts: [] })
  })

  it('uses safe fallback messages and omits optional event filters', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL) => new Response('{}', { status: 500 }))
    vi.stubGlobal('fetch', fetchMock)
    await expect(getPublicDashboard()).rejects.toMatchObject({ name: 'APIError', message: 'Public status is not available' })
    const events = vi.fn(async (input: RequestInfo | URL) => {
      expect(String(input)).toBe('/api/v1/events?limit=20&offset=0')
      return new Response(JSON.stringify({ events: [], pagination: { limit: 20, offset: 0, total: 0, has_more: false, next_offset: null } }), { status: 200 })
    })
    vi.stubGlobal('fetch', events)
    await apiRoutes.listEvents()
  })
})

describe('business unit API contract', () => {
  it('builds the platform routes with encoded IDs, methods, and write-only confirmations', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)
    setCSRF('csrf-token')
    await apiRoutes.platformSetup('setup-token', 'morgan', 'main admin password')
    await apiRoutes.listUnits()
    await apiRoutes.createUnit({ name: 'Retail', slug: 'retail' })
    await apiRoutes.getUnit('unit/1')
    await apiRoutes.updateUnit('unit/1', { revision: 2, capacity: { slot_cap: 1, max_probe_count: 10, max_naabu_probe_count: 20 } })
    await apiRoutes.disableUnit('unit/1', 'pw')
    await apiRoutes.enableUnit('unit/1', 'pw')
    await apiRoutes.deleteUnit('unit/1', 'Retail', 'pw')
    await apiRoutes.listUnitAccounts('unit/1')
    await apiRoutes.inviteUnitAccount('unit/1', { username: 'riley', display_name: 'Riley', role: 'administrator', password: 'pw' })
    await apiRoutes.updateUnitAccount('unit/1', 'user/2', { role: 'viewer', revision: 3, password: 'pw' })
    await apiRoutes.resetUnitAccountPassword('unit/1', 'user/2', 'pw')
    await apiRoutes.revokeUnitAccountSessions('unit/1', 'user/2', 'pw')
    await apiRoutes.getUnitNotifications('unit/1')
    await apiRoutes.setUnitNotifications('unit/1', ['deploy-ops-slack'], 4)
    await apiRoutes.listDeploymentNotifications()
    await apiRoutes.listPlatformAdmins()
    await apiRoutes.invitePlatformAdmin({ username: 'sam', display_name: 'Sam', password: 'pw' })
    await apiRoutes.platformCapacity()
    const calls = fetchMock.mock.calls.map(([url, init]) => `${init?.method ?? 'GET'} ${String(url)}`)
    expect(calls).toEqual([
      'POST /api/v1/setup/platform',
      'GET /api/v1/platform/units',
      'POST /api/v1/platform/units',
      'GET /api/v1/platform/units/unit%2F1',
      'PATCH /api/v1/platform/units/unit%2F1',
      'POST /api/v1/platform/units/unit%2F1/disable',
      'POST /api/v1/platform/units/unit%2F1/enable',
      'DELETE /api/v1/platform/units/unit%2F1',
      'GET /api/v1/platform/units/unit%2F1/accounts',
      'POST /api/v1/platform/units/unit%2F1/accounts',
      'PATCH /api/v1/platform/units/unit%2F1/accounts/user%2F2',
      'POST /api/v1/platform/units/unit%2F1/accounts/user%2F2/password-reset',
      'DELETE /api/v1/platform/units/unit%2F1/accounts/user%2F2/sessions',
      'GET /api/v1/platform/units/unit%2F1/notifications',
      'PUT /api/v1/platform/units/unit%2F1/notifications',
      'GET /api/v1/platform/notifications',
      'GET /api/v1/platform/admins',
      'POST /api/v1/platform/admins',
      'GET /api/v1/platform/capacity',
    ])
    expect(JSON.parse(String(fetchMock.mock.calls[7][1]?.body))).toEqual({ confirm_name: 'Retail', password: 'pw' })
    expect(JSON.parse(String(fetchMock.mock.calls[14][1]?.body))).toEqual({ destinations: ['deploy-ops-slack'], revision: 4 })
    expect(new Headers(fetchMock.mock.calls[7][1]?.headers).get('X-CSRF-Token')).toBe('csrf-token')
  })

  it('pages both audit logs by keyset and forwards platform filters', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL) => new Response(JSON.stringify({ entries: [], next_before: null }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)
    await apiRoutes.unitAudit()
    await apiRoutes.unitAudit({ before: 51 })
    await apiRoutes.platformAudit({ before: null, limit: 20, unit: 'unit-retail', action: 'user.', since: '2026-09-01' })
    await apiRoutes.platformAudit()
    expect(fetchMock.mock.calls.map(([url]) => String(url))).toEqual([
      '/api/v1/audit?limit=50',
      '/api/v1/audit?before=51&limit=50',
      '/api/v1/platform/audit?limit=20&unit=unit-retail&action=user.&since=2026-09-01',
      '/api/v1/platform/audit?limit=50',
    ])
  })

  it('requests a business unit public page by slug', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response(JSON.stringify({ title: 'Retail', hosts: [] }), { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)
    await getPublicDashboard('retail stores')
    expect(String(fetchMock.mock.calls[0][0])).toBe('/api/public/v1/dashboard/retail%20stores')
    expect(fetchMock.mock.calls[0][1]?.credentials).toBe('omit')
  })
})

describe('session timezone contract', () => {
  afterEach(() => setDisplayTimeZone(undefined))

  it('applies the deployment timezone from the signed-in session', async () => {
    const session = { user_id: 'u', username: 'admin', role: 'administrator', permissions: [], csrf_token: 'csrf', totp_enabled: false, password_requirements: { minimum_length: 12 } }
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ ...session, timezone: 'Europe/Amsterdam' }), { status: 200, headers: { 'Content-Type': 'application/json' } })))
    await expect(apiRoutes.getSession()).resolves.toMatchObject({ timezone: 'Europe/Amsterdam' })
    expect(getDisplayTimeZone()).toBe('Europe/Amsterdam')

    // An older server or an omitted setting falls back to the browser timezone.
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify(session), { status: 200, headers: { 'Content-Type': 'application/json' } })))
    await apiRoutes.getSession()
    expect(getDisplayTimeZone()).toBeUndefined()
  })
})

describe('API route helpers', () => {
	it('builds the latest successful scan endpoint', async () => {
		const fetchMock = vi.fn(async (input: RequestInfo | URL) => new Response(JSON.stringify({ scan: null }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
		vi.stubGlobal('fetch', fetchMock)
		await apiRoutes.latestSuccessfulScan('job/1')
		expect(String(fetchMock.mock.calls[0][0])).toBe('/api/v1/jobs/job/1/scans/latest-successful')
	})

	it('covers the remaining authenticated route builders', async () => {
		const fetchMock = vi.fn(async (_input: RequestInfo | URL) => new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } }))
		vi.stubGlobal('fetch', fetchMock)
		setCSRF('csrf-token')
		const form = {} as Parameters<typeof apiRoutes.createJob>[0]
		const profile = { name: 'profile', engine: 'nmap' } as Parameters<typeof apiRoutes.createScannerProfile>[0]
		await apiRoutes.getSession()
		await recordActivity()
		await apiRoutes.logout()
		await apiRoutes.logoutAllSessions()
		await apiRoutes.updateDisplayName('Operator')
		await apiRoutes.listJobs(true)
		await apiRoutes.getJob('job/1')
		await apiRoutes.createJob(form)
		await apiRoutes.updateJob('job/1', 2, form, true)
		await apiRoutes.archiveJob('job/1', 2)
		await apiRoutes.restoreJob('job/1', 3)
		await apiRoutes.deleteJob('job/1', 'job')
		await apiRoutes.pauseJob('job/1', 4)
		await apiRoutes.resumeJob('job/1', 5)
		await apiRoutes.runJob('job/1')
		await apiRoutes.scanCycle('job/1')
		await apiRoutes.discardScanCycle('job/1', 'cycle/1')
		await apiRoutes.cancelScan('scan/1')
		await apiRoutes.resetBaseline('job/1')
		await apiRoutes.approveBaseline('job/1', 'scan/1')
		await apiRoutes.jobScans('job/1')
		await apiRoutes.latestSuccessfulScan('job/1')
		await apiRoutes.jobBaseline('job/1')
		await apiRoutes.baselineHostRDAP('job/1', '192.0.2.1')
		await apiRoutes.scanHosts('job/1', 'scan/1')
		await apiRoutes.scanHost('job/1', 'scan/1', '192.0.2.1')
		await apiRoutes.scanHostRDAP('job/1', 'scan/1', '192.0.2.1')
		await apiRoutes.historicalScanHosts('scan/1')
		await apiRoutes.historicalScanHostRDAP('scan/1', '192.0.2.1')
		await apiRoutes.getScan('scan/1')
		await apiRoutes.scanDetail('job/1', 'scan/1')
		await apiRoutes.scanResults('job/1', 'scan/1')
		await apiRoutes.scanChanges('job/1', 'scan/1')
		await apiRoutes.activeScans()
		await apiRoutes.listIncidents()
		await apiRoutes.listEvents(0, 20, 'job/1')
		await apiRoutes.notificationTest()
		await apiRoutes.listNotificationDestinations()
		await apiRoutes.getNotificationDestination('destination/1')
		await apiRoutes.testNotificationDestination('destination/1')
		await apiRoutes.deleteNotificationDestination('destination/1', 2, 'password')
		await apiRoutes.updateNotificationRouting(['destination/1'], 'password')
		await apiRoutes.scannerCapabilities()
		await apiRoutes.listScannerProfiles(true)
		await apiRoutes.getScannerProfile('profile/1')
		await apiRoutes.createScannerProfile(profile)
		await apiRoutes.updateScannerProfile('profile/1', profile, 1)
		await apiRoutes.archiveScannerProfile('profile/1', 1, 'password')
		await apiRoutes.restoreScannerProfile('profile/1', 2, 'password')
		await apiRoutes.validateScannerProfile(profile)
		await apiRoutes.revokeUserActivation('user/1')
		await apiRoutes.getPublicDashboardConfig()
		await apiRoutes.savePublicDashboardConfig({ enabled: true, title: 'Status', introduction: '', hosts: [], updated_at: '2026-09-12T08:00:00Z' })
		expect(fetchMock.mock.calls.length).toBeGreaterThan(50)
	})
})
