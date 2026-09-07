import { afterEach, describe, expect, it, vi } from 'vitest'
import { APIError, acceptIncident, activate, api, baselineHost, baselineHosts, createNotificationDestination, createUser, getPublicDashboard, historicalScanHost, issueUserActivation, listHosts, listScans, listUsers, login, revokeUserSessions, scheduleSuggestion, setCSRF, setup, suppressIncident, updateNotificationDestination, updateUser } from './api'

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
    const fetchMock = vi.fn(async (_input: RequestInfo | URL) => new Response(JSON.stringify({ hosts: [], pagination: { limit: 50, offset: 0, total: 0, has_more: false, next_offset: null } }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)
    await listHosts({ q: 'router', protocol: 'udp', has_open_ports: false })
    expect(String(fetchMock.mock.calls[0][0])).toBe('/api/v1/hosts?limit=50&offset=0&q=router&protocol=udp&has_open_ports=false')
    await historicalScanHost('scan-1', '2001:db8::1')
    expect(String(fetchMock.mock.calls[1][0])).toBe('/api/v1/scans/scan-1/hosts/2001%3Adb8%3A%3A1')
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

    await acceptIncident('job/1', 'port|192.0.2.1|tcp|443')
    await suppressIncident('job/1', 'port|192.0.2.1|tcp|443')

    expect(String(fetchMock.mock.calls[0][0])).toBe('/api/v1/jobs/job%2F1/incidents/accept')
    expect(JSON.parse(String(fetchMock.mock.calls[0][1]?.body))).toEqual({ key: 'port|192.0.2.1|tcp|443' })
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
})
