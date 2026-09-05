import { afterEach, describe, expect, it, vi } from 'vitest'
import { APIError, api, baselineHost, baselineHosts, createNotificationDestination, listScans, setCSRF, updateNotificationDestination } from './api'

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
})
