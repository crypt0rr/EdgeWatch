import { afterEach, describe, expect, it, vi } from 'vitest'
import { APIError, api, listScans, setCSRF } from './api'

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
