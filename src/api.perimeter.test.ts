import { afterEach, describe, expect, it, vi } from 'vitest'
import { APIError, declarePerimeterSeeds, deletePerimeterSeed, getPerimeter, getPerimeterRange, perimeterLineErrors, setCSRF } from './api'

afterEach(() => {
  vi.unstubAllGlobals()
  setCSRF('')
})

function respond(status: number, body?: unknown) {
  return new Response(body === undefined ? null : JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

describe('perimeter API client', () => {
  it('builds the perimeter routes with encoded IDs, their methods, the CSRF token, and no body on DELETE', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => init?.method === 'DELETE' ? respond(204) : respond(200, { created: 1, skipped: 0 }))
    vi.stubGlobal('fetch', fetchMock)
    setCSRF('csrf-token')
    await getPerimeter()
    await expect(declarePerimeterSeeds([{ kind: 'prefix', value: '203.0.113.0/24', label: 'DC1 edge' }, { kind: 'authorized', value: '198.51.100.7' }])).resolves.toEqual({ created: 1, skipped: 0 })
    await getPerimeterRange('seed/1')
    await expect(deletePerimeterSeed('seed/1')).resolves.toBeUndefined()
    expect(fetchMock.mock.calls.map(([url, init]) => `${init?.method ?? 'GET'} ${String(url)}`)).toEqual([
      'GET /api/v1/perimeter',
      'POST /api/v1/perimeter/seeds',
      'GET /api/v1/perimeter/seeds/seed%2F1',
      'DELETE /api/v1/perimeter/seeds/seed%2F1',
    ])
    const declare = fetchMock.mock.calls[1][1]
    expect(JSON.parse(String(declare?.body))).toEqual({ entries: [{ kind: 'prefix', value: '203.0.113.0/24', label: 'DC1 edge' }, { kind: 'authorized', value: '198.51.100.7' }] })
    expect(new Headers(declare?.headers).get('X-CSRF-Token')).toBe('csrf-token')
    const remove = fetchMock.mock.calls[3][1]
    expect(remove?.body).toBeUndefined()
    expect(new Headers(remove?.headers).get('X-CSRF-Token')).toBe('csrf-token')
  })

  it('keeps the refused entries of a declaration from the error envelope', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => respond(400, { error: { code: 'validation_failed', message: 'Some entries were refused; nothing was saved.', details: { entries: [{ index: 0, value: 'example.com', reason: 'not an IP address or CIDR prefix' }, { index: 2, value: '127.0.0.1', reason: 'loopback address space is not allowed' }] } } })))
    const error = await declarePerimeterSeeds([{ kind: 'prefix', value: 'example.com' }]).catch(cause => cause)
    expect(error).toBeInstanceOf(APIError)
    expect(perimeterLineErrors(error)).toEqual([
      { index: 0, value: 'example.com', reason: 'not an IP address or CIDR prefix' },
      { index: 2, value: '127.0.0.1', reason: 'loopback address space is not allowed' },
    ])
  })

  it('finds no refused entries in other errors or malformed details', () => {
    expect(perimeterLineErrors(new Error('network'))).toEqual([])
    expect(perimeterLineErrors(new APIError('limit', 'perimeter_limit', { limit: 1024, held: 1000, new: 30 }, 400))).toEqual([])
    expect(perimeterLineErrors(new APIError('count', 'validation_failed', { limit: 256 }, 400))).toEqual([])
    expect(perimeterLineErrors(new APIError('bad', 'validation_failed', { entries: 'nope' }, 400))).toEqual([])
    expect(perimeterLineErrors(new APIError('bad', 'validation_failed', { entries: [null, { index: -1, value: 'x', reason: 'r' }, { index: 1.5, value: 'x', reason: 'r' }, { index: 1, value: 2, reason: 'r' }, { index: 3, value: 'kept', reason: 'r' }] }, 400))).toEqual([{ index: 3, value: 'kept', reason: 'r' }])
  })
})
