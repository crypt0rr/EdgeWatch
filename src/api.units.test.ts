import { afterEach, describe, expect, it, vi } from 'vitest'
import * as apiRoutes from './api'

afterEach(() => {
  vi.unstubAllGlobals()
  apiRoutes.setCSRF('')
})

describe('business units API contract', () => {
  it('builds the platform routes with encoded IDs, their methods, and password confirmations', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)
    apiRoutes.setCSRF('csrf-token')
    await apiRoutes.platformSetup('setup-token', 'morgan', 'platform password')
    await apiRoutes.listUnits()
    await apiRoutes.createUnit({ name: 'Retail', slug: 'retail' })
    await apiRoutes.getUnit('unit/1')
    await apiRoutes.renameUnit('unit/1', { revision: 2, name: 'Stores' })
    await apiRoutes.disableUnit('unit/1', 2, 'pw')
    await apiRoutes.enableUnit('unit/1', 3, 'pw')
    await apiRoutes.deleteUnit('unit/1', 'Retail', 'pw')
    await apiRoutes.getUnitCapacity('unit/1')
    await apiRoutes.updateUnitCapacity('unit/1', { max_concurrent_scans: 2, high_cost_ceiling: null })
    await apiRoutes.listUnitAccounts('unit/1')
    await apiRoutes.inviteUnitAdmin('unit/1', { username: 'riley', display_name: 'Riley', password: 'pw' })
    await apiRoutes.resetUnitAdminPassword('unit/1', 'user/2', 'pw')
    await apiRoutes.revokeUnitAccountSessions('unit/1', 'user/2', 'pw')
    await apiRoutes.listPlatformAdmins()
    await apiRoutes.invitePlatformAdmin({ username: 'sam', display_name: 'Sam', password: 'pw' })
    await apiRoutes.setPlatformAdminEnabled('user/3', false, 4, 'pw')
    await apiRoutes.revokePlatformAdminInvitation('user/3', 'pw')
    await apiRoutes.renewPlatformAdminInvitation('user/3', 'pw')
    await apiRoutes.deletePendingPlatformAdmin('user/3', 'pw')
    await apiRoutes.listPlatformNotifications()
    await apiRoutes.createPlatformNotification('Ops', 'generic://example.test/hook', 'pw')
    await apiRoutes.updatePlatformNotification('dest/1', 5, 'Ops', 'pw', { enabled: false })
    await apiRoutes.deletePlatformNotification('dest/1', 5, 'pw')
    await apiRoutes.updatePlatformNotificationRouting(['dest-1'], 'pw')
    await apiRoutes.platformStatus()
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
      'GET /api/v1/platform/units/unit%2F1/capacity',
      'PATCH /api/v1/platform/units/unit%2F1/capacity',
      'GET /api/v1/platform/units/unit%2F1/accounts',
      'POST /api/v1/platform/units/unit%2F1/accounts',
      'POST /api/v1/platform/units/unit%2F1/accounts/user%2F2/password-reset',
      'DELETE /api/v1/platform/units/unit%2F1/accounts/user%2F2/sessions',
      'GET /api/v1/platform/admins',
      'POST /api/v1/platform/admins',
      'PATCH /api/v1/platform/admins/user%2F3',
      'DELETE /api/v1/platform/admins/user%2F3/activation',
      'POST /api/v1/platform/admins/user%2F3/activation',
      'DELETE /api/v1/platform/admins/user%2F3',
      'GET /api/v1/platform/notifications',
      'POST /api/v1/platform/notifications',
      'PATCH /api/v1/platform/notifications/dest%2F1',
      'DELETE /api/v1/platform/notifications/dest%2F1',
      'PUT /api/v1/platform/notifications/update-routing',
      'GET /api/v1/platform/status',
    ])
    const body = (index: number) => JSON.parse(String(fetchMock.mock.calls[index][1]?.body))
    expect(body(0)).toEqual({ token: 'setup-token', username: 'morgan', password: 'platform password' })
    expect(body(4)).toEqual({ revision: 2, name: 'Stores' })
    expect(body(5)).toEqual({ revision: 2, password: 'pw' })
    expect(body(7)).toEqual({ confirm_name: 'Retail', password: 'pw' })
    expect(body(9)).toEqual({ max_concurrent_scans: 2, high_cost_ceiling: null })
    // The platform invites only administrators.
    expect(body(11)).toEqual({ username: 'riley', display_name: 'Riley', password: 'pw', role: 'administrator' })
    expect(body(12)).toEqual({ password: 'pw' })
    expect(body(16)).toEqual({ enabled: false, revision: 4, password: 'pw' })
    expect(body(17)).toEqual({ password: 'pw' })
    expect(body(18)).toEqual({ password: 'pw' })
    expect(body(19)).toEqual({ password: 'pw' })
    expect(body(21)).toEqual({ name: 'Ops', url: 'generic://example.test/hook', password: 'pw', enabled: true })
    expect(body(22)).toEqual({ name: 'Ops', revision: 5, password: 'pw', enabled: false })
    expect(body(24)).toEqual({ destinations: ['dest-1'], password: 'pw' })
    expect(new Headers(fetchMock.mock.calls[7][1]?.headers).get('X-CSRF-Token')).toBe('csrf-token')
  })

  it('pages both audits by keyset and passes the platform filters', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL) => new Response(JSON.stringify({ entries: [], next_before: null }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)
    await apiRoutes.unitAudit()
    await apiRoutes.unitAudit({ before: 51 })
    await apiRoutes.platformAudit({ before: null, limit: 20, unit: 'unit-retail', action: 'user.', since: '2026-09-01T00:00:00Z', until: '2026-09-02T00:00:00Z' })
    await apiRoutes.platformAudit()
    expect(fetchMock.mock.calls.map(([url]) => String(url))).toEqual([
      '/api/v1/audit?limit=50',
      '/api/v1/audit?before=51&limit=50',
      '/api/v1/platform/audit?limit=20&unit=unit-retail&action=user.&since=2026-09-01T00%3A00%3A00Z&until=2026-09-02T00%3A00%3A00Z',
      '/api/v1/platform/audit?limit=50',
    ])
  })
})
