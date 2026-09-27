/** @vitest-environment jsdom */

import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { useLocation } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { adminStatus, getPublicDashboard, getPublicDashboardConfig, getSession, listHosts, listIncidents, listJobs, listUnits, platformStatus, recordActivity, setupStatus, unitAudit } from './api'
import type { SessionUser } from './api'
import { ProtectedApp } from './main'
import { deploymentLimits, platformSession } from './test/platform-fixtures'
import { renderWithProviders } from './test/test-utils'

vi.mock('./api', async () => {
  const actual = await vi.importActual<typeof import('./api')>('./api')
  return { ...actual, adminStatus: vi.fn(), getPublicDashboard: vi.fn(), getPublicDashboardConfig: vi.fn(), getSession: vi.fn(), listHosts: vi.fn(), listIncidents: vi.fn(), listJobs: vi.fn(), listUnits: vi.fn(), platformStatus: vi.fn(), recordActivity: vi.fn(), setCSRF: vi.fn(), setupStatus: vi.fn(), unitAudit: vi.fn() }
})

class EventSourceStub {
  static instances = 0
  onopen: (() => void) | null = null
  onerror: (() => void) | null = null
  onmessage: ((event: MessageEvent) => void) | null = null
  constructor() { EventSourceStub.instances += 1 }
  close() {}
}

function CurrentPath() {
  return <output data-testid="current-path">{useLocation().pathname}</output>
}

const administratorPermissions = ['account.self', 'audit.read', 'baselines.read', 'hosts.read', 'incidents.read', 'jobs.read', 'jobs.write', 'overview.read', 'public_dashboard.manage', 'scans.read', 'stream.read', 'users.manage']

function unitAdministrator(overrides: Partial<SessionUser> = {}): SessionUser {
  return { user_id: 'acct-riley', username: 'riley', display_name: 'Riley Novak', role: 'administrator', permissions: administratorPermissions, csrf_token: 'csrf', totp_enabled: true, password_requirements: { minimum_length: 12 }, scope: 'unit', unit: { id: 'unit-retail', name: 'Retail', slug: 'retail' }, multi_unit: true, ...overrides }
}

function renderApp(route: string) {
  return renderWithProviders(<><ProtectedApp onLogout={async () => {}} /><CurrentPath /></>, { route: [route] })
}

describe('business units in the console', () => {
  beforeEach(() => {
    vi.mocked(setupStatus).mockResolvedValue({ configured: true, password_requirements: { minimum_length: 12 } })
    vi.mocked(adminStatus).mockResolvedValue({ version: 'v0.19.0' })
    vi.mocked(listIncidents).mockResolvedValue({ incidents: [], pagination: { limit: 1, offset: 0, total: 0, has_more: false, next_offset: null } })
    vi.mocked(listJobs).mockResolvedValue({ jobs: [] })
    vi.mocked(listUnits).mockResolvedValue({ limits: deploymentLimits, units: [] })
    vi.mocked(platformStatus).mockRejectedValue(new Error('not needed'))
    vi.mocked(recordActivity).mockResolvedValue(undefined)
    vi.mocked(unitAudit).mockResolvedValue({ entries: [], next_before: null })
    vi.mocked(getPublicDashboard).mockResolvedValue({ title: 'Retail status', updated_at: '2026-09-20T00:00:00Z', hosts: [] })
    vi.mocked(getPublicDashboardConfig).mockResolvedValue({ enabled: true, title: 'Retail status', introduction: '', updated_at: '2026-09-20T00:00:00Z', hosts: [] })
    vi.mocked(listHosts).mockResolvedValue({ hosts: [], pagination: { limit: 100, offset: 0, total: 0, has_more: false, next_offset: null } } as never)
    EventSourceStub.instances = 0
    vi.stubGlobal('EventSource', EventSourceStub)
  })
  afterEach(() => { vi.unstubAllGlobals(); vi.clearAllMocks() })

  it('gives a platform administrator the platform console and never a unit page', async () => {
    vi.mocked(getSession).mockResolvedValue(platformSession())
    renderApp('/incidents')
    await waitFor(() => expect(screen.getByTestId('current-path')).toHaveTextContent('/platform/units'))
    expect(await screen.findByRole('heading', { name: 'Business units' })).toBeInTheDocument()
    expect(screen.getByText('Morgan Reyes')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Incidents' })).not.toBeInTheDocument()
    for (const unitRequest of [listIncidents, listJobs, adminStatus]) expect(unitRequest).not.toHaveBeenCalled()
    expect(EventSourceStub.instances).toBe(0)
  })

  it('shows a unit administrator its unit, its audit, and its own public page address', async () => {
    vi.mocked(getSession).mockResolvedValue(unitAdministrator())
    const view = renderApp('/audit')
    expect(await screen.findByRole('heading', { name: 'Audit' })).toBeInTheDocument()
    expect(screen.getByTitle('Business unit: Retail')).toHaveTextContent('Retail')
    expect(screen.getByRole('link', { name: 'Audit' })).toHaveClass('active')
    await waitFor(() => expect(unitAudit).toHaveBeenCalledWith({ before: null }))
    view.unmount()

    const highlights = renderApp('/highlights')
    expect(await screen.findByRole('heading', { name: 'Retail status' })).toBeInTheDocument()
    expect(getPublicDashboard).toHaveBeenCalledWith('retail')
    highlights.unmount()

    renderApp('/public-dashboard')
    const preview = await screen.findByRole('link', { name: /Preview public page/ })
    expect(preview).toHaveAttribute('href', '/public/retail')
  })

  it('keeps the single-unit console unchanged without business units or with one unit', async () => {
    for (const session of [
      // Business units off: the session has no scope, unit, or multi_unit.
      { user_id: 'admin', username: 'admin', role: 'administrator' as const, permissions: administratorPermissions.filter(permission => permission !== 'audit.read'), csrf_token: 'csrf', totp_enabled: false, password_requirements: { minimum_length: 12 } },
      // Business units on with a single unit.
      unitAdministrator({ multi_unit: false, unit: { id: 'default', name: 'Default', slug: 'default' } }),
    ]) {
      vi.mocked(getSession).mockResolvedValue(session)
      vi.mocked(getPublicDashboard).mockClear()
      const view = renderApp('/highlights')
      expect(await screen.findByRole('heading', { name: 'Retail status' })).toBeInTheDocument()
      expect(getPublicDashboard).toHaveBeenCalledWith(undefined)
      expect(screen.queryByText('Business unit')).not.toBeInTheDocument()
      const navigation = screen.getByRole('complementary', { name: 'Primary navigation', hidden: true })
      expect(within(navigation).queryByRole('link', { name: 'Audit' }) !== null).toBe(session.permissions.includes('audit.read'))
      view.unmount()
      const admin = renderApp('/public-dashboard')
      expect(await screen.findByRole('link', { name: /Preview public page/ })).toHaveAttribute('href', '/public')
      admin.unmount()
    }
  })

  it('treats /audit as an unknown page without business units', async () => {
    vi.mocked(getSession).mockResolvedValue({ user_id: 'admin', username: 'admin', role: 'administrator', permissions: administratorPermissions.filter(permission => permission !== 'audit.read'), csrf_token: 'csrf', totp_enabled: false, password_requirements: { minimum_length: 12 } })
    renderApp('/audit')
    await waitFor(() => expect(screen.getByTestId('current-path')).toHaveTextContent(/^\/$/))
    expect(unitAudit).not.toHaveBeenCalled()
  })

  it('refuses the unit audit page to accounts without audit.read', async () => {
    vi.mocked(getSession).mockResolvedValue(unitAdministrator({ role: 'operator', permissions: ['account.self', 'jobs.read'] }))
    renderApp('/audit')
    await waitFor(() => expect(screen.getByTestId('current-path')).toHaveTextContent('/jobs'))
    expect(screen.queryByRole('link', { name: 'Audit' })).not.toBeInTheDocument()
    expect(unitAudit).not.toHaveBeenCalled()
    expect(screen.getByTitle('Business unit: Retail')).toBeInTheDocument()
  })

  it('shows only the TOTP enrolment until the administrator enrols, and keeps it while the recovery codes are shown', async () => {
    vi.mocked(getSession).mockResolvedValue(unitAdministrator({ totp_enabled: false, totp_enrollment_required: true, permissions: ['account.self'] }))
    const { client } = renderApp('/jobs')
    expect(await screen.findByRole('heading', { name: 'Set up an authenticator' })).toBeInTheDocument()
    await waitFor(() => expect(screen.getByTestId('current-path')).toHaveTextContent('/security'))
    expect(screen.queryByRole('link', { name: 'Jobs' })).not.toBeInTheDocument()
    for (const request of [listJobs, listIncidents, adminStatus]) expect(request).not.toHaveBeenCalled()
    expect(EventSourceStub.instances).toBe(0)

    // Enabling TOTP lifts the requirement; the screen stays until sign-out.
    vi.mocked(getSession).mockResolvedValue(unitAdministrator())
    const sessionReads = vi.mocked(getSession).mock.calls.length
    await client.invalidateQueries({ queryKey: ['session'] })
    await waitFor(() => expect(vi.mocked(getSession).mock.calls.length).toBeGreaterThan(sessionReads))
    await waitFor(() => expect(screen.getByText('TOTP is protecting your sign-in.')).toBeInTheDocument())
    expect(screen.getByRole('heading', { name: 'Set up an authenticator' })).toBeInTheDocument()
    expect(listJobs).not.toHaveBeenCalled()
  })

  it('gives a platform administrator who must enrol the enrolment first', async () => {
    vi.mocked(getSession).mockResolvedValue(platformSession({ totp_enabled: false, totp_enrollment_required: true, permissions: ['account.self'] }))
    renderApp('/platform/units')
    expect(await screen.findByRole('heading', { name: 'Set up an authenticator' })).toBeInTheDocument()
    expect(listUnits).not.toHaveBeenCalled()
  })

  it('gives a platform administrator only a notice and sign-out while business units are off', async () => {
    // Business units off: the session has no scope, unit, or multi_unit, and
    // lists only the account's self-service.
    const { scope: _scope, unit: _unit, multi_unit: _multiUnit, ...offSession } = platformSession({ permissions: ['account.self'] })
    vi.mocked(getSession).mockResolvedValue(offSession)
    for (const route of ['/platform/units', '/jobs', '/']) {
      const onLogout = vi.fn(async () => {})
      const view = renderWithProviders(<><ProtectedApp onLogout={onLogout} /><CurrentPath /></>, { route: [route] })
      expect(await screen.findByRole('heading', { name: 'Business units are turned off' })).toBeInTheDocument()
      expect(screen.getByText('Morgan Reyes')).toBeInTheDocument()
      expect(screen.getByTestId('current-path')).toHaveTextContent(new RegExp(`^${route}$`))
      expect(screen.queryByRole('complementary', { name: 'Primary navigation', hidden: true })).not.toBeInTheDocument()
      expect(screen.queryByRole('link')).not.toBeInTheDocument()
      fireEvent.click(screen.getByRole('button', { name: 'Sign out' }))
      expect(onLogout).toHaveBeenCalledTimes(1)
      view.unmount()
    }
    for (const request of [listIncidents, listJobs, adminStatus, listUnits, platformStatus, recordActivity]) expect(request).not.toHaveBeenCalled()
    expect(EventSourceStub.instances).toBe(0)
  })

  it('redirects a session without jobs.read to a page it can open, and stops there', async () => {
    const locations: string[] = []
    function LocationLog() {
      const location = useLocation()
      locations.push(`${location.pathname}#${location.key}`)
      return null
    }
    vi.mocked(getSession).mockResolvedValue(unitAdministrator({ role: 'operator', permissions: ['account.self'] }))
    for (const route of ['/jobs', '/', '/incidents', '/unknown']) {
      locations.length = 0
      const view = renderWithProviders(<><ProtectedApp onLogout={async () => {}} /><CurrentPath /><LocationLog /></>, { route: [route] })
      expect(await screen.findByRole('heading', { name: 'Security' })).toBeInTheDocument()
      expect(screen.getByTestId('current-path')).toHaveTextContent('/security')
      // One navigation from the requested page to Security, and no further.
      expect(new Set(locations).size).toBe(2)
      view.unmount()
    }
    expect(listJobs).not.toHaveBeenCalled()
  })
})
