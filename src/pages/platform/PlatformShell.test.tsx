/** @vitest-environment jsdom */

import { act, fireEvent, screen, waitFor } from '@testing-library/react'
import { useLocation } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { getSession, listIncidents, listJobs, listUnits, platformAudit, platformCapacity, recordActivity } from '../../api'
import { renderWithProviders } from '../../test/test-utils'
import { PlatformShell } from './PlatformShell'

vi.mock('../../api', async () => {
  const actual = await vi.importActual<typeof import('../../api')>('../../api')
  return { ...actual, getSession: vi.fn(), listIncidents: vi.fn(), listJobs: vi.fn(), listUnits: vi.fn(), platformAudit: vi.fn(), platformCapacity: vi.fn(), recordActivity: vi.fn() }
})

const platformPermissions = ['units.manage', 'unit_accounts.manage', 'platform_audit.read', 'platform_notifications.manage', 'platform_status.read', 'account.self']
const limits = { max_concurrent_scans: 4, max_probe_count: 5_000_000, max_naabu_probe_count: 20_000_000, max_probe_count_limit: 100_000_000 }

function Location() {
  return <output data-testid="location">{useLocation().pathname}</output>
}

function renderShell(path: string, permissions = platformPermissions, onLogout = vi.fn()) {
  return renderWithProviders(<><PlatformShell displayName="Morgan Reyes" permissions={permissions} onLogout={onLogout} /><Location /></>, { route: [path] })
}

describe('platform console shell', () => {
  beforeEach(() => {
    vi.mocked(listUnits).mockResolvedValue({ limits, units: [] })
    vi.mocked(platformCapacity).mockResolvedValue({ version: 'v0.18.145', limits, totals: { slots_in_use: 0, queued: 0, slot_caps: 0 }, units: [] })
    vi.mocked(getSession).mockResolvedValue({ user_id: 'acct-morgan', username: 'morgan', role: 'platform_admin', permissions: platformPermissions, csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 }, scope: 'platform', unit: null, multi_unit: true })
    vi.mocked(recordActivity).mockResolvedValue(undefined)
    vi.mocked(platformAudit).mockResolvedValue({ entries: [], next_before: null })
  })
  afterEach(() => { vi.unstubAllGlobals(); vi.clearAllMocks() })

  it('offers only platform navigation', async () => {
    const onLogout = vi.fn()
    renderShell('/platform/units', platformPermissions, onLogout)
    for (const label of ['Units', 'Platform admins', 'Capacity', 'Deployment notifications', 'Audit', 'Security']) expect(screen.getByRole('link', { name: label })).toBeInTheDocument()
    for (const label of ['Overview', 'Jobs', 'Hosts', 'Incidents', 'Notifications', 'Users', 'Public status', 'Scanner profiles']) expect(screen.queryByRole('link', { name: label })).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Units' })).toHaveAttribute('aria-current', 'page')
    expect(screen.getByText('Main administration')).toBeInTheDocument()
    expect(screen.getByLabelText('Breadcrumb: Platform / Units')).toBeInTheDocument()
    await waitFor(() => expect(screen.getByText('EdgeWatch v0.18.145')).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }))
    expect(onLogout).toHaveBeenCalledOnce()
  })

  it('redirects every unit route to the unit list without requesting unit data', async () => {
    for (const path of ['/', '/jobs', '/jobs/job-1', '/hosts', '/incidents', '/notifications', '/users', '/audit', '/public-dashboard', '/scanner-profiles']) {
      const view = renderShell(path)
      await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent('/platform/units'))
      expect(await screen.findByRole('heading', { name: 'Business units' })).toBeInTheDocument()
      view.unmount()
    }
    expect(listJobs).not.toHaveBeenCalled()
    expect(listIncidents).not.toHaveBeenCalled()
  })

  it('guards pages by platform permission and always keeps Security', async () => {
    renderShell('/platform/audit', ['account.self'])
    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent('/security'))
    expect(screen.getByRole('link', { name: 'Security' })).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Units' })).not.toBeInTheDocument()
    expect(platformCapacity).not.toHaveBeenCalled()
    expect(screen.getByText('EdgeWatch dev')).toBeInTheDocument()
  })

  it('opens and closes the mobile navigation drawer', async () => {
    vi.stubGlobal('matchMedia', vi.fn().mockReturnValue({ matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn() }))
    renderShell('/platform/capacity')
    const menu = screen.getByRole('button', { name: 'Open navigation' })
    expect(menu).toHaveAttribute('aria-expanded', 'false')
    fireEvent.click(menu)
    expect(screen.getByRole('dialog', { name: 'Primary navigation' })).toBeInTheDocument()
    act(() => { fireEvent.keyDown(document, { key: 'Escape' }) })
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Primary navigation' })).not.toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: 'Open navigation' }))
    fireEvent.click(screen.getByRole('link', { name: 'Audit' }))
    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent('/platform/audit'))
    expect(screen.queryByRole('dialog', { name: 'Primary navigation' })).not.toBeInTheDocument()
  })
})
