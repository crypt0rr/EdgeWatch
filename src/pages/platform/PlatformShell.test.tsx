/** @vitest-environment jsdom */

import { act, fireEvent, screen, waitFor } from '@testing-library/react'
import { useLocation } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { activeScans, adminStatus, getSession, getUnitCapacity, listIncidents, listJobs, listScans, listUnits, platformAudit, platformStatus, recordActivity } from '../../api'
import type { PlatformStatus } from '../../api'
import { deploymentLimits as limits, platformPermissions, platformSession } from '../../test/platform-fixtures'
import { renderWithProviders } from '../../test/test-utils'
import { PlatformShell } from './PlatformShell'

vi.mock('../../api', async () => {
  const actual = await vi.importActual<typeof import('../../api')>('../../api')
  return { ...actual, activeScans: vi.fn(), adminStatus: vi.fn(), getSession: vi.fn(), getUnitCapacity: vi.fn(), listIncidents: vi.fn(), listJobs: vi.fn(), listScans: vi.fn(), listUnits: vi.fn(), platformAudit: vi.fn(), platformStatus: vi.fn(), recordActivity: vi.fn() }
})

const status: PlatformStatus = { version: 'v0.19.0', units: { total: 2, active: 2, disabled: 0, deleting: 0 }, accounts: 5, jobs: 3, platform_admins: { total: 1, enabled: 1 }, capacity: { limits, slots: { capacity: 4, in_use: 1, queued: 0 } } }

function Location() {
  return <output data-testid="location">{useLocation().pathname}</output>
}

function renderShell(path: string, permissions = platformPermissions, onLogout = vi.fn()) {
  return renderWithProviders(<><PlatformShell displayName="Morgan Reyes" permissions={permissions} onLogout={onLogout} /><Location /></>, { route: [path] })
}

class EventSourceStub {
  static instances = 0
  constructor() { EventSourceStub.instances += 1 }
  close() {}
}

describe('platform console shell', () => {
  beforeEach(() => {
    vi.mocked(listUnits).mockResolvedValue({ limits, units: [] })
    vi.mocked(platformStatus).mockResolvedValue(status)
    vi.mocked(getSession).mockResolvedValue(platformSession())
    vi.mocked(recordActivity).mockResolvedValue(undefined)
    vi.mocked(platformAudit).mockResolvedValue({ entries: [], next_before: null })
    vi.mocked(getUnitCapacity).mockRejectedValue(new Error('not used'))
    EventSourceStub.instances = 0
    vi.stubGlobal('EventSource', EventSourceStub)
  })
  afterEach(() => { vi.unstubAllGlobals(); vi.clearAllMocks() })

  it('offers only the platform navigation', async () => {
    const onLogout = vi.fn()
    renderShell('/platform/units', platformPermissions, onLogout)
    for (const label of ['Units', 'Platform admins', 'Notifications', 'Audit', 'Status', 'Security']) expect(screen.getByRole('link', { name: label })).toBeInTheDocument()
    for (const label of ['Overview', 'Jobs', 'Hosts', 'Incidents', 'Users', 'Public status', 'Scanner profiles']) expect(screen.queryByRole('link', { name: label })).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Units' })).toHaveAttribute('aria-current', 'page')
    expect(screen.getByText('All business units')).toBeInTheDocument()
    expect(screen.getByText('Platform administrator')).toBeInTheDocument()
    expect(screen.getByLabelText('Breadcrumb: Platform / Units')).toBeInTheDocument()
    await waitFor(() => expect(screen.getByText('EdgeWatch v0.19.0')).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }))
    expect(onLogout).toHaveBeenCalledOnce()
    expect(EventSourceStub.instances).toBe(0)
  })

  it('never mounts a unit page: every unit route leads to the unit list without requesting unit data', async () => {
    for (const path of ['/', '/highlights', '/jobs', '/jobs/new', '/jobs/job-1', '/jobs/job-1/baseline', '/hosts', '/scans/scan-1', '/incidents', '/notifications', '/users', '/audit', '/public-dashboard', '/scanner-profiles', '/platform', '/platform/unknown']) {
      const view = renderShell(path)
      await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent(/^\/platform\/units$/))
      expect(await screen.findByRole('heading', { name: 'Business units' })).toBeInTheDocument()
      view.unmount()
    }
    for (const unitRequest of [listJobs, listIncidents, listScans, activeScans, adminStatus]) expect(unitRequest).not.toHaveBeenCalled()
    expect(EventSourceStub.instances).toBe(0)
  })

  it('guards each page by its platform permission and always keeps Security', async () => {
    const view = renderShell('/platform/audit', ['account.self'])
    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent('/security'))
    expect(screen.getByRole('link', { name: 'Security' })).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Units' })).not.toBeInTheDocument()
    expect(platformStatus).not.toHaveBeenCalled()
    expect(screen.getByText('EdgeWatch dev')).toBeInTheDocument()
    view.unmount()

    renderShell('/platform/units', ['account.self', 'platform_audit.read'])
    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent('/platform/audit'))
    expect(await screen.findByRole('heading', { name: 'Audit' })).toBeInTheDocument()
    expect(listUnits).toHaveBeenCalled()
    expect(screen.getByLabelText('Breadcrumb: Platform / Audit')).toBeInTheDocument()
  })

  it('opens and closes the mobile navigation drawer', async () => {
    vi.stubGlobal('matchMedia', vi.fn().mockReturnValue({ matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn() }))
    renderShell('/platform/status')
    expect(await screen.findByRole('heading', { name: 'Status' })).toBeInTheDocument()
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
