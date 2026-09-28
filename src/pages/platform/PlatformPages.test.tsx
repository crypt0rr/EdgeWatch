/** @vitest-environment jsdom */

import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { APIError, createPlatformNotification, deletePlatformNotification, getSession, invitePlatformAdmin, listPlatformAdmins, listPlatformNotifications, listUnits, platformAudit, platformStatus, setPlatformAdminEnabled, updatePlatformNotification, updatePlatformNotificationRouting } from '../../api'
import type { AuditEntry, NotificationDestination, UserSummary } from '../../api'
import { businessUnit, deploymentLimits as limits, platformSession } from '../../test/platform-fixtures'
import { renderWithProviders } from '../../test/test-utils'
import { PlatformAdmins } from './PlatformAdmins'
import { dayBound, PlatformAudit } from './PlatformAudit'
import { PlatformNotifications } from './PlatformNotifications'
import { PlatformStatusPage, updateSummary } from './PlatformStatus'

vi.mock('../../api', async () => {
  const actual = await vi.importActual<typeof import('../../api')>('../../api')
  return { ...actual, createPlatformNotification: vi.fn(), deletePlatformNotification: vi.fn(), getSession: vi.fn(), invitePlatformAdmin: vi.fn(), listPlatformAdmins: vi.fn(), listPlatformNotifications: vi.fn(), listUnits: vi.fn(), platformAudit: vi.fn(), platformStatus: vi.fn(), setPlatformAdminEnabled: vi.fn(), updatePlatformNotification: vi.fn(), updatePlatformNotificationRouting: vi.fn() }
})

function admin(overrides: Partial<UserSummary> & Pick<UserSummary, 'id' | 'username'>): UserSummary {
  return { display_name: overrides.username, role: 'platform_admin', enabled: true, pending: false, totp_enabled: true, created_at: '2026-08-01T00:00:00Z', updated_at: '2026-08-01T00:00:00Z', revision: 1, ...overrides }
}

function destination(overrides: Partial<NotificationDestination> & Pick<NotificationDestination, 'id' | 'name'>): NotificationDestination {
  return { provider: 'generic', source: 'web', enabled: true, locked: false, read_only: false, revision: 1, ...overrides }
}

function auditEntry(id: number, overrides: Partial<AuditEntry> = {}): AuditEntry {
  return { id, created_at: '2026-09-20T10:00:00Z', action: 'user.created', category: 'account', actor: { kind: 'platform', username: 'morgan', display_name: 'Morgan Reyes' }, detail: `entry ${id}`, ...overrides }
}

async function confirmWithPassword(label = 'Your password', password = 'my-password') {
  const dialog = await screen.findByRole('dialog')
  await act(async () => {
    fireEvent.change(within(dialog).getByLabelText(label), { target: { value: password } })
    fireEvent.submit(within(dialog).getByLabelText(label).closest('form')!)
    await Promise.resolve()
  })
  return dialog
}

afterEach(() => vi.clearAllMocks())

describe('platform administrators', () => {
  beforeEach(() => {
    vi.mocked(getSession).mockResolvedValue(platformSession())
    vi.mocked(listPlatformAdmins).mockResolvedValue({ admins: [
      admin({ id: 'acct-morgan', username: 'morgan', display_name: 'Morgan Reyes', last_login_at: '2026-09-24T08:00:00Z' }),
      admin({ id: 'acct-sam', username: 'sam', totp_enabled: false, revision: 3 }),
      admin({ id: 'acct-kim', username: 'kim', enabled: false }),
      admin({ id: 'acct-lee', username: 'lee', pending: true, enabled: false }),
    ] })
    vi.mocked(invitePlatformAdmin).mockResolvedValue({ user: admin({ id: 'acct-new', username: 'avery', pending: true, enabled: false }), activation_token: 'token', activation_path: '/activate#token=token' })
    vi.mocked(setPlatformAdminEnabled).mockResolvedValue(admin({ id: 'acct-sam', username: 'sam', enabled: false }))
  })

  it('lists them and enables or disables another, never itself or a pending one', async () => {
    renderWithProviders(<PlatformAdmins />)
    const self = await screen.findByTestId('admin-morgan')
    await waitFor(() => expect(within(self).getByText('Morgan Reyes (you)')).toBeInTheDocument())
    expect(within(self).queryByRole('button')).not.toBeInTheDocument()
    expect(within(screen.getByTestId('admin-lee')).queryByRole('button')).not.toBeInTheDocument()
    expect(within(screen.getByTestId('admin-lee')).getByText('Pending activation')).toBeInTheDocument()
    expect(within(screen.getByTestId('admin-sam')).getByText('No TOTP')).toBeInTheDocument()
    expect(within(screen.getByTestId('admin-kim')).getByRole('button', { name: 'Enable' })).toBeInTheDocument()

    vi.mocked(setPlatformAdminEnabled).mockRejectedValueOnce(new APIError('the platform keeps at least one enabled platform administrator', 'last_platform_admin'))
    fireEvent.click(within(screen.getByTestId('admin-sam')).getByRole('button', { name: 'Disable' }))
    const dialog = await confirmWithPassword()
    expect(await within(dialog).findByText('the platform keeps at least one enabled platform administrator')).toBeInTheDocument()
    await act(async () => {
      fireEvent.submit(within(dialog).getByLabelText('Your password').closest('form')!)
      await Promise.resolve()
    })
    await waitFor(() => expect(setPlatformAdminEnabled).toHaveBeenLastCalledWith('acct-sam', false, 3, 'my-password'))
    expect(await screen.findByText('sam disabled and signed out.')).toBeInTheDocument()
    fireEvent.click(within(screen.getByTestId('admin-kim')).getByRole('button', { name: 'Enable' }))
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Cancel' }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('invites another platform administrator with a one-time link', async () => {
    renderWithProviders(<PlatformAdmins />)
    await screen.findByTestId('admin-morgan')
    fireEvent.change(screen.getByLabelText(/^Username/), { target: { value: 'a:b' } })
    fireEvent.submit(screen.getByLabelText(/^Username/).closest('form')!)
    expect(await screen.findByText(/cannot contain control characters/)).toBeInTheDocument()
    vi.mocked(invitePlatformAdmin).mockRejectedValueOnce(new APIError('username is not available', 'conflict', { username: 'username is not available' }))
    fireEvent.change(screen.getByLabelText(/^Username/), { target: { value: 'avery' } })
    fireEvent.change(screen.getByLabelText('Your password'), { target: { value: 'my-password' } })
    fireEvent.submit(screen.getByLabelText(/^Username/).closest('form')!)
    expect(await screen.findByText('username is not available')).toBeInTheDocument()
    fireEvent.submit(screen.getByLabelText(/^Username/).closest('form')!)
    await waitFor(() => expect(invitePlatformAdmin).toHaveBeenLastCalledWith({ username: 'avery', display_name: '', password: 'my-password' }))
    expect(await screen.findByLabelText('Activation link for avery')).toHaveTextContent('/activate#token=token')
  })

  it('reports a list that cannot be loaded', async () => {
    vi.mocked(listPlatformAdmins).mockRejectedValueOnce(new Error('offline'))
    renderWithProviders(<PlatformAdmins />)
    expect(await screen.findByText('Could not load the platform administrators.')).toBeInTheDocument()
  })
})

describe('platform notifications', () => {
  beforeEach(() => {
    vi.mocked(listPlatformNotifications).mockResolvedValue({
      destinations: [destination({ id: 'p-ops', name: 'Operations', revision: 2 }), destination({ id: 'p-sec', name: 'Security desk', enabled: false })],
      status: { deployment: 0, managed: 2, active: 1, locked: 0, key_state: 'ready', config_import: 'imported' },
      update_routing: { configured: false, destinations: [] },
    })
    vi.mocked(createPlatformNotification).mockResolvedValue(destination({ id: 'p-new', name: 'New' }))
    vi.mocked(updatePlatformNotification).mockResolvedValue(destination({ id: 'p-ops', name: 'Operations' }))
    vi.mocked(deletePlatformNotification).mockResolvedValue(undefined)
    vi.mocked(updatePlatformNotificationRouting).mockResolvedValue({ configured: true, destinations: ['p-ops'] })
  })

  it('manages the platform’s own destinations with write-only URLs and routes update alerts to none by default', async () => {
    renderWithProviders(<PlatformNotifications />)
    expect(await screen.findByText('Operations')).toBeInTheDocument()
    expect(screen.getByText(/Each business unit manages its own destinations/)).toBeInTheDocument()
    // The platform's routing never defaults to every enabled destination.
    expect(screen.getByRole('checkbox', { name: 'Enable update alerts for Operations' })).not.toBeChecked()
    expect(screen.queryByRole('button', { name: /Test/ })).not.toBeInTheDocument()
    expect(document.querySelector('.notification-config-import')).toBeNull()

    fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'Pager' } })
    fireEvent.change(screen.getByLabelText(/^Shoutrrr URL/), { target: { value: 'generic://pager.example.test/hook' } })
    fireEvent.change(screen.getByLabelText(/^Password confirmation/), { target: { value: 'my-password' } })
    await act(async () => {
      fireEvent.submit(screen.getByLabelText(/^Name/).closest('form')!)
      await Promise.resolve()
    })
    await waitFor(() => expect(createPlatformNotification).toHaveBeenCalledWith('Pager', 'generic://pager.example.test/hook', 'my-password', true))
    expect(await screen.findByText(/The URL is stored encrypted and will not be shown again/)).toBeInTheDocument()

    fireEvent.click(screen.getByRole('checkbox', { name: 'Enable update alerts for Operations' }))
    await confirmWithPassword('Account password')
    await waitFor(() => expect(updatePlatformNotificationRouting).toHaveBeenCalledWith(['p-ops'], 'my-password'))

    const operations = screen.getByText('Operations').closest('.notification-row') as HTMLElement
    fireEvent.click(within(operations).getByRole('button', { name: 'Pause' }))
    await confirmWithPassword('Account password')
    await waitFor(() => expect(updatePlatformNotification).toHaveBeenCalledWith('p-ops', 2, 'Operations', 'my-password', { enabled: false }))
    fireEvent.click(within(operations).getByRole('button', { name: /Remove/ }))
    await confirmWithPassword('Account password')
    await waitFor(() => expect(deletePlatformNotification).toHaveBeenCalledWith('p-ops', 2, 'my-password'))
  })
})

describe('platform audit', () => {
  beforeEach(() => {
    vi.mocked(listUnits).mockResolvedValue({ limits, units: [businessUnit()] })
    vi.mocked(platformAudit).mockImplementation(async query => query?.before
      ? { entries: [auditEntry(1, { unit: { id: 'unit-gone', name: '', slug: '' } })], next_before: null }
      : { entries: [auditEntry(3, { unit: { id: 'unit-retail', name: 'Retail', slug: 'retail' }, source_ip: '203.0.113.9' }), auditEntry(2, { action: 'tenant.created', actor: { kind: 'host' }, detail: 'created from the host' })], next_before: 2 })
  })

  it('pages the platform audit and names each entry’s unit', async () => {
    renderWithProviders(<PlatformAudit />)
    const entries = await screen.findByRole('list', { name: 'Audit entries' })
    expect(within(entries).getByText('entry 3')).toBeInTheDocument()
    expect(within(entries).getByText('Retail')).toBeInTheDocument()
    expect(within(entries).getByText('From 203.0.113.9')).toBeInTheDocument()
    expect(within(entries).getByText('Platform', { selector: '.audit-unit' })).toBeInTheDocument()
    expect(within(entries).getByText('Host command line')).toBeInTheDocument()
    expect(platformAudit).toHaveBeenLastCalledWith({ before: null, unit: undefined, action: undefined, since: undefined, until: undefined })
    fireEvent.click(screen.getByRole('button', { name: 'Load older' }))
    await waitFor(() => expect(platformAudit).toHaveBeenLastCalledWith(expect.objectContaining({ before: 2 })))
    expect(await within(entries).findByText('entry 1')).toBeInTheDocument()
    expect(within(entries).getByText('Unknown unit')).toBeInTheDocument()
    expect(screen.getByText('No older entries.')).toBeInTheDocument()
  })

  it('filters by unit, action, and days', async () => {
    renderWithProviders(<PlatformAudit />)
    await screen.findByRole('list', { name: 'Audit entries' })
    await waitFor(() => expect(screen.getByRole('option', { name: 'Retail' })).toBeInTheDocument())
    fireEvent.change(screen.getByLabelText('Unit'), { target: { value: 'unit-retail' } })
    fireEvent.change(screen.getByLabelText('Action starts with'), { target: { value: ' user. ' } })
    fireEvent.change(screen.getByLabelText('On or after'), { target: { value: '2026-09-01' } })
    fireEvent.change(screen.getByLabelText('On or before'), { target: { value: '2026-09-30' } })
    await waitFor(() => expect(platformAudit).toHaveBeenLastCalledWith({ before: null, unit: 'unit-retail', action: 'user.', since: dayBound('2026-09-01'), until: dayBound('2026-09-30', 1) }))
    vi.mocked(platformAudit).mockResolvedValue({ entries: [], next_before: null })
    fireEvent.click(screen.getByRole('button', { name: 'Clear filters' }))
    await waitFor(() => expect(platformAudit).toHaveBeenLastCalledWith({ before: null, unit: undefined, action: undefined, since: undefined, until: undefined }))
  })

  it('turns a day into a local-midnight RFC 3339 bound', () => {
    expect(dayBound('')).toBeUndefined()
    expect(dayBound('not a day')).toBeUndefined()
    expect(dayBound('2026-09-01')).toBe(new Date(2026, 8, 1).toISOString().replace(/\.\d{3}Z$/, 'Z'))
    expect(dayBound('2026-09-30', 1)).toBe(new Date(2026, 9, 1).toISOString().replace(/\.\d{3}Z$/, 'Z'))
  })
})

describe('platform status', () => {
  it('shows the deployment as numbers and its release status', async () => {
    vi.mocked(platformStatus).mockResolvedValue({ version: 'v0.19.0', version_release_url: 'https://example.test/v0.19.0', updates: { enabled: true, status: 'update_available', available: true, current_version: 'v0.19.0', latest_version: 'v0.20.0', release_url: 'https://example.test/v0.20.0' }, units: { total: 3, active: 2, disabled: 1, deleting: 0 }, accounts: 12, jobs: 9, stored_scans: 4321, platform_admins: { total: 2, enabled: 1 }, capacity: { limits, slots: { capacity: 4, in_use: 3, queued: 1 } } })
    renderWithProviders(<PlatformStatusPage />)
    expect(await screen.findByText('2 active · 1 disabled · 0 deleting')).toBeInTheDocument()
    expect(screen.getByText('9 jobs across all units')).toBeInTheDocument()
    expect(screen.getByText('enabled of 2')).toBeInTheDocument()
    expect(screen.getByText('3 of 4')).toBeInTheDocument()
    expect(screen.getByText('1 scan queued')).toBeInTheDocument()
    expect(screen.getByText('Version v0.20.0 is available.')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'EdgeWatch v0.19.0' })).toHaveAttribute('href', 'https://example.test/v0.19.0')
    expect(screen.getByRole('link', { name: 'v0.20.0' })).toHaveAttribute('href', 'https://example.test/v0.20.0')
  })

  it('reports a status that cannot be loaded and describes each release state', async () => {
    vi.mocked(platformStatus).mockRejectedValueOnce(new Error('offline'))
    renderWithProviders(<PlatformStatusPage />)
    expect(await screen.findByText('Could not load the platform status.')).toBeInTheDocument()
    const status = (value: string) => ({ enabled: true, status: value, current_version: 'v1' })
    expect(updateSummary(undefined)).toBe('Release checks are off.')
    expect(updateSummary(status('up_to_date'))).toBe('Up to date.')
    expect(updateSummary(status('check_failed'))).toBe('The last release check failed.')
    expect(updateSummary(status('development_build'))).toContain('development build')
    expect(updateSummary(status('ahead'))).toBe('Newer than the latest release.')
    expect(updateSummary(status('something-new'))).toBe('Release status unknown.')
    expect(updateSummary({ ...status('update_available') })).toBe('Version unknown is available.')
  })
})
