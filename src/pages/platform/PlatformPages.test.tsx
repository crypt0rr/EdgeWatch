/** @vitest-environment jsdom */

import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { APIError, getSession, invitePlatformAdmin, listDeploymentNotifications, listPlatformAdmins, listUnits, platformAudit, platformCapacity } from '../../api'
import type { AuditEntry, UserSummary } from '../../api'
import { renderWithProviders } from '../../test/test-utils'
import { Capacity } from './Capacity'
import { DeploymentNotifications } from './DeploymentNotifications'
import { PlatformAdmins } from './PlatformAdmins'
import { PLATFORM_ONLY, PlatformAudit } from './PlatformAudit'

vi.mock('../../api', async () => {
  const actual = await vi.importActual<typeof import('../../api')>('../../api')
  return { ...actual, getSession: vi.fn(), invitePlatformAdmin: vi.fn(), listDeploymentNotifications: vi.fn(), listPlatformAdmins: vi.fn(), listUnits: vi.fn(), platformAudit: vi.fn(), platformCapacity: vi.fn() }
})

const limits = { max_concurrent_scans: 4, max_probe_count: 5_000_000, max_naabu_probe_count: 20_000_000, max_probe_count_limit: 100_000_000 }
const admin = (overrides: Partial<UserSummary>): UserSummary => ({ id: 'acct-morgan', username: 'morgan', display_name: 'Morgan Reyes', role: 'platform_admin', enabled: true, pending: false, totp_enabled: false, created_at: '2026-08-01T00:00:00Z', updated_at: '2026-08-01T00:00:00Z', revision: 1, ...overrides })
const entry = (id: number, overrides: Partial<AuditEntry> = {}): AuditEntry => ({ id, at: '2026-09-20T10:00:00Z', action: 'auth.session_created', category: 'account', actor: { kind: 'unit', username: 'riley', display_name: 'Riley Novak' }, unit: { id: 'unit-retail', name: 'Retail', slug: 'retail' }, target: 'riley', detail: `Row ${id}`, ...overrides })

describe('platform pages', () => {
  beforeEach(() => {
    vi.mocked(getSession).mockResolvedValue({ user_id: 'acct-morgan', username: 'morgan', role: 'platform_admin', permissions: [], csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 }, scope: 'platform', unit: null, multi_unit: true })
    vi.mocked(listPlatformAdmins).mockResolvedValue({ admins: [admin({ last_login_at: '2026-09-25T08:00:00Z' }), admin({ id: 'acct-sam', username: 'sam', display_name: 'Sam Okafor', totp_enabled: true }), admin({ id: 'acct-new', username: 'kim', display_name: 'Kim', pending: true, enabled: false }), admin({ id: 'acct-old', username: 'old', display_name: 'Old', enabled: false })] })
    vi.mocked(invitePlatformAdmin).mockResolvedValue({ user: admin({ id: 'acct-kai', username: 'kai', pending: true }), activation_token: 'tok', activation_path: '/activate#token=tok' })
    vi.mocked(platformCapacity).mockResolvedValue({ version: 'v0.18.145', limits, totals: { slots_in_use: 3, queued: 1, slot_caps: 5 }, units: [
      { id: 'default', name: 'Default', slug: 'default', status: 'active', is_default: true, capacity: { slot_cap: 2, slots_in_use: 2, queued: 1, max_probe_count: 5_000_000, max_naabu_probe_count: 20_000_000 } },
      { id: 'unit-retail', name: 'Retail', slug: 'retail', status: 'active', is_default: false, capacity: { slot_cap: 2, slots_in_use: 1, queued: 0, max_probe_count: 2_000_000, max_naabu_probe_count: 10_000_000 } },
      { id: 'unit-zero', name: 'Zero', slug: 'zero', status: 'disabled', is_default: false, capacity: { slot_cap: 0, slots_in_use: 0, queued: 0, max_probe_count: 1, max_naabu_probe_count: 1 } },
      { id: 'unit-gone', name: 'Gone', slug: 'gone', status: 'deleted', is_default: false, capacity: { slot_cap: 1, slots_in_use: 0, queued: 0, max_probe_count: 1, max_naabu_probe_count: 1 } },
    ] })
    vi.mocked(listDeploymentNotifications).mockResolvedValue({ destinations: [
      { id: 'deploy-ops-slack', name: 'Ops Slack', provider: 'slack', enabled: true, units: [{ id: 'default', name: 'Default', slug: 'default' }, { id: 'unit-retail', name: 'Retail', slug: 'retail' }] },
      { id: 'deploy-pager', name: 'Pager', provider: 'pushover', enabled: false, units: [] },
    ] })
    vi.mocked(listUnits).mockResolvedValue({ limits, units: [
      { id: 'unit-retail', name: 'Retail', slug: 'retail', status: 'active', is_default: false, revision: 1, created_at: '', updated_at: '', accounts: 1, administrators: 1, pending_invitations: 0, public_enabled: false, capacity: { slot_cap: 1, slots_in_use: 0, queued: 0, max_probe_count: 1, max_naabu_probe_count: 1 } },
      { id: 'unit-gone', name: 'Gone', slug: 'gone', status: 'deleted', is_default: false, revision: 1, created_at: '', updated_at: '', accounts: 0, administrators: 0, pending_invitations: 0, public_enabled: false, capacity: { slot_cap: 1, slots_in_use: 0, queued: 0, max_probe_count: 1, max_naabu_probe_count: 1 } },
    ] })
    vi.mocked(platformAudit).mockResolvedValue({ entries: [entry(3), entry(2, { action: 'user.password_reset_issued', actor: { kind: 'platform', username: 'morgan', display_name: 'Morgan Reyes' }, detail: 'Reset link issued.' }), entry(1, { action: 'platform.setup_token_issued', category: 'platform', actor: { kind: 'host' }, unit: null, target: undefined })], next_before: null })
  })
  afterEach(() => vi.clearAllMocks())

  it('lists main administrators and invites a new one with a one-time link', async () => {
    renderWithProviders(<PlatformAdmins />)
    expect(await screen.findByText('Morgan Reyes (you)')).toBeInTheDocument()
    expect(screen.getByText('Sam Okafor')).toBeInTheDocument()
    expect(screen.getByText('Pending activation')).toBeInTheDocument()
    expect(screen.getByText('Disabled')).toBeInTheDocument()
    expect(screen.getAllByText('TOTP on')).toHaveLength(1)
    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'bad:name' } })
    fireEvent.change(screen.getByLabelText('Display name'), { target: { value: 'Kai' } })
    fireEvent.change(screen.getByLabelText('Your password'), { target: { value: 'my-password' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create activation link' }))
    expect(await screen.findByText(/cannot contain/)).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'kai' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create activation link' }))
    await waitFor(() => expect(invitePlatformAdmin).toHaveBeenCalledWith({ username: 'kai', display_name: 'Kai', password: 'my-password' }))
    expect(await screen.findByLabelText('Activation link for kai')).toHaveTextContent('/activate#token=tok')
    fireEvent.click(screen.getByRole('button', { name: 'Done' }))
    expect(screen.queryByLabelText('Activation link for kai')).not.toBeInTheDocument()

    vi.mocked(invitePlatformAdmin).mockRejectedValueOnce(new APIError('That username is already in use.', 'username_taken'))
    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'sam' } })
    fireEvent.change(screen.getByLabelText('Display name'), { target: { value: 'Sam' } })
    fireEvent.change(screen.getByLabelText('Your password'), { target: { value: 'my-password' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create activation link' }))
    expect(await screen.findByText('That username is already in use.')).toBeInTheDocument()
  })

  it('reports a failed administrator list', async () => {
    vi.mocked(listPlatformAdmins).mockRejectedValueOnce(new Error('offline'))
    renderWithProviders(<PlatformAdmins />)
    expect(await screen.findByText('Could not load main administrators.')).toBeInTheDocument()
  })

  it('shows deployment capacity totals and each unit’s share', async () => {
    renderWithProviders(<Capacity />)
    expect(await screen.findByText('3 of 4')).toBeInTheDocument()
    expect(screen.getByText(/Above the deployment total/)).toBeInTheDocument()
    const meter = screen.getByRole('meter', { name: 'Default scan slots in use' })
    expect(meter).toHaveAttribute('aria-valuenow', '2')
    expect(screen.getByText('2 in use · 1 queued · cap 2')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Edit capacity for Retail' })).toHaveAttribute('href', '/platform/units/unit-retail/capacity')
    expect(screen.getByRole('meter', { name: 'Zero scan slots in use' })).toHaveAttribute('aria-valuemax', '0')
    expect(screen.queryByText('Gone')).not.toBeInTheDocument()
    expect(screen.getByText('3 units · 3 in use · 1 queued')).toBeInTheDocument()
  })

  it('shows capacity within the deployment total, an empty list, and failures', async () => {
    vi.mocked(platformCapacity).mockResolvedValueOnce({ limits, totals: { slots_in_use: 0, queued: 0, slot_caps: 2 }, units: [] })
    const view = renderWithProviders(<Capacity />)
    expect(await screen.findByText('Within the deployment total')).toBeInTheDocument()
    expect(screen.getByText('No business units.')).toBeInTheDocument()
    view.unmount()
    vi.mocked(platformCapacity).mockRejectedValueOnce(new Error('offline'))
    renderWithProviders(<Capacity />)
    expect(await screen.findByText('Could not load scan capacity.')).toBeInTheDocument()
  })

  it('lists deployment destinations by name with their assigned units', async () => {
    const { container } = renderWithProviders(<DeploymentNotifications />)
    const units = await screen.findByLabelText('Units assigned to Ops Slack')
    expect(within(units).getByRole('link', { name: 'Retail' })).toHaveAttribute('href', '/platform/units/unit-retail/notifications')
    expect(screen.getByText('pushover · disabled in config.yaml')).toBeInTheDocument()
    expect(within(screen.getByLabelText('Units assigned to Pager')).getByText('Not assigned to any unit')).toBeInTheDocument()
    expect(container.textContent).not.toContain('://')
  })

  it('reports failed and empty deployment destination lists', async () => {
    vi.mocked(listDeploymentNotifications).mockRejectedValueOnce(new Error('offline'))
    const view = renderWithProviders(<DeploymentNotifications />)
    expect(await screen.findByText('Could not load deployment destinations.')).toBeInTheDocument()
    view.unmount()
    vi.mocked(listDeploymentNotifications).mockResolvedValueOnce({ destinations: [] })
    renderWithProviders(<DeploymentNotifications />)
    expect(await screen.findByText('config.yaml defines no deployment destinations.')).toBeInTheDocument()
  })

  it('filters the platform audit by unit, action prefix, and date', async () => {
    renderWithProviders(<PlatformAudit />)
    expect(await screen.findByText('Reset link issued.')).toBeInTheDocument()
    expect(platformAudit).toHaveBeenLastCalledWith({ before: null, unit: undefined, action: undefined, since: undefined })
    expect(screen.getByText('No unit (platform)')).toBeInTheDocument()
    expect(screen.getByText('Host command line')).toBeInTheDocument()
    const unitFilter = screen.getByLabelText('Unit')
    await waitFor(() => expect(within(unitFilter).getByRole('option', { name: 'Gone (deleted)' })).toBeInTheDocument())
    fireEvent.change(unitFilter, { target: { value: 'unit-retail' } })
    await waitFor(() => expect(platformAudit).toHaveBeenLastCalledWith({ before: null, unit: 'unit-retail', action: undefined, since: undefined }))
    fireEvent.change(unitFilter, { target: { value: PLATFORM_ONLY } })
    await waitFor(() => expect(platformAudit).toHaveBeenLastCalledWith({ before: null, unit: 'platform', action: undefined, since: undefined }))
    fireEvent.change(screen.getByLabelText('Action starts with'), { target: { value: ' user. ' } })
    await waitFor(() => expect(platformAudit).toHaveBeenLastCalledWith({ before: null, unit: 'platform', action: 'user.', since: undefined }))
    fireEvent.change(screen.getByLabelText('On or after'), { target: { value: '2026-09-01' } })
    await waitFor(() => expect(platformAudit).toHaveBeenLastCalledWith({ before: null, unit: 'platform', action: 'user.', since: '2026-09-01' }))
    fireEvent.click(screen.getByRole('button', { name: 'Clear filters' }))
    await waitFor(() => expect(platformAudit).toHaveBeenLastCalledWith({ before: null, unit: undefined, action: undefined, since: undefined }))
    expect(screen.queryByRole('button', { name: 'Clear filters' })).not.toBeInTheDocument()
  })

  it('explains when no platform audit entries match', async () => {
    vi.mocked(platformAudit).mockResolvedValue({ entries: [], next_before: null })
    renderWithProviders(<PlatformAudit />)
    expect(await screen.findByText('No audit entries yet.')).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('On or after'), { target: { value: '2030-01-01' } })
    expect(await screen.findByText('No audit entries match these filters.')).toBeInTheDocument()
  })
})
