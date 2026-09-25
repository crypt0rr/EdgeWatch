/** @vitest-environment jsdom */

import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { getSession, unitAudit } from '../api'
import type { AuditEntry } from '../api'
import { renderWithProviders } from '../test/test-utils'
import { Audit } from './Audit'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return { ...actual, getSession: vi.fn(), unitAudit: vi.fn() }
})

const retail = { id: 'unit-retail', name: 'Retail', slug: 'retail' }
const entry = (id: number, overrides: Partial<AuditEntry> = {}): AuditEntry => ({ id, at: '2026-09-20T10:00:00Z', action: 'auth.session_created', category: 'account', actor: { kind: 'unit', username: 'casey', display_name: 'Casey Lindqvist' }, unit: retail, target: 'casey', detail: `Row ${id}`, ...overrides })

describe('unit audit page', () => {
  beforeEach(() => {
    vi.mocked(getSession).mockResolvedValue({ user_id: 'acct-riley', username: 'riley', role: 'administrator', permissions: ['audit.read'], csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 }, scope: 'unit', unit: retail, multi_unit: true })
    vi.mocked(unitAudit).mockImplementation(async ({ before } = {}) => before == null
      ? { entries: [entry(60, { action: 'user.password_reset_issued', actor: { kind: 'platform', username: 'morgan', display_name: 'Morgan Reyes' }, target: 'riley', detail: 'Password reset link issued by a main administrator.' }), entry(59)], next_before: 59 }
      : { entries: [entry(12, { action: 'user.totp_disabled', actor: { kind: 'host', username: 'host-cli' }, target: 'dana', detail: 'TOTP disabled from the host.' })], next_before: null })
  })
  afterEach(() => vi.clearAllMocks())

  it('shows main-administrator actions with scope badges and loads older rows by keyset', async () => {
    renderWithProviders(<Audit />)
    expect(await screen.findByText('Password reset link issued by a main administrator.')).toBeInTheDocument()
    await waitFor(() => expect(screen.getByText(/configuration changes in Retail/)).toBeInTheDocument())
    const list = screen.getByRole('list', { name: 'Audit entries' })
    expect(within(list).getAllByRole('listitem')).toHaveLength(2)
    expect(within(list).getByText('Platform', { selector: '.pill' })).toBeInTheDocument()
    expect(within(list).getByText('Morgan Reyes')).toBeInTheDocument()
    expect(within(list).getByText('Target: riley')).toBeInTheDocument()
    expect(within(list).queryByText('Target: casey')).not.toBeInTheDocument()
    expect(unitAudit).toHaveBeenCalledWith({ before: null })

    fireEvent.click(screen.getByRole('button', { name: 'Load older' }))
    await waitFor(() => expect(unitAudit).toHaveBeenLastCalledWith({ before: 59 }))
    expect(await within(list).findByText('TOTP disabled from the host.')).toBeInTheDocument()
    expect(within(list).getAllByRole('listitem')).toHaveLength(3)
    expect(within(list).getByText('Host', { selector: '.pill' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Load older' })).not.toBeInTheDocument()
    expect(screen.getByText('No older entries.')).toBeInTheDocument()
  })

  it('reports a failed first page with a retry and a failed older page inline', async () => {
    vi.mocked(unitAudit).mockRejectedValueOnce(new Error('offline'))
    renderWithProviders(<Audit />)
    expect(await screen.findByText(/Could not load the audit log/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByText('Row 59')).toBeInTheDocument()
    vi.mocked(unitAudit).mockRejectedValueOnce(new Error('offline'))
    fireEvent.click(screen.getByRole('button', { name: 'Load older' }))
    expect(await screen.findByText('Could not load older entries. Try again.')).toBeInTheDocument()
    expect(screen.getByText('Row 59')).toBeInTheDocument()
  })

  it('explains an empty audit log', async () => {
    vi.mocked(unitAudit).mockResolvedValue({ entries: [], next_before: null })
    renderWithProviders(<Audit />)
    expect(await screen.findByText('No audit entries have been recorded for this unit yet.')).toBeInTheDocument()
    expect(screen.queryByText('No older entries.')).not.toBeInTheDocument()
  })
})
