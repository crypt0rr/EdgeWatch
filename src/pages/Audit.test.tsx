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

function entry(id: number, overrides: Partial<AuditEntry> = {}): AuditEntry {
  return { id, created_at: '2026-09-20T10:00:00Z', action: 'job.updated', category: 'data', actor: { kind: 'unit', username: 'riley', display_name: 'Riley Novak' }, detail: `entry ${id}`, ...overrides }
}

describe('unit audit', () => {
  beforeEach(() => {
    vi.mocked(getSession).mockResolvedValue({ user_id: 'acct-riley', username: 'riley', role: 'administrator', permissions: ['audit.read'], csrf_token: '', totp_enabled: true, password_requirements: { minimum_length: 12 }, scope: 'unit', unit: { id: 'unit-retail', name: 'Retail', slug: 'retail' }, multi_unit: true })
  })
  afterEach(() => vi.clearAllMocks())

  it('pages older entries by keyset without repeating or shifting the ones shown', async () => {
    vi.mocked(unitAudit)
      .mockResolvedValueOnce({ entries: [entry(9, { source_ip: '203.0.113.4' }), entry(8, { action: 'user.password_reset_issued', actor: { kind: 'platform', username: 'morgan' }, detail: 'password reset issued for riley by platform administrator morgan' })], next_before: 8 })
      .mockRejectedValueOnce(new Error('offline'))
      .mockResolvedValueOnce({ entries: [entry(7, { actor: { kind: 'host' }, detail: 'reset from the host' }), entry(6, { actor: { kind: 'system' } }), entry(5, { actor: { kind: '' } })], next_before: null })
    renderWithProviders(<Audit />)
    const list = await screen.findByRole('list', { name: 'Audit entries' })
    expect(await screen.findByText(/in Retail/)).toBeInTheDocument()
    expect(within(list).getAllByRole('listitem')).toHaveLength(2)
    expect(within(list).getByText('Riley Novak')).toBeInTheDocument()
    expect(within(list).getByText('· riley')).toBeInTheDocument()
    expect(within(list).getByText('From 203.0.113.4')).toBeInTheDocument()
    expect(within(list).getByText('Platform', { selector: '.pill' })).toBeInTheDocument()
    expect(within(list).queryByText(/No unit|Unknown unit/)).not.toBeInTheDocument()
    expect(unitAudit).toHaveBeenLastCalledWith({ before: null })

    fireEvent.click(screen.getByRole('button', { name: 'Load older' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not load older entries. Try again.')
    fireEvent.click(screen.getByRole('button', { name: 'Load older' }))
    await waitFor(() => expect(within(list).getAllByRole('listitem')).toHaveLength(5))
    expect(unitAudit).toHaveBeenLastCalledWith({ before: 8 })
    expect(within(list).getAllByRole('listitem').map(item => item.querySelector('p')?.textContent)).toEqual(['entry 9', 'password reset issued for riley by platform administrator morgan', 'reset from the host', 'entry 6', 'entry 5'])
    expect(within(list).getByText('Host command line')).toBeInTheDocument()
    expect(within(list).getByText('System')).toBeInTheDocument()
    expect(within(list).getByText('Account')).toBeInTheDocument()
    expect(screen.getByText('No older entries.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Load older' })).not.toBeInTheDocument()
  })

  it('offers a retry when the audit cannot be loaded, and explains an empty audit', async () => {
    vi.mocked(unitAudit).mockRejectedValueOnce(new Error('offline')).mockResolvedValueOnce({ entries: [], next_before: null })
    renderWithProviders(<Audit />)
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not load the audit log.')
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByText('No audit entries have been recorded yet.')).toBeInTheDocument()
  })

  it('names no unit when only one exists', async () => {
    vi.mocked(getSession).mockResolvedValue({ user_id: 'admin', username: 'admin', role: 'administrator', permissions: ['audit.read'], csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 }, scope: 'unit', unit: { id: 'default', name: 'Default', slug: 'default' }, multi_unit: false })
    vi.mocked(unitAudit).mockResolvedValue({ entries: [], next_before: null })
    renderWithProviders(<Audit />)
    await screen.findByText('No audit entries have been recorded yet.')
    await waitFor(() => expect(getSession).toHaveBeenCalled())
    expect(screen.queryByText(/in Default/)).not.toBeInTheDocument()
  })
})
