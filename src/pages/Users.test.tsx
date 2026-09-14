/** @vitest-environment jsdom */

import { fireEvent, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { APIError, createUser, issueUserActivation, listUsers, revokeUserActivation, updateUser } from '../api'
import { renderWithProviders } from '../test/test-utils'
import { Users } from './Users'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return { ...actual, createUser: vi.fn(), issueUserActivation: vi.fn(), listUsers: vi.fn(), revokeUserActivation: vi.fn(), updateUser: vi.fn() }
})

const user = { id: 'user-2', username: 'operator', display_name: 'Operator', role: 'operator' as const, enabled: true, pending: false, totp_enabled: false, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z', revision: 4 }
const pending = { ...user, id: 'user-3', username: 'new-user', display_name: 'New User', pending: true, enabled: false, revision: 1 }

describe('user administration', () => {
  beforeEach(() => {
    vi.mocked(listUsers).mockResolvedValue({ users: [user, pending] })
    vi.mocked(createUser).mockResolvedValue({ user, activation_token: 'token-123', activation_path: '/activate?token=token-123' })
    vi.mocked(issueUserActivation).mockResolvedValue({ activation_token: 'renewed-token', activation_path: '/activate?token=renewed-token', expires_at: '2026-01-01T01:00:00Z' })
    vi.mocked(revokeUserActivation).mockResolvedValue(undefined)
    vi.mocked(updateUser).mockResolvedValue({ ...user, enabled: false, revision: 5 })
  })
  afterEach(() => vi.clearAllMocks())

  it('creates an invitation, exposes the token once, and clears the form', async () => {
    renderWithProviders(<Users />)
    await waitFor(() => expect(screen.getByText('Operator')).toBeInTheDocument())
    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'operator' } })
    fireEvent.change(screen.getByLabelText('Display name'), { target: { value: 'Operator' } })
    fireEvent.change(screen.getByLabelText('Role'), { target: { value: 'operator' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create activation link' }))
    await waitFor(() => expect(createUser).toHaveBeenCalledWith('operator', 'Operator', 'operator'))
    expect(screen.getByText('token-123')).toBeInTheDocument()
    expect(screen.getByText(/Created operator/)).toBeInTheDocument()
  })

  it('toggles enabled users and handles optimistic-concurrency conflicts', async () => {
    renderWithProviders(<Users />)
    await waitFor(() => expect(screen.getByText('Operator')).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: 'Disable' }))
    await waitFor(() => expect(updateUser).toHaveBeenCalledWith('user-2', { enabled: false, revision: 4 }))
    expect(screen.getByText('operator disabled.')).toBeInTheDocument()

    vi.mocked(updateUser).mockRejectedValueOnce(new APIError('stale', 'conflict', { current: { ...user, revision: 5 } }))
    fireEvent.click(screen.getByRole('button', { name: 'Disable' }))
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('changed in another session'))
  })

  it('renews and revokes pending activation links', async () => {
    renderWithProviders(<Users />)
    await waitFor(() => expect(screen.getByRole('button', { name: 'Renew activation' })).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: 'Renew activation' }))
    await waitFor(() => expect(issueUserActivation).toHaveBeenCalledWith('user-3'))
    expect(screen.getByText('renewed-token')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Revoke link' }))
    await waitFor(() => expect(revokeUserActivation).toHaveBeenCalledWith('user-3'))
    expect(screen.getByText('The outstanding activation link was revoked.')).toBeInTheDocument()
  })

  it('renders API failures without hiding the account list', async () => {
    vi.mocked(listUsers).mockRejectedValue(new Error('database unavailable'))
    renderWithProviders(<Users />)
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Could not load users.'))
    expect(screen.getByRole('heading', { name: 'Users' })).toBeInTheDocument()
  })
})
