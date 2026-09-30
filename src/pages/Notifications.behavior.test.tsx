/** @vitest-environment jsdom */

import { fireEvent, screen, waitFor } from '@testing-library/react'
import { act } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { APIError, createNotificationDestination, deleteNotificationDestination, getSession, listNotificationDestinations, testNotificationDestination, updateNotificationDestination } from '../api'
import { renderWithProviders, defaultUnitScope } from '../test/test-utils'
import { Notifications } from './Notifications'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return { ...actual, createNotificationDestination: vi.fn(), deleteNotificationDestination: vi.fn(), getSession: vi.fn(), listNotificationDestinations: vi.fn(), testNotificationDestination: vi.fn(), updateNotificationDestination: vi.fn() }
})

const destination = { id: 'destination-1', name: 'Mattermost', provider: 'mattermost', source: 'web', enabled: true, locked: false, revision: 4, pending: 1, retrying: 2, last_success_at: '2026-01-01T00:00:00Z' }
const response = { destinations: [destination], status: { deployment: 0, managed: 1, active: 1, locked: 0, key_state: 'ready' }, update_routing: { configured: true, destinations: ['destination-1'] } }

describe('notification destination workflows', () => {
  beforeEach(() => {
    vi.mocked(getSession).mockResolvedValue({ role: 'administrator', user_id: 'admin', username: 'admin', permissions: ['notifications.manage'], csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 }, ...defaultUnitScope })
    vi.mocked(listNotificationDestinations).mockResolvedValue(response as never)
    vi.mocked(createNotificationDestination).mockResolvedValue(destination as never)
    vi.mocked(updateNotificationDestination).mockResolvedValue(destination as never)
    vi.mocked(deleteNotificationDestination).mockResolvedValue(undefined)
    vi.mocked(testNotificationDestination).mockResolvedValue({ sent: 1 })
  })
  afterEach(() => vi.clearAllMocks())

  async function confirmDialog(password = 'administrator-password') {
    const dialog = await screen.findByRole('dialog')
    const input = dialog.querySelector('input[type="password"]') as HTMLInputElement
    await act(async () => {
      fireEvent.change(input, { target: { value: password } })
      fireEvent.click(dialog.querySelector('button[type="submit"]')!)
      await Promise.resolve()
    })
  }

  it('creates, edits, pauses, tests, and removes a destination', async () => {
    renderWithProviders(<Notifications />)
    await waitFor(() => expect(screen.getByText('Mattermost')).toBeInTheDocument())

    fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'Alerts' } })
    fireEvent.change(screen.getByLabelText(/^Shoutrrr URL/), { target: { value: 'generic://example.test/path' } })
    const createForm = screen.getByRole('button', { name: 'Add destination' }).closest('form')!
    fireEvent.change(createForm.querySelector('input[type="password"]')!, { target: { value: 'administrator-password' } })
    fireEvent.click(screen.getByRole('button', { name: 'Add destination' }))
    await waitFor(() => expect(createNotificationDestination).toHaveBeenCalledWith('Alerts', 'generic://example.test/path', 'administrator-password', true))

    fireEvent.click(screen.getByRole('button', { name: 'Edit' }))
    const editForm = screen.getByRole('button', { name: 'Save changes' }).closest('form')!
    fireEvent.change(editForm.querySelector('input')!, { target: { value: 'Alerts renamed' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save changes' }))
    await confirmDialog()
    await waitFor(() => expect(updateNotificationDestination).toHaveBeenCalledWith('destination-1', 4, 'Alerts renamed', 'administrator-password', { enabled: true }))

    fireEvent.click(screen.getByRole('button', { name: 'Pause' }))
    await confirmDialog()
    await waitFor(() => expect(updateNotificationDestination).toHaveBeenCalledWith('destination-1', 4, 'Mattermost', 'administrator-password', { enabled: false }))

    fireEvent.click(screen.getByRole('button', { name: 'Test' }))
    await waitFor(() => expect(testNotificationDestination).toHaveBeenCalledWith('destination-1'))
    fireEvent.click(screen.getByRole('button', { name: 'Remove' }))
    await confirmDialog()
    await waitFor(() => expect(deleteNotificationDestination).toHaveBeenCalledWith('destination-1', 4, 'administrator-password'))
  })

  // Only a new URL discards the alerts queued for a destination; a rename or
  // a pause saved through the edit form keeps them.
  async function saveEdit(change: (form: HTMLFormElement) => void) {
    renderWithProviders(<Notifications />)
    await waitFor(() => expect(screen.getByText('Mattermost')).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: 'Edit' }))
    const editForm = screen.getByRole('button', { name: 'Save changes' }).closest('form')!
    change(editForm)
    fireEvent.click(screen.getByRole('button', { name: 'Save changes' }))
    await confirmDialog()
    await waitFor(() => expect(updateNotificationDestination).toHaveBeenCalledTimes(1))
    return (await screen.findByText(/^Notification destination updated\./)).textContent
  }

  it('does not report discarded alerts after a rename-only edit', async () => {
    const banner = await saveEdit(form => fireEvent.change(form.querySelector('input')!, { target: { value: 'Alerts renamed' } }))
    expect(updateNotificationDestination).toHaveBeenCalledWith('destination-1', 4, 'Alerts renamed', 'administrator-password', { enabled: true })
    expect(banner).toBe('Notification destination updated.')
  })

  it('does not report discarded alerts after an edit that only pauses the destination', async () => {
    const banner = await saveEdit(form => fireEvent.click(form.querySelector('input[type="checkbox"]')!))
    expect(updateNotificationDestination).toHaveBeenCalledWith('destination-1', 4, 'Mattermost', 'administrator-password', { enabled: false })
    expect(banner).toBe('Notification destination updated.')
  })

  it('reports discarded alerts after an edit that replaces the URL', async () => {
    const banner = await saveEdit(form => fireEvent.change(form.querySelector('input[type="url"]')!, { target: { value: ' generic://example.test/rotated ' } }))
    expect(updateNotificationDestination).toHaveBeenCalledWith('destination-1', 4, 'Mattermost', 'administrator-password', { enabled: true, url: 'generic://example.test/rotated' })
    expect(banner).toBe('Notification destination updated. Alerts queued for the previous URL were discarded.')
  })

  it('keeps protected destination state unchanged when confirmation fails', async () => {
    vi.mocked(updateNotificationDestination).mockRejectedValue(new APIError('wrong password', 'invalid_password'))
    renderWithProviders(<Notifications />)
    await waitFor(() => expect(screen.getByText('Mattermost')).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: 'Pause' }))
    await confirmDialog('wrong-password')
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('wrong password'))
    expect(screen.getByRole('button', { name: 'Pause' })).toBeInTheDocument()
  })

  it('renders delivery health and locks management controls for locked destinations', async () => {
    vi.mocked(listNotificationDestinations).mockResolvedValue({ ...response, destinations: [{ ...destination, locked: true, error_code: 'key_unavailable' }] } as never)
    renderWithProviders(<Notifications />)
    await waitFor(() => expect(screen.getByText(/Credentials cannot be decrypted/)).toBeInTheDocument())
    expect(screen.getByText('1 pending')).toBeInTheDocument()
    expect(screen.getByText('2 retrying')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Edit' })).toBeDisabled()
  })
})
