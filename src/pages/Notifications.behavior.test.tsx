/** @vitest-environment jsdom */

import { fireEvent, screen, waitFor } from '@testing-library/react'
import { act } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { APIError, createNotificationDestination, deleteNotificationDestination, getSession, listNotificationDestinations, listPlatformNotifications, testNotificationDestination, updateNotificationDestination, updatePlatformNotification } from '../api'
import { renderWithProviders, defaultUnitScope } from '../test/test-utils'
import { Notifications } from './Notifications'
import { PlatformNotifications } from './platform/PlatformNotifications'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return { ...actual, createNotificationDestination: vi.fn(), deleteNotificationDestination: vi.fn(), getSession: vi.fn(), listNotificationDestinations: vi.fn(), listPlatformNotifications: vi.fn(), testNotificationDestination: vi.fn(), updateNotificationDestination: vi.fn(), updatePlatformNotification: vi.fn() }
})

const destination = { id: 'destination-1', name: 'Mattermost', provider: 'mattermost', source: 'web', enabled: true, locked: false, revision: 4, pending: 1, retrying: 2, last_success_at: '2026-01-01T00:00:00Z' }
const response = { destinations: [destination], status: { deployment: 0, managed: 1, active: 1, locked: 0, key_state: 'ready' }, update_routing: { configured: true, destinations: ['destination-1'] } }

describe('notification destination workflows', () => {
  beforeEach(() => {
    vi.mocked(getSession).mockResolvedValue({ role: 'administrator', user_id: 'admin', username: 'admin', permissions: ['notifications.manage'], csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 }, ...defaultUnitScope })
    vi.mocked(listNotificationDestinations).mockResolvedValue(response as never)
    vi.mocked(createNotificationDestination).mockResolvedValue(destination as never)
    vi.mocked(updateNotificationDestination).mockResolvedValue(destination as never)
    vi.mocked(listPlatformNotifications).mockResolvedValue(response as never)
    vi.mocked(updatePlatformNotification).mockResolvedValue(destination as never)
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

  it('retries an unavailable destination list', async () => {
    vi.mocked(listNotificationDestinations).mockRejectedValueOnce(new Error('destination store unavailable'))
    renderWithProviders(<Notifications />)
    await waitFor(() => expect(screen.getByText('Could not load notification destinations.')).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    await waitFor(() => expect(screen.getByText('Mattermost')).toBeInTheDocument())
  })

  it('lets an administrator cancel destination editing', async () => {
    renderWithProviders(<Notifications />)
    await waitFor(() => expect(screen.getByText('Mattermost')).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: 'Edit' }))
    expect(screen.getByRole('button', { name: 'Save changes' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(screen.queryByRole('button', { name: 'Save changes' })).not.toBeInTheDocument()
  })

  it('creates, edits, pauses, tests, and removes a destination', async () => {
    renderWithProviders(<Notifications />)
    await waitFor(() => expect(screen.getByText('Mattermost')).toBeInTheDocument())

    fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'Alerts' } })
    fireEvent.change(screen.getByRole('combobox', { name: 'Notification service' }), { target: { value: 'url' } })
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

  it('creates a Discord destination from its native webhook URL', async () => {
    renderWithProviders(<Notifications />)
    await waitFor(() => expect(screen.getByText('Mattermost')).toBeInTheDocument())

    fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'Discord alerts' } })
    fireEvent.change(screen.getByRole('combobox', { name: 'Notification service' }), { target: { value: 'discord' } })
    fireEvent.change(screen.getByLabelText(/^Discord webhook URL/), { target: { value: 'https://discord.com/api/webhooks/12345678/secret-token' } })
    const createForm = screen.getByRole('button', { name: 'Add destination' }).closest('form')!
    fireEvent.change(createForm.querySelector('input[type="password"]')!, { target: { value: 'administrator-password' } })
    fireEvent.click(screen.getByRole('button', { name: 'Add destination' }))

    await waitFor(() => expect(createNotificationDestination).toHaveBeenCalledWith(
      'Discord alerts',
      { provider: 'discord', fields: { webhook_url: 'https://discord.com/api/webhooks/12345678/secret-token' } },
      'administrator-password',
      true,
    ))
    expect(screen.queryByDisplayValue('https://discord.com/api/webhooks/12345678/secret-token')).not.toBeInTheDocument()
  })

  it('creates an SMTP destination from server, sender, and recipient fields', async () => {
    renderWithProviders(<Notifications />)
    await waitFor(() => expect(screen.getByText('Mattermost')).toBeInTheDocument())

    fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'Mail alerts' } })
    fireEvent.change(screen.getByLabelText(/^SMTP server/), { target: { value: 'mail.example.test' } })
    fireEvent.change(screen.getByLabelText(/^Port/), { target: { value: '587' } })
    fireEvent.change(screen.getByLabelText(/^From address/), { target: { value: 'edgewatch@example.test' } })
    fireEvent.change(screen.getByLabelText(/^Recipients/), { target: { value: 'ops@example.test, oncall@example.test' } })
    fireEvent.change(screen.getByLabelText(/^SMTP username/), { target: { value: 'edgewatch' } })
    fireEvent.change(screen.getByLabelText(/^SMTP password/), { target: { value: 'smtp-token' } })
    fireEvent.change(screen.getByLabelText(/^Password confirmation/), { target: { value: 'administrator-password' } })
    fireEvent.click(screen.getByRole('button', { name: 'Add destination' }))

    await waitFor(() => expect(createNotificationDestination).toHaveBeenCalledWith(
      'Mail alerts',
      { provider: 'smtp', fields: { host: 'mail.example.test', port: '587', from: 'edgewatch@example.test', to: 'ops@example.test, oncall@example.test', username: 'edgewatch', password: 'smtp-token' } },
      'administrator-password',
      true,
    ))
  })

  it('creates an ntfy destination using the default server when left blank', async () => {
    renderWithProviders(<Notifications />)
    await waitFor(() => expect(screen.getByText('Mattermost')).toBeInTheDocument())

    fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'Push alerts' } })
    fireEvent.change(screen.getByRole('combobox', { name: 'Notification service' }), { target: { value: 'ntfy' } })
    fireEvent.change(screen.getByLabelText(/^Topic/), { target: { value: 'edgewatch-alerts' } })
    fireEvent.change(screen.getByLabelText(/^Password or token/), { target: { value: 'ntfy-token' } })
    fireEvent.change(screen.getByLabelText(/^Password confirmation/), { target: { value: 'administrator-password' } })
    fireEvent.click(screen.getByRole('button', { name: 'Add destination' }))

    await waitFor(() => expect(createNotificationDestination).toHaveBeenCalledWith(
      'Push alerts',
      { provider: 'ntfy', fields: { topic: 'edgewatch-alerts', password: 'ntfy-token' } },
      'administrator-password',
      true,
    ))
  })

  // Only replacement credentials discard the alerts queued for a destination; a rename or
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
    expect(banner).toBe('Notification destination updated. Alerts queued for the previous credentials were discarded.')
  })

  it('saves a unit destination against the revision opened and reloads after a conflict', async () => {
    const latest = { ...destination, name: 'Paused elsewhere', enabled: false, revision: 5 }
    vi.mocked(listNotificationDestinations).mockResolvedValueOnce(response as never).mockResolvedValue({ ...response, destinations: [latest] } as never)
    vi.mocked(updateNotificationDestination).mockRejectedValueOnce(new APIError('stale revision', 'conflict'))
    const { client } = renderWithProviders(<Notifications />)
    await waitFor(() => expect(screen.getByText('Mattermost')).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: 'Edit' }))
    const editForm = screen.getByRole('button', { name: 'Save changes' }).closest('form')!
    fireEvent.change(editForm.querySelector('input')!, { target: { value: 'My rename' } })
    await act(async () => { await client.invalidateQueries({ queryKey: ['notifications'] }) })
    await waitFor(() => expect(screen.getByText('Paused elsewhere')).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: 'Save changes' }))
    await confirmDialog()
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('The latest values are loaded; review them and save again.'))

    expect(updateNotificationDestination).toHaveBeenCalledWith('destination-1', 4, 'My rename', 'administrator-password', { enabled: true })
    expect(screen.getByRole('button', { name: 'Save changes' })).toBeInTheDocument()
    const refreshedForm = screen.getByRole('button', { name: 'Save changes' }).closest('form')!
    expect(refreshedForm.querySelector('input')?.value).toBe('Paused elsewhere')
    expect((refreshedForm.querySelector('input[type="checkbox"]') as HTMLInputElement).checked).toBe(false)
  })

  it('uses the edit-opening revision for platform destinations too', async () => {
    const latest = { ...destination, name: 'Platform changed elsewhere', enabled: false, revision: 8 }
    vi.mocked(listPlatformNotifications).mockResolvedValueOnce(response as never).mockResolvedValue({ ...response, destinations: [latest] } as never)
    vi.mocked(updatePlatformNotification).mockRejectedValueOnce(new APIError('stale revision', 'conflict'))
    const { client } = renderWithProviders(<PlatformNotifications />)
    await waitFor(() => expect(screen.getByText('Mattermost')).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: 'Edit' }))
    const editForm = screen.getByRole('button', { name: 'Save changes' }).closest('form')!
    fireEvent.change(editForm.querySelector('input')!, { target: { value: 'Platform rename' } })
    await act(async () => { await client.invalidateQueries({ queryKey: ['platform-notifications'] }) })
    await waitFor(() => expect(screen.getByText('Platform changed elsewhere')).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: 'Save changes' }))
    await confirmDialog()
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('The latest values are loaded; review them and save again.'))

    expect(updatePlatformNotification).toHaveBeenCalledWith('destination-1', 4, 'Platform rename', 'administrator-password', { enabled: true })
    expect(screen.getByRole('button', { name: 'Save changes' })).toBeInTheDocument()
    const refreshedForm = screen.getByRole('button', { name: 'Save changes' }).closest('form')!
    expect(refreshedForm.querySelector('input')?.value).toBe('Platform changed elsewhere')
    expect((refreshedForm.querySelector('input[type="checkbox"]') as HTMLInputElement).checked).toBe(false)
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
