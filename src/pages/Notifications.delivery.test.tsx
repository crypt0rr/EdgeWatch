/** @vitest-environment jsdom */

import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { act } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { APIError, getSession, listNotificationDestinations, listPlatformNotifications, listTerminalDeliveries, redeliverTerminalDeliveries, testNotificationDestination, updateNotificationDestination } from '../api'
import { renderWithProviders, defaultUnitScope } from '../test/test-utils'
import { Notifications } from './Notifications'
import { PlatformNotifications } from './platform/PlatformNotifications'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return { ...actual, getSession: vi.fn(), listNotificationDestinations: vi.fn(), listPlatformNotifications: vi.fn(), listTerminalDeliveries: vi.fn(), redeliverTerminalDeliveries: vi.fn(), testNotificationDestination: vi.fn(), updateNotificationDestination: vi.fn() }
})

const destination = { id: 'destination-1', name: 'Mattermost', provider: 'mattermost', source: 'web', enabled: true, locked: false, read_only: false, revision: 4, terminal_failures: 2 }
const response = { destinations: [destination], status: { deployment: 0, managed: 1, active: 1, locked: 0, key_state: 'ready' }, update_routing: { configured: true, destinations: [] } }
const failed = [
  { id: 12, event_type: 'changes-detected', job: 'edge', event_at: '2026-10-01T08:30:00Z', terminal_at: '2026-10-04T12:00:00Z', attempts: 15, deferrals: 0, error_code: 'provider_timeout' },
  { id: 9, event_type: 'application-update-available', terminal_at: '2026-10-04T11:00:00Z', attempts: 1, deferrals: 8, error_code: 'destination_locked' },
]

describe('notification delivery outcomes', () => {
  beforeEach(() => {
    vi.mocked(getSession).mockResolvedValue({ role: 'administrator', user_id: 'admin', username: 'admin', permissions: ['notifications.manage'], csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 }, ...defaultUnitScope })
    vi.mocked(listNotificationDestinations).mockResolvedValue(response as never)
    vi.mocked(listPlatformNotifications).mockResolvedValue(response as never)
    vi.mocked(listTerminalDeliveries).mockResolvedValue({ deliveries: failed, next_before: 9 })
    vi.mocked(redeliverTerminalDeliveries).mockResolvedValue({ redelivered: 2 })
    vi.mocked(updateNotificationDestination).mockResolvedValue(destination as never)
  })
  afterEach(() => vi.clearAllMocks())

  async function confirmDialog() {
    const dialog = await screen.findByRole('dialog')
    await act(async () => {
      fireEvent.change(dialog.querySelector('input[type="password"]')!, { target: { value: 'administrator-password' } })
      fireEvent.click(dialog.querySelector('button[type="submit"]')!)
      await Promise.resolve()
    })
  }

  async function openFailedAlerts() {
    renderWithProviders(<Notifications />)
    fireEvent.click(await screen.findByRole('button', { name: 'Failed alerts' }))
    const panel = await screen.findByRole('region', { name: 'Failed alerts for Mattermost' })
    await within(panel).findByText('Incident opened · edge')
    return panel
  }

  it('lists a destination’s failed alerts by their metadata and pages through them', async () => {
    const panel = await openFailedAlerts()
    expect(within(panel).getByText('Update available')).toBeInTheDocument()
    expect(within(panel).getByText(/15 attempts · provider_timeout/)).toBeInTheDocument()
    expect(within(panel).getByText(/1 attempt, 8 deferrals · destination_locked/)).toBeInTheDocument()
    expect(listTerminalDeliveries).toHaveBeenCalledWith('destination-1', undefined)

    fireEvent.click(within(panel).getByRole('button', { name: 'Older' }))
    await waitFor(() => expect(listTerminalDeliveries).toHaveBeenCalledWith('destination-1', 9))
    fireEvent.click(await within(panel).findByRole('button', { name: 'Newest' }))
    fireEvent.click(screen.getByRole('button', { name: 'Hide failed alerts' }))
    expect(screen.queryByRole('region', { name: 'Failed alerts for Mattermost' })).not.toBeInTheDocument()
  })

  it('redelivers one failed alert or all of them', async () => {
    const panel = await openFailedAlerts()
    vi.mocked(redeliverTerminalDeliveries).mockResolvedValueOnce({ redelivered: 1 })
    fireEvent.click(within(panel).getByRole('button', { name: 'Redeliver Incident opened for edge' }))
    await within(panel).findByText('1 alert queued for redelivery to Mattermost.')
    expect(redeliverTerminalDeliveries).toHaveBeenCalledWith('destination-1', [12])

    fireEvent.click(within(panel).getByRole('button', { name: 'Redeliver all' }))
    await within(panel).findByText('2 alerts queued for redelivery to Mattermost.')
    expect(redeliverTerminalDeliveries).toHaveBeenLastCalledWith('destination-1', undefined)
  })

  it('reports a redelivery with nothing left and one that fails', async () => {
    const panel = await openFailedAlerts()
    vi.mocked(redeliverTerminalDeliveries).mockResolvedValueOnce({ redelivered: 0 })
    fireEvent.click(within(panel).getByRole('button', { name: 'Redeliver all' }))
    await within(panel).findByText('No failed alerts were left to redeliver.')

    vi.mocked(redeliverTerminalDeliveries).mockRejectedValueOnce(new APIError('notification destination not found', 'not_found'))
    fireEvent.click(within(panel).getByRole('button', { name: 'Redeliver all' }))
    expect(await within(panel).findByRole('alert')).toHaveTextContent('notification destination not found')
  })

  it('reports an empty or unavailable failed alert list', async () => {
    vi.mocked(listTerminalDeliveries).mockResolvedValueOnce({ deliveries: [], next_before: null })
    const empty = renderWithProviders(<Notifications />)
    fireEvent.click(await screen.findByRole('button', { name: 'Failed alerts' }))
    expect(await screen.findByText('No failed alerts are waiting for redelivery.')).toBeInTheDocument()
    empty.unmount()

    vi.mocked(listTerminalDeliveries).mockRejectedValueOnce(new Error('unavailable'))
    renderWithProviders(<Notifications />)
    fireEvent.click(await screen.findByRole('button', { name: 'Failed alerts' }))
    expect(await screen.findByText('Could not load the failed alerts.')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByText('Incident opened · edge')).toBeInTheDocument()
  })

  it('offers no failed alerts without terminal failures, to operators, or for platform destinations', async () => {
    vi.mocked(listNotificationDestinations).mockResolvedValue({ ...response, destinations: [{ ...destination, terminal_failures: 0 }] } as never)
    const { unmount } = renderWithProviders(<Notifications />)
    await screen.findByText('Mattermost')
    expect(screen.queryByRole('button', { name: 'Failed alerts' })).not.toBeInTheDocument()
    unmount()

    vi.mocked(listNotificationDestinations).mockResolvedValue(response as never)
    vi.mocked(getSession).mockResolvedValue({ role: 'operator', user_id: 'operator', username: 'operator', permissions: ['notifications.options'], csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 }, ...defaultUnitScope })
    const operator = renderWithProviders(<Notifications />)
    await screen.findByText('Mattermost')
    expect(screen.queryByRole('button', { name: 'Failed alerts' })).not.toBeInTheDocument()
    operator.unmount()

    renderWithProviders(<PlatformNotifications />)
    await screen.findByText('Mattermost')
    expect(screen.queryByRole('button', { name: 'Failed alerts' })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Edit' }))
    const editForm = screen.getByRole('button', { name: 'Save changes' }).closest('form')!
    fireEvent.change(editForm.querySelector('input[type="url"]')!, { target: { value: 'generic://example.test/rotated' } })
    expect(screen.queryByText('Keep queued alerts')).not.toBeInTheDocument()
  })

  it('keeps the queued alerts of a repaired URL when asked', async () => {
    renderWithProviders(<Notifications />)
    await screen.findByText('Mattermost')
    fireEvent.click(screen.getByRole('button', { name: 'Edit' }))
    expect(screen.queryByText('Keep queued alerts')).not.toBeInTheDocument()
    const editForm = screen.getByRole('button', { name: 'Save changes' }).closest('form')!
    fireEvent.change(editForm.querySelector('input[type="url"]')!, { target: { value: 'generic://example.test/repaired' } })
    fireEvent.click(screen.getByRole('checkbox', { name: /Keep queued alerts/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Save changes' }))
    await confirmDialog()
    await waitFor(() => expect(updateNotificationDestination).toHaveBeenCalledWith('destination-1', 4, 'Mattermost', 'administrator-password', { enabled: true, url: 'generic://example.test/repaired', keep_pending: true }))
    expect(await screen.findByText('Notification destination updated. Alerts queued for the previous credentials will be sent with the new ones.')).toBeInTheDocument()
  })

  it('reports a test that the destination did not answer in time', async () => {
    vi.mocked(testNotificationDestination).mockRejectedValueOnce(new APIError('the destination did not answer in time; the message may still arrive', 'notification_timeout', undefined, 504))
    renderWithProviders(<Notifications />)
    fireEvent.click(await screen.findByRole('button', { name: 'Test' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Mattermost did not answer in time. The test message may still arrive; check the recipient before testing again.')
  })
})
