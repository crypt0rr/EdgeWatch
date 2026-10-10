/** @vitest-environment jsdom */

import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  getSession,
  listNotificationDestinations,
  toggleNotificationSecurityAlert,
  toggleNotificationUpdateAlert,
  updateIncidentReminders,
} from '../api'
import { Notifications } from './Notifications'
import { defaultUnitScope } from '../test/test-utils'

vi.mock('../api', () => ({
  APIError: class APIError extends Error {
    details?: Record<string, unknown>
  },
  createNotificationDestination: vi.fn(),
  deleteNotificationDestination: vi.fn(),
  getSession: vi.fn(),
  listNotificationDestinations: vi.fn(),
  testNotificationDestination: vi.fn(),
  updateNotificationDestination: vi.fn(),
  toggleNotificationSecurityAlert: vi.fn(),
  toggleNotificationUpdateAlert: vi.fn(),
  updateIncidentReminders: vi.fn(),
}))

;(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true

const destinations = [
  { id: 'dest-1', name: 'Operations', provider: 'generic', source: 'web', enabled: true, locked: false, read_only: false, revision: 1 },
  { id: 'dest-2', name: 'Backup', provider: 'generic', source: 'web', enabled: false, locked: false, read_only: false, revision: 1 },
]

function response(configured: boolean, selected: string[]) {
  return {
    destinations,
    status: { deployment: 0, managed: 2, active: 1, locked: 0, key_state: 'ready' },
    update_routing: { configured, destinations: selected },
    incident_reminders_enabled: true,
    incident_reminder_cadence: 'hourly' as const,
  }
}

function setInputValue(input: HTMLInputElement, value: string) {
  act(() => {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set
    setter?.call(input, value)
    input.dispatchEvent(new Event('input', { bubbles: true }))
  })
}

describe('notification update-alert routing', () => {
  let root: Root
  let container: HTMLDivElement
  let queryClient: QueryClient

  beforeEach(() => {
    container = document.createElement('div')
    document.body.appendChild(container)
    root = createRoot(container)
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    vi.mocked(getSession).mockResolvedValue({ role: 'administrator', user_id: 'admin', username: 'admin', permissions: ['notifications.manage'], csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 }, ...defaultUnitScope })
    vi.mocked(listNotificationDestinations).mockResolvedValue(response(false, []))
    vi.mocked(toggleNotificationUpdateAlert).mockResolvedValue({ configured: true, destinations: [] })
    vi.mocked(updateIncidentReminders).mockResolvedValue({ enabled: false, cadence: 'hourly' })
  })

  afterEach(() => {
    act(() => root.unmount())
    queryClient.clear()
    container.remove()
    document.body.querySelector('.modal-backdrop')?.remove()
    vi.clearAllMocks()
  })

  async function renderPage() {
    await act(async () => {
      root.render(<QueryClientProvider client={queryClient}><Notifications /></QueryClientProvider>)
      await Promise.resolve()
      await Promise.resolve()
    })
    await vi.waitFor(() => expect(container.querySelectorAll('.notification-row')).toHaveLength(2), { timeout: 1000 })
    // The update-alert toggles follow the session's permissions, which can
    // resolve after the destinations on a slow runner.
    await vi.waitFor(() => expect(container.querySelectorAll('.notification-update-toggle input')).toHaveLength(2), { timeout: 1000 })
  }

  it('keeps every existing destination selected when legacy update routing has never been configured', async () => {
    await renderPage()
    expect(container.querySelector('input[aria-label="Disable update alerts for Operations"]')).toBeTruthy()
    expect(container.querySelector('input[aria-label="Disable update alerts for Backup"]')).toBeTruthy()
    expect(container.querySelector('.notification-update-toggle small')?.textContent).toBe('Alerts on')
    expect(container.querySelector('.notification-update-toggle small')?.getAttribute('title')).toBe('Release and upgrade alerts on')
  })

  it('keeps the default-on reminder switch unchanged until password confirmation succeeds', async () => {
    await renderPage()
    const reminder = container.querySelector('input[aria-label="Send reminders for incidents that remain open"]') as HTMLInputElement
    expect(reminder.checked).toBe(true)
    act(() => reminder.click())
    expect(reminder.checked).toBe(true)
    expect(document.body.querySelector('[role="dialog"]')?.textContent).toContain('Confirm incident reminders')
    const dialog = document.body.querySelector('[role="dialog"]') as HTMLElement
    act(() => (dialog.querySelector('button[type="button"]') as HTMLButtonElement).click())
    expect(updateIncidentReminders).not.toHaveBeenCalled()
    expect(reminder.checked).toBe(true)
  })

  it('shows the reminder setting read-only without notification management permission', async () => {
    vi.mocked(getSession).mockResolvedValue({ role: 'viewer', user_id: 'viewer', username: 'viewer', permissions: ['notifications.read'], csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 }, ...defaultUnitScope })
    await act(async () => {
      root.render(<QueryClientProvider client={queryClient}><Notifications /></QueryClientProvider>)
      await Promise.resolve()
    })
    await vi.waitFor(() => expect(container.querySelector('input[aria-label="Send reminders for incidents that remain open"]')).toBeTruthy())
    const reminder = container.querySelector('input[aria-label="Send reminders for incidents that remain open"]') as HTMLInputElement
    expect(reminder.disabled).toBe(true)
    expect(reminder.checked).toBe(true)
  })

  it('saves a disabled reminder setting and rolls back a failed change', async () => {
    vi.mocked(listNotificationDestinations).mockResolvedValue({ ...response(true, []), incident_reminders_enabled: false })
    vi.mocked(updateIncidentReminders).mockRejectedValueOnce(new Error('setting unavailable'))
    await renderPage()
    const reminder = container.querySelector('input[aria-label="Send reminders for incidents that remain open"]') as HTMLInputElement
    expect(reminder.checked).toBe(false)
    act(() => reminder.click())
    let dialog = document.body.querySelector('[role="dialog"]') as HTMLElement
    setInputValue(dialog.querySelector('input[type="password"]') as HTMLInputElement, 'fixture-password')
    await act(async () => {
      ;(dialog.querySelector('button[type="submit"]') as HTMLButtonElement).click()
      await Promise.resolve()
    })
    await vi.waitFor(() => expect(container.querySelector('.notification-reminder-settings [role="alert"]')?.textContent).toContain('setting unavailable'))
    expect(reminder.checked).toBe(false)
    vi.mocked(updateIncidentReminders).mockResolvedValue({ enabled: true, cadence: 'hourly' })
    vi.mocked(listNotificationDestinations).mockResolvedValue({ ...response(true, []), incident_reminders_enabled: true })
    act(() => reminder.click())
    dialog = document.body.querySelector('[role="dialog"]') as HTMLElement
    setInputValue(dialog.querySelector('input[type="password"]') as HTMLInputElement, 'fixture-password')
    await act(async () => {
      ;(dialog.querySelector('button[type="submit"]') as HTMLButtonElement).click()
      await Promise.resolve()
    })
    await vi.waitFor(() => expect(reminder.checked).toBe(true))
    expect(container.querySelector('.notification-reminder-settings [role="status"]')?.textContent).toContain('Incident reminders enabled.')
    expect(updateIncidentReminders).toHaveBeenNthCalledWith(2, { enabled: true }, 'fixture-password')
  })

  it('saves a slower reminder cadence after password confirmation', async () => {
    vi.mocked(updateIncidentReminders).mockResolvedValue({ enabled: true, cadence: 'daily' })
    vi.mocked(listNotificationDestinations).mockResolvedValueOnce(response(true, [])).mockResolvedValue({ ...response(true, []), incident_reminder_cadence: 'daily' })
    await renderPage()
    const cadence = container.querySelector('select[aria-label="Reminder cadence"]') as HTMLSelectElement
    expect(cadence.value).toBe('hourly')
    expect(container.querySelector('.notification-reminder-settings')?.textContent).toContain('first successful follow-up may remind immediately')
    act(() => {
      Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value')?.set?.call(cadence, 'daily')
      cadence.dispatchEvent(new Event('change', { bubbles: true }))
    })
    const dialog = document.body.querySelector('[role="dialog"]') as HTMLElement
    setInputValue(dialog.querySelector('input[type="password"]') as HTMLInputElement, 'fixture-password')
    await act(async () => {
      ;(dialog.querySelector('button[type="submit"]') as HTMLButtonElement).click()
      await Promise.resolve()
    })
    await vi.waitFor(() => expect(cadence.value).toBe('daily'))
    expect(updateIncidentReminders).toHaveBeenCalledWith({ cadence: 'daily' }, 'fixture-password')
    expect(container.querySelector('.notification-reminder-settings [role="status"]')?.textContent).toContain('once per day')
  })

  it('preserves an explicitly empty update-alert selection', async () => {
    vi.mocked(listNotificationDestinations).mockResolvedValue(response(true, []))
    await renderPage()
    expect(container.querySelector('input[aria-label="Enable update alerts for Operations"]')).toBeTruthy()
    expect(container.querySelector('input[aria-label="Enable update alerts for Backup"]')).toBeTruthy()
  })

  it('does not render writable update routing when destination state is unavailable', async () => {
    vi.mocked(listNotificationDestinations).mockRejectedValueOnce(new Error('routing unavailable'))
    await act(async () => {
      root.render(<QueryClientProvider client={queryClient}><Notifications /></QueryClientProvider>)
      await Promise.resolve()
    })
    await vi.waitFor(() => expect(container.textContent).toContain('Could not load notification destinations'), { timeout: 1000 })
    expect(container.querySelector('.notification-update-toggle')).toBeNull()
    expect(toggleNotificationUpdateAlert).not.toHaveBeenCalled()
  })

  it('leaves the toggle unchanged when password confirmation is cancelled', async () => {
    vi.mocked(listNotificationDestinations).mockResolvedValue(response(true, ['dest-1']))
    await renderPage()

    const first = container.querySelector('input[aria-label="Disable update alerts for Operations"]') as HTMLInputElement
    act(() => first.click())
    const dialog = document.body.querySelector('[role="dialog"]') as HTMLElement
    act(() => (dialog.querySelector('button[type="button"]') as HTMLButtonElement).click())

    expect(first.checked).toBe(true)
    expect(toggleNotificationUpdateAlert).not.toHaveBeenCalled()
  })

  it('confirms each toggle, rolls back failed saves, and disables other toggles while pending', async () => {
    vi.mocked(listNotificationDestinations).mockResolvedValue(response(true, ['dest-1']))
    vi.mocked(toggleNotificationUpdateAlert).mockRejectedValueOnce(new Error('server refused'))
    await renderPage()

    const first = container.querySelector('input[aria-label="Disable update alerts for Operations"]') as HTMLInputElement
    const second = container.querySelector('input[aria-label="Enable update alerts for Backup"]') as HTMLInputElement
    expect(first.checked).toBe(true)
    act(() => first.click())
    expect(second.disabled).toBe(true)

    let dialog = document.body.querySelector('[role="dialog"]') as HTMLElement
    expect(dialog.textContent).toContain('Confirm update alerts for Operations')
    setInputValue(dialog.querySelector('input[type="password"]') as HTMLInputElement, 'fixture-password')
    await act(async () => {
      ;(dialog.querySelector('button[type="submit"]') as HTMLButtonElement).click()
      await Promise.resolve()
      await Promise.resolve()
    })
    await vi.waitFor(() => expect(container.querySelector('[role="alert"]')?.textContent).toContain('server refused'), { timeout: 1000 })
    expect(first.checked).toBe(true)

    act(() => first.click())
    dialog = document.body.querySelector('[role="dialog"]') as HTMLElement
    // The server stores the new routing; the page's follow-up refetch reads it.
    vi.mocked(listNotificationDestinations).mockResolvedValue(response(true, []))
    setInputValue(dialog.querySelector('input[type="password"]') as HTMLInputElement, 'fixture-password')
    await act(async () => {
      ;(dialog.querySelector('button[type="submit"]') as HTMLButtonElement).click()
      await Promise.resolve()
      await Promise.resolve()
    })
    await vi.waitFor(() => expect(container.querySelector('[role="status"]')?.textContent).toContain('Application update alerts disabled for Operations'), { timeout: 1000 })
    expect(first.checked).toBe(false)
    expect(toggleNotificationUpdateAlert).toHaveBeenNthCalledWith(1, 'dest-1', false, 'fixture-password')
    expect(toggleNotificationUpdateAlert).toHaveBeenNthCalledWith(2, 'dest-1', false, 'fixture-password')
  })

  describe('with routing changed in another session', () => {
    const pager = { id: 'dest-3', name: 'Pager', provider: 'generic', source: 'web', enabled: true, locked: false, read_only: false, revision: 1 }
    const routed = (selected: string[]) => ({ ...response(true, selected), destinations: [...destinations, pager] })

    async function renderThreeDestinations() {
      await act(async () => {
        root.render(<QueryClientProvider client={queryClient}><Notifications /></QueryClientProvider>)
        await Promise.resolve()
      })
      await vi.waitFor(() => expect(container.querySelectorAll('.notification-row')).toHaveLength(3), { timeout: 1000 })
      await vi.waitFor(() => expect(container.querySelectorAll('.notification-update-toggle input')).toHaveLength(3), { timeout: 1000 })
    }

    async function confirm(password: string) {
      const dialog = document.body.querySelector('[role="dialog"]') as HTMLElement
      setInputValue(dialog.querySelector('input[type="password"]') as HTMLInputElement, password)
      await act(async () => {
        ;(dialog.querySelector('button[type="submit"]') as HTMLButtonElement).click()
        await Promise.resolve()
        await Promise.resolve()
      })
    }

    beforeEach(() => {
      vi.mocked(listNotificationDestinations).mockResolvedValue(routed(['dest-1']))
      vi.mocked(toggleNotificationUpdateAlert).mockImplementation(async (id, enabled) => ({ configured: true, destinations: enabled ? [id] : [] }))
    })

    it('shows the refetched routing and toggles only the chosen destination', async () => {
      await renderThreeDestinations()
      expect(container.querySelector('input[aria-label="Enable update alerts for Backup"]')).toBeTruthy()

      vi.mocked(listNotificationDestinations).mockResolvedValue(routed(['dest-1', 'dest-2']))
      await act(async () => { await queryClient.invalidateQueries({ queryKey: ['notifications'] }) })
      await vi.waitFor(() => expect(container.querySelector('input[aria-label="Disable update alerts for Backup"]')).toBeTruthy(), { timeout: 1000 })

      act(() => (container.querySelector('input[aria-label="Enable update alerts for Pager"]') as HTMLInputElement).click())
      await confirm('fixture-password')
      await vi.waitFor(() => expect(toggleNotificationUpdateAlert).toHaveBeenCalledWith('dest-3', true, 'fixture-password'), { timeout: 1000 })
    })

    it('applies a toggle to routing that changed while the password prompt was open', async () => {
      await renderThreeDestinations()
      act(() => (container.querySelector('input[aria-label="Enable update alerts for Pager"]') as HTMLInputElement).click())

      vi.mocked(listNotificationDestinations).mockResolvedValue(routed(['dest-1', 'dest-2']))
      await act(async () => { await queryClient.invalidateQueries({ queryKey: ['notifications'] }) })
      await confirm('fixture-password')
      await vi.waitFor(() => expect(toggleNotificationUpdateAlert).toHaveBeenCalledWith('dest-3', true, 'fixture-password'), { timeout: 1000 })
    })
  })
})

describe('notification URLs imported from config.yaml', () => {
  let root: Root
  let container: HTMLDivElement
  let queryClient: QueryClient

  beforeEach(() => {
    container = document.createElement('div')
    document.body.appendChild(container)
    root = createRoot(container)
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    vi.mocked(getSession).mockResolvedValue({ role: 'administrator', user_id: 'admin', username: 'admin', permissions: ['notifications.manage'], csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 }, ...defaultUnitScope })
  })

  afterEach(() => {
    act(() => root.unmount())
    queryClient.clear()
    container.remove()
    vi.clearAllMocks()
  })

  async function renderWithImport(configImport?: string) {
    const imported = { id: 'imported-1', name: 'Deployment destination', provider: 'generic', source: 'web', enabled: true, locked: false, read_only: false, revision: 1 }
    vi.mocked(listNotificationDestinations).mockResolvedValue({
      destinations: [imported],
      status: { deployment: 0, managed: 1, active: 1, locked: 0, key_state: 'ready', ...(configImport ? { config_import: configImport } : {}) },
      update_routing: { configured: false, destinations: [] },
    })
    await act(async () => {
      root.render(<QueryClientProvider client={queryClient}><Notifications /></QueryClientProvider>)
      await Promise.resolve()
      await Promise.resolve()
    })
    await vi.waitFor(() => expect(container.querySelectorAll('.notification-row')).toHaveLength(1), { timeout: 1000 })
  }

  it('asks the operator to remove imported URLs from config.yaml', async () => {
    await renderWithImport('imported')
    const banner = container.querySelector('.notification-config-import')
    expect(banner?.textContent).toContain('Notification URLs in config.yaml were imported.')
    expect(banner?.textContent).toContain('Remove notifications.urls and notifications.urls_file from config.yaml')
    // Imported destinations are ordinary web-managed destinations.
    const row = container.querySelector('.notification-row') as HTMLElement
    expect(row.textContent).toContain('Deployment destination')
    expect(row.textContent).toContain('revision 1')
    expect(row.textContent).not.toContain('Read-only')
  })

  it('reports a failed import that keeps delivering from config.yaml', async () => {
    await renderWithImport('failed')
    const banner = container.querySelector('.notification-config-import')
    expect(banner?.textContent).toContain('could not be imported')
    expect(banner?.textContent).toContain('still delivers to them from config.yaml')
  })

  it('shows no import banner when config.yaml lists no imported URLs', async () => {
    await renderWithImport()
    expect(container.querySelector('.notification-config-import')).toBeNull()
  })
})

describe('notification security-alert routing', () => {
  let root: Root
  let container: HTMLDivElement
  let queryClient: QueryClient
  const deployment = { id: 'file:deploy', name: 'Deployment', provider: 'generic', source: 'deployment', enabled: true, locked: false, read_only: true }

  beforeEach(() => {
    container = document.createElement('div')
    document.body.appendChild(container)
    root = createRoot(container)
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    vi.mocked(getSession).mockResolvedValue({ role: 'administrator', user_id: 'admin', username: 'admin', permissions: ['notifications.manage'], csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 }, ...defaultUnitScope })
    vi.mocked(listNotificationDestinations).mockResolvedValue({ ...response(true, []), destinations: [...destinations, deployment], security_routing: { configured: true, destinations: ['dest-1'] } })
    vi.mocked(toggleNotificationSecurityAlert).mockResolvedValue({ configured: true, destinations: ['dest-1', 'dest-2'] })
  })

  afterEach(() => {
    act(() => root.unmount())
    queryClient.clear()
    container.remove()
    vi.clearAllMocks()
  })

  it('turns a web-managed destination’s security alerts on after confirmation', async () => {
    await act(async () => {
      root.render(<QueryClientProvider client={queryClient}><Notifications /></QueryClientProvider>)
      await Promise.resolve()
    })
    await vi.waitFor(() => expect(container.querySelectorAll('.notification-alert-toggle input')).toHaveLength(2), { timeout: 1000 })
    // A deployment destination from config.yaml cannot receive security alerts.
    expect(container.querySelector('input[aria-label="Enable security alerts for Deployment"]')).toBeNull()
    expect((container.querySelector('input[aria-label="Disable security alerts for Operations"]') as HTMLInputElement).checked).toBe(true)
    const backup = container.querySelector('input[aria-label="Enable security alerts for Backup"]') as HTMLInputElement
    expect(backup.checked).toBe(false)
    act(() => backup.click())
    const dialog = document.body.querySelector('[role="dialog"]') as HTMLElement
    expect(dialog.textContent).toContain('Confirm security alerts for Backup')
    expect(dialog.textContent).toContain('platform administrator actions on this unit’s accounts')
    vi.mocked(listNotificationDestinations).mockResolvedValue({ ...response(true, []), destinations: [...destinations, deployment], security_routing: { configured: true, destinations: ['dest-1', 'dest-2'] } })
    setInputValue(dialog.querySelector('input[type="password"]') as HTMLInputElement, 'fixture-password')
    await act(async () => {
      ;(dialog.querySelector('button[type="submit"]') as HTMLButtonElement).click()
      await Promise.resolve()
      await Promise.resolve()
    })
    await vi.waitFor(() => expect(container.querySelector('[role="status"]')?.textContent).toContain('Security alerts enabled for Backup.'), { timeout: 1000 })
    expect(toggleNotificationSecurityAlert).toHaveBeenCalledWith('dest-2', true, 'fixture-password')
    await vi.waitFor(() => expect((container.querySelector('input[aria-label="Disable security alerts for Backup"]') as HTMLInputElement).checked).toBe(true), { timeout: 1000 })
  })

  it('reports a routing change that fails', async () => {
    vi.mocked(toggleNotificationSecurityAlert).mockRejectedValueOnce(new Error('server refused'))
    await act(async () => {
      root.render(<QueryClientProvider client={queryClient}><Notifications /></QueryClientProvider>)
      await Promise.resolve()
    })
    await vi.waitFor(() => expect(container.querySelector('input[aria-label="Disable security alerts for Operations"]')).toBeTruthy(), { timeout: 1000 })
    act(() => (container.querySelector('input[aria-label="Disable security alerts for Operations"]') as HTMLInputElement).click())
    const dialog = document.body.querySelector('[role="dialog"]') as HTMLElement
    setInputValue(dialog.querySelector('input[type="password"]') as HTMLInputElement, 'fixture-password')
    await act(async () => {
      ;(dialog.querySelector('button[type="submit"]') as HTMLButtonElement).click()
      await Promise.resolve()
      await Promise.resolve()
    })
    await vi.waitFor(() => expect(container.querySelector('[role="alert"]')?.textContent).toContain('server refused'), { timeout: 1000 })
    expect(toggleNotificationSecurityAlert).toHaveBeenCalledWith('dest-1', false, 'fixture-password')
  })
})
