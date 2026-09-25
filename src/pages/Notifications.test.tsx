/** @vitest-environment jsdom */

import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  getSession,
  listNotificationDestinations,
  updateNotificationRouting,
} from '../api'
import { Notifications } from './Notifications'

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
  updateNotificationRouting: vi.fn(),
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
    vi.mocked(getSession).mockResolvedValue({ role: 'administrator', user_id: 'admin', username: 'admin', permissions: ['notifications.manage'], csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 } })
    vi.mocked(listNotificationDestinations).mockResolvedValue(response(false, []))
    vi.mocked(updateNotificationRouting).mockResolvedValue({ configured: true, destinations: [] })
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
  }

  it('uses globally enabled destinations when update routing has never been configured', async () => {
    await renderPage()
    expect(container.querySelector('input[aria-label="Disable update alerts for Operations"]')).toBeTruthy()
    expect(container.querySelector('input[aria-label="Enable update alerts for Backup"]')).toBeTruthy()
  })

  it('preserves an explicitly empty update-alert selection', async () => {
    vi.mocked(listNotificationDestinations).mockResolvedValue(response(true, []))
    await renderPage()
    expect(container.querySelector('input[aria-label="Enable update alerts for Operations"]')).toBeTruthy()
    expect(container.querySelector('input[aria-label="Enable update alerts for Backup"]')).toBeTruthy()
  })

  it('leaves the toggle unchanged when password confirmation is cancelled', async () => {
    vi.mocked(listNotificationDestinations).mockResolvedValue(response(true, ['dest-1']))
    await renderPage()

    const first = container.querySelector('input[aria-label="Disable update alerts for Operations"]') as HTMLInputElement
    act(() => first.click())
    const dialog = document.body.querySelector('[role="dialog"]') as HTMLElement
    act(() => (dialog.querySelector('button[type="button"]') as HTMLButtonElement).click())

    expect(first.checked).toBe(true)
    expect(updateNotificationRouting).not.toHaveBeenCalled()
  })

  it('confirms each toggle, rolls back failed saves, and disables other toggles while pending', async () => {
    vi.mocked(listNotificationDestinations).mockResolvedValue(response(true, ['dest-1']))
    vi.mocked(updateNotificationRouting).mockRejectedValueOnce(new Error('server refused'))
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
    expect(updateNotificationRouting).toHaveBeenNthCalledWith(1, [], 'fixture-password')
    expect(updateNotificationRouting).toHaveBeenNthCalledWith(2, [], 'fixture-password')
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
      vi.mocked(updateNotificationRouting).mockImplementation(async selected => ({ configured: true, destinations: selected }))
    })

    it('shows the refetched routing and toggles only the chosen destination', async () => {
      await renderThreeDestinations()
      expect(container.querySelector('input[aria-label="Enable update alerts for Backup"]')).toBeTruthy()

      vi.mocked(listNotificationDestinations).mockResolvedValue(routed(['dest-1', 'dest-2']))
      await act(async () => { await queryClient.invalidateQueries({ queryKey: ['notifications'] }) })
      await vi.waitFor(() => expect(container.querySelector('input[aria-label="Disable update alerts for Backup"]')).toBeTruthy(), { timeout: 1000 })

      act(() => (container.querySelector('input[aria-label="Enable update alerts for Pager"]') as HTMLInputElement).click())
      await confirm('fixture-password')
      await vi.waitFor(() => expect(updateNotificationRouting).toHaveBeenCalledWith(['dest-1', 'dest-2', 'dest-3'], 'fixture-password'), { timeout: 1000 })
    })

    it('applies a toggle to routing that changed while the password prompt was open', async () => {
      await renderThreeDestinations()
      act(() => (container.querySelector('input[aria-label="Enable update alerts for Pager"]') as HTMLInputElement).click())

      vi.mocked(listNotificationDestinations).mockResolvedValue(routed(['dest-1', 'dest-2']))
      await act(async () => { await queryClient.invalidateQueries({ queryKey: ['notifications'] }) })
      await confirm('fixture-password')
      await vi.waitFor(() => expect(updateNotificationRouting).toHaveBeenCalledWith(['dest-1', 'dest-2', 'dest-3'], 'fixture-password'), { timeout: 1000 })
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
    vi.mocked(getSession).mockResolvedValue({ role: 'administrator', user_id: 'admin', username: 'admin', permissions: ['notifications.manage'], csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 } })
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
