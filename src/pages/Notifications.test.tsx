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
})
