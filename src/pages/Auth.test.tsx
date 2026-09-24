/** @vitest-environment jsdom */

import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter, MemoryRouter, useLocation } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { activate, login, setCSRF, setup, setupStatus } from '../api'
import { Activate, Login, Setup } from './Auth'

vi.mock('../api', () => ({
  activate: vi.fn(),
  login: vi.fn(),
  setCSRF: vi.fn(),
  setup: vi.fn(),
  setupStatus: vi.fn(),
}))

;(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true

function setInputValue(input: HTMLInputElement, value: string) {
  act(() => {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set
    setter?.call(input, value)
    input.dispatchEvent(new Event('input', { bubbles: true }))
  })
}

function submitForm(form: HTMLFormElement) {
  act(() => form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })))
}

function LocationProbe() {
  const location = useLocation()
  return <output data-testid="location">{location.pathname}{location.search}{location.hash}</output>
}

describe('authentication pages', () => {
  let root: Root
  let container: HTMLDivElement
  let queryClient: QueryClient

  beforeEach(() => {
    container = document.createElement('div')
    document.body.appendChild(container)
    root = createRoot(container)
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    vi.mocked(setupStatus).mockResolvedValue({
      configured: true,
      setup_available: false,
      public_dashboard_enabled: true,
      password_requirements: { minimum_length: 12 },
    })
    vi.mocked(login).mockResolvedValue({
      username: 'admin',
      display_name: 'Administrator',
      role: 'administrator',
      permissions: [],
      csrf_token: 'csrf-token',
      totp_required: false,
    })
    vi.mocked(setup).mockResolvedValue(undefined)
    vi.mocked(activate).mockResolvedValue(undefined)
  })

  afterEach(() => {
    act(() => root.unmount())
    queryClient.clear()
    container.remove()
    window.history.replaceState({}, '', '/')
    vi.clearAllMocks()
  })

  async function renderPage(element: React.ReactNode, initialEntry: string) {
    await act(async () => {
      root.render(
        <QueryClientProvider client={queryClient}>
          <MemoryRouter initialEntries={[initialEntry]}>
            {element}
            <LocationProbe />
          </MemoryRouter>
        </QueryClientProvider>,
      )
      await Promise.resolve()
      await Promise.resolve()
    })
  }

  async function renderBrowserPage(element: React.ReactNode, initialEntry: string) {
    window.history.replaceState({}, '', initialEntry)
    await act(async () => {
      root.render(
        <QueryClientProvider client={queryClient}>
          <BrowserRouter>
            {element}
            <LocationProbe />
          </BrowserRouter>
        </QueryClientProvider>,
      )
      await Promise.resolve()
      await Promise.resolve()
    })
  }

  it('logs in and routes administrators to the dashboard', async () => {
    await renderPage(<Login />, '/login')
    const inputs = Array.from(container.querySelectorAll('input')) as HTMLInputElement[]
    setInputValue(inputs[0], 'admin')
    setInputValue(inputs[1], 'correct horse battery staple')

    await act(async () => {
      submitForm(container.querySelector('form') as HTMLFormElement)
      await Promise.resolve()
      await Promise.resolve()
    })

    expect(login).toHaveBeenCalledWith('correct horse battery staple', '', undefined, 'admin')
    expect(setCSRF).toHaveBeenCalledWith('csrf-token')
    expect(container.querySelector('[data-testid="location"]')?.textContent).toBe('/')
    expect(container.querySelector('[role="alert"]')).toBeNull()
  })

  it('supports recovery-code login and displays authentication failures', async () => {
    vi.mocked(login).mockRejectedValue(new Error('invalid credentials'))
    await renderPage(<Login />, '/login')
    const recoveryToggle = Array.from(container.querySelectorAll('button')).find(button => button.textContent?.includes('recovery code')) as HTMLButtonElement
    act(() => recoveryToggle.click())

    const inputs = Array.from(container.querySelectorAll('input')) as HTMLInputElement[]
    expect(container.textContent).toContain('Recovery code')
    expect(inputs[2].inputMode).toBe('text')
    setInputValue(inputs[1], 'wrong password')
    setInputValue(inputs[2], 'AB12CD34EF')
    await act(async () => {
      submitForm(container.querySelector('form') as HTMLFormElement)
      await Promise.resolve()
      await Promise.resolve()
    })

    expect(login).toHaveBeenCalledWith('wrong password', '', 'AB12CD34EF', 'admin')
    expect(container.querySelector('.form-error')?.textContent).toContain('invalid credentials')
    expect(container.querySelector('[data-testid="location"]')?.textContent).toBe('/login')
  })

  it('validates setup locally, toggles password visibility, and creates the administrator', async () => {
    await renderPage(<Setup />, '/setup')
    const inputs = Array.from(container.querySelectorAll('input')) as HTMLInputElement[]
    setInputValue(inputs[0], '  setup-token  ')
    setInputValue(inputs[1], 'short')
    setInputValue(inputs[2], 'short')
    await act(async () => submitForm(container.querySelector('form') as HTMLFormElement))
    expect(container.querySelector('.form-error')?.textContent).toContain('at least 12 characters')
    expect(setup).not.toHaveBeenCalled()

    setInputValue(inputs[1], 'correct horse battery staple')
    setInputValue(inputs[2], 'different password')
    await act(async () => submitForm(container.querySelector('form') as HTMLFormElement))
    expect(container.querySelector('.form-error')?.textContent).toContain('Passwords do not match')

    const visibility = container.querySelector('button[aria-label="Show password"]') as HTMLButtonElement
    act(() => visibility.click())
    expect(inputs[1].type).toBe('text')
    act(() => (container.querySelector('button[aria-label="Hide password"]') as HTMLButtonElement).click())
    expect(inputs[1].type).toBe('password')

    setInputValue(inputs[2], 'correct horse battery staple')
    await act(async () => {
      submitForm(container.querySelector('form') as HTMLFormElement)
      await Promise.resolve()
      await Promise.resolve()
    })
    expect(setup).toHaveBeenCalledWith('setup-token', 'correct horse battery staple')
    expect(container.querySelector('[data-testid="location"]')?.textContent).toBe('/login')
  })

  it('prefills a fragment activation token, removes it from browser history, and activates the account', async () => {
    await renderBrowserPage(<Activate />, '/activate?source=invite#token=%20invite-token%20')
    const inputs = Array.from(container.querySelectorAll('input')) as HTMLInputElement[]
    expect(inputs[0].value).toBe(' invite-token ')
    expect(window.location.pathname).toBe('/activate')
    expect(window.location.search).toBe('?source=invite')
    expect(window.location.hash).toBe('')
    setInputValue(inputs[0], ' invite-token ')
    setInputValue(inputs[1], 'correct horse battery staple')
    setInputValue(inputs[2], 'different password')
    await act(async () => submitForm(container.querySelector('form') as HTMLFormElement))
    expect(container.querySelector('.form-error')?.textContent).toContain('Passwords do not match')
    expect(activate).not.toHaveBeenCalled()

    setInputValue(inputs[2], 'correct horse battery staple')
    await act(async () => {
      submitForm(container.querySelector('form') as HTMLFormElement)
      await Promise.resolve()
      await Promise.resolve()
    })
    expect(activate).toHaveBeenCalledWith('invite-token', 'correct horse battery staple')
    expect(container.querySelector('[data-testid="location"]')?.textContent).toBe('/login')
  })

  it('accepts and immediately scrubs a legacy query activation token', async () => {
    vi.mocked(activate).mockRejectedValueOnce(new Error('activation could not be completed; the token may be invalid or expired'))
    await renderBrowserPage(<Activate />, '/activate?source=legacy&token=old-token')
    const inputs = Array.from(container.querySelectorAll('input')) as HTMLInputElement[]
    expect(inputs[0].value).toBe('old-token')
    expect(window.location.search).toBe('?source=legacy')
    expect(window.location.hash).toBe('')

    setInputValue(inputs[1], 'correct horse battery staple')
    setInputValue(inputs[2], 'correct horse battery staple')
    await act(async () => {
      submitForm(container.querySelector('form') as HTMLFormElement)
      await Promise.resolve()
      await Promise.resolve()
    })
    expect(activate).toHaveBeenCalledWith('old-token', 'correct horse battery staple')
    expect(container.querySelector('[role="alert"]')?.textContent).toContain('invalid or expired')
    expect(window.location.href).not.toContain('old-token')
  })

  it('announces setup and activation failures accessibly', async () => {
    vi.mocked(setup).mockRejectedValueOnce(new Error('setup unavailable'))
    await renderPage(<Setup />, '/setup')
    let inputs = Array.from(container.querySelectorAll('input')) as HTMLInputElement[]
    setInputValue(inputs[0], 'setup-token')
    setInputValue(inputs[1], 'correct horse battery staple')
    setInputValue(inputs[2], 'correct horse battery staple')
    await act(async () => {
      submitForm(container.querySelector('form') as HTMLFormElement)
      await Promise.resolve()
      await Promise.resolve()
    })
    expect(container.querySelector('[role="alert"]')?.textContent).toContain('setup unavailable')

    act(() => root.unmount())
    container.innerHTML = ''
    root = createRoot(container)
    vi.mocked(activate).mockRejectedValueOnce(new Error('activation unavailable'))
    await renderPage(<Activate />, '/activate?token=invite-token')
    inputs = Array.from(container.querySelectorAll('input')) as HTMLInputElement[]
    setInputValue(inputs[0], 'invite-token')
    setInputValue(inputs[1], 'correct horse battery staple')
    setInputValue(inputs[2], 'correct horse battery staple')
    await act(async () => {
      submitForm(container.querySelector('form') as HTMLFormElement)
      await Promise.resolve()
      await Promise.resolve()
    })
    expect(container.querySelector('[role="alert"]')?.textContent).toContain('activation unavailable')
  })
})
