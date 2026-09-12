/** @vitest-environment jsdom */

import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ActionDialog } from './ActionDialog'

;(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true

function setInputValue(input: HTMLInputElement, value: string) {
  // Use the native setter so React's value tracker observes the synthetic
  // input event just as it would from a real browser keystroke.
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set
  setter?.call(input, value)
  input.dispatchEvent(new Event('input', { bubbles: true }))
}

function submitForm(form: HTMLFormElement) {
  form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))
}

describe('ActionDialog accessibility', () => {
  let root: Root
  let shell: HTMLElement
  let trigger: HTMLButtonElement

  beforeEach(() => {
    document.body.innerHTML = '<div class="app-shell"><button id="trigger">Open</button></div><div id="root"></div>'
    shell = document.querySelector('.app-shell') as HTMLElement
    trigger = document.querySelector('#trigger') as HTMLButtonElement
    trigger.focus()
    root = createRoot(document.querySelector('#root') as HTMLElement)
  })

  afterEach(() => {
    act(() => root.unmount())
    document.body.innerHTML = ''
  })

  it('portals the dialog and makes the application shell inert', () => {
    act(() => {
      root.render(<ActionDialog title="Confirm" description="Confirm this action." confirmLabel="Continue" onConfirm={vi.fn()} onCancel={vi.fn()} />)
    })

    const dialog = document.querySelector('[role="dialog"]')
    expect(dialog).toBeTruthy()
    expect(dialog?.closest('.app-shell')).toBeNull()
    expect(shell.hasAttribute('inert')).toBe(true)
    expect(shell.getAttribute('aria-hidden')).toBe('true')
    expect(dialog?.querySelector('[aria-live="polite"]')).toBeTruthy()
    expect(dialog?.getAttribute('aria-busy')).toBe('false')
  })

  it('restores background state and focus when dismissed', () => {
    act(() => {
      root.render(<ActionDialog title="Confirm" description="Confirm this action." confirmLabel="Continue" onConfirm={vi.fn()} onCancel={vi.fn()} />)
    })

    act(() => root.render(null))

    expect(shell.hasAttribute('inert')).toBe(false)
    expect(shell.hasAttribute('aria-hidden')).toBe(false)
    expect(document.activeElement).toBe(trigger)
  })

  it('validates required and confirmation values before invoking the action', async () => {
    const onConfirm = vi.fn()
    act(() => {
      root.render(<ActionDialog title="Remove" description="Remove this destination." confirmLabel="Remove" valueLabel="Password" valueRequired expectedValue="secret" onConfirm={onConfirm} onCancel={vi.fn()} />)
    })
    const form = document.querySelector('form') as HTMLFormElement
    const input = document.querySelector('input') as HTMLInputElement
    const confirm = document.querySelector('button[type="submit"]') as HTMLButtonElement
    expect(input.type).toBe('text')
    expect(confirm.disabled).toBe(true)

    act(() => submitForm(form))
    expect(document.querySelector('[role="alert"]')?.textContent).toContain('Password is required.')

    act(() => setInputValue(input, 'wrong'))
    expect(confirm.disabled).toBe(false)
    await act(async () => {
      confirm.click()
      await Promise.resolve()
    })
    expect(document.querySelector('[role="alert"]')?.textContent).toContain('confirmation text does not match')
    expect(onConfirm).not.toHaveBeenCalled()

    act(() => setInputValue(input, 'secret'))
    await act(async () => {
      confirm.click()
      await Promise.resolve()
    })
    expect(onConfirm).toHaveBeenCalledWith('secret')
  })

  it('supports cancellation, external errors, and async busy state', async () => {
    const onCancel = vi.fn()
    let release!: () => void
    const pending = new Promise<void>(resolve => { release = resolve })
    const onConfirm = vi.fn(() => pending)
    act(() => {
      root.render(<ActionDialog title="Confirm" description="Confirm this action." confirmLabel="Continue" valueLabel="Code" valueType="password" error="Server rejected the request." onConfirm={onConfirm} onCancel={onCancel} />)
    })
    const input = document.querySelector('input') as HTMLInputElement
    const confirm = document.querySelector('button[type="submit"]') as HTMLButtonElement
    expect(input.type).toBe('password')
    expect(document.querySelector('[role="alert"]')?.textContent).toContain('Server rejected')
    act(() => setInputValue(input, 'value'))
    await act(async () => {
      confirm.click()
      await Promise.resolve()
    })
    expect(onConfirm).toHaveBeenCalledWith('value')
    expect(document.querySelector('[role="dialog"]')?.getAttribute('aria-busy')).toBe('true')
    expect(confirm.disabled).toBe(true)
    act(() => document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true })))
    expect(onCancel).not.toHaveBeenCalled()
    release()
    await act(async () => {
      await pending
      await Promise.resolve()
    })
    expect(document.querySelector('[role="dialog"]')?.getAttribute('aria-busy')).toBe('false')

    act(() => document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true })))
    expect(onCancel).toHaveBeenCalledTimes(1)
  })

  it('keeps keyboard focus inside the dialog while tabbing', () => {
    act(() => {
      root.render(<ActionDialog title="Confirm" description="Confirm this action." confirmLabel="Continue" onConfirm={vi.fn()} onCancel={vi.fn()} />)
    })
    const dialog = document.querySelector('[role="dialog"]') as HTMLElement
    const buttons = Array.from(dialog.querySelectorAll('button')) as HTMLButtonElement[]
    expect(buttons).toHaveLength(2)
    buttons[0].focus()
    act(() => document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Tab', shiftKey: true, bubbles: true })))
    expect(document.activeElement).toBe(buttons[1])
    act(() => document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Tab', bubbles: true })))
    expect(document.activeElement).toBe(buttons[0])
    act(() => document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true })))
    expect(document.activeElement).toBe(buttons[0])
  })
})
