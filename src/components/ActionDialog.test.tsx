/** @vitest-environment jsdom */

import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ActionDialog } from './ActionDialog'

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
})
