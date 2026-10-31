/** @vitest-environment jsdom */

import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { useDebouncedValue } from './useDebouncedValue'

;(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true

function Probe({ value, onRender }: { value: string, onRender: (settled: string) => void }) {
  onRender(useDebouncedValue(value))
  return null
}

describe('useDebouncedValue', () => {
  let container: HTMLDivElement
  let root: Root

  beforeEach(() => {
    vi.useFakeTimers()
    container = document.createElement('div')
    root = createRoot(container)
  })

  afterEach(() => {
    act(() => root.unmount())
    vi.useRealTimers()
  })

  it('settles a changed value after the delay and schedules nothing for a settled one', () => {
    const settled: string[] = []
    const render = (value: string) => act(() => root.render(<Probe value={value} onRender={value => settled.push(value)} />))

    // A value that is already settled, as on mount, schedules no update that
    // could land outside act() or re-render the page for nothing.
    render('a')
    expect(vi.getTimerCount()).toBe(0)

    render('ab')
    expect(vi.getTimerCount()).toBe(1)
    act(() => vi.advanceTimersByTime(249))
    expect(settled.at(-1)).toBe('a')
    act(() => vi.advanceTimersByTime(1))
    expect(settled.at(-1)).toBe('ab')
    expect(vi.getTimerCount()).toBe(0)

    // Typing back to the settled value before the delay cancels the update.
    render('abc')
    render('ab')
    expect(vi.getTimerCount()).toBe(0)
    const renders = settled.length
    act(() => vi.advanceTimersByTime(1000))
    expect(settled.length).toBe(renders)
    expect(settled.at(-1)).toBe('ab')
  })
})
