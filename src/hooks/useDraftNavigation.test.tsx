/** @vitest-environment jsdom */
import { act, fireEvent, renderHook, waitFor } from '@testing-library/react'
import { BrowserRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { useDraftNavigation } from './useDraftNavigation'

const allowDestination = (path: string) => path === '/jobs/new/advanced'
const stateForLink = () => ({ returnTo: '/jobs?q=router' })
function setup(dirty = true, saving = false) {
  return renderHook(({ dirty, saving }) => useDraftNavigation({ dirty, saving, allowDestination, stateForLink }), {
    initialProps: { dirty, saving }, wrapper: BrowserRouter,
  })
}
beforeEach(() => {
  window.history.replaceState({ idx: 0, key: 'jobs', usr: { filter: 'active' } }, '', '/jobs')
  window.history.pushState({ idx: 1, key: 'new', usr: { draft: 'keep' } }, '', '/jobs/new')
})
afterEach(() => vi.restoreAllMocks())

describe('useDraftNavigation', () => {
  it('keeps history state on canceled Back and repeats Back after confirmation', async () => {
    const { result } = setup()
    const state = window.history.state
    act(() => window.history.back())
    await waitFor(() => expect(result.current.discardNavigation?.historyPop).toBe(true))
    expect(window.location.pathname).toBe('/jobs/new')
    expect(window.history.state).toEqual(state)
    act(() => result.current.cancelDiscard())
    expect(window.history.state).toEqual(state)
    act(() => window.history.back())
    await waitFor(() => expect(result.current.discardNavigation?.historyPop).toBe(true))
    act(() => result.current.confirmDiscard())
    await waitFor(() => expect(window.location.pathname).toBe('/jobs'))
    expect(window.history.state.usr).toEqual({ filter: 'active' })
  })

  it('preserves explicit state for requested navigation', async () => {
    const { result } = setup()
    act(() => result.current.requestNavigation('/jobs', { returnTo: '/jobs?q=test' }))
    expect(window.location.pathname).toBe('/jobs/new')
    act(() => result.current.confirmDiscard())
    await waitFor(() => expect(window.location.pathname).toBe('/jobs'))
    expect(window.history.state.usr).toEqual({ returnTo: '/jobs?q=test' })
  })

  it('intercepts ordinary links with page-specific state and ignores modified clicks', () => {
    const { result } = setup()
    const anchor = document.createElement('a')
    anchor.href = '/jobs'
    document.body.append(anchor)
    try {
      anchor.addEventListener('click', event => event.preventDefault())
      fireEvent.click(anchor, { ctrlKey: true })
      expect(result.current.discardNavigation).toBeNull()
      fireEvent.click(anchor)
      expect(result.current.discardNavigation).toMatchObject({ destination: '/jobs', state: { returnTo: '/jobs?q=router' } })
    } finally { anchor.remove() }
  })

  it('allows creation paths and clean navigation without a dialog', async () => {
    const { result, rerender } = setup()
    act(() => result.current.requestNavigation('/jobs/new/advanced'))
    await waitFor(() => expect(window.location.pathname).toBe('/jobs/new/advanced'))
    expect(result.current.discardNavigation).toBeNull()
    rerender({ dirty: false, saving: false })
    act(() => result.current.requestNavigation('/jobs'))
    await waitFor(() => expect(window.location.pathname).toBe('/jobs'))
  })

  it('blocks requested navigation, Back, and discard confirmation while saving', async () => {
    const { result, rerender } = setup()
    act(() => result.current.requestNavigation('/jobs'))
    rerender({ dirty: true, saving: true })
    act(() => result.current.confirmDiscard())
    expect(window.location.pathname).toBe('/jobs/new')
    act(() => result.current.cancelDiscard())
    act(() => result.current.requestNavigation('/jobs/new/advanced'))
    expect(window.location.pathname).toBe('/jobs/new')
    const push = vi.spyOn(window.history, 'pushState')
    act(() => window.history.back())
    await waitFor(() => expect(push).toHaveBeenCalled())
    expect(window.location.pathname).toBe('/jobs/new')
    expect(result.current.discardNavigation).toBeNull()
  })

  it('guards unload only while dirty or saving and removes listeners on unmount', () => {
    const { rerender, unmount } = setup()
    const unload = () => {
      const event = new Event('beforeunload', { cancelable: true })
      window.dispatchEvent(event)
      return event.defaultPrevented
    }
    expect(unload()).toBe(true)
    rerender({ dirty: false, saving: false })
    expect(unload()).toBe(false)
    rerender({ dirty: false, saving: true })
    expect(unload()).toBe(true)
    unmount()
    expect(unload()).toBe(false)
  })
})
