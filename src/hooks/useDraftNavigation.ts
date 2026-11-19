import { useEffect, useRef, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'

type PendingNavigation = { destination: string; historyPop: boolean; state?: unknown }

type Options = {
  dirty: boolean
  saving: boolean
  allowDestination: (path: string) => boolean
  stateForLink?: (destination: URL) => unknown
}

/** Shares the browser event/history protocol while callers own draft policy and dialogs. */
export function useDraftNavigation({ dirty, saving, allowDestination, stateForLink }: Options) {
  const location = useLocation()
  const navigate = useNavigate()
  const [discardNavigation, setDiscardNavigation] = useState<PendingNavigation | null>(null)
  const currentHistoryEntry = useRef<{ path: string; state: unknown } | null>(null)
  const allowHistoryPop = useRef(false)

  useEffect(() => {
    currentHistoryEntry.current = { path: `${location.pathname}${location.search}${location.hash}`, state: window.history.state }
  }, [location.hash, location.key, location.pathname, location.search])

  useEffect(() => {
    if (!dirty && !saving) return
    const currentPath = `${location.pathname}${location.search}${location.hash}`
    const onInternalLinkClick = (event: MouseEvent) => {
      if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return
      const target = event.target
      if (!(target instanceof Element)) return
      const anchor = target.closest<HTMLAnchorElement>('a[href]')
      if (!anchor || anchor.hasAttribute('download') || (anchor.target && anchor.target !== '_self')) return
      const destination = new URL(anchor.href, window.location.href)
      if (destination.origin !== window.location.origin) return
      const nextPath = `${destination.pathname}${destination.search}${destination.hash}`
      if (nextPath === currentPath) return
      if (saving) {
        event.preventDefault()
        event.stopPropagation()
        return
      }
      if (allowDestination(nextPath)) return
      event.preventDefault()
      event.stopPropagation()
      const state = stateForLink?.(destination)
      setDiscardNavigation({ destination: nextPath, historyPop: false, state })
    }
    const onPopState = (event: PopStateEvent) => {
      if (allowHistoryPop.current) {
        allowHistoryPop.current = false
        return
      }
      const nextPath = `${window.location.pathname}${window.location.search}${window.location.hash}`
      if (nextPath === currentPath) return
      if (saving) {
        event.stopImmediatePropagation()
        const current = currentHistoryEntry.current
        if (current) window.history.pushState(current.state, '', current.path)
        return
      }
      if (allowDestination(nextPath)) return

      // Browser history has already moved by the time popstate fires. Stop
      // BrowserRouter from applying that location, then restore the exact
      // current router entry and let the user either cancel or repeat the pop.
      event.stopImmediatePropagation()
      const current = currentHistoryEntry.current
      setDiscardNavigation({ destination: nextPath, historyPop: true })
      if (current) window.history.pushState(current.state, '', current.path)
    }
    const onBeforeUnload = (event: BeforeUnloadEvent) => {
      event.preventDefault()
      event.returnValue = ''
    }
    document.addEventListener('click', onInternalLinkClick, true)
    window.addEventListener('popstate', onPopState, true)
    window.addEventListener('beforeunload', onBeforeUnload)
    return () => {
      document.removeEventListener('click', onInternalLinkClick, true)
      window.removeEventListener('popstate', onPopState, true)
      window.removeEventListener('beforeunload', onBeforeUnload)
    }
  }, [dirty, location.hash, location.pathname, location.search, saving, allowDestination, stateForLink])
  function requestNavigation(destination: string, state?: unknown) {
    if (saving) return
    if (allowDestination(destination)) navigate(destination, { state })
    else if (dirty) setDiscardNavigation({ destination, historyPop: false, state })
    else navigate(destination, { state })
  }

  function confirmDiscard() {
    if (!discardNavigation || saving) return
    const pending = discardNavigation
    setDiscardNavigation(null)
    if (pending.historyPop) {
      allowHistoryPop.current = true
      window.history.back()
    } else navigate(pending.destination, { state: pending.state })
  }

  function cancelDiscard() {
    setDiscardNavigation(null)
  }

  return { discardNavigation, requestNavigation, confirmDiscard, cancelDiscard }
}
