import { useEffect, useRef, useState } from 'react'
import { useLocation, useNavigationType, useSearchParams } from 'react-router-dom'
import { MAX_PAGINATION_OFFSET } from './pagination'

/** URL-backed filters and pagination shared by the global and baseline host explorers. */
export function useHostListState() {
  const [searchParams, setSearchParams] = useSearchParams()
  const location = useLocation()
  const navigationType = useNavigationType()
  const urlSearch = searchParams.get('q') ?? ''
  const [search, setSearch] = useState(urlSearch)
  const rawProtocol = searchParams.get('protocol')
  const protocol = rawProtocol === 'tcp' || rawProtocol === 'udp' ? rawProtocol : ''
  const rawOpen = searchParams.get('has_open_ports')
  const open = rawOpen === 'true' || rawOpen === 'false' ? rawOpen : ''
  const rawOffset = searchParams.get('offset')
  const parsedOffset = rawOffset !== null && /^\d+$/.test(rawOffset) ? Number(rawOffset) : 0
  const offset = Number.isSafeInteger(parsedOffset) && parsedOffset > 0 && parsedOffset <= MAX_PAGINATION_OFFSET ? parsedOffset : 0
  const returnTo = `${location.pathname}${location.search}`

  // Keep typing independent of router transitions. Search URL replacements
  // are intentionally skipped; PUSH and POP navigations restore the value
  // from the URL.
  useEffect(() => {
    if (navigationType !== 'REPLACE') setSearch(urlSearch)
  }, [location.key, location.pathname, location.search, navigationType, urlSearch])

  // Replace the current list entry so a detail navigation has one clean
  // history step, while the URL remains reloadable and shareable. The entry
  // keeps its route state, such as the job list path that the baseline
  // explorer's ← Job link returns with.
  const replaceOptions = { replace: true, state: location.state as unknown }

  function updateParam(key: string, value: string) {
    setSearchParams(current => {
      const next = new URLSearchParams(current)
      if (value) next.set(key, value)
      else next.delete(key)
      next.delete('offset')
      return next
    }, replaceOptions)
  }

  function updateOffset(value: number) {
    setSearchParams(current => {
      const next = new URLSearchParams(current)
      if (value > 0) next.set('offset', String(value))
      else next.delete('offset')
      return next
    }, replaceOptions)
  }

  function resetFilters() {
    setSearchParams(current => {
      const next = new URLSearchParams(current)
      next.delete('protocol')
      next.delete('has_open_ports')
      next.delete('offset')
      return next
    }, replaceOptions)
  }

  function updateSearch(value: string) {
    setSearch(value)
    updateParam('q', value)
  }

  return {
    search,
    protocol,
    open,
    offset,
    returnTo,
    updateSearch,
    updateProtocol: (value: string) => updateParam('protocol', value),
    updateOpen: (value: string) => updateParam('has_open_ports', value),
    updateOffset,
    resetFilters,
  }
}

/**
 * Keeps keyboard focus on a host explorer through its recovery actions. Each
 * action replaces the list URL, and the loading state for the new query
 * unmounts the results panel together with the button that was pressed, which
 * would leave focus on the document body. Clear search therefore focuses the
 * search input, which stays mounted. Go to first page and Reset filters focus
 * the panel heading, but only once the reloaded list has settled, because the
 * heading is unmounted while it loads; if the list cannot show its panel, the
 * search input is focused instead. Focus that the user has moved elsewhere in
 * the meantime is left alone.
 *
 * `settled` is true when the list query is neither fetching nor waiting for
 * its first answer.
 */
export function useHostListFocus(settled: boolean) {
  const location = useLocation()
  const searchRef = useRef<HTMLInputElement>(null)
  const headingRef = useRef<HTMLHeadingElement>(null)
  // The location key the action replaced; the reload has not committed while
  // the router still shows it.
  const headingFocusFrom = useRef<string | null>(null)

  useEffect(() => {
    const from = headingFocusFrom.current
    if (from === null || from === location.key || !settled) return
    headingFocusFrom.current = null
    const active = document.activeElement
    if (active && active !== document.body) return
    ;(headingRef.current ?? searchRef.current)?.focus()
  }, [location.key, settled])

  return {
    searchRef,
    headingRef,
    focusSearch() {
      searchRef.current?.focus()
    },
    focusHeadingAfterReload() {
      headingFocusFrom.current = location.key
    },
  }
}
