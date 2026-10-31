import { useEffect, useState } from 'react'
import { useLocation, useNavigationType, useSearchParams } from 'react-router-dom'

export type JobsFilter = 'all' | 'attention'

/**
 * The job list URL that a page reached from it returns to, with the list's
 * search and filter. Only a path of the job list itself is accepted, so route
 * state cannot send a return link anywhere else; any other value falls back
 * to the unfiltered list.
 */
export function jobListReturnTo(value: unknown): string {
  return typeof value === 'string' && (
    value === '/jobs' || value === '/jobs/' ||
    value.startsWith('/jobs?') || value.startsWith('/jobs/?')
  ) ? value : '/jobs'
}

/**
 * Reads the job list return path from route state. The job pages carry it as
 * `returnTo`; a host page, whose `returnTo` is its own host list, carries it
 * as `jobsReturnTo`.
 */
export function jobListReturnToFromState(state: unknown, key: 'returnTo' | 'jobsReturnTo' = 'returnTo'): string {
  if (!state || typeof state !== 'object' || !(key in state)) return '/jobs'
  return jobListReturnTo((state as Record<string, unknown>)[key])
}

/** URL-backed search and filtering for the job list. */
export function useJobListState() {
  const [searchParams, setSearchParams] = useSearchParams()
  const location = useLocation()
  const navigationType = useNavigationType()
  const urlSearch = searchParams.get('q') ?? ''
  const filter: JobsFilter = searchParams.get('filter') === 'attention' ? 'attention' : 'all'
  const [search, setSearch] = useState(urlSearch)
  const returnTo = `${location.pathname}${location.search}`

  // Keep typing independent of router transitions. Search URL replacements
  // are intentionally skipped; PUSH and POP navigations restore the value
  // from the URL.
  useEffect(() => {
    if (navigationType !== 'REPLACE') setSearch(urlSearch)
  }, [location.key, location.pathname, location.search, navigationType, urlSearch])

  function updateParam(key: string, value: string) {
    setSearchParams(current => {
      const next = new URLSearchParams(current)
      if (value) next.set(key, value)
      else next.delete(key)
      return next
    }, { replace: true })
  }

  function updateSearch(value: string) {
    setSearch(value)
    updateParam('q', value)
  }

  function updateFilter(value: JobsFilter) {
    updateParam('filter', value === 'all' ? '' : value)
  }

  return { search, filter, returnTo, updateSearch, updateFilter }
}
