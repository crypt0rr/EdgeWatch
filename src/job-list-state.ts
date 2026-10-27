import { useEffect, useState } from 'react'
import { useLocation, useNavigationType, useSearchParams } from 'react-router-dom'

export type JobsFilter = 'all' | 'attention'

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
