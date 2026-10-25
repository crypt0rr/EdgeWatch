import { useLocation, useSearchParams } from 'react-router-dom'

/** URL-backed filters and pagination shared by the global and baseline host explorers. */
export function useHostListState() {
  const [searchParams, setSearchParams] = useSearchParams()
  const location = useLocation()
  const search = searchParams.get('q') ?? ''
  const rawProtocol = searchParams.get('protocol')
  const protocol = rawProtocol === 'tcp' || rawProtocol === 'udp' ? rawProtocol : ''
  const rawOpen = searchParams.get('has_open_ports')
  const open = rawOpen === 'true' || rawOpen === 'false' ? rawOpen : ''
  const rawOffset = searchParams.get('offset')
  const parsedOffset = rawOffset === null ? 0 : Number(rawOffset)
  const offset = Number.isSafeInteger(parsedOffset) && parsedOffset > 0 ? parsedOffset : 0
  const returnTo = `${location.pathname}${location.search}`

  // Replace the current list entry so a detail navigation has one clean
  // history step, while the URL remains reloadable and shareable.
  function updateParam(key: string, value: string) {
    setSearchParams(current => {
      const next = new URLSearchParams(current)
      if (value) next.set(key, value)
      else next.delete(key)
      next.delete('offset')
      return next
    }, { replace: true })
  }

  function updateOffset(value: number) {
    setSearchParams(current => {
      const next = new URLSearchParams(current)
      if (value > 0) next.set('offset', String(value))
      else next.delete('offset')
      return next
    }, { replace: true })
  }

  function resetFilters() {
    setSearchParams(current => {
      const next = new URLSearchParams(current)
      next.delete('protocol')
      next.delete('has_open_ports')
      next.delete('offset')
      return next
    }, { replace: true })
  }

  return {
    search,
    protocol,
    open,
    offset,
    returnTo,
    updateSearch: (value: string) => updateParam('q', value),
    updateProtocol: (value: string) => updateParam('protocol', value),
    updateOpen: (value: string) => updateParam('has_open_ports', value),
    updateOffset,
    resetFilters,
  }
}
