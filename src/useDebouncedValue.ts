import { useEffect, useState } from 'react'

/**
 * Keep fast-changing form input local while exposing a settled value for
 * expensive queries. Cleanup also ensures a superseded value never commits,
 * and a value that already equals the settled one schedules no update, such
 * as on mount or after typing back to it.
 */
export function useDebouncedValue<T>(value: T, delay = 250) {
  const [debounced, setDebounced] = useState(value)

  useEffect(() => {
    if (Object.is(value, debounced)) return
    const timer = window.setTimeout(() => setDebounced(value), delay)
    return () => window.clearTimeout(timer)
  }, [debounced, delay, value])

  return debounced
}
