import { useEffect, useState } from 'react'

/**
 * Keep fast-changing form input local while exposing a settled value for
 * expensive queries. Cleanup also ensures a superseded value never commits.
 */
export function useDebouncedValue<T>(value: T, delay = 250) {
  const [debounced, setDebounced] = useState(value)

  useEffect(() => {
    const timer = window.setTimeout(() => setDebounced(value), delay)
    return () => window.clearTimeout(timer)
  }, [delay, value])

  return debounced
}
