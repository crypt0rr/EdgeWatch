import { incidentDateTimeCandidates } from './incident-time'

export type ChangeWindowLocalTime = {
  /** RFC 3339 time with the numeric offset for the job's timezone. */
  value: string
  /** The same instant in UTC, for an exact confirmation in the form. */
  instant: string
  /** A readable numeric offset such as UTC+02:00. */
  offset: string
}

export function isChangeWindowTimeZoneSupported(timeZone: string): boolean {
  try {
    new Intl.DateTimeFormat('en-US', { timeZone })
    return true
  } catch {
    return false
  }
}

function offsetAt(instant: string, timeZone: string): string | null {
  let name: string | undefined
  try {
    name = new Intl.DateTimeFormat('en-US', { timeZone, timeZoneName: 'longOffset' })
      .formatToParts(new Date(instant))
      .find(part => part.type === 'timeZoneName')?.value
  } catch {
    return null
  }
  if (name === 'GMT') return '+00:00'
  const match = name?.match(/^GMT([+-]\d{2}:\d{2})$/)
  return match?.[1] ?? null
}

/**
 * Resolve a datetime-local value in the job's timezone. Gaps have no
 * candidate; folds return both instants so an operator can choose the
 * matching UTC offset explicitly.
 */
export function changeWindowLocalTime(input: string, timeZone: string): ChangeWindowLocalTime[] {
  let instants: string[]
  try {
    instants = incidentDateTimeCandidates(input, timeZone)
  } catch {
    return []
  }
  return instants.flatMap(instant => {
    const offset = offsetAt(instant, timeZone)
    if (!offset) return []
    return [{ value: `${input}:00${offset}`, instant, offset: `UTC${offset}` }]
  })
}

/** Return a candidate only when the selected numeric offset matches the zone. */
export function selectChangeWindowLocalTime(input: string, timeZone: string, selectedValue: string): ChangeWindowLocalTime | null {
  return changeWindowLocalTime(input, timeZone).find(candidate => candidate.value === selectedValue) ?? null
}

/** Render a saved UTC instant in its job timezone with an explicit offset. */
export function formatChangeWindowTime(instant: string, timeZone: string): string {
  const offset = offsetAt(instant, timeZone)
  let local: string
  try {
    local = new Intl.DateTimeFormat(undefined, {
      timeZone,
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: 'numeric',
      minute: '2-digit',
      second: '2-digit',
    }).format(new Date(instant))
  } catch {
    return `${instant} (${timeZone})`
  }
  return `${local} (${timeZone}${offset ? `, UTC${offset}` : ''})`
}
