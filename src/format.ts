/**
 * Format the Go duration returned by the status API for human-facing copy.
 * Retention is configured and stored with full duration precision, but the
 * dashboard only needs whole days and remaining hours.
 */
export function formatRetention(value: string): string {
  const input = value.trim()
  const match = input.match(/^(?:(\d+(?:\.\d+)?)h)?(?:(\d+(?:\.\d+)?)m)?(?:(\d+(?:\.\d+)?)s)?$/)
  if (!match || !input) return input || 'Unknown'

  const totalHours = Math.floor((Number(match[1] ?? 0) * 3600 + Number(match[2] ?? 0) * 60 + Number(match[3] ?? 0)) / 3600)
  const days = Math.floor(totalHours / 24)
  const hours = totalHours % 24
  const parts: string[] = []
  if (days > 0) parts.push(`${days} day${days === 1 ? '' : 's'}`)
  if (hours > 0) parts.push(`${hours} hour${hours === 1 ? '' : 's'}`)
  return parts.join(' ') || '0 hours'
}

type DateInput = string | number | Date

let displayTimeZone: string | undefined

function supportedTimeZone(zone: string) {
  try {
    new Intl.DateTimeFormat(undefined, { timeZone: zone })
    return true
  } catch {
    return false
  }
}

/**
 * Render console timestamps in the deployment timezone from config.yaml. An
 * omitted value, or one this browser cannot render, keeps the browser's own
 * timezone so the console still shows a valid local time.
 */
export function setDisplayTimeZone(value?: string | null) {
  const zone = value?.trim()
  displayTimeZone = zone && supportedTimeZone(zone) ? zone : undefined
}

/** The configured deployment timezone, when one is in effect. */
export function getDisplayTimeZone(): string | undefined {
  return displayTimeZone
}

/** Date and time in the deployment timezone (or the browser's own). */
export function formatDateTime(value: DateInput, options: Intl.DateTimeFormatOptions = {}): string {
  return new Date(value).toLocaleString(undefined, { ...options, timeZone: displayTimeZone })
}

/** Calendar date in the deployment timezone (or the browser's own). */
export function formatDate(value: DateInput, options: Intl.DateTimeFormatOptions = {}): string {
  return new Date(value).toLocaleDateString(undefined, { ...options, timeZone: displayTimeZone })
}

/** Time of day in the deployment timezone (or the browser's own). */
export function formatTime(value: DateInput, options: Intl.DateTimeFormatOptions = {}): string {
  return new Date(value).toLocaleTimeString(undefined, { ...options, timeZone: displayTimeZone })
}
