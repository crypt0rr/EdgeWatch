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

const DAY_MS = 24 * 60 * 60 * 1000

let offsetFormat: { zone: string; format: Intl.DateTimeFormat } | undefined

/** The offset of the timezone from UTC at the instant, in milliseconds. */
function zoneOffset(instant: number, zone: string) {
  if (offsetFormat?.zone !== zone) offsetFormat = { zone, format: new Intl.DateTimeFormat('en-US', { timeZone: zone, hourCycle: 'h23', year: 'numeric', month: 'numeric', day: 'numeric', hour: 'numeric', minute: 'numeric', second: 'numeric' }) }
  const parts = offsetFormat.format.formatToParts(instant)
  const part = (type: Intl.DateTimeFormatPartTypes) => Number(parts.find(item => item.type === type)?.value)
  const wallClock = Date.UTC(part('year'), part('month') - 1, part('day'), part('hour'), part('minute'), part('second'))
  return wallClock - Math.floor(instant / 1000) * 1000
}

/**
 * The first instant of a calendar day in the deployment timezone (or the
 * browser's own), so a day that a filter names is the day the console shows.
 * The month is 1-based, and a day past the end of the month rolls over.
 */
export function startOfDay(year: number, month: number, day: number): Date {
  const zone = displayTimeZone
  if (!zone) return new Date(year, month - 1, day)
  const midnight = Date.UTC(year, month - 1, day)
  // The zone's offsets a day before and a day after bracket a clock change
  // on the day. The day starts at the earlier candidate that has the offset
  // it assumes. When neither has it, the change skips midnight, and the day
  // starts where the skipped hour ends.
  const candidates = [zoneOffset(midnight - DAY_MS, zone), zoneOffset(midnight + DAY_MS, zone)].map(offset => ({ time: midnight - offset, offset }))
  const valid = candidates.filter(candidate => zoneOffset(candidate.time, zone) === candidate.offset).map(candidate => candidate.time)
  return new Date(valid.length ? Math.min(...valid) : Math.max(...candidates.map(candidate => candidate.time)))
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
