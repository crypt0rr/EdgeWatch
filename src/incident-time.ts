import { getDisplayTimeZone } from './format'

/** The local wall time entered by a reviewer is interpreted in this zone. */
export function incidentTimeZone() {
  return getDisplayTimeZone() || Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'
}

type WallTime = { year: number; month: number; day: number; hour: number; minute: number }

function wallTimeAt(instant: number, timeZone: string): WallTime {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone,
    hourCycle: 'h23',
    year: 'numeric',
    month: 'numeric',
    day: 'numeric',
    hour: 'numeric',
    minute: 'numeric',
  }).formatToParts(instant)
  const part = (name: Intl.DateTimeFormatPartTypes) => Number(parts.find(item => item.type === name)?.value)
  return { year: part('year'), month: part('month'), day: part('day'), hour: part('hour'), minute: part('minute') }
}

/** Render an exact UTC due instant in the reviewer's configured local zone. */
export function incidentDateTimeInput(instant: string | null | undefined, timeZone = incidentTimeZone()) {
  if (!instant) return ''
  const value = Date.parse(instant)
  if (!Number.isFinite(value)) return ''
  const { year, month, day, hour, minute } = wallTimeAt(value, timeZone)
  const pad = (part: number) => String(part).padStart(2, '0')
  return `${year}-${pad(month)}-${pad(day)}T${pad(hour)}:${pad(minute)}`
}

/**
 * Return every exact UTC instant matching a local datetime input. A DST gap
 * returns no candidates; a repeated clock hour returns both candidates so the
 * UI can ask the reviewer which occurrence they mean.
 */
export function incidentDateTimeCandidates(input: string, timeZone = incidentTimeZone()) {
  const match = input.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$/)
  if (!match) return []
  const wanted: WallTime = {
    year: Number(match[1]), month: Number(match[2]), day: Number(match[3]),
    hour: Number(match[4]), minute: Number(match[5]),
  }
  const naive = Date.UTC(wanted.year, wanted.month - 1, wanted.day, wanted.hour, wanted.minute)
  if (wanted.month < 1 || wanted.month > 12 || wanted.hour > 23 || wanted.minute > 59 ||
      wallTimeAt(naive, 'UTC').year !== wanted.year || wallTimeAt(naive, 'UTC').month !== wanted.month ||
      wallTimeAt(naive, 'UTC').day !== wanted.day) return []

  const candidates = new Set<number>()
  const hour = 60 * 60 * 1000
  for (let delta = -36; delta <= 36; delta += 6) {
    const probe = naive + delta * hour
    const atProbe = wallTimeAt(probe, timeZone)
    const offset = Date.UTC(atProbe.year, atProbe.month - 1, atProbe.day, atProbe.hour, atProbe.minute) - probe
    const instant = naive - offset
    const actual = wallTimeAt(instant, timeZone)
    if (actual.year === wanted.year && actual.month === wanted.month && actual.day === wanted.day && actual.hour === wanted.hour && actual.minute === wanted.minute) candidates.add(instant)
  }
  return [...candidates].sort((left, right) => left - right).map(value => new Date(value).toISOString())
}

/** A short explicit offset for disambiguating repeated local times. */
export function incidentTimeOffset(instant: string, timeZone = incidentTimeZone()) {
  return new Intl.DateTimeFormat(undefined, { timeZone, timeZoneName: 'shortOffset' })
    .formatToParts(new Date(instant))
    .find(part => part.type === 'timeZoneName')?.value ?? timeZone
}
