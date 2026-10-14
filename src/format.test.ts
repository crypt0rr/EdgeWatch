import { afterEach, describe, expect, it } from 'vitest'
import { editableDuration, formatDate, formatDateTime, formatDateTimeInTimeZone, formatRetention, formatTime, getDisplayTimeZone, setDisplayTimeZone } from './format'

describe('editableDuration', () => {
  it('turns Go durations into the units the job editor accepts', () => {
    expect(editableDuration('192h0m0s')).toBe('8d')
    expect(editableDuration('24h0m0s')).toBe('1d')
    expect(editableDuration('1h0m0s')).toBe('1h')
    expect(editableDuration('36h0m0s')).toBe('36h')
    expect(editableDuration('1h30m0s')).toBe('1h30m')
    expect(editableDuration('1h0m30s')).toBe('1h30s')
    expect(editableDuration('30m0s')).toBe('30m')
    expect(editableDuration('1m30s')).toBe('1m30s')
    expect(editableDuration('45s')).toBe('45s')
  })

  it('leaves values it cannot read unchanged', () => {
    expect(editableDuration('8d')).toBe('8d')
    expect(editableDuration('1.5s')).toBe('1.5s')
    expect(editableDuration('0s')).toBe('0s')
    expect(editableDuration('')).toBe('')
  })
})

describe('formatRetention', () => {
  it('formats whole days without unnecessary zero units', () => {
    expect(formatRetention('2160h0m0s')).toBe('90 days')
    expect(formatRetention('24h0m0s')).toBe('1 day')
  })

  it('formats remaining hours after days', () => {
    expect(formatRetention('49h0m0s')).toBe('2 days 1 hour')
    expect(formatRetention('26h45m30s')).toBe('1 day 2 hours')
  })

  it('handles sub-day durations and an unavailable value', () => {
    expect(formatRetention('3h30m0s')).toBe('3 hours')
    expect(formatRetention('')).toBe('Unknown')
  })
})

describe('deployment timezone formatting', () => {
  // 10:00 UTC is 15:45 in Kathmandu (+05:45, no daylight saving), which cannot
  // coincide with the test runner's own timezone offset.
  const instant = '2026-07-01T10:00:00Z'
  const clock = { hour: '2-digit', minute: '2-digit', hourCycle: 'h23' } as const
  afterEach(() => setDisplayTimeZone(undefined))

  it('formats timestamps in the configured deployment timezone', () => {
    setDisplayTimeZone(' Asia/Kathmandu ')
    expect(getDisplayTimeZone()).toBe('Asia/Kathmandu')
    expect(formatTime(instant, clock)).toBe(new Date(instant).toLocaleTimeString(undefined, { ...clock, timeZone: 'Asia/Kathmandu' }))
    expect(formatTime(instant, clock)).toContain('15:45')
    expect(formatDateTime(instant)).toBe(new Date(instant).toLocaleString(undefined, { timeZone: 'Asia/Kathmandu' }))
    expect(formatDate('2026-07-01T20:00:00Z')).toBe(new Date('2026-07-01T20:00:00Z').toLocaleDateString(undefined, { timeZone: 'Asia/Kathmandu' }))
  })

  it("keeps the browser's timezone when none is configured or the zone is unsupported", () => {
    for (const value of [undefined, null, '', '   ', 'Mars/Olympus']) {
      setDisplayTimeZone(value)
      expect(getDisplayTimeZone()).toBeUndefined()
      expect(formatDateTime(instant)).toBe(new Date(instant).toLocaleString())
      expect(formatTime(instant, clock)).toBe(new Date(instant).toLocaleTimeString(undefined, clock))
      expect(formatDate(instant)).toBe(new Date(instant).toLocaleDateString())
    }
  })
})

describe('named timezone formatting', () => {
  const instant = '2026-10-13T07:00:00Z'
  afterEach(() => setDisplayTimeZone(undefined))

  it('uses the named timezone instead of the deployment timezone', () => {
    setDisplayTimeZone('Europe/Amsterdam')
    const options = { weekday: 'short', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' } as const
    expect(formatDateTimeInTimeZone(instant, 'America/New_York', options)).toBe(
      new Date(instant).toLocaleString(undefined, { ...options, timeZone: 'America/New_York' }),
    )
    expect(formatDateTimeInTimeZone(instant, 'America/New_York', options)).not.toBe(formatDateTime(instant))
    expect(formatDateTime(instant)).toBe(new Date(instant).toLocaleString(undefined, { timeZone: 'Europe/Amsterdam' }))
  })

  it('returns the original timestamp when the instant or timezone is unsupported', () => {
    expect(formatDateTimeInTimeZone(instant, 'Mars/Olympus')).toBe(instant)
    expect(formatDateTimeInTimeZone('not-a-time', 'America/New_York')).toBe('not-a-time')
  })
})
