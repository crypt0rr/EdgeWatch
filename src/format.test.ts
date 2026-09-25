import { afterEach, describe, expect, it } from 'vitest'
import { formatDate, formatDateTime, formatRetention, formatTime, getDisplayTimeZone, setDisplayTimeZone } from './format'

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
