import { describe, expect, it } from 'vitest'
import { formatRetention } from './format'

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
