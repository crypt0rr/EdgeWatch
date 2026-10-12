import { describe, expect, it } from 'vitest'
import { changeWindowLocalTime, formatChangeWindowTime, isChangeWindowTimeZoneSupported, selectChangeWindowLocalTime } from './change-window-time'

describe('change-window timezone values', () => {
  it('produces an RFC 3339 value with the job timezone offset', () => {
    expect(changeWindowLocalTime('2026-07-15T09:30', 'Europe/Amsterdam')).toEqual([{
      value: '2026-07-15T09:30:00+02:00',
      instant: '2026-07-15T07:30:00.000Z',
      offset: 'UTC+02:00',
    }])
  })

  it('returns no instant for a daylight-saving gap', () => {
    expect(changeWindowLocalTime('2026-03-29T02:30', 'Europe/Amsterdam')).toEqual([])
  })

  it('returns both valid fold instants and rejects an offset that does not match either one', () => {
    const candidates = changeWindowLocalTime('2026-10-25T02:30', 'Europe/Amsterdam')
    expect(candidates).toHaveLength(2)
    expect(candidates.map(candidate => candidate.value)).toEqual([
      '2026-10-25T02:30:00+02:00',
      '2026-10-25T02:30:00+01:00',
    ])
    expect(selectChangeWindowLocalTime('2026-10-25T02:30', 'Europe/Amsterdam', candidates[0].value)).toEqual(candidates[0])
    expect(selectChangeWindowLocalTime('2026-10-25T02:30', 'Europe/Amsterdam', candidates[1].value)).toEqual(candidates[1])
    expect(selectChangeWindowLocalTime('2026-10-25T02:30', 'Europe/Amsterdam', '2026-10-25T02:30:00+03:00')).toBeNull()
  })

  it('rejects a timezone the browser cannot resolve', () => {
    expect(isChangeWindowTimeZoneSupported('Invalid/Zone')).toBe(false)
    expect(changeWindowLocalTime('2026-07-15T09:30', 'Invalid/Zone')).toEqual([])
  })

  it('formats saved instants in the job timezone with the numeric offset', () => {
    expect(formatChangeWindowTime('2026-07-15T07:30:00Z', 'Europe/Amsterdam'))
      .toContain('(Europe/Amsterdam, UTC+02:00)')
  })
})
