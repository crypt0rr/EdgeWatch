import { describe, expect, it } from 'vitest'
import { incidentDateTimeCandidates, incidentDateTimeInput } from './incident-time'

describe('incident local due times', () => {
  it('round-trips an exact instant in the requested timezone', () => {
    expect(incidentDateTimeInput('2026-01-15T11:30:00Z', 'Europe/Amsterdam')).toBe('2026-01-15T12:30')
    expect(incidentDateTimeCandidates('2026-01-15T12:30', 'Europe/Amsterdam')).toEqual(['2026-01-15T11:30:00.000Z'])
  })

  it('returns both exact instants for a repeated daylight-saving time', () => {
    expect(incidentDateTimeCandidates('2026-10-25T02:30', 'Europe/Amsterdam')).toEqual([
      '2026-10-25T00:30:00.000Z',
      '2026-10-25T01:30:00.000Z',
    ])
  })

  it('rejects nonexistent and invalid local times', () => {
    expect(incidentDateTimeCandidates('2026-03-29T02:30', 'Europe/Amsterdam')).toEqual([])
    expect(incidentDateTimeCandidates('2026-02-30T12:00', 'Europe/Amsterdam')).toEqual([])
    expect(incidentDateTimeCandidates('not-a-date', 'Europe/Amsterdam')).toEqual([])
  })
})
