import { describe, expect, it } from 'vitest'
import { changeKindLabel, hostStatusLabel, jobStatePresentation, scanOutcomeTone, severityLabel, severityTone } from './status'

describe('shared status presentation', () => {
  it('uses consistent job labels and tones', () => {
    expect(jobStatePresentation(false, true)).toEqual({ label: 'Scheduled', tone: 'green' })
    expect(jobStatePresentation(false, false)).toEqual({ label: 'Paused', tone: 'amber' })
    expect(jobStatePresentation(true, false)).toEqual({ label: 'Archived', tone: 'gray' })
  })

  it('emphasizes failed scans while keeping canceled and incomplete scans neutral', () => {
    expect(scanOutcomeTone('success')).toBe('success')
    expect(scanOutcomeTone('failed')).toBe('fail')
    expect(scanOutcomeTone('canceled')).toBe('neutral')
    expect(scanOutcomeTone('cancelled')).toBe('neutral')
    expect(scanOutcomeTone('incomplete')).toBe('neutral')
  })

  it('treats timeouts as failures unless a resumable attempt saved its progress', () => {
    expect(scanOutcomeTone('timed_out')).toBe('fail')
    expect(scanOutcomeTone({ status: 'timed_out', resumable: true, cycle_status: 'failed' })).toBe('fail')
    expect(scanOutcomeTone({ status: 'timed_out', resumable: true, cycle_status: 'paused' })).toBe('neutral')
    expect(scanOutcomeTone({ status: 'failed', resumable: true, cycle_status: 'paused' })).toBe('neutral')
    expect(scanOutcomeTone({ status: 'failed', resumable: false, cycle_status: 'paused' })).toBe('fail')
    expect(scanOutcomeTone({ status: 'canceled', resumable: true, cycle_status: 'paused' })).toBe('neutral')
  })

  it('turns change identifiers into readable labels', () => {
    expect(changeKindLabel('Port_closed')).toBe('Port closed')
    expect(changeKindLabel('dns')).toBe('DNS')
    expect(changeKindLabel('host')).toBe('Host state')
    expect(changeKindLabel('service')).toBe('Service')
    expect(changeKindLabel('port', 'closed', 'open')).toBe('Port opened')
    expect(changeKindLabel('port', 'open', 'not-open')).toBe('Port closed')
    expect(changeKindLabel('other_change')).toBe('Other change')
  })

  it('uses explicit readable labels for lower-case severity and host states', () => {
    expect(severityLabel('critical')).toBe('Critical')
    expect(severityLabel('warning')).toBe('Warning')
    expect(severityTone('critical')).toBe('red')
    expect(severityTone('warning')).toBe('amber')
    expect(severityTone('info')).toBe('gray')
    expect(hostStatusLabel('no-response')).toBe('No response')
    expect(hostStatusLabel('up')).toBe('Up')
  })
})
