import { describe, expect, it } from 'vitest'
import { cidrWarning, duplicateTarget, targetKind } from './target'

describe('target helpers', () => {
  it('detects IP, CIDR, and DNS rows', () => {
    expect(targetKind(' 192.0.2.10 ')).toBe('IP')
    expect(targetKind('2001:db8::1')).toBe('IP')
    expect(targetKind('192.0.2.0/24')).toBe('CIDR')
    expect(targetKind('router.example.com')).toBe('DNS')
    expect(targetKind('deadbeef')).toBe('DNS')
    expect(targetKind('not a target')).toBe('Target')
  })

  it('does not label malformed dotted numeric targets as IP or DNS', () => {
    expect(targetKind('192.168.1.300')).toBe('Target')
    expect(targetKind('256.1.1.1')).toBe('Target')
    expect(targetKind('10.0.0')).toBe('Target')
    expect(targetKind('001.2.3.4')).toBe('Target')
    expect(targetKind('255.255.255.255')).toBe('IP')
  })

  it('warns about broad and invalid CIDRs', () => {
    expect(cidrWarning('10.0.0.0/8')).toContain('many hosts')
    expect(cidrWarning('10.0.0.0/not-a-prefix')).toContain('Check the CIDR')
    expect(cidrWarning('10.0.0.1')).toBe('')
  })

  it('finds case-insensitive duplicate rows', () => {
    expect(duplicateTarget(['one.example', ' ONE.EXAMPLE '])).toBe('ONE.EXAMPLE')
    expect(duplicateTarget(['one.example', 'two.example'])).toBeUndefined()
  })
})
