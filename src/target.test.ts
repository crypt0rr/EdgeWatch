import { describe, expect, it } from 'vitest'
import { cidrWarning, duplicateTarget, targetKind } from './target'

describe('target helpers', () => {
  it('detects IP, CIDR, and DNS rows', () => {
    expect(targetKind(' 192.0.2.10 ')).toBe('IP')
    expect(targetKind('192.0.2.0/24')).toBe('CIDR')
    expect(targetKind('router.example.com')).toBe('DNS')
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
