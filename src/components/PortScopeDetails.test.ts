import { describe, expect, it } from 'vitest'
import { compactPortExpression } from './PortScopeDetails'

describe('compactPortExpression', () => {
  it('keeps short scopes readable', () => {
    expect(compactPortExpression('22,443')).toBe('22,443')
    expect(compactPortExpression('1-65535')).toBe('1-65535')
  })

  it('summarizes long custom scopes without losing the detail view', () => {
    expect(compactPortExpression('1,2,3,4,5,6,7,8,9')).toBe('custom ports in use')
    expect(compactPortExpression('1-20,22,80,443,8080,8443,9000,10000')).toBe('custom ports in use')
  })
})
