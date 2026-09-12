/** @vitest-environment jsdom */

import { act, createElement } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { compactPortExpression } from './PortScopeDetails'
import { PortScopeDetails } from './PortScopeDetails'

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

describe('PortScopeDetails', () => {
	let root: Root
	let container: HTMLDivElement

	beforeEach(() => {
		container = document.createElement('div')
		document.body.appendChild(container)
		root = createRoot(container)
	})

	afterEach(() => {
		act(() => root.unmount())
		container.remove()
	})

	it('omits empty scopes and renders exact expandable expressions', () => {
		act(() => root.render(createElement(PortScopeDetails, { items: [{ protocol: 'tcp', ports: ' ' }, { protocol: 'udp', ports: '53', portCount: 1 }, { protocol: 'tcp', ports: '80,443' }] })))
		expect(container.querySelectorAll('details')).toHaveLength(2)
		expect(container.textContent).toContain('UDP · 1 ports')
		expect(container.textContent).toContain('TCP · 80,443')
		expect(container.querySelectorAll('code')[0].textContent).toBe('53')
	})

	it('returns no markup when every scope is empty', () => {
		act(() => root.render(createElement(PortScopeDetails, { items: [{ protocol: 'tcp', ports: '' }] })))
		expect(container.firstChild).toBeNull()
	})
})
