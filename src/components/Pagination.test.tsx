/** @vitest-environment jsdom */

import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { Pagination } from './Pagination'

describe('Pagination', () => {
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

	it('does not render when there is no second page', () => {
		act(() => root.render(<Pagination onChange={vi.fn()} />))
		expect(container.querySelector('nav')).toBeNull()
		act(() => root.render(<Pagination page={{ limit: 20, offset: 0, total: 20, has_more: false, next_offset: null }} onChange={vi.fn()} />))
		expect(container.querySelector('nav')).toBeNull()
	})

	it('renders bounds and invokes previous/next callbacks', () => {
		const onChange = vi.fn()
		act(() => root.render(<Pagination page={{ limit: 10, offset: 10, total: 25, has_more: true, next_offset: 20 }} onChange={onChange} />))
		expect(container.querySelector('[aria-label="Pagination"]')).toBeTruthy()
		expect(container.textContent).toContain('11–20 of 25')
		const buttons = Array.from(container.querySelectorAll('button')) as HTMLButtonElement[]
		expect(buttons[0].disabled).toBe(false)
		expect(buttons[1].disabled).toBe(false)
		act(() => buttons[0].click())
		act(() => buttons[1].click())
		expect(onChange.mock.calls).toEqual([[0], [20]])
	})

	it('disables controls at the beginning and end of the result set', () => {
		const onChange = vi.fn()
		act(() => root.render(<Pagination page={{ limit: 10, offset: 0, total: 25, has_more: false, next_offset: null }} onChange={onChange} />))
		const buttons = Array.from(container.querySelectorAll('button')) as HTMLButtonElement[]
		expect(buttons[0].disabled).toBe(true)
		expect(buttons[1].disabled).toBe(true)
		act(() => buttons[0].click())
		act(() => buttons[1].click())
		expect(onChange).not.toHaveBeenCalled()
	})
})
