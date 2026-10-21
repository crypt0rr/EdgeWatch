/** @vitest-environment jsdom */

import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { APIError } from '../../api'
import { perimeterMonitor } from '../../test/perimeter-fixtures'
import { declareResultMessage, parsePerimeterLines } from './DeclareRanges'
import { countLabel, CoverageShare, formatCount, formatMinimumScanDuration, formatShare, ipv6Explanation, isNotFound, kindLabel, monitorStateLabel, monitorStateTone, reasonDescription, unprovenReasons } from './presentation'

describe('perimeter presentation', () => {
  it('formats shares rounded down, so partial coverage never reads 100% and some coverage never reads 0%', () => {
    expect(formatShare(0, 256)).toBe('0%')
    expect(formatShare(128, 256)).toBe('50%')
    expect(formatShare(29, 100)).toBe('29%')
    expect(formatShare(1, 3)).toBe('33.3%')
    expect(formatShare(255, 256)).toBe('99.6%')
    expect(formatShare(4_294_967_295, 4_294_967_296)).toBe('99.9%')
    expect(formatShare(1, 16_777_216)).toBe('<0.1%')
    expect(formatShare(256, 256)).toBe('100%')
    expect(formatShare(300, 256)).toBe('100%')
    expect(formatShare(5, 0)).toBe('')
  })

  it('marks counts that saturated at the API limit', () => {
    expect(formatCount(16_777_216)).toBe('16,777,216')
    expect(formatCount(Number.MAX_SAFE_INTEGER)).toBe('at least 9,007,199,254,740,991')
    expect(countLabel(1, 'address', 'addresses')).toBe('1 address')
    expect(countLabel(0, 'monitor')).toBe('0 monitors')
  })

  it('formats the Full TCP lower-bound duration for display', () => {
    expect(formatMinimumScanDuration(16_777)).toBe('4h 39m 37s')
    expect(formatMinimumScanDuration(60)).toBe('1m')
  })

  it('derives the IPv6 block that one monitor can scan from scanner.max_job_hosts', () => {
    expect(ipv6Explanation(65_536)).toContain('at most 65,536 addresses (scanner.max_job_hosts), a /112,')
    expect(ipv6Explanation(1)).toContain('at most 1 address (scanner.max_job_hosts), a /128,')
    expect(ipv6Explanation(256)).toContain('a /120,')
    expect(ipv6Explanation(1_000_000)).toContain('more than a /109 and less than a /108,')
    expect(ipv6Explanation(300)).toContain('more than a /120 and less than a /119,')
    for (const unknown of [undefined, 0, -5]) expect(ipv6Explanation(unknown)).toMatch(/^One monitor scans a limited number of addresses/)
  })

  it('labels kinds, states, and reasons, and keeps unknown values readable', () => {
    expect(kindLabel('prefix')).toBe('Owned')
    expect(kindLabel('authorized')).toBe('Authorized')
    expect(kindLabel('asn')).toBe('asn')
    expect(monitorStateLabel('over_expansion')).toBe('Over expansion limit')
    expect(monitorStateLabel('brand_new_state')).toBe('brand new state')
    expect(reasonDescription('brand_new_state')).toBe('brand new state')
    expect(['covering', 'paused', 'invalid_config', 'excluded_target', 'over_budget', 'over_expansion'].map(monitorStateTone)).toEqual(['green', 'gray', 'red', 'red', 'amber', 'amber'])
  })

  it('explains unproven coverage only for covering monitors', () => {
    expect(unprovenReasons(perimeterMonitor())).toEqual([])
    expect(unprovenReasons(perimeterMonitor({ state: 'paused', stale: true, stalled_cycle: true, last_attempt_status: 'failed' }))).toEqual([])
    expect(unprovenReasons(perimeterMonitor({ stale: true, stale_reason: 'overdue', last_success_at: null }))).toEqual(['Not scanned yet'])
    expect(unprovenReasons(perimeterMonitor({ last_success_at: null }))).toEqual(['Not scanned yet'])
    expect(unprovenReasons(perimeterMonitor({ stale: true, stale_reason: 'schedule never fires', last_success_at: '2026-10-19T08:00:00Z' }))).toEqual(['Schedule never fires', expect.stringMatching(/^Last successful scan .*2026/)])
    expect(unprovenReasons(perimeterMonitor({ scope_changed: true }))).toEqual(['Not scanned since its targets or protocols changed'])
    expect(unprovenReasons(perimeterMonitor({ cycle_in_progress: true, last_attempt_status: 'timed_out' }))).toEqual([])
    expect(unprovenReasons(perimeterMonitor({ cycle_in_progress: true, last_attempt_status: 'timed_out', last_success_at: null }))).toEqual(['Not scanned yet'])
    expect(unprovenReasons(perimeterMonitor({ scope_changed: true, cycle_in_progress: true, last_attempt_status: 'timed_out' }))).toEqual(['Not scanned since its targets or protocols changed'])
    expect(unprovenReasons(perimeterMonitor({ last_attempt_status: 'canceled' }))).toEqual([])
  })

  it('reports a not-found answer by status or code', () => {
    expect(isNotFound(new APIError('missing', 'not_found', undefined, 404))).toBe(true)
    expect(isNotFound(new APIError('missing', undefined, undefined, 404))).toBe(true)
    expect(isNotFound(new APIError('missing', 'not_found'))).toBe(true)
    expect(isNotFound(new APIError('boom', 'internal_error', undefined, 500))).toBe(false)
    expect(isNotFound(new Error('not_found'))).toBe(false)
  })

  it('renders a share with its bar and text, and a fully excluded range as text only', () => {
    const { container, rerender } = render(<CoverageShare label="UDP" covered={64} total={256} />)
    expect(container).toHaveTextContent('UDP25%64 of 256 addresses')
    const meter = container.querySelector('meter')
    expect(meter).toHaveAttribute('max', '256')
    expect(meter).toHaveAttribute('value', '64')
    rerender(<CoverageShare label="UDP" covered={0} total={0} />)
    expect(screen.getByText('All addresses excluded')).toBeInTheDocument()
    expect(container.querySelector('meter')).toBeNull()
  })
})

describe('perimeter declare parsing', () => {
  it('splits each non-blank line into its value and its trimmed label, keeping line numbers', () => {
    expect(parsePerimeterLines('')).toEqual([])
    expect(parsePerimeterLines('203.0.113.0/24\r\n\r\n  198.51.100.7   Mail relay  \rfe80::1   Lab\n2001:db8::/48\tDC2\tcore')).toEqual([
      { line: 1, value: '203.0.113.0/24', label: '' },
      { line: 3, value: '198.51.100.7', label: 'Mail relay' },
      { line: 4, value: 'fe80::1', label: 'Lab' },
      { line: 5, value: '2001:db8::/48', label: 'DC2\tcore' },
    ])
  })

  it('describes the outcome of an accepted declaration', () => {
    expect(declareResultMessage({ created: 1, skipped: 0 })).toBe('Declared 1 new range.')
    expect(declareResultMessage({ created: 3, skipped: 2 })).toBe('Declared 3 new ranges. 2 already declared entries were skipped.')
    expect(declareResultMessage({ created: 0, skipped: 1 })).toBe('No new ranges were declared. 1 already declared entry was skipped.')
    expect(declareResultMessage({ created: 0, skipped: 0 })).toBe('No new ranges were declared.')
  })
})
