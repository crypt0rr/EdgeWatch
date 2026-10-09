import { describe, expect, it } from 'vitest'
import { consumeFirstScanIntent, issueFirstScanIntent } from './firstScanIntent'

describe('first scan intent', () => {
  it('is job-bound and consumed exactly once', () => {
    const token = issueFirstScanIntent('job-a')

    expect(consumeFirstScanIntent('job-b', token)).toBe(false)
    expect(consumeFirstScanIntent('job-a', token)).toBe(true)
    expect(consumeFirstScanIntent('job-a', token)).toBe(false)
  })

  it('keeps separate jobs from consuming each other’s start action', () => {
    const first = issueFirstScanIntent('job-a')
    const second = issueFirstScanIntent('job-b')

    expect(first).not.toBe(second)
    expect(consumeFirstScanIntent('job-a', second)).toBe(false)
    expect(consumeFirstScanIntent('job-b', second)).toBe(true)
    expect(consumeFirstScanIntent('job-a', first)).toBe(true)
  })

  it('rejects a missing or unknown history marker', () => {
    expect(consumeFirstScanIntent('job-a', undefined)).toBe(false)
    expect(consumeFirstScanIntent('job-a', 'old-history-token')).toBe(false)
  })
})
