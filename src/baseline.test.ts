import { describe, expect, it } from 'vitest'
import { baselinePresentation } from './baseline'

describe('baseline presentation', () => {
  it('distinguishes ready, stalled, and learning states', () => {
    expect(baselinePresentation({ status: 'complete' })).toMatchObject({ status: 'complete', label: 'Ready', tone: 'green', marker: '●' })
    expect(baselinePresentation({ status: 'stalled', incomplete_attempts: 2 })).toMatchObject({ status: 'stalled', label: 'Stalled', tone: 'red', marker: '⚠' })
    expect(baselinePresentation({ status: 'learning', samples: 1 })).toMatchObject({ status: 'learning', label: 'Learning', tone: 'amber', marker: '◌' })
  })
})
