import { describe, expect, it } from 'vitest'
import { jobListReturnTo, jobListReturnToFromState } from './job-list-state'

describe('job list return path', () => {
  it('accepts the job list with or without its search and filter', () => {
    for (const path of ['/jobs', '/jobs/', '/jobs?q=database&filter=attention', '/jobs/?q=database']) {
      expect(jobListReturnTo(path)).toBe(path)
    }
  })

  it('falls back to the unfiltered list for any other destination', () => {
    for (const value of [
      undefined, null, 42, {}, '', 'jobs', '/jobsx', '/jobs-archive?q=x', '/jobs/job-1', '/jobs/job-1/baseline',
      '/jobs#top', '//example.test', '//example.test/jobs?q=x', 'https://example.test/jobs?q=x', '/hosts?q=router',
      'javascript:alert(1)', ' /jobs?q=x',
    ]) {
      expect(jobListReturnTo(value)).toBe('/jobs')
    }
  })

  it('reads the path from route state under the requested key', () => {
    const returnTo = '/jobs?q=database&filter=attention'
    expect(jobListReturnToFromState({ returnTo })).toBe(returnTo)
    expect(jobListReturnToFromState({ jobsReturnTo: returnTo }, 'jobsReturnTo')).toBe(returnTo)
    // A host page's returnTo names its own host list, never the job list.
    expect(jobListReturnToFromState({ returnTo: '/jobs/job-1/baseline?q=router', jobsReturnTo: returnTo }, 'jobsReturnTo')).toBe(returnTo)
    expect(jobListReturnToFromState({ returnTo: '/jobs/job-1/baseline?q=router' })).toBe('/jobs')
    expect(jobListReturnToFromState({ jobsReturnTo: returnTo })).toBe('/jobs')
    expect(jobListReturnToFromState({ returnTo: '//example.test' })).toBe('/jobs')
    expect(jobListReturnToFromState(null)).toBe('/jobs')
    expect(jobListReturnToFromState('/jobs?q=database')).toBe('/jobs')
  })
})
