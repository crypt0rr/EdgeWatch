/** @vitest-environment jsdom */

import { fireEvent, screen } from '@testing-library/react'
import type { ComponentProps } from 'react'
import { describe, expect, it, vi } from 'vitest'
import type { ScheduleSuggestion } from '../api'
import { renderWithProviders } from '../test/test-utils'
import type { Job } from '../types'
import type { ScanSummary } from '../generated/api-types'
import { MonitorNextActions } from './MonitorNextActions'

const baseJob: Job = {
  id: 'job-1', revision: 4, enabled: true, archived: false, security_hash: 'scope-current',
  created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z',
  job: { name: 'Production', schedule: '0 * * * *', timezone: 'Europe/Amsterdam', targets: ['192.0.2.10'], max_expanded_hosts: 32, tcp: { ports: '22,443', mode: 'connect', service_detection: false }, timing: 'balanced', timeout: '1h', baseline_samples: 2, change_confirmations: 1 },
  baseline: { status: 'learning', samples: 1, attempts: 1 },
  scan_budget: { exceeded: false },
}

const schedule: ScheduleSuggestion = { suggested: false, draft_next_run: '2026-10-10T09:00:00+02:00', gap_minutes: 90 }
const incompleteScan: ScanSummary = { id: 'scan-incomplete', job_id: 'job-1', job: 'Production', started_at: '2026-10-09T08:00:00Z', finished_at: '2026-10-09T08:01:00Z', status: 'incomplete', error: 'target did not respond', config_hash: 'scope-current' }

function renderActions(overrides: Partial<ComponentProps<typeof MonitorNextActions>> = {}) {
  const onRun = vi.fn()
  const props: ComponentProps<typeof MonitorNextActions> = {
    job: baseJob,
    canRun: true,
    canReadScans: true,
    canReadBaseline: true,
    canReadIncidents: true,
    liveStatusRequested: true,
    liveStatusReady: true,
    liveStatusLoading: false,
    liveStatusError: false,
    pendingRun: false,
    cycleKnown: true,
    cycle: null,
    scansLoading: false,
    scansError: false,
    baseline: { snapshot: { units: [] }, pagination: { limit: 10, offset: 0, total: 0, has_more: false, next_offset: null } },
    baselineLoading: false,
    baselineError: false,
    schedule,
    scheduleLoading: false,
    scheduleError: false,
    runBusy: false,
    onRun,
    onRetryScans: vi.fn(),
    onRetrySchedule: vi.fn(),
    ...overrides,
  }
  const view = renderWithProviders(<MonitorNextActions {...props} />, { route: ['/jobs/job-1'] })
  return {
    ...view,
    onRun,
    rerenderActions: (next: Partial<ComponentProps<typeof MonitorNextActions>>) => view.rerender(<MonitorNextActions {...props} {...next} />),
  }
}

describe('monitor next actions', () => {
  it('shows persisted sample progress, the next scheduled run, and an explicit run action', () => {
    const { onRun } = renderActions()

    expect(screen.getByText('1 of 2 successful samples collected.')).toBeInTheDocument()
    expect(screen.getByText(/Next scheduled sample:/)).toHaveTextContent('Europe/Amsterdam')
    fireEvent.click(screen.getByRole('button', { name: 'Run another sample' }))
    expect(onRun).toHaveBeenCalledTimes(1)
  })

  it('explains a paused schedule and keeps manual sampling explicit', () => {
    renderActions({ job: { ...baseJob, enabled: false } })

    expect(screen.getByText(/The schedule is paused, so no automatic sample is planned/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Run another sample' })).toBeEnabled()
    expect(screen.queryByText(/Next scheduled sample:/)).not.toBeInTheDocument()
  })

  it('does not offer another sample while a job scan is active or queued', () => {
    const active = { id: 'active-1', job_id: 'job-1', job: 'Production', started_at: '2026-10-09T08:00:00Z', progress_percent: 20 } as const
    const queued = { job_id: 'job-1', job: 'Production', queued_at: '2026-10-09T08:00:00Z', trigger: 'manual' } as const

    const activeView = renderActions({ activeScan: active })
    expect(screen.getByText(/A scan is running/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Run another sample' })).not.toBeInTheDocument()
    activeView.rerenderActions({ activeScan: undefined, queuedRun: queued })
    expect(screen.getByText(/waiting for an available unit scan slot/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Run another sample' })).not.toBeInTheDocument()
  })

  it('keeps the run action hidden when live state or the probe budget is unknown', () => {
    const statusError = renderActions({ liveStatusReady: false, liveStatusError: true })
    expect(screen.getByText(/Current scan status could not be confirmed/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Run another sample' })).not.toBeInTheDocument()
    statusError.rerenderActions({ job: { ...baseJob, scan_budget: undefined }, liveStatusReady: true, liveStatusError: false })
    expect(screen.getByText(/probe budget could not be confirmed/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Run another sample' })).not.toBeInTheDocument()
  })

  it('reports the latest incomplete sample and links evidence and correction only to permitted roles', () => {
    const job = { ...baseJob, baseline: { status: 'stalled', samples: 1, attempts: 3, incomplete_attempts: 2 } }
    renderActions({ job, scans: [incompleteScan] })

    expect(screen.getByText(/2 incomplete observations did not count as samples; 1 of 2 successful samples are collected/)).toBeInTheDocument()
    expect(screen.getByText(/The latest scan was incomplete/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Review scan evidence →' })).toHaveAttribute('href', '/jobs/job-1/scans/scan-incomplete')
    expect(screen.getByRole('link', { name: 'Review targets and scanner profile →' })).toHaveAttribute('href', '/jobs/job-1/edit')
    expect(screen.getByRole('button', { name: 'Retry baseline scan' })).toBeInTheDocument()
  })

  it('does not call an older failure the latest attempt after a newer success', () => {
    const newerSuccess: ScanSummary = { ...incompleteScan, id: 'scan-new-success', status: 'success', finished_at: '2026-10-09T09:00:00Z' }
    renderActions({ scans: [newerSuccess, incompleteScan] })

    expect(screen.queryByText(/The latest scan was incomplete/)).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Review scan evidence →' })).not.toBeInTheDocument()
  })

  it('treats zero positive ports as a valid active baseline and gates evidence links by permission', () => {
    const job = { ...baseJob, baseline: { status: 'complete', samples: 2, host_count: 0 } }
    const baseline = { snapshot: { units: [{ target: '192.0.2.10', protocol: 'tcp', ports: [] }] }, pagination: { limit: 10, offset: 0, total: 1, has_more: false, next_offset: null } }
    const ready = renderActions({ job, baseline, latestSuccessfulScan: { ...incompleteScan, status: 'success', id: 'scan-ready' } })

    expect(screen.getByText(/valid complete baseline with zero positive ports/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'View baseline evidence →' })).toHaveAttribute('href', '/jobs/job-1/baseline')
    expect(screen.getByRole('link', { name: 'Open latest scan →' })).toHaveAttribute('href', '/jobs/job-1/scans/scan-ready')
    expect(screen.getByRole('link', { name: 'View scan activity →' })).toHaveAttribute('href', '/activity?job_id=job-1')
    expect(screen.getByRole('link', { name: 'View incidents →' })).toHaveAttribute('href', '/incidents')

    ready.rerenderActions({ job, baseline, canReadBaseline: false, canReadScans: false, canReadIncidents: false })
    expect(screen.queryByRole('link', { name: 'View baseline evidence →' })).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'View scan activity →' })).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'View incidents →' })).not.toBeInTheDocument()
  })

  it('does not turn baseline evidence read errors into a zero-port result', () => {
    renderActions({
      job: { ...baseJob, baseline: { status: 'complete', samples: 2 } },
      baseline: undefined,
      baselineError: true,
    })

    expect(screen.queryByText(/zero positive ports/)).not.toBeInTheDocument()
  })

  it('does not call a paginated empty page a zero-port baseline', () => {
    const job = { ...baseJob, baseline: { status: 'complete', samples: 2, host_count: 0 } }
    renderActions({
      job,
      baseline: { snapshot: { units: [] }, pagination: { limit: 10, offset: 0, total: 12, has_more: true, next_offset: 10 } },
    })

    expect(screen.queryByText(/zero positive ports/)).not.toBeInTheDocument()
  })

  it('does not show a live-status error when the role cannot request live scan state', () => {
    renderActions({ liveStatusRequested: false, liveStatusReady: false, liveStatusError: false })

    expect(screen.queryByText(/Current scan status/)).not.toBeInTheDocument()
    expect(screen.queryByText(/Checking for an active or queued scan/)).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Run another sample' })).not.toBeInTheDocument()
  })
})
