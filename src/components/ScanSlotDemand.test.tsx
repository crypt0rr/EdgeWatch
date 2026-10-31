/** @vitest-environment jsdom */

import { screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { scanSlotDemand } from '../api'
import { renderWithProviders } from '../test/test-utils'
import { ScanSlotDemandNotice, scanSlotDemandQueryKey } from './ScanSlotDemand'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return { ...actual, scanSlotDemand: vi.fn() }
})

describe('ScanSlotDemandNotice', () => {
  beforeEach(() => {
    vi.mocked(scanSlotDemand).mockResolvedValue({
      enabled_jobs: 16,
      history_jobs: 0,
      lower_bound_jobs: 16,
      unestimated_jobs: 16,
      work_limited_jobs: 0,
      cadence_unattainable_jobs: 0,
      slots: 1,
      estimated_slot_seconds_per_day: 298.257 * 3600,
      capacity_slot_seconds_per_day: 24 * 3600,
      utilization_percent: 1242.7,
      over_capacity: true,
    })
  })

  afterEach(() => vi.clearAllMocks())

  it('shows the warning at the projected demand and explains the lower-bound caveat', async () => {
    renderWithProviders(<ScanSlotDemandNotice />)
    expect(await screen.findByText('Scheduled scan demand exceeds capacity')).toBeInTheDocument()
    expect(screen.getByRole('region', { name: 'Scan-slot demand' })).toHaveClass('warning')
    expect(screen.getByText(/298\.3 slot-hours\/day/)).toBeInTheDocument()
    expect(screen.getByText(/The scan slots are shared by all business units and not reserved for this one\./)).toBeInTheDocument()
    expect(screen.getByText('16 enabled jobs have work the estimate cannot fully bound or a schedule it cannot use, so actual demand may be higher.')).toBeInTheDocument()
    expect(screen.getByText(/configured maximum scanner rates, as a lower bound/)).toBeInTheDocument()
    expect(screen.getByText(/samples with its current scan settings/)).toBeInTheDocument()
    expect(screen.getByText(/whether it succeeded, was incomplete, or timed out, is one run, and so is each attempt of a completed resumable cycle or of the cycle in progress/)).toBeInTheDocument()
    expect(screen.getByText(/the estimate uses the mean run duration/)).toBeInTheDocument()
    expect(screen.getByText(/pausing and resuming it keeps its samples/)).toBeInTheDocument()
    expect(screen.getByText(/A run that timed out counts at the job’s current timeout, and if the job’s newest runs with those settings all timed out, every run does/)).toBeInTheDocument()
    expect(screen.getByText(/skips a tick when the previous estimated run is still active/)).toBeInTheDocument()
    expect(screen.getByText(/still finishing at the tick at exactly its timeout, so that tick is skipped too/)).toBeInTheDocument()
    expect(screen.getByText(/Each run counts at most the job’s timeout, which ends it/)).toBeInTheDocument()
    expect(screen.getByText(/adds at most 24 slot-hours\/day/)).toBeInTheDocument()
    expect(screen.queryByText(/median/)).not.toBeInTheDocument()
    expect(screen.queryByText(/work limit/)).not.toBeInTheDocument()
    expect(screen.queryByText(/longer than (its|their) schedules? allows?/)).not.toBeInTheDocument()
  })

  it('counts jobs left out at the work limit apart from jobs it cannot estimate', async () => {
    vi.mocked(scanSlotDemand).mockResolvedValue({
      enabled_jobs: 4,
      history_jobs: 3,
      lower_bound_jobs: 0,
      unestimated_jobs: 0,
      work_limited_jobs: 1,
      cadence_unattainable_jobs: 0,
      slots: 1,
      estimated_slot_seconds_per_day: 6 * 3600,
      capacity_slot_seconds_per_day: 24 * 3600,
      utilization_percent: 25,
      over_capacity: false,
    })
    const first = renderWithProviders(<ScanSlotDemandNotice />)
    expect(await screen.findByText('1 enabled job has a schedule too costly to simulate within the estimate’s work limit, so it is left out and actual demand may be higher.')).toBeInTheDocument()
    expect(screen.queryByText(/cannot fully bound/)).not.toBeInTheDocument()
    first.unmount()

    vi.mocked(scanSlotDemand).mockResolvedValue({
      enabled_jobs: 4,
      history_jobs: 1,
      lower_bound_jobs: 0,
      unestimated_jobs: 1,
      work_limited_jobs: 2,
      cadence_unattainable_jobs: 0,
      slots: 1,
      estimated_slot_seconds_per_day: 2 * 3600,
      capacity_slot_seconds_per_day: 24 * 3600,
      utilization_percent: 8.3,
      over_capacity: false,
    })
    renderWithProviders(<ScanSlotDemandNotice />)
    expect(await screen.findByText('2 enabled jobs have schedules too costly to simulate within the estimate’s work limit, so they are left out and actual demand may be higher.')).toBeInTheDocument()
    expect(screen.getByText('1 enabled job has work the estimate cannot fully bound or a schedule it cannot use, so actual demand may be higher.')).toBeInTheDocument()
  })

  it('counts jobs whose estimated runs make the scheduler skip ticks', async () => {
    vi.mocked(scanSlotDemand).mockResolvedValue({
      enabled_jobs: 3,
      history_jobs: 3,
      lower_bound_jobs: 0,
      unestimated_jobs: 0,
      work_limited_jobs: 0,
      cadence_unattainable_jobs: 1,
      slots: 2,
      estimated_slot_seconds_per_day: 30 * 3600,
      capacity_slot_seconds_per_day: 48 * 3600,
      utilization_percent: 62.5,
      over_capacity: false,
    })
    const first = renderWithProviders(<ScanSlotDemandNotice />)
    expect(await screen.findByText('1 job’s estimated run would still be active at one or more scheduled ticks, so the scheduler skips those ticks.')).toBeInTheDocument()
    first.unmount()

    vi.mocked(scanSlotDemand).mockResolvedValue({
      enabled_jobs: 3,
      history_jobs: 3,
      lower_bound_jobs: 0,
      unestimated_jobs: 0,
      work_limited_jobs: 0,
      cadence_unattainable_jobs: 2,
      slots: 2,
      estimated_slot_seconds_per_day: 48 * 3600,
      capacity_slot_seconds_per_day: 48 * 3600,
      utilization_percent: 100,
      over_capacity: false,
    })
    renderWithProviders(<ScanSlotDemandNotice />)
    expect(await screen.findByText('2 jobs’ estimated runs would still be active at one or more scheduled ticks, so the scheduler skips those ticks.')).toBeInTheDocument()
  })

  it('polls every five minutes, between the live updates that refresh it', async () => {
    const { client } = renderWithProviders(<ScanSlotDemandNotice />)
    await screen.findByText('Scheduled scan demand exceeds capacity')
    const query = client.getQueryCache().find({ queryKey: scanSlotDemandQueryKey })
    expect(query?.observers[0]?.options.refetchInterval).toBe(5 * 60_000)
  })

  it('shows an estimate without a warning below the 80 percent threshold', async () => {
    vi.mocked(scanSlotDemand).mockResolvedValue({
      enabled_jobs: 1,
      history_jobs: 1,
      lower_bound_jobs: 0,
      unestimated_jobs: 0,
      work_limited_jobs: 0,
      cadence_unattainable_jobs: 0,
      slots: 1,
      estimated_slot_seconds_per_day: 0.799 * 24 * 3600,
      capacity_slot_seconds_per_day: 24 * 3600,
      utilization_percent: 79.9,
      over_capacity: false,
    })
    renderWithProviders(<ScanSlotDemandNotice />)
    expect(await screen.findByText('Estimated scan-slot demand')).toBeInTheDocument()
    expect(screen.getByRole('region', { name: 'Scan-slot demand' })).not.toHaveClass('warning')
  })

  it('shows a warning at exactly 80 percent', async () => {
    vi.mocked(scanSlotDemand).mockResolvedValue({
      enabled_jobs: 1,
      history_jobs: 1,
      lower_bound_jobs: 0,
      unestimated_jobs: 0,
      work_limited_jobs: 0,
      cadence_unattainable_jobs: 0,
      slots: 1,
      estimated_slot_seconds_per_day: 0.8 * 24 * 3600,
      capacity_slot_seconds_per_day: 24 * 3600,
      utilization_percent: 80,
      over_capacity: false,
    })
    renderWithProviders(<ScanSlotDemandNotice />)
    expect(await screen.findByText('Scheduled scan demand is near capacity')).toBeInTheDocument()
    expect(screen.getByRole('region', { name: 'Scan-slot demand' })).toHaveClass('warning')
  })
})
