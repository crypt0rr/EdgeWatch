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
    expect(screen.getByText(/estimate cannot fully bound, so actual demand may be higher/)).toBeInTheDocument()
    expect(screen.getByText(/configured maximum scanner rates, as a lower bound/)).toBeInTheDocument()
    expect(screen.getByText(/samples with its current scan settings/)).toBeInTheDocument()
    expect(screen.getByText(/pausing and resuming it keeps its samples/)).toBeInTheDocument()
    expect(screen.getByText(/Each run counts at most the job’s timeout, which ends it/)).toBeInTheDocument()
    expect(screen.getByText(/adds at most 24 slot-hours\/day/)).toBeInTheDocument()
    expect(screen.queryByText(/longer than (its|their) schedules? allows?/)).not.toBeInTheDocument()
  })

  it('names the jobs that run longer than their schedules allow', async () => {
    vi.mocked(scanSlotDemand).mockResolvedValue({
      enabled_jobs: 3,
      history_jobs: 3,
      lower_bound_jobs: 0,
      unestimated_jobs: 0,
      cadence_unattainable_jobs: 1,
      slots: 2,
      estimated_slot_seconds_per_day: 30 * 3600,
      capacity_slot_seconds_per_day: 48 * 3600,
      utilization_percent: 62.5,
      over_capacity: false,
    })
    const first = renderWithProviders(<ScanSlotDemandNotice />)
    expect(await screen.findByText('1 job runs longer than its schedule allows, so some of its scheduled runs are skipped.')).toBeInTheDocument()
    first.unmount()

    vi.mocked(scanSlotDemand).mockResolvedValue({
      enabled_jobs: 3,
      history_jobs: 3,
      lower_bound_jobs: 0,
      unestimated_jobs: 0,
      cadence_unattainable_jobs: 2,
      slots: 2,
      estimated_slot_seconds_per_day: 48 * 3600,
      capacity_slot_seconds_per_day: 48 * 3600,
      utilization_percent: 100,
      over_capacity: false,
    })
    renderWithProviders(<ScanSlotDemandNotice />)
    expect(await screen.findByText('2 jobs run longer than their schedules allow, so some of their scheduled runs are skipped.')).toBeInTheDocument()
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
