import { useQuery } from '@tanstack/react-query'
import { scanSlotDemand } from '../api'

export const scanSlotDemandQueryKey = ['scan-slot-demand'] as const

/**
 * Demand changes slowly, and the live updates refresh it when a job changes
 * or a scan completes, so the poll only catches what they miss.
 */
const scanSlotDemandRefetchInterval = 5 * 60_000

/** Shows one business unit's scheduled scan demand beside its slot capacity. */
export function ScanSlotDemandNotice() {
  const demand = useQuery({ queryKey: scanSlotDemandQueryKey, queryFn: scanSlotDemand, refetchInterval: scanSlotDemandRefetchInterval })
  if (demand.isLoading) return <p className="muted scan-slot-demand-loading" role="status">Loading scan-slot demand…</p>
  if (demand.error || !demand.data) {
    return <div className="notice warning scan-slot-demand" role="status">
      <span>Could not load the scan-slot demand estimate.</span>
      <button className="text-button" type="button" onClick={() => void demand.refetch()}>Retry</button>
    </div>
  }

  const value = demand.data
  const nearCapacity = value.utilization_percent >= 80
  const overCapacity = value.over_capacity
  const heading = overCapacity ? 'Scheduled scan demand exceeds capacity'
    : nearCapacity ? 'Scheduled scan demand is near capacity'
      : 'Estimated scan-slot demand'
  const estimatedHours = formatSlotHours(value.estimated_slot_seconds_per_day)
  const capacityHours = formatSlotHours(value.capacity_slot_seconds_per_day)
  const utilization = formatSlotPercent(value.utilization_percent)
  return <section className={`notice scan-slot-demand${nearCapacity ? ' warning' : ''}`} aria-label="Scan-slot demand">
    <div>
      <strong>{heading}</strong>
      <p>Estimated scheduled demand is {estimatedHours} slot-hours/day ({utilization}% of {capacityHours} available slot-hours/day across {value.slots} scan slot{value.slots === 1 ? '' : 's'}). The scan slots are shared by all business units and not reserved for this one.</p>
      <p>Expected durations use the median of each job’s 11 most recent completed scan samples with its current scan settings. A completed cycle sums its recorded attempt durations, excluding idle time between attempts; a completed scan without a cycle is one sample. Renaming a job, editing its schedule or notifications, or pausing and resuming it keeps its samples. Editing its targets, ports, protocols, scanner engine or TCP scanner profile starts new samples, and for a job that scans in resumable cycles so does any other scan setting, such as its timeout. Until a scan with the new settings completes, the estimate uses only known work divided by configured maximum scanner rates, as a lower bound. Each run counts at most the job’s timeout, which ends it; a resumable cycle that needs more continues in later runs. A job runs at most once at a time, so it adds at most 24 slot-hours/day.</p>
      {value.cadence_unattainable_jobs > 0 && <p>{value.cadence_unattainable_jobs === 1
        ? '1 job runs longer than its schedule allows, so some of its scheduled runs are skipped.'
        : `${value.cadence_unattainable_jobs} jobs run longer than their schedules allow, so some of their scheduled runs are skipped.`}</p>}
      {value.unestimated_jobs > 0 && <p>{value.unestimated_jobs} enabled job{value.unestimated_jobs === 1 ? ' has' : 's have'} work or a schedule frequency the estimate cannot fully bound, so actual demand may be higher.</p>}
      {value.enabled_jobs === 0 && <p>No enabled jobs contribute scheduled demand.</p>}
    </div>
  </section>
}

/** Slot-seconds as slot-hours, to one decimal. */
export function formatSlotHours(seconds: number) {
  return new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 }).format(seconds / 3600)
}

/** A utilization percentage, to one decimal, without the percent sign. */
export function formatSlotPercent(percent: number) {
  return new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 }).format(percent)
}
