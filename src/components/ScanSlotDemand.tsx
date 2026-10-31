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
      <p>Expected durations come from each job’s 11 most recent scan samples with its current scan settings. Each completed scan without a cycle, whether it succeeded, was incomplete, or timed out, is one run, and so is each attempt of a completed resumable cycle or of the cycle in progress, without the idle time between attempts; the estimate uses the mean run duration. A job whose resumable cycle stalled adds nothing until someone retries the cycle or its resume window ends, because scheduled runs skip it until then. A run that timed out counts at the job’s current timeout, and if the job’s newest runs with those settings all timed out, every run does. Renaming a job, editing its schedule or notifications, or pausing and resuming it keeps its samples. Editing its targets, ports, protocols, scanner engine or TCP scanner profile starts new samples, and for a job that scans in resumable cycles so does any other scan setting, such as its timeout. Until a scan with the new settings completes, the estimate uses only known work divided by configured maximum scanner rates, as a lower bound. Each run counts at most the job’s timeout, which ends it; a resumable cycle that needs more continues in later runs. The estimate follows the cron ticks over a representative four-year calendar cycle in the job’s timezone, averaging leap-day schedules over that cycle, and skips a tick when the previous estimated run is still active. A run that its timeout ends is still finishing at the tick at exactly its timeout, so that tick is skipped too. A job runs at most once at a time, so it adds at most 24 slot-hours/day.</p>
      {value.cadence_unattainable_jobs > 0 && <p>{value.cadence_unattainable_jobs === 1
        ? '1 job’s estimated run would still be active at one or more scheduled ticks, so the scheduler skips those ticks.'
        : `${value.cadence_unattainable_jobs} jobs’ estimated runs would still be active at one or more scheduled ticks, so the scheduler skips those ticks.`}</p>}
      {value.unestimated_jobs > 0 && <p>{value.unestimated_jobs} enabled job{value.unestimated_jobs === 1 ? ' has' : 's have'} work the estimate cannot fully bound or a schedule it cannot use, so actual demand may be higher.</p>}
      {value.work_limited_jobs > 0 && <p>{value.work_limited_jobs === 1
        ? '1 enabled job has a schedule too costly to simulate within the estimate’s work limit, so it is left out and actual demand may be higher.'
        : `${value.work_limited_jobs} enabled jobs have schedules too costly to simulate within the estimate’s work limit, so they are left out and actual demand may be higher.`}</p>}
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
