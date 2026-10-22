import { useQuery } from '@tanstack/react-query'
import { scanSlotDemand } from '../api'

export const scanSlotDemandQueryKey = ['scan-slot-demand'] as const

/** Shows one business unit's scheduled scan demand beside its slot capacity. */
export function ScanSlotDemandNotice() {
  const demand = useQuery({ queryKey: scanSlotDemandQueryKey, queryFn: scanSlotDemand, refetchInterval: 30_000 })
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
  const estimatedHours = formatHours(value.estimated_slot_seconds_per_day)
  const capacityHours = formatHours(value.capacity_slot_seconds_per_day)
  const utilization = formatPercent(value.utilization_percent)
  return <section className={`notice scan-slot-demand${nearCapacity ? ' warning' : ''}`} aria-label="Scan-slot demand">
    <div>
      <strong>{heading}</strong>
      <p>Estimated scheduled demand is {estimatedHours} slot-hours/day ({utilization}% of {capacityHours} available slot-hours/day across {value.slots} scan slot{value.slots === 1 ? '' : 's'}).</p>
      <p>Expected durations use the median of each job’s 11 most recent completed cycles. Without history, the estimate uses only known work divided by configured maximum scanner rates, as a lower bound.</p>
      {value.unestimated_jobs > 0 && <p>{value.unestimated_jobs} enabled job{value.unestimated_jobs === 1 ? ' has' : 's have'} work or a schedule frequency the estimate cannot fully bound, so actual demand may be higher.</p>}
      {value.enabled_jobs === 0 && <p>No enabled jobs contribute scheduled demand.</p>}
    </div>
  </section>
}

function formatHours(seconds: number) {
  return new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 }).format(seconds / 3600)
}

function formatPercent(percent: number) {
  return new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 }).format(percent)
}
