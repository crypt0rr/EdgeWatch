import { useQuery } from '@tanstack/react-query'
import { Activity, AlertTriangle, ArrowUp } from 'lucide-react'
import { platformStatus } from '../../api'
import type { ApplicationUpdateStatus, PlatformScanDemand } from '../../generated/api-types'
import { UntrustedProxyBanner } from '../../components/UntrustedProxyBanner'
import { ScheduledBackupBanner } from '../../components/ScheduledBackupBanner'
import { ErrorNotice } from '../../components/ErrorNotice'
import { formatSlotHours, formatSlotPercent } from '../../components/ScanSlotDemand'
import { formatBytes, formatTime } from '../../format'
import { formatCount, Loading, plural } from './common'

/** How the release check describes the running version. */
export function updateSummary(updates?: ApplicationUpdateStatus) {
  if (!updates || !updates.enabled || updates.status === 'disabled') return 'Release checks are off.'
  if (updates.available || updates.status === 'update_available') return `Version ${updates.latest_version ?? 'unknown'} is available.`
  if (updates.status === 'up_to_date') return 'Up to date.'
  if (updates.status === 'check_failed') return 'The last release check failed.'
  if (updates.status === 'development_build') return 'A development build; release checks do not apply.'
  if (updates.status === 'ahead') return 'Newer than the latest release.'
  return 'Release status unknown.'
}

/** The utilization at which the scheduled scan demand is near capacity, as on a unit's own notice. */
const scanDemandWarningPercent = 80

/**
 * The scheduled scan demand of every active unit together against the scan
 * slots that all units share. The server sends sums and counts only, so the
 * panel names no unit and no job.
 */
export function PlatformScanDemandPanel({ demand }: { demand: PlatformScanDemand }) {
  const overCapacity = demand.over_capacity
  const nearCapacity = overCapacity || demand.utilization_percent >= scanDemandWarningPercent
  return <div className="panel platform-scan-demand"><div className="panel-heading"><div><h2>Scheduled scan demand</h2><p className="muted">The enabled jobs of {plural(demand.units, 'active unit')} together, against the {plural(demand.slots, 'scan slot')} that all units share. Each unit’s contribution is capped at its effective slot capacity; its Jobs page shows its own estimate. Unit slots are shared and none are reserved. Estimated at most every minute.</p></div></div>
    {nearCapacity && <div className="notice warning platform-scan-demand-warning" role="status"><AlertTriangle size={15} aria-hidden="true" /><span><strong>{overCapacity ? 'Scheduled scan demand exceeds the shared capacity.' : 'Scheduled scan demand is near the shared capacity.'}</strong> {overCapacity ? 'Scans wait for free slots, so they start late and some scheduled runs are skipped.' : 'Scans may wait for free slots at busy times.'} Raise scheduler.max_concurrent_scans in config.yaml, or ask the units to space out or shorten their scans.</span></div>}
    <p className="platform-scan-demand-summary">Scheduled scan demand: {formatSlotHours(demand.estimated_slot_seconds_per_day)} of {formatSlotHours(demand.capacity_slot_seconds_per_day)} slot-hours/day ({formatSlotPercent(demand.utilization_percent)}%)</p>
    <dl className="fact-grid">
      <div><dt>Enabled jobs</dt><dd>{formatCount(demand.enabled_jobs)}</dd></div>
      <div><dt>Estimated from scan history</dt><dd>{formatCount(demand.history_jobs)}</dd></div>
      <div><dt>Lower bound from scanner rates</dt><dd>{formatCount(demand.lower_bound_jobs)}</dd></div>
      <div><dt>Not fully estimated (may overlap lower bound)</dt><dd>{formatCount(demand.unestimated_jobs)}</dd></div>
      <div><dt>Left out at the work limit</dt><dd>{formatCount(demand.work_limited_jobs)}</dd></div>
    </dl>
    {demand.cadence_unattainable_jobs > 0 && <div className="notice warning platform-scan-demand-cadence"><AlertTriangle size={15} aria-hidden="true" /><span>{demand.cadence_unattainable_jobs === 1
      ? '1 job’s estimated run would still be active at one or more scheduled ticks, so the scheduler skips those ticks.'
      : `${formatCount(demand.cadence_unattainable_jobs)} jobs’ estimated runs would still be active at one or more scheduled ticks, so the scheduler skips those ticks.`}</span></div>}
    {demand.unestimated_jobs > 0 && <p className="muted">{plural(demand.unestimated_jobs, 'enabled job')} {demand.unestimated_jobs === 1 ? 'has' : 'have'} work the estimate cannot fully bound or a schedule it cannot use, so actual demand may be higher.</p>}
    {demand.work_limited_jobs > 0 && <p className="muted">{plural(demand.work_limited_jobs, 'enabled job')} {demand.work_limited_jobs === 1 ? 'has a schedule' : 'have schedules'} too costly to simulate within the estimate’s work limit, so {demand.work_limited_jobs === 1 ? 'it is' : 'they are'} left out and actual demand may be higher. Each job has its own limit, and the jobs of every unit take turns with a small first share each, so ordinary jobs are usually estimated before dense schedules get more work.</p>}
  </div>
}

/**
 * The deployment as numbers: its business units by state, their accounts and
 * jobs, the platform administrators, the scan capacity and its use, the
 * active units' scheduled scan demand together, and the database size and
 * notification backlog of the whole deployment, with warnings about an
 * untrusted proxy, failing scheduled backups, and scan demand near or over
 * the shared capacity. It names no unit and no unit's data.
 */
export function PlatformStatusPage() {
  const status = useQuery({ queryKey: ['platform-status'], queryFn: platformStatus, refetchInterval: 15_000 })
  if (status.isLoading) return <Loading label="Loading the platform status…" />
  if (!status.data) return <section className="page"><div className="page-heading"><div><p className="eyebrow">Platform</p><h1>Status</h1><p className="muted">The deployment at a glance. Which jobs run is visible only inside each unit.</p></div><Activity className="muted-icon" size={24} /></div><ErrorNotice message="Could not load the platform status." onRetry={() => status.refetch()} /></section>
  const value = status.data
  const { limits, slots } = value.capacity
  const releaseURL = value.updates?.release_url
  const updateAvailable = !!value.updates && (value.updates.available === true || value.updates.status === 'update_available')
  return <section className="page">
    <div className="page-heading"><div><p className="eyebrow">Platform</p><h1>Status</h1><p className="muted">The deployment at a glance. Which jobs run is visible only inside each unit.</p></div><Activity className="muted-icon" size={24} /></div>
    <UntrustedProxyBanner proxy={value.untrusted_proxy} />
    <ScheduledBackupBanner backups={value.backups} />
    <div className="detail-summary platform-status">
      <div className="summary-card"><span className="summary-label">Business units</span><strong>{value.units.total}</strong><span className="muted">{value.units.active} active · {value.units.disabled} disabled · {value.units.deleting} deleting</span></div>
      <div className="summary-card"><span className="summary-label">Accounts in units</span><strong>{formatCount(value.accounts)}</strong><span className="muted">{plural(value.jobs, 'job')} across all units</span></div>
      <div className="summary-card"><span className="summary-label">Platform administrators</span><strong>{value.platform_admins.enabled}</strong><span className="muted">enabled of {value.platform_admins.total}</span></div>
      <div className="summary-card"><span className="summary-label">Scan slots in use</span><strong>{slots.in_use} of {slots.capacity}</strong><span className="muted">{plural(slots.queued, 'scan')} queued</span></div>
    </div>
    <div className="settings-grid">
      <div className="panel"><div className="panel-heading"><div><h2>Deployment limits</h2><p className="muted">Set in config.yaml on the EdgeWatch host. Each unit’s capacity stays within them.</p></div></div>
        <dl className="fact-grid">
          <div><dt>Scan slots</dt><dd>{limits.max_concurrent_scans}</dd></div>
          <div><dt>Nmap probes per run</dt><dd>{formatCount(limits.max_probe_count)}</dd></div>
          <div><dt>Naabu probes per run</dt><dd>{formatCount(limits.max_naabu_probe_count)}</dd></div>
          <div><dt>Absolute probe ceiling</dt><dd>{formatCount(limits.max_probe_count_limit)}</dd></div>
        </dl>
      </div>
      {value.scan_demand && <PlatformScanDemandPanel demand={value.scan_demand} />}
      {value.telemetry && <div className="panel platform-telemetry"><div className="panel-heading"><div><h2>Storage and delivery</h2><p className="muted">Every unit’s data together, counted at most every 30 seconds; collected <time dateTime={value.telemetry.collected_at}>{formatTime(value.telemetry.collected_at, { hour: '2-digit', minute: '2-digit' })}</time>.</p></div></div>
        <dl className="fact-grid">
          <div><dt>Database</dt><dd>{formatBytes(value.telemetry.database_bytes)}</dd></div>
          <div><dt>Alerts waiting</dt><dd>{formatCount(Math.max(value.telemetry.outbox_pending - value.telemetry.outbox_failed, 0))}</dd></div>
          <div><dt>Alerts retrying</dt><dd>{formatCount(value.telemetry.outbox_retrying)}</dd></div>
          <div><dt>Alerts failed for good</dt><dd>{formatCount(value.telemetry.outbox_failed)}</dd></div>
        </dl>
      </div>}
      <div className="panel"><div className="panel-heading"><div><h2>Version</h2>{!updateAvailable && <p className="muted">{updateSummary(value.updates)}</p>}</div></div>
        {updateAvailable && <div className="notice platform-update-notice" role="status"><ArrowUp size={15} aria-hidden="true" /><span>{updateSummary(value.updates)}{releaseURL && <> <a className="text-button" href={releaseURL} target="_blank" rel="noopener noreferrer">Release notes</a></>}</span></div>}
        <dl className="fact-grid">
          <div><dt>Running</dt><dd>{value.version_release_url ? <a className="text-button" href={value.version_release_url} target="_blank" rel="noopener noreferrer">EdgeWatch {value.version}</a> : `EdgeWatch ${value.version}`}</dd></div>
          {value.updates?.latest_version && <div><dt>Latest release</dt><dd>{releaseURL ? <a className="text-button" href={releaseURL} target="_blank" rel="noopener noreferrer">{value.updates.latest_version}</a> : value.updates.latest_version}</dd></div>}
        </dl>
      </div>
    </div>
  </section>
}
