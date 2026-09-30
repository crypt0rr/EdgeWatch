import { useQuery } from '@tanstack/react-query'
import { Activity } from 'lucide-react'
import { platformStatus } from '../../api'
import type { ApplicationUpdateStatus } from '../../api'
import { UntrustedProxyBanner } from '../../components/UntrustedProxyBanner'
import { ErrorNotice } from '../../components/ErrorNotice'
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

/**
 * The deployment as numbers: its business units by state, their accounts and
 * jobs, the platform administrators, and the scan capacity and its use. It
 * names no unit and no unit's data.
 */
export function PlatformStatusPage() {
  const status = useQuery({ queryKey: ['platform-status'], queryFn: platformStatus, refetchInterval: 15_000 })
  if (status.isLoading) return <Loading label="Loading the platform status…" />
  if (!status.data) return <section className="page"><div className="page-heading"><div><p className="eyebrow">Platform</p><h1>Status</h1><p className="muted">The deployment at a glance. Which jobs run is visible only inside each unit.</p></div><Activity className="muted-icon" size={24} /></div><ErrorNotice message="Could not load the platform status." onRetry={() => status.refetch()} /></section>
  const value = status.data
  const { limits, slots } = value.capacity
  const releaseURL = value.updates?.release_url
  return <section className="page">
    <div className="page-heading"><div><p className="eyebrow">Platform</p><h1>Status</h1><p className="muted">The deployment at a glance. Which jobs run is visible only inside each unit.</p></div><Activity className="muted-icon" size={24} /></div>
    <UntrustedProxyBanner proxy={value.untrusted_proxy} />
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
      <div className="panel"><div className="panel-heading"><div><h2>Version</h2><p className="muted">{updateSummary(value.updates)}</p></div></div>
        <dl className="fact-grid">
          <div><dt>Running</dt><dd>{value.version_release_url ? <a className="text-button" href={value.version_release_url} target="_blank" rel="noopener noreferrer">EdgeWatch {value.version}</a> : `EdgeWatch ${value.version}`}</dd></div>
          {value.updates?.latest_version && <div><dt>Latest release</dt><dd>{releaseURL ? <a className="text-button" href={releaseURL} target="_blank" rel="noopener noreferrer">{value.updates.latest_version}</a> : value.updates.latest_version}</dd></div>}
        </dl>
      </div>
    </div>
  </section>
}
