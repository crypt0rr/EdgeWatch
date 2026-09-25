import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Gauge } from 'lucide-react'
import { platformCapacity } from '../../api'
import { formatCount, Loading, plural, UnitStatusPill } from './common'

/** Deployment scan capacity and how each unit uses its share of it. */
export function Capacity() {
  const capacity = useQuery({ queryKey: ['platform-capacity'], queryFn: platformCapacity, refetchInterval: 15_000 })
  if (capacity.isLoading) return <Loading label="Loading capacity…" />
  if (!capacity.data) return <section className="page"><div className="error-card" role="alert">Could not load scan capacity.</div></section>
  const { limits, totals, units } = capacity.data
  const visible = units.filter(unit => unit.status !== 'deleted')
  const oversubscribed = totals.slot_caps > limits.max_concurrent_scans
  return <section className="page">
    <div className="page-heading"><div><p className="eyebrow">Platform</p><h1>Capacity</h1><p className="muted">All units share this deployment’s scanner. Each unit’s cap limits how many scan slots it can hold at once; queued scans are served round-robin across units.</p></div><Gauge className="muted-icon" size={24} /></div>
    <div className="detail-summary">
      <div className="summary-card"><span className="summary-label">Scan slots in use</span><strong>{totals.slots_in_use} of {limits.max_concurrent_scans}</strong><span className="muted">Deployment total from config.yaml</span></div>
      <div className="summary-card"><span className="summary-label">Queued scans</span><strong>{totals.queued}</strong><span className="muted">Waiting for a free slot</span></div>
      <div className="summary-card"><span className="summary-label">Sum of unit caps</span><strong>{totals.slot_caps}</strong><span className="muted">{oversubscribed ? 'Above the deployment total; caps are limits, not reservations' : 'Within the deployment total'}</span></div>
      <div className="summary-card"><span className="summary-label">Probe budgets per run</span><strong>{formatCount(limits.max_probe_count)}</strong><span className="muted">Nmap · {formatCount(limits.max_naabu_probe_count)} Naabu</span></div>
    </div>
    <div className="panel"><div className="panel-heading"><div><h2>Per unit</h2><p className="muted">Counts only. Which jobs are running is visible only inside each unit.</p></div></div>
      <div className="capacity-list">{visible.map(unit => {
        const used = Math.min(unit.capacity.slots_in_use, unit.capacity.slot_cap)
        const percent = unit.capacity.slot_cap ? Math.round(used / unit.capacity.slot_cap * 100) : 0
        return <div className="capacity-row" key={unit.id}>
          <div className="capacity-name"><strong>{unit.name}</strong><UnitStatusPill status={unit.status} /></div>
          <div className="capacity-usage"><div className="capacity-meter" role="meter" aria-label={`${unit.name} scan slots in use`} aria-valuemin={0} aria-valuemax={unit.capacity.slot_cap} aria-valuenow={used}><span style={{ width: `${percent}%` }} /></div><small>{unit.capacity.slots_in_use} in use · {unit.capacity.queued} queued · cap {unit.capacity.slot_cap}</small></div>
          <small className="capacity-probes">{formatCount(unit.capacity.max_probe_count)} Nmap · {formatCount(unit.capacity.max_naabu_probe_count)} Naabu</small>
          <Link className="text-button" to={`/platform/units/${encodeURIComponent(unit.id)}/capacity`} aria-label={`Edit capacity for ${unit.name}`}>Edit</Link>
        </div>
      })}</div>
      {!visible.length && <div className="inline-empty">No business units.</div>}
      <p className="muted capacity-footnote">{plural(visible.length, 'unit')} · {totals.slots_in_use} in use · {totals.queued} queued</p>
    </div>
  </section>
}
