import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useNavigate } from 'react-router-dom'
import { Building2, Plus } from 'lucide-react'
import { createUnit, listUnits } from '../../api'
import type { BusinessUnit } from '../../api'
import { ActionDialog } from '../../components/ActionDialog'
import { errorMessage, formatCount, Loading, plural, slugify, slugProblem, UnitStatusPill } from './common'

/** The main administrator's unit list: accounts and capacity only, never job data. */
export function Units() {
  const navigate = useNavigate()
  const client = useQueryClient()
  const units = useQuery({ queryKey: ['platform-units'], queryFn: listUnits })
  const [creating, setCreating] = useState(false)
  const [error, setError] = useState('')
  async function create(name: string, requestedSlug?: string) {
    setError('')
    const slug = requestedSlug?.trim() || slugify(name)
    const problem = slugProblem(slug)
    if (problem) {
      setError(problem)
      return
    }
    try {
      const unit = await createUnit({ name: name.trim(), slug })
      await client.invalidateQueries({ queryKey: ['platform-units'] })
      setCreating(false)
      navigate(`/platform/units/${encodeURIComponent(unit.id)}/accounts`)
    } catch (err) {
      setError(errorMessage(err, 'The unit could not be created.'))
    }
  }
  const visible = units.data?.units.filter(unit => unit.status !== 'deleted') ?? []
  const limits = units.data?.limits
  return <section className="page">
    <div className="page-heading"><div><p className="eyebrow">Platform</p><h1>Business units</h1><p className="muted">Each unit owns its jobs, results, notification destinations, and accounts. You manage the units and their accounts; you never see their scan data.</p></div><div className="heading-actions"><button type="button" className="button primary" onClick={() => { setError(''); setCreating(true) }}><Plus size={16} /> New unit</button></div></div>
    {units.isLoading ? <Loading label="Loading business units…" /> : units.error || !units.data ? <div className="error-card" role="alert">Could not load business units.</div> : <div className="panel">
      <div className="panel-heading"><div><h2>{plural(visible.length, 'unit')}</h2>{limits && <p className="muted">Deployment limits: {plural(limits.max_concurrent_scans, 'scan slot')} · {formatCount(limits.max_probe_count)} Nmap and {formatCount(limits.max_naabu_probe_count)} Naabu probes per run.</p>}</div><Building2 className="muted-icon" size={20} /></div>
      {visible.length ? <div className="unit-list">{visible.map(unit => <UnitRow key={unit.id} unit={unit} />)}</div> : <div className="inline-empty">No business units yet.</div>}
    </div>}
    {creating && <ActionDialog title="New business unit" description="Create an empty unit. Invite its first administrator from the unit’s Accounts tab; that administrator then sets up jobs and destinations." confirmLabel="Create unit" valueLabel="Unit name" valueRequired placeholder="For example, Logistics" autoComplete="off" secondaryValueLabel="Slug for the public link (optional)" secondaryPlaceholder="Derived from the name" secondaryAutoComplete="off" onConfirm={create} onCancel={() => { setCreating(false); setError('') }} error={error} />}
  </section>
}

function UnitRow({ unit }: { unit: BusinessUnit }) {
  const capacity = unit.capacity
  return <Link className="unit-row" to={`/platform/units/${encodeURIComponent(unit.id)}`} aria-label={`Open ${unit.name}`}>
    <span className="unit-row-name"><strong>{unit.name}</strong><small>/public/{unit.slug}</small></span>
    <span className="unit-row-badges"><UnitStatusPill status={unit.status} />{unit.is_default && <span className="pill blue">Default</span>}</span>
    <dl className="unit-facts">
      <div><dt>Accounts</dt><dd>{plural(unit.accounts, 'account')} · {plural(unit.administrators, 'admin')}{unit.pending_invitations ? ` · ${unit.pending_invitations} pending` : ''}</dd></div>
      <div><dt>Scan slots</dt><dd>{capacity.slots_in_use} in use · {capacity.queued} queued · cap {capacity.slot_cap}</dd></div>
      <div><dt>Probe budget</dt><dd>{formatCount(capacity.max_probe_count)} Nmap · {formatCount(capacity.max_naabu_probe_count)} Naabu</dd></div>
    </dl>
  </Link>
}
