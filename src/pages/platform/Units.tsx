import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useNavigate } from 'react-router-dom'
import { Building2, Plus } from 'lucide-react'
import { createUnit, getUnitCapacity, listUnits } from '../../api'
import type { BusinessUnit, SessionUser } from '../../api'
import { ActionDialog } from '../../components/ActionDialog'
import { errorMessage, formatCount, Loading, plural, slugProblem, UnitStatusPill } from './common'

/**
 * The platform administrator's list of business units. It shows each unit's
 * identity, state, and counts only: accounts, administrators, jobs, and scan
 * slot use against the unit's cap. A unit's jobs, results, and destinations
 * are never shown here.
 */
export function Units() {
  const navigate = useNavigate()
  const client = useQueryClient()
  const units = useQuery({ queryKey: ['platform-units'], queryFn: listUnits, refetchInterval: 15_000 })
  const [creating, setCreating] = useState(false)
  const [error, setError] = useState('')
  async function create(name: string, requestedSlug = '') {
    setError('')
    const slug = requestedSlug.trim()
    const problem = slug ? slugProblem(slug) : ''
    if (problem) {
      setError(problem)
      return
    }
    try {
      const unit = await createUnit({ name: name.trim(), ...(slug ? { slug } : {}) })
      // A second unit restricts every administrator without TOTP to its own
      // account, this one included. Read the session again first: when it
      // now requires enrolment, the console shows the enrolment instead of
      // this page, and neither the list nor the new unit can be loaded.
      await client.refetchQueries({ queryKey: ['session'], exact: true })
      if (client.getQueryData<SessionUser>(['session'])?.totp_enrollment_required) return
      await client.invalidateQueries({ queryKey: ['platform-units'] })
      setCreating(false)
      navigate(`/platform/units/${encodeURIComponent(unit.id)}/accounts`)
    } catch (err) {
      setError(errorMessage(err, 'The business unit could not be created.'))
    }
  }
  const visible = units.data?.units.filter(unit => unit.status !== 'deleted') ?? []
  const limits = units.data?.limits
  return <section className="page">
    <div className="page-heading"><div><p className="eyebrow">Platform</p><h1>Business units</h1><p className="muted">Each unit owns its jobs, results, notification destinations, and accounts. You manage the units and their administrators; you never see their scan data.</p></div><div className="heading-actions"><button type="button" className="button primary" onClick={() => { setError(''); setCreating(true) }}><Plus size={16} /> New unit</button></div></div>
    {units.isLoading ? <Loading label="Loading business units…" /> : units.error || !units.data ? <div className="error-card" role="alert">Could not load business units.</div> : <div className="panel">
      <div className="panel-heading"><div><h2>{plural(visible.length, 'unit')}</h2>{limits && <p className="muted">Deployment limits: {plural(limits.max_concurrent_scans, 'scan slot')} · {formatCount(limits.max_probe_count)} Nmap and {formatCount(limits.max_naabu_probe_count)} Naabu probes per run.</p>}</div><Building2 className="muted-icon" size={20} /></div>
      {visible.length ? <div className="unit-list">{visible.map(unit => <UnitRow key={unit.id} unit={unit} />)}</div> : <div className="inline-empty">No business units yet.</div>}
    </div>}
    {creating && <ActionDialog title="New business unit" description="Create an empty unit, then invite its first administrator from the unit’s Accounts tab. That administrator sets up the unit’s jobs, destinations, and accounts." confirmLabel="Create unit" valueLabel="Unit name" valueRequired placeholder="For example, Logistics" autoComplete="off" secondaryValueLabel="Slug for the public link (optional)" secondaryPlaceholder="Derived from the name" secondaryAutoComplete="off" onConfirm={create} onCancel={() => { setCreating(false); setError('') }} error={error} />}
  </section>
}

function UnitRow({ unit }: { unit: BusinessUnit }) {
  // The list names each unit's slot use; the cap comes from its capacity.
  const capacity = useQuery({ queryKey: ['platform-unit-capacity', unit.id], queryFn: () => getUnitCapacity(unit.id), staleTime: 30_000, enabled: unit.status !== 'deleting' })
  const limit = capacity.data?.slots.limit
  const cap = limit !== undefined ? `cap ${limit}` : capacity.isError ? 'cap unavailable' : ''
  return <Link className="unit-row" to={`/platform/units/${encodeURIComponent(unit.id)}`} aria-label={`Open ${unit.name}`}>
    <span className="unit-row-name"><strong>{unit.name}</strong><small>/public/{unit.slug}</small></span>
    <span className="unit-row-badges"><UnitStatusPill status={unit.status} />{unit.is_default && <span className="pill blue">Default</span>}</span>
    <dl className="unit-facts">
      <div><dt>Accounts</dt><dd>{plural(unit.accounts, 'account')} · {plural(unit.administrators, 'admin')}</dd></div>
      <div><dt>Jobs</dt><dd>{plural(unit.jobs, 'job')}</dd></div>
      <div><dt>Scan slots</dt><dd>{unit.purge ? `Deleting · ${formatCount(unit.purge.rows)} rows erased` : [`${unit.slots.in_use} in use`, `${unit.slots.queued} queued`, cap].filter(Boolean).join(' · ')}</dd></div>
    </dl>
  </Link>
}
