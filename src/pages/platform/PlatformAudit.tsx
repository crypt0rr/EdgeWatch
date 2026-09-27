import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Filter, ScrollText } from 'lucide-react'
import { listUnits, platformAudit } from '../../api'
import { AuditLog } from '../../components/AuditLog'
import { useDebouncedValue } from '../../useDebouncedValue'

/**
 * The start of a local calendar day as an RFC 3339 time, for the audit's
 * since and until bounds. `days` moves to a later day. An empty or invalid
 * date is no bound.
 */
export function dayBound(date: string, days = 0) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return undefined
  const [year, month, day] = date.split('-').map(Number)
  const value = new Date(year, month - 1, day + days)
  return Number.isNaN(value.getTime()) ? undefined : value.toISOString().replace(/\.\d{3}Z$/, 'Z')
}

/**
 * The platform audit: the platform's own records and the account records of
 * every unit. Changes to a unit's jobs, baselines, and incidents are not
 * here; they stay in the unit's own audit, which only its administrators
 * read.
 */
export function PlatformAudit() {
  const units = useQuery({ queryKey: ['platform-units'], queryFn: listUnits })
  const [unit, setUnit] = useState('')
  const [action, setAction] = useState('')
  const [since, setSince] = useState('')
  const [until, setUntil] = useState('')
  const actionPrefix = useDebouncedValue(action.trim())
  const filtered = !!(unit || action || since || until)
  // The until bound is exclusive, so "on or before" a day ends where the
  // next day starts.
  const query = { unit: unit || undefined, action: actionPrefix || undefined, since: dayBound(since), until: dayBound(until, 1) }
  return <section className="page">
    <div className="page-heading"><div><p className="eyebrow">Platform</p><h1>Audit</h1><p className="muted">Platform actions and the account activity of every unit. Changes to a unit’s jobs, baselines, and incidents appear only in that unit’s own audit.</p></div><ScrollText className="muted-icon" size={24} /></div>
    <div className="host-toolbar audit-filters" role="search" aria-label="Filter audit entries">
      <Filter size={15} className="muted-icon" aria-hidden="true" />
      <label>Unit<select value={unit} onChange={event => setUnit(event.target.value)}><option value="">All units and the platform</option>{units.data?.units.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label>
      <label className="search-field">Action starts with<input value={action} onChange={event => setAction(event.target.value)} placeholder="For example user. or tenant." autoComplete="off" /></label>
      <label>On or after<input type="date" value={since} onChange={event => setSince(event.target.value)} /></label>
      <label>On or before<input type="date" value={until} onChange={event => setUntil(event.target.value)} /></label>
      {filtered && <button type="button" className="button ghost" onClick={() => { setUnit(''); setAction(''); setSince(''); setUntil('') }}>Clear filters</button>}
    </div>
    <AuditLog queryKey={['platform-audit', query]} load={before => platformAudit({ before, ...query })} showUnit emptyMessage={filtered ? 'No audit entries match these filters.' : 'No audit entries yet.'} />
  </section>
}
