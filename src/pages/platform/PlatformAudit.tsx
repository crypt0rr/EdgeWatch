import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Filter, ScrollText } from 'lucide-react'
import { listUnits, platformAudit } from '../../api'
import { AuditLog } from '../../components/AuditLog'
import { useDebouncedValue } from '../../useDebouncedValue'

/** The value of the unit filter that selects rows without a unit. */
export const PLATFORM_ONLY = 'platform'

/**
 * Platform and account activity across all units. Data changes inside a unit
 * (jobs, baselines, incidents) are deliberately absent: they stay in each
 * unit's own audit, which only that unit's administrators can read.
 */
export function PlatformAudit() {
  const units = useQuery({ queryKey: ['platform-units'], queryFn: listUnits })
  const [unit, setUnit] = useState('')
  const [action, setAction] = useState('')
  const [since, setSince] = useState('')
  const actionPrefix = useDebouncedValue(action.trim())
  const filtered = !!(unit || action || since)
  return <section className="page">
    <div className="page-heading"><div><p className="eyebrow">Platform</p><h1>Audit</h1><p className="muted">Platform actions and account activity in every unit. Changes to a unit’s jobs, baselines, and incidents appear only in that unit’s own audit.</p></div><ScrollText className="muted-icon" size={24} /></div>
    <div className="host-toolbar audit-filters" role="search" aria-label="Filter audit entries">
      <Filter size={15} className="muted-icon" aria-hidden="true" />
      <label>Unit<select value={unit} onChange={event => setUnit(event.target.value)}><option value="">All units</option><option value={PLATFORM_ONLY}>Platform only (no unit)</option>{units.data?.units.map(item => <option key={item.id} value={item.id}>{item.name}{item.status === 'deleted' ? ' (deleted)' : ''}</option>)}</select></label>
      <label className="search-field">Action starts with<input value={action} onChange={event => setAction(event.target.value)} placeholder="For example user. or unit." autoComplete="off" /></label>
      <label>On or after<input type="date" value={since} onChange={event => setSince(event.target.value)} /></label>
      {filtered && <button type="button" className="button ghost" onClick={() => { setUnit(''); setAction(''); setSince('') }}>Clear filters</button>}
    </div>
    <AuditLog queryKey={['platform-audit', unit, actionPrefix, since]} load={before => platformAudit({ before, unit: unit || undefined, action: actionPrefix || undefined, since: since || undefined })} showUnit emptyMessage={filtered ? 'No audit entries match these filters.' : 'No audit entries yet.'} />
  </section>
}
