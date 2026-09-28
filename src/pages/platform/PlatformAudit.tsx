import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Filter, ScrollText } from 'lucide-react'
import { listUnits, platformAudit } from '../../api'
import { AuditLog } from '../../components/AuditLog'
import { startOfDay } from '../../format'
import { useDebouncedValue } from '../../useDebouncedValue'

/**
 * The start of a calendar day as an RFC 3339 time, for the audit's since and
 * until bounds. The day is the one the console shows: in the deployment
 * timezone when one is configured, and in the browser's otherwise. `days`
 * moves to a later day. An empty or invalid date is no bound.
 */
export function dayBound(date: string, days = 0) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return undefined
  const [year, month, day] = date.split('-').map(Number)
  const value = startOfDay(year, month, day + days)
  return Number.isNaN(value.getTime()) ? undefined : value.toISOString().replace(/\.\d{3}Z$/, 'Z')
}

// The server takes an action prefix of at most 64 of these characters.
const actionPrefixPattern = /^[a-z0-9._-]{0,64}$/

/**
 * The action filter as the server takes it. Audit actions are lower-case, so
 * the prefix is too; a prefix with other characters is explained instead of
 * sent, because the server refuses it.
 */
export function actionFilter(value: string): { prefix: string; problem?: string } {
  const prefix = value.trim().toLowerCase()
  return actionPrefixPattern.test(prefix) ? { prefix } : { prefix, problem: 'Actions use only a-z, 0-9, “.”, “_”, and “-”, at most 64 characters.' }
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
  const typed = actionFilter(action)
  const settled = actionFilter(useDebouncedValue(action))
  const filtered = !!(unit || action || since || until)
  // The until bound is exclusive, so "on or before" a day ends where the
  // next day starts.
  const query = { unit: unit || undefined, action: settled.prefix || undefined, since: dayBound(since), until: dayBound(until, 1) }
  return <section className="page">
    <div className="page-heading"><div><p className="eyebrow">Platform</p><h1>Audit</h1><p className="muted">Platform actions and the account activity of every unit. Changes to a unit’s jobs, baselines, and incidents appear only in that unit’s own audit.</p></div><ScrollText className="muted-icon" size={24} /></div>
    <div className="host-toolbar audit-filters" role="search" aria-label="Filter audit entries">
      <Filter size={15} className="muted-icon" aria-hidden="true" />
      <label>Unit<select value={unit} onChange={event => setUnit(event.target.value)}><option value="">All units and the platform</option>{units.data?.units.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label>
      <label className="search-field">Action starts with<input value={action} onChange={event => setAction(event.target.value)} placeholder="For example user. or tenant." autoComplete="off" aria-invalid={!!typed.problem} aria-describedby={typed.problem ? 'audit-action-problem' : undefined} /></label>
      <label>On or after<input type="date" value={since} onChange={event => setSince(event.target.value)} /></label>
      <label>On or before<input type="date" value={until} onChange={event => setUntil(event.target.value)} /></label>
      {filtered && <button type="button" className="button ghost" onClick={() => { setUnit(''); setAction(''); setSince(''); setUntil('') }}>Clear filters</button>}
    </div>
    {typed.problem && <p className="field-error audit-filter-problem" id="audit-action-problem" role="alert">{typed.problem}</p>}
    {settled.problem
      ? <div className="panel audit-panel"><div className="inline-empty">Correct the action filter to list audit entries.</div></div>
      : <AuditLog queryKey={['platform-audit', query]} load={before => platformAudit({ before, ...query })} showUnit emptyMessage={filtered ? 'No audit entries match these filters.' : 'No audit entries yet.'} />}
  </section>
}
