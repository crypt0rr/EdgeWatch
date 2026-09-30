import { FormEvent, useEffect, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useParams } from 'react-router-dom'
import { AlertTriangle, Gauge, Globe2, Trash2 } from 'lucide-react'
import { APIError, deleteUnit, disableUnit, enableUnit, getUnit, getUnitCapacity, highCostNotGranted, renameUnit, updateUnitCapacity } from '../../api'
import type { BusinessUnit, DeploymentLimits, UnitCapacity, UnitCapacitySettings } from '../../api'
import { ActionDialog } from '../../components/ActionDialog'
import { formatDateTime } from '../../format'
import { errorMessage, formatCount, isConflict, Loading, plural, publicPath, publicURL, slugProblem, UnitStatusPill } from './common'
import { UnitAccounts } from './UnitAccounts'

const tabs = [
  { key: 'overview', label: 'Overview' },
  { key: 'accounts', label: 'Accounts', permission: 'unit_accounts.manage' },
  { key: 'capacity', label: 'Capacity' },
  { key: 'danger', label: 'Danger zone' },
]

/**
 * One business unit as the platform administrator manages it: its name and
 * public link, its administrators, its capacity, and its lifecycle. The unit's
 * own data never appears; the counts come from the unit list.
 */
export function UnitDetail({ permissions }: { permissions: string[] }) {
  const { id = '', tab = 'overview' } = useParams()
  const unit = useQuery({ queryKey: ['platform-unit', id], queryFn: () => getUnit(id), refetchInterval: query => query.state.data?.status === 'deleting' ? 2000 : false })
  const visibleTabs = tabs.filter(item => !item.permission || permissions.includes(item.permission))
  const active = visibleTabs.some(item => item.key === tab) ? tab : 'overview'
  if (unit.isLoading) return <Loading label="Loading business unit…" />
  if (unit.error || !unit.data) return <section className="page"><Link className="back-link" to="/platform/units">← Business units</Link><div className="error-card" role="alert">This business unit could not be loaded.</div></section>
  const value = unit.data
  return <section className="page">
    <div className="page-heading"><div><Link className="back-link" to="/platform/units">← Business units</Link><div className="title-row"><h1>{value.name}</h1><UnitStatusPill status={value.status} />{value.is_default && <span className="pill blue">Default</span>}</div><p className="muted">/public/{value.slug} · {plural(value.accounts, 'account')} · {plural(value.jobs, 'job')} · {plural(value.stored_scans, 'stored scan')} · created {formatDateTime(value.created_at)}</p></div></div>
    {value.status === 'deleted' ? <DeletedNotice unit={value} /> : value.status === 'deleting' ? <DeleteProgress unit={value} /> : <>
      {value.status === 'disabled' && <div className="legacy-banner" role="status"><AlertTriangle size={17} /><span><strong>This unit is disabled.</strong> Its members cannot sign in, its schedules are stopped, and its public page is offline. Its data is kept until the unit is deleted.</span></div>}
      <nav className="tab-bar" aria-label={`${value.name} sections`}>{visibleTabs.map(item => <Link key={item.key} to={`/platform/units/${encodeURIComponent(value.id)}/${item.key}`} aria-current={active === item.key ? 'page' : undefined} className={active === item.key ? 'tab active' : 'tab'}>{item.label}</Link>)}</nav>
      {active === 'overview' && <UnitOverview unit={value} />}
      {active === 'accounts' && <UnitAccounts unit={value} />}
      {active === 'capacity' && <UnitCapacityTab unit={value} />}
      {active === 'danger' && <UnitDangerZone unit={value} />}
    </>}
  </section>
}

async function refreshUnit(client: ReturnType<typeof useQueryClient>, id: string) {
  await client.invalidateQueries({ queryKey: ['platform-unit', id] })
  await client.invalidateQueries({ queryKey: ['platform-units'] })
}

function UnitOverview({ unit }: { unit: BusinessUnit }) {
  const client = useQueryClient()
  const [name, setName] = useState(unit.name)
  const [slug, setSlug] = useState(unit.slug)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  useEffect(() => { setName(unit.name); setSlug(unit.slug) }, [unit.name, unit.slug])
  const slugChanged = slug !== unit.slug
  async function save(event: FormEvent) {
    event.preventDefault()
    setMessage('')
    setError('')
    if (!name.trim()) { setError('Enter a unit name.'); return }
    const problem = slugChanged ? slugProblem(slug) : ''
    if (problem) { setError(problem); return }
    setBusy(true)
    try {
      await renameUnit(unit.id, { revision: unit.revision, name: name.trim(), ...(slugChanged ? { slug } : {}) })
      await refreshUnit(client, unit.id)
      setMessage(slugChanged ? `Saved. The public page is now at /public/${slug}.` : 'Saved.')
    } catch (err) {
      // A stale revision answers with the current unit; a name or slug that
      // another unit uses answers with that field.
      const stale = isConflict(err) && err instanceof APIError && !!err.details?.current
      if (stale) await refreshUnit(client, unit.id)
      setError(stale ? 'Another platform administrator changed this unit. The current values were loaded; review them and save again.' : errorMessage(err, 'The unit could not be saved.'))
    } finally {
      setBusy(false)
    }
  }
  return <div className="settings-grid">
    <div className="panel"><div className="panel-heading"><div><h2>Name and public link</h2><p className="muted">Members see the name in their console. The slug is part of the unit’s public status address.</p></div></div>
      {message && <div className="success-banner" role="status">{message}</div>}
      {error && <div className="form-error" role="alert">{error}</div>}
      <form className="settings-form" onSubmit={save}>
        <label>Unit name<input value={name} onChange={event => setName(event.target.value)} maxLength={80} required /></label>
        <label>Slug<input value={slug} onChange={event => setSlug(event.target.value.toLowerCase())} maxLength={40} required autoComplete="off" spellCheck={false} /><small>Lowercase letters, digits, and hyphens. Public address: {publicURL(slug || '…')}</small></label>
        <div className={slugChanged ? 'notice warning' : 'notice'} aria-live="polite"><AlertTriangle size={14} /><span>{slugChanged ? `Changing the slug changes the public link: ${publicURL(unit.slug)} stops working. Share ${publicURL(slug)} instead.` : 'Changing the slug changes the public link. Anyone who uses the current link then gets a page that is not available.'}</span></div>
        <button className="button primary" type="submit" disabled={busy || (name === unit.name && !slugChanged)}>{busy ? 'Saving…' : 'Save changes'}</button>
      </form>
    </div>
    <div className="panel"><div className="panel-heading"><div><h2>Public status page</h2><p className="muted">The unit’s administrators choose whether to publish it and what it shows.</p></div><Globe2 className="muted-icon" size={20} /></div>
      <dl className="fact-grid unit-overview-facts">
        <div><dt>Public address</dt><dd><a className="text-button" href={publicPath(unit.slug)} target="_blank" rel="noreferrer">{publicURL(unit.slug)}</a></dd></div>
        {unit.is_default && <div><dt>Legacy address</dt><dd>{window.location.origin}/public also serves this unit</dd></div>}
        <div><dt>Accounts</dt><dd>{plural(unit.accounts, 'account')}, {plural(unit.administrators, 'enabled administrator')}</dd></div>
        <div><dt>Jobs</dt><dd>{plural(unit.jobs, 'job')}</dd></div>
        <div><dt>Stored scans</dt><dd>{plural(unit.stored_scans, 'scan')}</dd></div>
        <div><dt>Created</dt><dd>{formatDateTime(unit.created_at)}</dd></div>
        {unit.status === 'disabled' && <div><dt>Disabled</dt><dd>{formatDateTime(unit.state_changed_at)}</dd></div>}
      </dl>
      {unit.is_default && <p className="muted">The default unit holds everything that existed before business units were enabled.</p>}
    </div>
  </div>
}

type CapacityField = keyof UnitCapacitySettings

const capacityFields: { key: CapacityField; label: string; help: (limits: DeploymentLimits) => string; maximum: (limits: DeploymentLimits) => number }[] = [
  { key: 'max_concurrent_scans', label: 'Scan slot cap', help: limits => `At most ${plural(limits.max_concurrent_scans, 'concurrent scan')}, the deployment’s total.`, maximum: limits => limits.max_concurrent_scans },
  { key: 'max_probe_count', label: 'Nmap probe budget per run', help: limits => `At most ${formatCount(limits.max_probe_count)}, the deployment’s budget.`, maximum: limits => limits.max_probe_count },
  { key: 'max_naabu_probe_count', label: 'Naabu probe budget per run', help: limits => `At most ${formatCount(limits.max_naabu_probe_count)}, the deployment’s budget.`, maximum: limits => limits.max_naabu_probe_count },
  { key: 'high_cost_ceiling', label: 'High-cost ceiling', help: limits => `The most probes a job with high-cost scanning may send, at most ${formatCount(limits.max_probe_count_limit)}. It never lowers the budgets above.`, maximum: limits => limits.max_probe_count_limit },
]

/**
 * How a setting is drafted: inherited from the deployment, set to the drafted
 * number, or, for the high-cost ceiling only, not granted.
 */
type CapacityMode = 'inherit' | 'set' | 'not_granted'
type CapacityDraft = Record<CapacityField, { mode: CapacityMode; value: string }>

// The high-cost ceiling's choices. Not granted is a state of its own, never
// a number, so saving the form cannot turn it into a grant. A granted
// ceiling is described by its field's help.
const ceilingModes: { mode: CapacityMode; label: string; help?: (limits: DeploymentLimits) => string }[] = [
  { mode: 'not_granted', label: 'Not granted', help: () => 'A job approved for high-cost scanning keeps this unit’s probe budgets, whatever config.yaml sets.' },
  { mode: 'set', label: 'Grant a ceiling' },
  { mode: 'inherit', label: 'Use the deployment’s setting', help: limits => `A job approved for high-cost scanning may send up to ${formatCount(limits.max_probe_count_limit)} probes, the absolute probe ceiling.` },
]

function capacityDraft(capacity: UnitCapacitySettings): CapacityDraft {
  const draft = {} as CapacityDraft
  for (const { key } of capacityFields) {
    const value = capacity[key]
    draft[key] = value === null ? { mode: 'inherit', value: '' }
      : key === 'high_cost_ceiling' && value === highCostNotGranted ? { mode: 'not_granted', value: '' }
        : { mode: 'set', value: String(value) }
  }
  return draft
}

/** The settings a draft saves: null inherits, and a ceiling that is not granted is highCostNotGranted. */
function capacitySettings(draft: CapacityDraft): UnitCapacitySettings {
  const value = {} as UnitCapacitySettings
  for (const { key } of capacityFields) {
    const entry = draft[key]
    value[key] = entry.mode === 'inherit' ? null : entry.mode === 'not_granted' ? highCostNotGranted : Number(entry.value)
  }
  return value
}

/** Validate a unit's capacity against the deployment's limits, as the server does. */
export function capacityProblems(draft: CapacityDraft, limits: DeploymentLimits) {
  const problems: Partial<Record<CapacityField, string>> = {}
  for (const field of capacityFields) {
    const entry = draft[field.key]
    if (entry.mode !== 'set') continue
    const number = Number(entry.value)
    const maximum = field.maximum(limits)
    if (entry.value.trim() === '' || !Number.isInteger(number) || number < 1 || number > maximum) problems[field.key] = `Use a whole number from 1 to ${formatCount(maximum)}.`
  }
  return problems
}

function UnitCapacityTab({ unit }: { unit: BusinessUnit }) {
  const capacity = useQuery({ queryKey: ['platform-unit-capacity', unit.id], queryFn: () => getUnitCapacity(unit.id), refetchInterval: 15_000 })
  if (capacity.isLoading) return <Loading label="Loading capacity…" />
  if (!capacity.data) return <div className="error-card" role="alert">Could not load the unit’s capacity.</div>
  return <UnitCapacityForm unit={unit} capacity={capacity.data} />
}

function UnitCapacityForm({ unit, capacity }: { unit: BusinessUnit; capacity: UnitCapacity }) {
  const client = useQueryClient()
  const limits = capacity.limits
  const [draft, setDraft] = useState(() => capacityDraft(capacity.capacity))
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const problems = capacityProblems(draft, limits)
  const invalid = Object.keys(problems).length > 0
  function change(key: CapacityField, next: Partial<{ mode: CapacityMode; value: string }>) {
    setMessage('')
    setDraft(current => ({ ...current, [key]: { ...current[key], ...next } }))
  }
  async function save(event: FormEvent) {
    event.preventDefault()
    setMessage('')
    setError('')
    if (invalid) return
    setBusy(true)
    try {
      const saved = await updateUnitCapacity(unit.id, capacitySettings(draft))
      client.setQueryData(['platform-unit-capacity', unit.id], saved)
      setDraft(capacityDraft(saved.capacity))
      // Saving the capacity moves the unit to a new revision, so the page
      // reloads the unit before its next rename, disable, or enable.
      await refreshUnit(client, unit.id)
      setMessage('Capacity saved. It applies to the next scan this unit queues.')
    } catch (err) {
      setError(errorMessage(err, 'The capacity could not be saved.'))
    } finally {
      setBusy(false)
    }
  }
  return <div className="settings-grid">
    <div className="panel"><div className="panel-heading"><div><h2>Unit share</h2><p className="muted">Now {capacity.slots.in_use} in use and {capacity.slots.queued} queued, with at most {plural(capacity.slots.limit ?? limits.max_concurrent_scans, 'slot')}.</p></div><Gauge className="muted-icon" size={20} /></div>
      {message && <div className="success-banner" role="status">{message}</div>}
      {error && <div className="form-error" role="alert">{error}</div>}
      <form className="settings-form" onSubmit={save} noValidate>
        {capacityFields.map(field => {
          const entry = draft[field.key]
          const problem = problems[field.key]
          const inputID = `capacity-${field.key}`
          // The ceiling offers its three states as choices. Grant a ceiling
          // proposes no number of its own, so a grant is always one that a
          // platform administrator typed or saved.
          const ceiling = field.key === 'high_cost_ceiling'
          const help = (ceiling && ceilingModes.find(option => option.mode === entry.mode)?.help) || field.help
          return <fieldset className="capacity-field" key={field.key}>
            <legend>{field.label}</legend>
            {ceiling
              ? ceilingModes.map(option => <label className="checkbox-label" key={option.mode} htmlFor={`${inputID}-${option.mode}`}><input id={`${inputID}-${option.mode}`} type="radio" name={`${inputID}-mode`} checked={entry.mode === option.mode} onChange={() => change(field.key, { mode: option.mode })} /><span>{option.label}</span></label>)
              : <label className="checkbox-label" htmlFor={`${inputID}-inherit`}><input id={`${inputID}-inherit`} type="checkbox" checked={entry.mode === 'inherit'} onChange={event => change(field.key, { mode: event.target.checked ? 'inherit' : 'set', value: entry.value || String(field.maximum(limits)) })} /><span>Use the deployment’s setting</span></label>}
            {entry.mode === 'set' && <label htmlFor={inputID}><span className="sr-only">{field.label}</span><input id={inputID} type="number" inputMode="numeric" min={1} max={field.maximum(limits)} step={1} value={entry.value} onChange={event => change(field.key, { value: event.target.value })} aria-invalid={!!problem} aria-describedby={`${inputID}-help`} /></label>}
            <small id={`${inputID}-help`} className={problem ? 'field-error' : undefined}>{problem ?? help(limits)}</small>
          </fieldset>
        })}
        <p className="notice">A cap is a limit, not a reservation. When units wait for slots, free slots go round-robin to the waiting units, up to each unit’s cap.</p>
        <button className="button primary" type="submit" disabled={busy || invalid}>{busy ? 'Saving…' : 'Save capacity'}</button>
      </form>
    </div>
    <div className="panel"><div className="panel-heading"><div><h2>Deployment limits</h2><p className="muted">Set in config.yaml on the EdgeWatch host. Read-only here.</p></div></div>
      <dl className="fact-grid">
        <div><dt>Scan slots</dt><dd>{limits.max_concurrent_scans}</dd></div>
        <div><dt>Nmap probes per run</dt><dd>{formatCount(limits.max_probe_count)}</dd></div>
        <div><dt>Naabu probes per run</dt><dd>{formatCount(limits.max_naabu_probe_count)}</dd></div>
        <div><dt>Absolute probe ceiling</dt><dd>{formatCount(limits.max_probe_count_limit)}</dd></div>
      </dl>
    </div>
  </div>
}

// What deleting a unit erases, in the order the purge works through it.
const erasedData = [
  { label: 'Jobs, schedules, and scan history', detail: 'Every job, scan result, baseline, and incident.' },
  { label: 'Notification destinations and queued alerts', detail: 'The unit’s own destinations, their encrypted URLs, and undelivered alerts.' },
  { label: 'Scanner profiles and the public page', detail: 'The unit’s profiles and its public status page and link.' },
  { label: 'Accounts, sessions, and invitations', detail: 'Every account of the unit; its members can no longer sign in.' },
  { label: 'The unit’s own audit', detail: 'The records of your actions on the unit stay in the platform audit.' },
]

function UnitDangerZone({ unit }: { unit: BusinessUnit }) {
  const client = useQueryClient()
  const [dialog, setDialog] = useState<'toggle' | 'delete' | null>(null)
  const [error, setError] = useState('')
  const disabled = unit.status === 'disabled'
  const deleteBlocked = unit.is_default
    ? 'The default unit cannot be deleted. It holds everything that existed before business units were enabled, and the legacy /public page serves it.'
    : !disabled ? 'Disable the unit first. Only a disabled unit can be deleted.' : ''
  function open(kind: 'toggle' | 'delete') {
    setError('')
    setDialog(kind)
  }
  async function toggle(password: string) {
    setError('')
    try {
      if (disabled) await enableUnit(unit.id, unit.revision, password)
      else await disableUnit(unit.id, unit.revision, password)
      await refreshUnit(client, unit.id)
      setDialog(null)
    } catch (err) {
      if (isConflict(err)) await refreshUnit(client, unit.id)
      setError(errorMessage(err, 'The unit could not be changed.'))
    }
  }
  async function remove(confirmName: string, password = '') {
    setError('')
    try {
      await deleteUnit(unit.id, confirmName, password)
      await refreshUnit(client, unit.id)
      setDialog(null)
    } catch (err) {
      setError(errorMessage(err, 'The unit could not be deleted.'))
    }
  }
  return <div className="danger-zone">
    <div className="panel danger-panel"><div className="panel-heading"><div><h2>{disabled ? 'Enable unit' : 'Disable unit'}</h2><p className="muted">{disabled ? 'Members can sign in again and schedules resume. Invitations that were revoked when the unit was disabled stay revoked, and held alerts are delivered.' : 'Ends every session in the unit and blocks sign-in, revokes open invitations, cancels running scans, stops schedules, holds alerts, and takes the public page offline. The data is kept.'}</p></div></div>
      <button type="button" className={disabled ? 'button secondary' : 'button danger'} onClick={() => open('toggle')}>{disabled ? 'Enable unit' : 'Disable unit'}</button>
    </div>
    <div className="panel danger-panel"><div className="panel-heading"><div><h2>Delete unit</h2><p className="muted">Permanently erases the unit and everything in it. This cannot be undone, and older backups still contain the unit.</p></div><Trash2 className="muted-icon" size={20} /></div>
      {deleteBlocked && <p className="notice" id="delete-unit-blocked">{deleteBlocked}</p>}
      <button type="button" className="button danger" disabled={!!deleteBlocked} aria-describedby={deleteBlocked ? 'delete-unit-blocked' : undefined} onClick={() => open('delete')}>Delete unit…</button>
    </div>
    {dialog === 'toggle' && <ActionDialog title={disabled ? `Enable ${unit.name}?` : `Disable ${unit.name}?`} description={disabled ? 'Members can sign in again and scheduled jobs resume at their next run. Confirm with your password.' : `Everyone in ${unit.name} is signed out and cannot sign in, and its scans stop. Nothing is deleted. Confirm with your password.`} confirmLabel={disabled ? 'Enable unit' : 'Disable unit'} destructive={!disabled} valueLabel="Your password" valueType="password" valueRequired autoComplete="current-password" onConfirm={toggle} onCancel={() => setDialog(null)} error={error} />}
    {dialog === 'delete' && <ActionDialog title={`Delete ${unit.name} permanently?`} description="EdgeWatch erases the following in the background. Nothing can be recovered afterwards." confirmLabel="Delete unit" destructive valueLabel={`Type “${unit.name}” to confirm`} valueRequired expectedValue={unit.name} autoComplete="off" secondaryValueLabel="Your password" secondaryValueType="password" secondaryValueRequired secondaryAutoComplete="current-password" onConfirm={remove} onCancel={() => setDialog(null)} error={error}>
      <ul className="erase-list" aria-label="Data that will be erased">{erasedData.map(item => <li key={item.label}><strong>{item.label}</strong><span>{item.detail}</span></li>)}</ul>
    </ActionDialog>}
  </div>
}

// purgeActivity describes the phase a deletion reached: a table it erases,
// or one of the phases after the last table, which the store names.
function purgeActivity(phase = '') {
  if (!phase) return 'Waiting to start'
  if (phase === 'verify') return 'Checking that nothing is left'
  if (phase.startsWith('compact:')) return 'Compacting the search indexes'
  if (phase === 'free-pages') return 'Overwriting free database pages'
  if (phase === 'checkpoint') return 'Truncating the database log'
  return `Erasing ${phase.replace(/_/g, ' ')}`
}

function DeleteProgress({ unit }: { unit: BusinessUnit }) {
  const purge = unit.purge
  return <div className="panel delete-progress" role="status" aria-live="polite"><h2>Deleting {unit.name}…</h2><p>{purgeActivity(purge?.phase)} · {plural(purge?.rows ?? 0, 'row')} erased so far.</p><p className="muted">EdgeWatch erases the unit in small batches, then compacts the search indexes and truncates the database log, which a running backup can delay. You can leave this page: the deletion continues in the background and resumes after a restart.</p></div>
}

function DeletedNotice({ unit }: { unit: BusinessUnit }) {
  return <div className="panel" role="status"><h2>{unit.name} was deleted</h2><p className="muted">Its jobs, results, destinations, and accounts were erased, and its name and slug can be used again. The platform audit keeps the record of the deletion.</p><Link className="button secondary" to="/platform/units">Back to business units</Link></div>
}
