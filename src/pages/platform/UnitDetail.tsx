import { FormEvent, useEffect, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useParams } from 'react-router-dom'
import { AlertTriangle, BellRing, Gauge, Globe2, Trash2 } from 'lucide-react'
import { deleteUnit, disableUnit, enableUnit, getUnit, getUnitNotifications, setUnitNotifications, updateUnit } from '../../api'
import type { BusinessUnitDetail, DeploymentLimits, UnitCapacityPatch } from '../../api'
import { ActionDialog } from '../../components/ActionDialog'
import { formatDateTime } from '../../format'
import { errorMessage, formatCount, isConflict, Loading, plural, publicURL, slugProblem, UnitStatusPill } from './common'
import { UnitAccounts } from './UnitAccounts'

const tabs = [
  { key: 'overview', label: 'Overview' },
  { key: 'accounts', label: 'Accounts', permission: 'unit_accounts.manage' },
  { key: 'capacity', label: 'Capacity' },
  { key: 'notifications', label: 'Notifications', permission: 'platform_notifications.manage' },
  { key: 'danger', label: 'Danger zone' },
]

export function UnitDetail({ permissions }: { permissions: string[] }) {
  const { id = '', tab = 'overview' } = useParams()
  const unit = useQuery({ queryKey: ['platform-unit', id], queryFn: () => getUnit(id), refetchInterval: query => query.state.data?.status === 'deleting' ? 600 : false })
  const visibleTabs = tabs.filter(item => !item.permission || permissions.includes(item.permission))
  const active = visibleTabs.some(item => item.key === tab) ? tab : 'overview'
  if (unit.isLoading) return <Loading label="Loading business unit…" />
  if (unit.error || !unit.data) return <section className="page"><Link className="back-link" to="/platform/units">← Business units</Link><div className="error-card" role="alert">This business unit could not be loaded.</div></section>
  const value = unit.data
  return <section className="page">
    <div className="page-heading"><div><Link className="back-link" to="/platform/units">← Business units</Link><div className="title-row"><h1>{value.name}</h1><UnitStatusPill status={value.status} />{value.is_default && <span className="pill blue">Default</span>}</div><p className="muted">/public/{value.slug} · {plural(value.accounts, 'account')} · created {formatDateTime(value.created_at)}</p></div></div>
    {value.status === 'deleted' ? <DeletedNotice unit={value} /> : value.status === 'deleting' ? <DeleteProgress unit={value} /> : <>
      {value.status === 'disabled' && <div className="legacy-banner" role="status"><AlertTriangle size={17} /><span><strong>This unit is disabled.</strong> Its members cannot sign in, its schedules are stopped, and its public page is offline. All data is kept until the unit is deleted.</span></div>}
      <nav className="tab-bar" aria-label={`${value.name} sections`}>{visibleTabs.map(item => <Link key={item.key} to={`/platform/units/${encodeURIComponent(value.id)}/${item.key}`} aria-current={active === item.key ? 'page' : undefined} className={active === item.key ? 'tab active' : 'tab'}>{item.label}</Link>)}</nav>
      {active === 'overview' && <UnitOverview unit={value} />}
      {active === 'accounts' && <UnitAccounts unit={value} />}
      {active === 'capacity' && <UnitCapacityTab unit={value} />}
      {active === 'notifications' && <UnitNotificationsTab unit={value} />}
      {active === 'danger' && <UnitDangerZone unit={value} />}
    </>}
  </section>
}

function UnitOverview({ unit }: { unit: BusinessUnitDetail }) {
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
    const problem = slugProblem(slug)
    if (problem) { setError(problem); return }
    setBusy(true)
    try {
      await updateUnit(unit.id, { revision: unit.revision, name: name.trim(), slug })
      await client.invalidateQueries({ queryKey: ['platform-unit', unit.id] })
      await client.invalidateQueries({ queryKey: ['platform-units'] })
      setMessage(slugChanged ? `Saved. The public page is now at /public/${slug}.` : 'Saved.')
    } catch (err) {
      if (isConflict(err)) await client.invalidateQueries({ queryKey: ['platform-unit', unit.id] })
      setError(isConflict(err) ? 'Another main administrator changed this unit. The current values were loaded; review them and save again.' : errorMessage(err, 'The unit could not be saved.'))
    } finally {
      setBusy(false)
    }
  }
  return <div className="settings-grid">
    <div className="panel"><div className="panel-heading"><div><h2>Name and public link</h2><p className="muted">Members see the name in their console. The slug is part of the unit’s public status URL.</p></div></div>
      {message && <div className="success-banner" role="status">{message}</div>}
      {error && <div className="form-error" role="alert">{error}</div>}
      <form className="settings-form" onSubmit={save}>
        <label>Unit name<input value={name} onChange={event => setName(event.target.value)} maxLength={80} required /></label>
        <label>Slug<input value={slug} onChange={event => setSlug(event.target.value.toLowerCase())} maxLength={40} required autoComplete="off" /><small>Lowercase letters, digits, and hyphens. Public URL: {publicURL(slug || '…')}</small></label>
        <div className={slugChanged ? 'notice warning' : 'notice'} aria-live="polite"><AlertTriangle size={14} /><span>{slugChanged ? `Changing the slug changes public links: ${publicURL(unit.slug)} will stop working. Share ${publicURL(slug)} instead.` : 'Changing the slug changes public links. Anyone who uses the current link would get “not found”.'}</span></div>
        <button className="button primary" type="submit" disabled={busy || (name === unit.name && !slugChanged)}>{busy ? 'Saving…' : 'Save changes'}</button>
      </form>
    </div>
    <div className="panel"><div className="panel-heading"><div><h2>Public status page</h2><p className="muted">The unit’s administrators choose what to publish. You only see whether the page is on.</p></div><Globe2 className="muted-icon" size={20} /></div>
      <dl className="fact-grid unit-overview-facts">
        <div><dt>Public URL</dt><dd><a className="text-button" href={`/public/${encodeURIComponent(unit.slug)}`} target="_blank" rel="noreferrer">{publicURL(unit.slug)}</a></dd></div>
        <div><dt>Published</dt><dd>{unit.public_enabled ? 'Yes' : 'No'}</dd></div>
        {unit.is_default && <div><dt>Legacy URL</dt><dd>{window.location.origin}/public also serves this unit</dd></div>}
        <div><dt>Accounts</dt><dd>{plural(unit.accounts, 'account')}, {plural(unit.administrators, 'administrator')}</dd></div>
        <div><dt>Created</dt><dd>{formatDateTime(unit.created_at)}</dd></div>
        {unit.disabled_at && <div><dt>Disabled</dt><dd>{formatDateTime(unit.disabled_at)}</dd></div>}
      </dl>
      {unit.is_default && <p className="muted">The default unit holds everything that existed before business units were enabled.</p>}
    </div>
  </div>
}

/** Validate a unit's share against the deployment limits from config.yaml. */
export function capacityProblems(value: UnitCapacityPatch, limits: DeploymentLimits) {
  const problems: Partial<Record<keyof UnitCapacityPatch, string>> = {}
  const within = (number: number, maximum: number) => Number.isInteger(number) && number >= 1 && number <= maximum
  if (!within(value.slot_cap, limits.max_concurrent_scans)) problems.slot_cap = `Use a whole number from 1 to ${limits.max_concurrent_scans}, the deployment’s scan slots.`
  if (!within(value.max_probe_count, limits.max_probe_count)) problems.max_probe_count = `Use a whole number from 1 to ${formatCount(limits.max_probe_count)}, the deployment’s Nmap budget.`
  if (!within(value.max_naabu_probe_count, limits.max_naabu_probe_count)) problems.max_naabu_probe_count = `Use a whole number from 1 to ${formatCount(limits.max_naabu_probe_count)}, the deployment’s Naabu budget.`
  return problems
}

function UnitCapacityTab({ unit }: { unit: BusinessUnitDetail }) {
  const client = useQueryClient()
  const limits = unit.limits
  const [slotCap, setSlotCap] = useState(String(unit.capacity.slot_cap))
  const [probes, setProbes] = useState(String(unit.capacity.max_probe_count))
  const [naabuProbes, setNaabuProbes] = useState(String(unit.capacity.max_naabu_probe_count))
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const value = { slot_cap: Number(slotCap), max_probe_count: Number(probes), max_naabu_probe_count: Number(naabuProbes) }
  const problems = capacityProblems(value, limits)
  const invalid = Object.keys(problems).length > 0
  async function save(event: FormEvent) {
    event.preventDefault()
    setMessage('')
    setError('')
    if (invalid) return
    setBusy(true)
    try {
      await updateUnit(unit.id, { revision: unit.revision, capacity: value })
      await client.invalidateQueries({ queryKey: ['platform-unit', unit.id] })
      await client.invalidateQueries({ queryKey: ['platform-units'] })
      await client.invalidateQueries({ queryKey: ['platform-capacity'] })
      setMessage('Capacity saved. It applies to the next scan this unit queues.')
    } catch (err) {
      setError(errorMessage(err, 'Capacity could not be saved.'))
    } finally {
      setBusy(false)
    }
  }
  return <div className="settings-grid">
    <div className="panel"><div className="panel-heading"><div><h2>Unit share</h2><p className="muted">Now {unit.capacity.slots_in_use} in use and {unit.capacity.queued} queued.</p></div><Gauge className="muted-icon" size={20} /></div>
      {message && <div className="success-banner" role="status">{message}</div>}
      {error && <div className="form-error" role="alert">{error}</div>}
      <form className="settings-form" onSubmit={save} noValidate>
        <CapacityField label="Scan slot cap" value={slotCap} onChange={setSlotCap} maximum={limits.max_concurrent_scans} problem={problems.slot_cap} help={`At most ${plural(limits.max_concurrent_scans, 'concurrent scan')}, the deployment total.`} />
        <CapacityField label="Nmap probe budget per run" value={probes} onChange={setProbes} maximum={limits.max_probe_count} problem={problems.max_probe_count} help={`At most ${formatCount(limits.max_probe_count)}.`} />
        <CapacityField label="Naabu probe budget per run" value={naabuProbes} onChange={setNaabuProbes} maximum={limits.max_naabu_probe_count} problem={problems.max_naabu_probe_count} help={`At most ${formatCount(limits.max_naabu_probe_count)}.`} />
        <p className="notice">A cap is a limit, not a reservation. When units compete for slots, queued scans are served round-robin, one unit at a time.</p>
        <button className="button primary" type="submit" disabled={busy || invalid}>{busy ? 'Saving…' : 'Save capacity'}</button>
      </form>
    </div>
    <div className="panel"><div className="panel-heading"><div><h2>Deployment limits</h2><p className="muted">Set in config.yaml on the EdgeWatch host. Read-only here.</p></div></div>
      <dl className="fact-grid">
        <div><dt>Scan slots</dt><dd>{limits.max_concurrent_scans}</dd></div>
        <div><dt>Nmap probes per run</dt><dd>{formatCount(limits.max_probe_count)}</dd></div>
        <div><dt>Naabu probes per run</dt><dd>{formatCount(limits.max_naabu_probe_count)}</dd></div>
        <div><dt>Absolute ceiling</dt><dd>{formatCount(limits.max_probe_count_limit)}</dd></div>
      </dl>
    </div>
  </div>
}

function CapacityField({ label, value, onChange, maximum, problem, help }: { label: string; value: string; onChange: (value: string) => void; maximum: number; problem?: string; help: string }) {
  return <label>{label}<input type="number" inputMode="numeric" min={1} max={maximum} step={1} value={value} onChange={event => onChange(event.target.value)} aria-invalid={!!problem} required /><small className={problem ? 'field-error' : undefined}>{problem ?? help}</small></label>
}

function UnitNotificationsTab({ unit }: { unit: BusinessUnitDetail }) {
  const client = useQueryClient()
  const assignment = useQuery({ queryKey: ['platform-unit-notifications', unit.id], queryFn: () => getUnitNotifications(unit.id) })
  const [selected, setSelected] = useState<string[] | null>(null)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  if (assignment.isLoading) return <Loading label="Loading deployment destinations…" />
  if (!assignment.data) return <div className="error-card" role="alert">Could not load deployment destinations.</div>
  const data = assignment.data
  const saved = data.destinations.filter(item => item.assigned).map(item => item.id)
  const current = selected ?? saved
  const dirty = selected !== null && (selected.length !== saved.length || selected.some(item => !saved.includes(item)))
  function toggle(id: string, checked: boolean) {
    setMessage('')
    setSelected(checked ? [...current, id] : current.filter(item => item !== id))
  }
  async function save() {
    setMessage('')
    setError('')
    setBusy(true)
    try {
      await setUnitNotifications(unit.id, current, data.revision)
      await client.invalidateQueries({ queryKey: ['platform-unit-notifications', unit.id] })
      await client.invalidateQueries({ queryKey: ['platform-deployment-notifications'] })
      setSelected(null)
      setMessage(`Saved. ${unit.name} can now route alerts to ${plural(current.length, 'deployment destination')}.`)
    } catch (err) {
      setError(errorMessage(err, 'The assignment could not be saved.'))
    } finally {
      setBusy(false)
    }
  }
  return <div className="panel"><div className="panel-heading"><div><h2>Deployment destinations</h2><p className="muted">Destinations from config.yaml on the EdgeWatch host. An assigned destination appears on the unit’s Notifications page, and the unit’s jobs can send alerts to it. URLs are never shown.</p></div><BellRing className="muted-icon" size={20} /></div>
    {message && <div className="success-banner" role="status">{message}</div>}
    {error && <div className="form-error" role="alert">{error}</div>}
    {data.destinations.length ? <fieldset className="destination-picker"><legend className="sr-only">Assign deployment destinations to {unit.name}</legend>{data.destinations.map(item => <label className="public-picker-row" key={item.id} htmlFor={`unit-destination-${item.id}`}><input id={`unit-destination-${item.id}`} type="checkbox" checked={current.includes(item.id)} onChange={event => toggle(item.id, event.target.checked)} /><span><strong>{item.name}</strong><small className="muted">{item.provider} · {item.enabled ? 'enabled' : 'disabled in config.yaml'}</small></span></label>)}</fieldset> : <div className="inline-empty">config.yaml defines no deployment destinations.</div>}
    <p className="notice">The unit’s own destinations are managed by its administrators and are not visible here.</p>
    <div className="heading-actions tab-actions"><button type="button" className="button primary" disabled={!dirty || busy} onClick={() => void save()}>{busy ? 'Saving…' : 'Save assignment'}</button></div>
  </div>
}

function UnitDangerZone({ unit }: { unit: BusinessUnitDetail }) {
  const client = useQueryClient()
  const [dialog, setDialog] = useState<'toggle' | 'delete' | null>(null)
  const [error, setError] = useState('')
  const disabled = unit.status === 'disabled'
  const deleteBlocked = unit.is_default
    ? 'The default unit cannot be deleted. It holds everything that existed before business units were enabled, and the legacy /public link resolves to it.'
    : !disabled ? 'Disable the unit first. Only a disabled unit can be deleted.' : ''
  function open(kind: 'toggle' | 'delete') {
    setError('')
    setDialog(kind)
  }
  async function refresh() {
    await client.invalidateQueries({ queryKey: ['platform-unit', unit.id] })
    await client.invalidateQueries({ queryKey: ['platform-units'] })
    await client.invalidateQueries({ queryKey: ['platform-capacity'] })
  }
  async function toggle(password: string) {
    setError('')
    try {
      if (disabled) await enableUnit(unit.id, password)
      else await disableUnit(unit.id, password)
      await refresh()
      setDialog(null)
    } catch (err) {
      setError(errorMessage(err, 'The unit could not be changed.'))
    }
  }
  async function remove(confirmName: string, password = '') {
    setError('')
    try {
      await deleteUnit(unit.id, confirmName, password)
      await refresh()
      setDialog(null)
    } catch (err) {
      setError(errorMessage(err, 'The unit could not be deleted.'))
    }
  }
  return <div className="danger-zone">
    <div className="panel danger-panel"><div className="panel-heading"><div><h2>{disabled ? 'Enable unit' : 'Disable unit'}</h2><p className="muted">{disabled ? 'Members can sign in again and schedules resume. Invitations that were revoked when the unit was disabled stay revoked.' : 'Blocks sign-in and ends every session in this unit, revokes open invitations, cancels queued and running scans, stops schedules, and takes the public page offline. All data is kept.'}</p></div></div>
      <button type="button" className={disabled ? 'button secondary' : 'button danger'} onClick={() => open('toggle')}>{disabled ? 'Enable unit' : 'Disable unit'}</button>
    </div>
    <div className="panel danger-panel"><div className="panel-heading"><div><h2>Delete unit</h2><p className="muted">Permanently erases the unit and everything in it. This cannot be undone.</p></div><Trash2 className="muted-icon" size={20} /></div>
      {deleteBlocked && <p className="notice" id="delete-unit-blocked">{deleteBlocked}</p>}
      <button type="button" className="button danger" disabled={!!deleteBlocked} aria-describedby={deleteBlocked ? 'delete-unit-blocked' : undefined} onClick={() => open('delete')}>Delete unit…</button>
    </div>
    {dialog === 'toggle' && <ActionDialog title={disabled ? `Enable ${unit.name}?` : `Disable ${unit.name}?`} description={disabled ? 'Members can sign in again and scheduled jobs resume at their next run.' : `Everyone in ${unit.name} is signed out and cannot sign in, and its scans stop. Nothing is deleted. Confirm with your password.`} confirmLabel={disabled ? 'Enable unit' : 'Disable unit'} destructive={!disabled} valueLabel="Your password" valueType="password" valueRequired autoComplete="current-password" onConfirm={toggle} onCancel={() => setDialog(null)} error={error} />}
    {dialog === 'delete' && <ActionDialog title={`Delete ${unit.name} permanently?`} description="EdgeWatch erases the following in the background. Nothing can be recovered afterwards." confirmLabel="Delete unit" destructive valueLabel={`Type “${unit.name}” to confirm`} valueRequired expectedValue={unit.name} autoComplete="off" secondaryValueLabel="Your password" secondaryValueType="password" secondaryValueRequired secondaryAutoComplete="current-password" onConfirm={remove} onCancel={() => setDialog(null)} error={error}>
      <ul className="erase-list" aria-label="Data that will be erased">{unit.erase_categories.map(category => <li key={category.key}><strong>{category.label}</strong><span>{category.detail}</span></li>)}</ul>
    </ActionDialog>}
  </div>
}

function DeleteProgress({ unit }: { unit: BusinessUnitDetail }) {
  const progress = Math.max(0, Math.min(100, unit.delete_progress ?? 0))
  return <div className="panel delete-progress" role="status" aria-live="polite"><h2>Deleting… {progress}%</h2><progress max={100} value={progress} aria-label={`Deleting ${unit.name}`} /><p className="muted">EdgeWatch erases the unit in small batches. You can leave this page: deletion continues in the background and resumes after a restart.</p></div>
}

function DeletedNotice({ unit }: { unit: BusinessUnitDetail }) {
  return <div className="panel" role="status"><h2>{unit.name} was deleted</h2><p className="muted">Its jobs, results, destinations, and accounts were erased, and its name and slug can be reused. The platform audit keeps a record of the deletion.</p><Link className="button secondary" to="/platform/units">Back to business units</Link></div>
}
