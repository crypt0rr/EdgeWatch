import { FormEvent, useState, type ReactNode } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, Bell, Check, KeyRound, LockKeyhole, Pencil, Plug, RefreshCw, Send, ShieldCheck, Trash2 } from 'lucide-react'
import {
  APIError,
  createNotificationDestination,
  deleteNotificationDestination,
  listNotificationDestinations,
  NotificationDestination,
  type NotificationDestinationsResponse,
  type NotificationUpdateRouting,
  testNotificationDestination,
  toggleNotificationUpdateAlert,
  updateNotificationDestination,
  updateIncidentReminders,
  getSession,
} from '../api'
import { ActionDialog } from '../components/ActionDialog'
import { ErrorNotice } from '../components/ErrorNotice'
import { formatDateTime } from '../format'

type EditState = {
  id: string
  name: string
  url: string
  enabled: boolean
}

type PasswordPromptState = {
  title: string
  description: string
  confirmLabel: string
  resolve: (password: string | null) => void
}

type DestinationFeedback = { message?: string; error?: string }

/**
 * Where a notifications page reads and changes its destinations: a unit's
 * own, or the platform's. Either way a destination's URL is write-only: it is
 * sent when it is created or replaced and never read back.
 */
export type NotificationScope = {
  queryKey: readonly unknown[]
  list: () => Promise<NotificationDestinationsResponse>
  create: (name: string, url: string, password: string, enabled: boolean) => Promise<unknown>
  update: (id: string, revision: number, name: string, password: string, options: { url?: string; enabled?: boolean }) => Promise<unknown>
  remove: (id: string, revision: number, password: string) => Promise<unknown>
  /** Sends a test message; the platform's destinations have none. */
  test?: (id: string) => Promise<unknown>
  toggleRouting: (destinationID: string, enabled: boolean, password: string) => Promise<NotificationUpdateRouting>
  /** Whether routing that was never saved sends update alerts to every enabled destination. */
  routingDefaultsToEnabled: boolean
  /** Whether the page reports the import of config.yaml notification URLs. */
  configImport: boolean
  eyebrow: string
  description: ReactNode
  listDescription: ReactNode
  /** Only business units have job incidents; the platform has no reminder setting. */
  incidentReminders?: (enabled: boolean, password: string) => Promise<{ enabled: boolean }>
}

// A unit's own destinations, including the deployment URLs of the default
// unit's config.yaml.
const unitNotifications: NotificationScope = {
  queryKey: ['notifications'],
  list: () => listNotificationDestinations(),
  create: (name, url, password, enabled) => createNotificationDestination(name, url, password, enabled),
  update: (id, revision, name, password, options) => updateNotificationDestination(id, revision, name, password, options),
  remove: (id, revision, password) => deleteNotificationDestination(id, revision, password),
  test: id => testNotificationDestination(id),
  toggleRouting: (destinationID, enabled, password) => toggleNotificationUpdateAlert(destinationID, enabled, password),
  routingDefaultsToEnabled: true,
  configImport: true,
  eyebrow: 'Delivery',
  description: 'Manage named Shoutrrr destinations without exposing their credentials.',
  listDescription: 'Deployment-managed URLs remain read-only here. Web-managed URLs are identified by name and provider. Use each destination’s Update alerts toggle to control release and upgrade notifications.',
  incidentReminders: (enabled, password) => updateIncidentReminders(enabled, password),
}

export function Notifications() {
  const session = useQuery({ queryKey: ['session'], queryFn: getSession })
  const canManage = session.data?.permissions.includes('notifications.manage') ?? false
  return <NotificationsView scope={unitNotifications} canManage={canManage} />
}

export function NotificationsView({ scope, canManage }: { scope: NotificationScope; canManage: boolean }) {
  const client = useQueryClient()
  const destinations = useQuery({ queryKey: scope.queryKey, queryFn: scope.list, refetchInterval: 30_000 })
  const [name, setName] = useState('')
  const [url, setURL] = useState('')
  const [enabled, setEnabled] = useState(true)
  const [password, setPassword] = useState('')
  const [edit, setEdit] = useState<EditState | null>(null)
  const [passwordPrompt, setPasswordPrompt] = useState<PasswordPromptState | null>(null)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const [reminderError, setReminderError] = useState('')
  const [reminderFeedback, setReminderFeedback] = useState('')
  const [busy, setBusy] = useState('')
  const [rowFeedback, setRowFeedback] = useState<Record<string, DestinationFeedback>>({})
  const [listFeedback, setListFeedback] = useState('')

  function resetFeedback() {
    setMessage('')
    setError('')
  }

  function reportError(err: unknown, fallback: string) {
    setError(destinationErrorText(err, fallback))
  }

  function clearRowFeedback(id: string) {
    setRowFeedback(current => {
      if (!current[id]) return current
      const next = { ...current }
      delete next[id]
      return next
    })
  }

  function reportRowError(id: string, err: unknown, fallback: string) {
    setRowFeedback(current => ({ ...current, [id]: { error: destinationErrorText(err, fallback) } }))
  }

  function reportRowMessage(id: string, text: string) {
    setRowFeedback(current => ({ ...current, [id]: { message: text } }))
  }

  function destinationErrorText(err: unknown, fallback: string) {
    if (err instanceof APIError && err.details) {
      const details = Object.values(err.details).filter(value => typeof value === 'string')
      if (details.length > 0) return details.join(' ')
    }
    return err instanceof Error ? err.message : fallback
  }

  async function create(event: FormEvent) {
    event.preventDefault()
    resetFeedback()
    if (!name.trim() || !url.trim() || !password) {
      setError('Name, Shoutrrr URL, and password confirmation are required.')
      return
    }
    setBusy('create')
    try {
      await scope.create(name.trim(), url.trim(), password, enabled)
      setName('')
      setURL('')
      setPassword('')
      setEnabled(true)
      setMessage('Notification destination added. The URL is stored encrypted and will not be shown again.')
      await client.invalidateQueries({ queryKey: scope.queryKey })
    } catch (err) {
      reportError(err, 'Could not add notification destination.')
    } finally {
      setBusy('')
    }
  }

  function beginEdit(destination: NotificationDestination) {
    resetFeedback()
    clearRowFeedback(destination.id)
    setEdit({ id: destination.id, name: destination.name, url: '', enabled: destination.enabled })
  }

  function askPassword(title: string, description: string, confirmLabel: string) {
    return new Promise<string | null>(resolve => {
      setPasswordPrompt({ title, description, confirmLabel, resolve })
    })
  }

  function resolvePassword(password: string | null) {
    const pending = passwordPrompt
    setPasswordPrompt(null)
    pending?.resolve(password)
  }

  async function saveEdit(event: FormEvent) {
    event.preventDefault()
    if (!edit) return
    clearRowFeedback(edit.id)
    const destination = destinations.data?.destinations.find(value => value.id === edit.id)
    if (!destination?.revision) {
      reportRowError(edit.id, new Error('This destination changed. Refresh the page and try again.'), 'This destination changed. Refresh the page and try again.')
      return
    }
    const confirmation = await askPassword('Confirm destination changes', 'Enter your account password to save this destination.', 'Save changes')
    if (confirmation === null) return
    setBusy(edit.id)
    try {
      const options: { url?: string; enabled?: boolean } = { enabled: edit.enabled }
      if (edit.url.trim()) options.url = edit.url.trim()
      await scope.update(edit.id, destination.revision, edit.name.trim(), confirmation, options)
      setEdit(null)
      // Only a new URL discards the queued alerts; a rename or a pause keeps
      // them for delivery.
      reportRowMessage(edit.id, options.url ? 'Notification destination updated. Alerts queued for the previous URL were discarded.' : 'Notification destination updated.')
      await client.invalidateQueries({ queryKey: scope.queryKey })
    } catch (err) {
      reportRowError(edit.id, err, 'Could not update notification destination.')
    } finally {
      setBusy('')
    }
  }

  async function toggle(destination: NotificationDestination) {
    if (destination.locked || destination.revision === undefined) return
    clearRowFeedback(destination.id)
    const action = destination.enabled ? 'pause' : 'enable'
    const confirmation = await askPassword(`Confirm ${action}`, `Enter your account password to ${action} this destination.`, destination.enabled ? 'Pause destination' : 'Enable destination')
    if (confirmation === null) return
    setBusy(destination.id)
    try {
      await scope.update(destination.id, destination.revision, destination.name, confirmation, { enabled: !destination.enabled })
      reportRowMessage(destination.id, destination.enabled ? 'Destination paused.' : 'Destination enabled.')
      await client.invalidateQueries({ queryKey: scope.queryKey })
    } catch (err) {
      reportRowError(destination.id, err, 'Could not change destination state.')
    } finally {
      setBusy('')
    }
  }

  async function remove(destination: NotificationDestination) {
    if (destination.revision === undefined) return
    clearRowFeedback(destination.id)
    setListFeedback('')
    const confirmation = await askPassword('Confirm removal', 'Enter your account password to remove this destination.', 'Remove destination')
    if (confirmation === null) return
    setBusy(destination.id)
    try {
      await scope.remove(destination.id, destination.revision, confirmation)
      setListFeedback(`Notification destination ${destination.name} removed.`)
      await client.invalidateQueries({ queryKey: scope.queryKey })
    } catch (err) {
      reportRowError(destination.id, err, 'Could not remove notification destination.')
    } finally {
      setBusy('')
    }
  }

  async function test(destination: NotificationDestination) {
    if (destination.locked || !scope.test) return
    clearRowFeedback(destination.id)
    setBusy(`test:${destination.id}`)
    try {
      await scope.test(destination.id)
      reportRowMessage(destination.id, `Test sent to ${destination.name}.`)
    } catch (err) {
      reportRowError(destination.id, err, 'Notification test failed.')
    } finally {
      setBusy('')
    }
  }

  async function toggleUpdateRouting(destination: NotificationDestination, checked: boolean) {
    if (!destinations.data || busy.startsWith('update-routing:') || passwordPrompt) return
    clearRowFeedback(destination.id)
    const confirmation = await askPassword(`Confirm update alerts for ${destination.name}`, `Enter your account password to ${checked ? 'send' : 'stop sending'} release and upgrade alerts through this destination.`, checked ? 'Enable update alerts' : 'Disable update alerts')
    if (confirmation === null) return
    setBusy(`update-routing:${destination.id}`)
    try {
      // This endpoint toggles just one selector against the latest persisted
      // state, so a change made in another session while the prompt was open
      // is preserved.
      const result = await scope.toggleRouting(destination.id, checked, confirmation)
      client.setQueryData<NotificationDestinationsResponse>(scope.queryKey, current => current && { ...current, update_routing: result })
      reportRowMessage(destination.id, `Application update alerts ${checked ? 'enabled' : 'disabled'} for ${destination.name}.`)
      await client.invalidateQueries({ queryKey: scope.queryKey })
    } catch (err) {
      reportRowError(destination.id, err, 'Could not change application update notification routing.')
    } finally {
      setBusy('')
    }
  }

  async function toggleIncidentReminders(checked: boolean) {
    if (!scope.incidentReminders || busy || passwordPrompt) return
    setReminderError('')
    setReminderFeedback('')
    const confirmation = await askPassword('Confirm incident reminders', `Enter your account password to ${checked ? 'enable' : 'disable'} reminders for incidents that remain open after a successful scan.`, checked ? 'Enable reminders' : 'Disable reminders')
    if (confirmation === null) return
    setBusy('incident-reminders')
    try {
      const result = await scope.incidentReminders(checked, confirmation)
      client.setQueryData<NotificationDestinationsResponse>(scope.queryKey, current => current && { ...current, incident_reminders_enabled: result.enabled })
      setReminderFeedback(`Incident reminders ${result.enabled ? 'enabled' : 'disabled'}.`)
      await client.invalidateQueries({ queryKey: scope.queryKey })
    } catch (err) {
      setReminderError(destinationErrorText(err, 'Could not change incident reminders.'))
    } finally {
      setBusy('')
    }
  }

  const status = destinations.data?.status
  const selectedUpdateDestinations = selectedUpdateDestinationIds(destinations.data, scope.routingDefaultsToEnabled)
  const updateRoutingBusy = busy.startsWith('update-routing:') || passwordPrompt !== null
  return <section className="page narrow notifications-page">
    <div className="page-heading"><div><p className="eyebrow">{scope.eyebrow}</p><h1>Notifications</h1><p className="muted">{scope.description}</p></div><Bell className="muted-icon" size={24} /></div>
    {status && <div className={status.key_state === 'ready' || status.key_state === 'not_required' ? 'notice notification-status' : 'notice warning notification-status'}><KeyRound size={17} /><span><strong>{status.key_state === 'ready' ? 'Encrypted destinations are available.' : status.key_state === 'not_required' ? 'No web-managed destinations yet.' : 'Managed destination key needs attention.'}</strong> {status.locked ? `${status.locked} destination${status.locked === 1 ? '' : 's'} locked; deployment URLs continue independently.` : 'Credentials are write-only and encrypted at rest.'}</span><button className="icon-button" type="button" onClick={() => destinations.refetch()} aria-label="Refresh notification status"><RefreshCw size={15} /></button></div>}
    {scope.configImport && status?.config_import === 'imported' && <div className="notice warning notification-config-import" role="status"><AlertTriangle size={17} /><span><strong>Notification URLs in config.yaml were imported.</strong> They are now web-managed destinations below and are no longer read from config.yaml. Remove <code>notifications.urls</code> and <code>notifications.urls_file</code> from config.yaml; a later release refuses to start while they are set.</span></div>}
    {scope.configImport && status?.config_import === 'failed' && <div className="notice warning notification-config-import" role="status"><AlertTriangle size={17} /><span><strong>Notification URLs in config.yaml could not be imported.</strong> EdgeWatch still delivers to them from config.yaml. Check the daemon log or <code>edgewatch health</code>, fix the cause, and restart EdgeWatch.</span></div>}

    {scope.incidentReminders && <div className="panel notification-reminder-settings">
      <div className="panel-heading">
        <div>
          <h2>Incident reminders</h2>
          <p className="muted">Send a reminder through each job’s selected destinations after every successful scan that still confirms an open incident. This setting does not affect initial incident alerts.</p>
        </div>
        <Bell className="muted-icon" size={20} />
      </div>
      <label className="switch-row notification-check">
        <input type="checkbox" checked={destinations.data?.incident_reminders_enabled ?? true} disabled={!canManage || destinations.isLoading || !!destinations.error || !!busy || passwordPrompt !== null} onChange={event => toggleIncidentReminders(event.currentTarget.checked)} aria-label="Send reminders for incidents that remain open" />
        <span><strong>{destinations.data?.incident_reminders_enabled === false ? 'Reminders off' : 'Reminders on'}</strong><small>Incomplete, failed, cancelled, and timed-out scans do not send reminders.</small></span>
      </label>
      {reminderError && <div className="form-error save-feedback" role="alert"><AlertTriangle size={17} />{reminderError}</div>}
      {reminderFeedback && <div className="success-banner notification-panel-feedback" role="status"><Check size={17} />{reminderFeedback}</div>}
    </div>}

    {canManage && <div className="panel notification-create">
      <div className="panel-heading"><div><h2>Add destination</h2><p className="muted">Paste one complete Shoutrrr URL. It is never returned by the API.</p></div><ShieldCheck className="green-icon" size={20} /></div>
      <form className="settings-form" onSubmit={create}>
        <div className="two-fields"><label>Name<input value={name} onChange={event => setName(event.target.value)} maxLength={100} placeholder="Production alerts" autoComplete="off" required /><small>A friendly label only; credentials are not included in it.</small></label><label>Shoutrrr URL<input type="url" value={url} onChange={event => setURL(event.target.value)} placeholder="generic://host/path?disabletls=yes" autoComplete="off" spellCheck={false} required /><small>Provider-specific URL syntax is validated by Shoutrrr.</small></label></div>
        <div className="two-fields"><label className="switch-row notification-check"><input type="checkbox" checked={enabled} onChange={event => setEnabled(event.target.checked)} /><span><strong>Enabled</strong><small>Include this destination in future deliveries.</small></span></label><label>Password confirmation<input type="password" value={password} onChange={event => setPassword(event.target.value)} autoComplete="current-password" required /><small>Required for every credential or delivery-state change.</small></label></div>
        <button className="button primary" type="submit" disabled={busy === 'create'}><Plug size={16} />{busy === 'create' ? 'Saving…' : 'Add destination'}</button>
        {message && <div className="success-banner save-feedback" role="status"><Check size={17} />{message}</div>}
        {error && <div className="form-error save-feedback" role="alert"><AlertTriangle size={17} />{error}</div>}
      </form>
    </div>}

    <div className="panel notification-list-panel">
      <div className="panel-heading"><div><h2>Configured destinations</h2><p className="muted">{scope.listDescription}</p></div><span className="pill blue">{status?.active ?? 0} active</span></div>
      {listFeedback && <div className="success-banner notification-panel-feedback" role="status"><Check size={17} />{listFeedback}</div>}
      {!canManage && <div className="notice notification-read-only" role="status"><LockKeyhole size={16} /><span>Notification destinations are managed by an administrator. You can review their availability and select them for jobs where permitted.</span></div>}
      {destinations.isLoading ? <div className="loading"><span className="spinner" />Loading destinations…</div> : destinations.error ? <ErrorNotice message="Could not load notification destinations." onRetry={() => destinations.refetch()} /> : destinations.data?.destinations.length ? <div className="notification-list">{destinations.data.destinations.map(destination => <DestinationRow key={destination.id} destination={destination} editing={canManage && edit?.id === destination.id ? edit : null} busy={busy} canManage={canManage} updateAlertSelected={selectedUpdateDestinations.includes(destination.id)} updateAlertsBusy={updateRoutingBusy} feedback={rowFeedback[destination.id]} onToggleUpdateAlerts={toggleUpdateRouting} onEdit={beginEdit} onCancel={() => setEdit(null)} onSave={saveEdit} onChange={setEdit} onToggle={toggle} onDelete={remove} onTest={scope.test ? test : undefined} />)}</div> : <div className="inline-empty">No notification destinations are configured.</div>}
    </div>
    <p className="helper notification-footnote"><LockKeyhole size={13} /><span>URLs containing credentials are encrypted with the local notification key. Back up <code>notification.key</code> with <code>edgewatch.db</code>; losing it locks web-managed destinations until the key is restored (or a destination is deleted and recreated).</span></p>
    {passwordPrompt && <ActionDialog title={passwordPrompt.title} description={passwordPrompt.description} confirmLabel={passwordPrompt.confirmLabel} valueLabel="Account password" valueType="password" valueRequired autoComplete="current-password" onConfirm={value => resolvePassword(value)} onCancel={() => resolvePassword(null)} />}
  </section>
}

// The update-alert checkboxes always follow the latest fetched routing, so a
// change saved in another session appears after the next refetch. A unit's
// routing that was never saved selects its enabled destinations; the
// platform's selects none.
function selectedUpdateDestinationIds(data: NotificationDestinationsResponse | undefined, defaultsToEnabled: boolean) {
  if (!data) return []
  const routing = data.update_routing
  if (!routing?.configured) return defaultsToEnabled ? data.destinations.filter(destination => destination.enabled).map(destination => destination.id) : []
  const available = new Set(data.destinations.map(destination => destination.id))
  return routing.destinations.filter(id => available.has(id))
}

function DestinationRow({ destination, editing, busy, canManage, updateAlertSelected, updateAlertsBusy, feedback, onToggleUpdateAlerts, onEdit, onCancel, onSave, onChange, onToggle, onDelete, onTest }: { destination: NotificationDestination; editing: EditState | null; busy: string; canManage: boolean; updateAlertSelected: boolean; updateAlertsBusy: boolean; feedback?: DestinationFeedback; onToggleUpdateAlerts: (destination: NotificationDestination, checked: boolean) => void; onEdit: (destination: NotificationDestination) => void; onCancel: () => void; onSave: (event: FormEvent) => void; onChange: (next: EditState | null) => void; onToggle: (destination: NotificationDestination) => void; onDelete: (destination: NotificationDestination) => void; onTest?: (destination: NotificationDestination) => void }) {
  const deployment = destination.read_only || destination.source === 'deployment'
  return <div className={destination.locked ? 'notification-row locked' : 'notification-row'}>
    <div className="notification-row-main"><span className={deployment ? 'notification-icon deployment' : 'notification-icon'}>{deployment ? <Plug size={16} /> : <Send size={16} />}</span><div className="notification-meta"><strong title={destination.name}>{destination.name}</strong><span>{destination.provider || 'unknown provider'} · {deployment ? 'deployment configuration' : `revision ${destination.revision}`}</span></div>{canManage && <label className="notification-update-toggle"><input type="checkbox" checked={updateAlertSelected} disabled={updateAlertsBusy} onChange={event => onToggleUpdateAlerts(destination, event.currentTarget.checked)} aria-label={`${updateAlertSelected ? 'Disable' : 'Enable'} update alerts for ${destination.name}`} /><span><strong>Update alerts</strong><small>{updateAlertSelected ? 'Release and upgrade alerts on' : 'Release and upgrade alerts off'}</small></span></label>}<div className="notification-state">{destination.locked ? <span className="pill amber"><LockKeyhole size={11} /> Locked</span> : deployment ? <span className="pill gray">Read-only</span> : <span className={destination.enabled ? 'pill green' : 'pill gray'}>{destination.enabled ? 'Enabled' : 'Paused'}</span>}</div></div>
    {destination.locked && <div className="notification-lock"><AlertTriangle size={14} /> Credentials cannot be decrypted ({destination.error_code ?? 'key unavailable'}). Restore the key before editing or enabling it; if it cannot be recovered, remove and recreate this destination.</div>}
    <DeliveryHealth destination={destination} />
    {!deployment && editing && <form className="notification-edit" onSubmit={onSave}><div className="two-fields"><label>Name<input value={editing.name} onChange={event => onChange({ ...editing, name: event.target.value })} maxLength={100} required /></label><label>Replace URL <span className="helper">(optional)</span><input type="url" value={editing.url} onChange={event => onChange({ ...editing, url: event.target.value })} placeholder="Leave blank to keep the encrypted URL" autoComplete="off" spellCheck={false} /></label></div><label className="switch-row notification-check"><input type="checkbox" checked={editing.enabled} onChange={event => onChange({ ...editing, enabled: event.target.checked })} /><span><strong>{editing.enabled ? 'Enabled' : 'Paused'}</strong><small>Saving creates a new destination revision.</small></span></label><div className="notification-edit-actions"><button className="button primary" type="submit" disabled={busy === destination.id}>Save changes</button><button className="button ghost" type="button" onClick={onCancel}>Cancel</button></div></form>}
    {canManage && !deployment && !editing && <div className="notification-actions">{onTest && <button className="button ghost" type="button" onClick={() => onTest(destination)} disabled={destination.locked || busy === `test:${destination.id}`}><Send size={14} />{busy === `test:${destination.id}` ? 'Sending…' : 'Test'}</button>}<button className="button ghost" type="button" onClick={() => onToggle(destination)} disabled={destination.locked || busy === destination.id}>{destination.enabled ? 'Pause' : 'Enable'}</button><button className="button ghost" type="button" onClick={() => onEdit(destination)} disabled={destination.locked || busy === destination.id}><Pencil size={14} />Edit</button><button className="button ghost danger-text" type="button" onClick={() => onDelete(destination)} disabled={busy === destination.id}><Trash2 size={14} />Remove</button></div>}
    {feedback?.message && <div className="success-banner destination-feedback save-feedback" role="status">{feedback.message}</div>}
    {feedback?.error && <div className="form-error destination-feedback save-feedback" role="alert">{feedback.error}</div>}
  </div>
}

function DeliveryHealth({ destination }: { destination: NotificationDestination }) {
  const pending = destination.pending ?? 0
  const retrying = destination.retrying ?? 0
  const deferrals = destination.deferrals ?? 0
  const terminal = destination.terminal_failures ?? 0
  const lastSuccess = destination.last_success_at ? formatDeliveryTime(destination.last_success_at) : ''
  const lastFailure = destination.last_failure_at ? formatDeliveryTime(destination.last_failure_at) : ''
  if (!pending && !retrying && !deferrals && !terminal && !lastSuccess && !lastFailure) return null
  return <div className="notification-health" role="status"><span className="notification-health-label">Delivery health</span>{pending > 0 && <span className="pill blue">{pending} pending</span>}{retrying > 0 && <span className="pill amber">{retrying} retrying</span>}{deferrals > 0 && <span className="pill amber">{deferrals} deferred</span>}{terminal > 0 && <span className="pill red">{terminal} terminal failure{terminal === 1 ? '' : 's'}</span>}{lastSuccess && <span className="notification-health-detail">Last success {lastSuccess}</span>}{lastFailure && !terminal && <span className="notification-health-detail">Last failure {lastFailure}{destination.last_error_code ? ` · ${destination.last_error_code}` : ''}</span>}</div>
}

function formatDeliveryTime(value: string) {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? 'unknown time' : formatDateTime(date)
}
