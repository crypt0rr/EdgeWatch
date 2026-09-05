import { FormEvent, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, Bell, Check, KeyRound, LockKeyhole, Pencil, Plug, RefreshCw, Send, ShieldCheck, Trash2 } from 'lucide-react'
import {
  APIError,
  createNotificationDestination,
  deleteNotificationDestination,
  listNotificationDestinations,
  NotificationDestination,
  testNotificationDestination,
  updateNotificationDestination,
} from '../api'
import { ActionDialog } from '../components/ActionDialog'

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

export function Notifications() {
  const client = useQueryClient()
  const destinations = useQuery({ queryKey: ['notifications'], queryFn: listNotificationDestinations, refetchInterval: 30_000 })
  const [name, setName] = useState('')
  const [url, setURL] = useState('')
  const [enabled, setEnabled] = useState(true)
  const [password, setPassword] = useState('')
  const [edit, setEdit] = useState<EditState | null>(null)
  const [passwordPrompt, setPasswordPrompt] = useState<PasswordPromptState | null>(null)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState('')

  function resetFeedback() {
    setMessage('')
    setError('')
  }

  function reportError(err: unknown, fallback: string) {
    if (err instanceof APIError && err.details) {
      const details = Object.values(err.details).filter(value => typeof value === 'string')
      if (details.length > 0) {
        setError(details.join(' '))
        return
      }
    }
    setError(err instanceof Error ? err.message : fallback)
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
      await createNotificationDestination(name.trim(), url.trim(), password, enabled)
      setName('')
      setURL('')
      setPassword('')
      setEnabled(true)
      setMessage('Notification destination added. The URL is stored encrypted and will not be shown again.')
      await client.invalidateQueries({ queryKey: ['notifications'] })
    } catch (err) {
      reportError(err, 'Could not add notification destination.')
    } finally {
      setBusy('')
    }
  }

  function beginEdit(destination: NotificationDestination) {
    resetFeedback()
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
    resetFeedback()
    const destination = destinations.data?.destinations.find(value => value.id === edit.id)
    if (!destination?.revision) {
      setError('This destination changed. Refresh the page and try again.')
      return
    }
    const confirmation = await askPassword('Confirm destination changes', 'Enter the administrator password to save this destination.', 'Save changes')
    if (confirmation === null) return
    setBusy(edit.id)
    try {
      const options: { url?: string; enabled?: boolean } = { enabled: edit.enabled }
      if (edit.url.trim()) options.url = edit.url.trim()
      await updateNotificationDestination(edit.id, destination.revision, edit.name.trim(), confirmation, options)
      setEdit(null)
      setMessage('Notification destination updated. Any pending deliveries for the previous revision were discarded.')
      await client.invalidateQueries({ queryKey: ['notifications'] })
    } catch (err) {
      reportError(err, 'Could not update notification destination.')
    } finally {
      setBusy('')
    }
  }

  async function toggle(destination: NotificationDestination) {
    if (destination.locked || destination.revision === undefined) return
    resetFeedback()
    const action = destination.enabled ? 'pause' : 'enable'
    const confirmation = await askPassword(`Confirm ${action}`, `Enter the administrator password to ${action} this destination.`, destination.enabled ? 'Pause destination' : 'Enable destination')
    if (confirmation === null) return
    setBusy(destination.id)
    try {
      await updateNotificationDestination(destination.id, destination.revision, destination.name, confirmation, { enabled: !destination.enabled })
      setMessage(destination.enabled ? 'Destination paused.' : 'Destination enabled.')
      await client.invalidateQueries({ queryKey: ['notifications'] })
    } catch (err) {
      reportError(err, 'Could not change destination state.')
    } finally {
      setBusy('')
    }
  }

  async function remove(destination: NotificationDestination) {
    if (destination.revision === undefined) return
    resetFeedback()
    const confirmation = await askPassword('Confirm removal', 'Enter the administrator password to remove this destination.', 'Remove destination')
    if (confirmation === null) return
    setBusy(destination.id)
    try {
      await deleteNotificationDestination(destination.id, destination.revision, confirmation)
      setMessage('Notification destination removed.')
      await client.invalidateQueries({ queryKey: ['notifications'] })
    } catch (err) {
      reportError(err, 'Could not remove notification destination.')
    } finally {
      setBusy('')
    }
  }

  async function test(destination: NotificationDestination) {
    if (destination.locked) return
    resetFeedback()
    setBusy(`test:${destination.id}`)
    try {
      await testNotificationDestination(destination.id)
      setMessage(`Test sent to ${destination.name}.`)
    } catch (err) {
      reportError(err, 'Notification test failed.')
    } finally {
      setBusy('')
    }
  }

  const status = destinations.data?.status
  return <section className="page narrow notifications-page">
    <div className="page-heading"><div><p className="eyebrow">Delivery</p><h1>Notifications</h1><p className="muted">Manage named Shoutrrr destinations without exposing their credentials.</p></div><Bell className="muted-icon" size={24} /></div>
    {message && <div className="success-banner" role="status"><Check size={17} />{message}</div>}
    {error && <div className="form-error banner" role="alert"><AlertTriangle size={17} />{error}</div>}
    {status && <div className={status.key_state === 'ready' || status.key_state === 'not_required' ? 'notice notification-status' : 'notice warning notification-status'}><KeyRound size={17} /><span><strong>{status.key_state === 'ready' ? 'Encrypted destinations are available.' : status.key_state === 'not_required' ? 'No web-managed destinations yet.' : 'Managed destination key needs attention.'}</strong> {status.locked ? `${status.locked} destination${status.locked === 1 ? '' : 's'} locked; deployment URLs continue independently.` : 'Credentials are write-only and encrypted at rest.'}</span><button className="icon-button" type="button" onClick={() => destinations.refetch()} aria-label="Refresh notification status"><RefreshCw size={15} /></button></div>}

    <div className="panel notification-create">
      <div className="panel-heading"><div><h2>Add destination</h2><p className="muted">Paste one complete Shoutrrr URL. It is never returned by the API.</p></div><ShieldCheck className="green-icon" size={20} /></div>
      <form className="settings-form" onSubmit={create}>
        <div className="two-fields"><label>Name<input value={name} onChange={event => setName(event.target.value)} maxLength={100} placeholder="Production alerts" autoComplete="off" required /><small>A friendly label only; credentials are not included in it.</small></label><label>Shoutrrr URL<input type="url" value={url} onChange={event => setURL(event.target.value)} placeholder="generic://host/path?disabletls=yes" autoComplete="off" spellCheck={false} required /><small>Provider-specific URL syntax is validated by Shoutrrr.</small></label></div>
        <div className="two-fields"><label className="switch-row notification-check"><input type="checkbox" checked={enabled} onChange={event => setEnabled(event.target.checked)} /><span><strong>Enabled</strong><small>Include this destination in future deliveries.</small></span></label><label>Password confirmation<input type="password" value={password} onChange={event => setPassword(event.target.value)} autoComplete="current-password" required /><small>Required for every credential or delivery-state change.</small></label></div>
        <button className="button primary" type="submit" disabled={busy === 'create'}><Plug size={16} />{busy === 'create' ? 'Saving…' : 'Add destination'}</button>
      </form>
    </div>

    <div className="panel notification-list-panel">
      <div className="panel-heading"><div><h2>Configured destinations</h2><p className="muted">Deployment-managed URLs remain read-only here. Web-managed URLs are identified by name and provider.</p></div><span className="pill blue">{status?.active ?? 0} active</span></div>
      {destinations.isLoading ? <div className="loading"><span className="spinner" />Loading destinations…</div> : destinations.error ? <div className="error-card">{destinations.error.message}</div> : destinations.data?.destinations.length ? <div className="notification-list">{destinations.data.destinations.map(destination => <DestinationRow key={destination.id} destination={destination} editing={edit?.id === destination.id ? edit : null} busy={busy} onEdit={beginEdit} onCancel={() => setEdit(null)} onSave={saveEdit} onChange={setEdit} onToggle={toggle} onDelete={remove} onTest={test} />)}</div> : <div className="inline-empty">No notification destinations are configured.</div>}
    </div>
    <p className="helper notification-footnote"><LockKeyhole size={13} /> URLs containing credentials are encrypted with the local notification key. Back up <code>notification.key</code> with <code>edgewatch.db</code>; losing it locks web-managed destinations until the key is restored (or a destination is deleted and recreated).</p>
    {passwordPrompt && <ActionDialog title={passwordPrompt.title} description={passwordPrompt.description} confirmLabel={passwordPrompt.confirmLabel} valueLabel="Administrator password" valueType="password" valueRequired autoComplete="current-password" onConfirm={value => resolvePassword(value)} onCancel={() => resolvePassword(null)} />}
  </section>
}

function DestinationRow({ destination, editing, busy, onEdit, onCancel, onSave, onChange, onToggle, onDelete, onTest }: { destination: NotificationDestination; editing: EditState | null; busy: string; onEdit: (destination: NotificationDestination) => void; onCancel: () => void; onSave: (event: FormEvent) => void; onChange: (next: EditState | null) => void; onToggle: (destination: NotificationDestination) => void; onDelete: (destination: NotificationDestination) => void; onTest: (destination: NotificationDestination) => void }) {
  const deployment = destination.read_only || destination.source === 'deployment'
  return <div className={destination.locked ? 'notification-row locked' : 'notification-row'}>
    <div className="notification-row-main"><span className={deployment ? 'notification-icon deployment' : 'notification-icon'}>{deployment ? <Plug size={16} /> : <Send size={16} />}</span><div className="notification-meta"><strong>{destination.name}</strong><span>{destination.provider || 'unknown provider'} · {deployment ? 'deployment configuration' : `revision ${destination.revision}`}</span></div><div className="notification-state">{destination.locked ? <span className="pill amber"><LockKeyhole size={11} /> Locked</span> : deployment ? <span className="pill gray">Read-only</span> : <span className={destination.enabled ? 'pill green' : 'pill gray'}>{destination.enabled ? 'Enabled' : 'Paused'}</span>}</div></div>
    {destination.locked && <div className="notification-lock"><AlertTriangle size={14} /> Credentials cannot be decrypted ({destination.error_code ?? 'key unavailable'}). Restore the key before editing or enabling it; if it cannot be recovered, remove and recreate this destination.</div>}
    {!deployment && editing && <form className="notification-edit" onSubmit={onSave}><div className="two-fields"><label>Name<input value={editing.name} onChange={event => onChange({ ...editing, name: event.target.value })} maxLength={100} required /></label><label>Replace URL <span className="helper">(optional)</span><input type="url" value={editing.url} onChange={event => onChange({ ...editing, url: event.target.value })} placeholder="Leave blank to keep the encrypted URL" autoComplete="off" spellCheck={false} /></label></div><label className="switch-row notification-check"><input type="checkbox" checked={editing.enabled} onChange={event => onChange({ ...editing, enabled: event.target.checked })} /><span><strong>{editing.enabled ? 'Enabled' : 'Paused'}</strong><small>Saving creates a new destination revision.</small></span></label><div className="notification-edit-actions"><button className="button primary" type="submit" disabled={busy === destination.id}>Save changes</button><button className="button ghost" type="button" onClick={onCancel}>Cancel</button></div></form>}
    {!deployment && !editing && <div className="notification-actions"><button className="button ghost" type="button" onClick={() => onTest(destination)} disabled={destination.locked || busy === `test:${destination.id}`}><Send size={14} />{busy === `test:${destination.id}` ? 'Sending…' : 'Test'}</button><button className="button ghost" type="button" onClick={() => onToggle(destination)} disabled={destination.locked || busy === destination.id}>{destination.enabled ? 'Pause' : 'Enable'}</button><button className="button ghost" type="button" onClick={() => onEdit(destination)} disabled={destination.locked || busy === destination.id}><Pencil size={14} />Edit</button><button className="button ghost danger-text" type="button" onClick={() => onDelete(destination)} disabled={busy === destination.id}><Trash2 size={14} />Remove</button></div>}
  </div>
}
