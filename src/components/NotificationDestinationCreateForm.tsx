import { useRef, useState, type FormEvent } from 'react'
import { AlertTriangle, Check, Plug, Send } from 'lucide-react'
import { APIError, type NotificationDestination, type NotificationProviderConfig } from '../api'
import { credentialsFromNotificationDraft, initialNotificationConfigDraft, NotificationDestinationConfig, type NotificationConfigDraft } from './NotificationDestinationConfig'

export type CreateNotificationDestination = (name: string, credentials: string | NotificationProviderConfig, password: string, enabled: boolean) => Promise<NotificationDestination>

/**
 * Small reusable create/test form. Its credential and password state lives
 * only in this component and is destroyed when the form is closed.
 */
export function NotificationDestinationCreateForm({
  create,
  onCreated,
  onTest,
  onCancel,
  idPrefix = 'new-destination',
  createLabel = 'Add destination',
}: {
  create: CreateNotificationDestination
  onCreated?: (destination: NotificationDestination) => void | Promise<void>
  onTest?: (destination: NotificationDestination) => Promise<unknown>
  onCancel?: () => void
  idPrefix?: string
  createLabel?: string
}) {
  const [name, setName] = useState('')
  const [configuration, setConfiguration] = useState<NotificationConfigDraft>(initialNotificationConfigDraft)
  const [enabled, setEnabled] = useState(true)
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState<'create' | 'test' | ''>('')
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const [refreshError, setRefreshError] = useState('')
  const [created, setCreated] = useState<NotificationDestination | null>(null)
  const operationLock = useRef(false)

  function clearCredentials() {
    setConfiguration(initialNotificationConfigDraft())
    setPassword('')
  }

  function cancel() {
    setName('')
    clearCredentials()
    setEnabled(true)
    setCreated(null)
    setMessage('')
    setError('')
    setRefreshError('')
    onCancel?.()
  }

  async function submit(event: FormEvent) {
    event.preventDefault()
    setMessage('')
    setError('')
    const credentials = credentialsFromNotificationDraft(configuration)
    if (operationLock.current) return
    if (!name.trim() || !credentials || !password) {
      setError('Name, provider details, and password confirmation are required.')
      return
    }
    operationLock.current = true
    setBusy('create')
    try {
      const providerInput = 'url' in credentials ? credentials.url : credentials.config
      const destination = await create(name.trim(), providerInput, password, enabled)
      setName('')
      clearCredentials()
      setEnabled(true)
      setCreated(destination)
      setMessage('Notification destination added. Credentials are stored encrypted and cannot be read back.')
      setRefreshError('')
      try {
        await onCreated?.(destination)
      } catch {
        setRefreshError('The destination was created, but the destination list could not be refreshed or selected. It remains in Notifications.')
      }
    } catch (err) {
      setError(destinationErrorText(err, 'Could not add notification destination.', secretValues(configuration, password)))
    } finally {
      operationLock.current = false
      setBusy('')
    }
  }

  async function retryRefresh() {
    if (!created || operationLock.current) return
    operationLock.current = true
    setBusy('create')
    try {
      await onCreated?.(created)
      setRefreshError('')
    } catch {
      setRefreshError('The destination was created, but the destination list could not be refreshed or selected. It remains in Notifications.')
    } finally {
      operationLock.current = false
      setBusy('')
    }
  }

  async function testCreated() {
    if (!created || !onTest || operationLock.current) return
    operationLock.current = true
    setBusy('test')
    setError('')
    setMessage('')
    try {
      await onTest(created)
      setMessage(`Test send completed for ${created.name}. Check that the message arrived.`)
    } catch (err) {
      setError(destinationErrorText(err, 'Notification test failed.', []))
    } finally {
      operationLock.current = false
      setBusy('')
    }
  }

  return <form className="settings-form notification-destination-create-form" onSubmit={submit}>
    <label>Name<input value={name} onChange={event => setName(event.currentTarget.value)} maxLength={100} placeholder="Production alerts" autoComplete="off" required /><small>A friendly label only; credentials are not included in it.</small></label>
    <NotificationDestinationConfig idPrefix={idPrefix} draft={configuration} onChange={setConfiguration} />
    <div className="two-fields">
      <label className="switch-row notification-check"><input type="checkbox" checked={enabled} onChange={event => setEnabled(event.currentTarget.checked)} /><span><strong>Enabled</strong><small>Include this destination in future deliveries.</small></span></label>
      <label>Password confirmation<input type="password" value={password} onChange={event => setPassword(event.currentTarget.value)} autoComplete="current-password" required /><small>Required to add this destination.</small></label>
    </div>
    <div className="notification-create-actions">
      <button className="button primary" type="submit" disabled={busy !== ''}><Plug size={16} />{busy === 'create' ? 'Saving…' : createLabel}</button>
      {onTest && created && <button className="button secondary" type="button" onClick={() => void testCreated()} disabled={busy !== ''}><Send size={15} />{busy === 'test' ? 'Sending…' : 'Test destination'}</button>}
      {onCancel && <button className="button ghost" type="button" onClick={cancel} disabled={busy !== ''}>Cancel</button>}
    </div>
    {message && <div className="success-banner save-feedback" role="status"><Check size={17} />{message}</div>}
    {error && <div className="form-error save-feedback" role="alert"><AlertTriangle size={17} />{error}</div>}
    {refreshError && <div className="form-error save-feedback" role="alert"><AlertTriangle size={17} />{refreshError} <button type="button" className="link-button" onClick={() => void retryRefresh()} disabled={busy !== ''}>Retry list refresh</button></div>}
  </form>
}

function secretValues(draft: NotificationConfigDraft, password: string) {
  const sensitiveField = /password|token|url|webhook|secret|key|username/i
  const providerSecrets = Object.entries(draft.fields)
    .filter(([field]) => sensitiveField.test(field))
    .map(([, value]) => value)
  return [...providerSecrets, password].filter(value => value.length > 0).sort((left, right) => right.length - left.length)
}

function destinationErrorText(err: unknown, fallback: string, secrets: string[]) {
  let message = fallback
  if (err instanceof APIError && err.details) {
    const details = Object.values(err.details).filter(value => typeof value === 'string')
    if (details.length > 0) message = details.join(' ')
    else message = err.message
  } else if (err instanceof Error) {
    message = err.message
  }
  for (const secret of secrets) message = message.replaceAll(secret, '[redacted]')
  return message
}
