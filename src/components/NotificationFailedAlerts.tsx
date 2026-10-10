import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, Check, RotateCcw } from 'lucide-react'
import type { TerminalDeliveriesPage, TerminalDelivery } from '../api'
import { formatDateTime } from '../format'
import { eventTypeLabel } from '../status'
import { ErrorNotice } from './ErrorNotice'

/** Where the failed alerts of a destination are read and queued again. */
export type FailedAlertsSource = {
  list: (destinationID: string, before?: number) => Promise<TerminalDeliveriesPage>
  redeliver: (destinationID: string, deliveryIDs?: number[]) => Promise<{ redelivered: number }>
}

/**
 * The alerts that a destination dropped after its retries ran out. They are
 * listed by event, job, and time only: the console never sees an alert's
 * message or the destination's URL. Redelivering queues them again for the
 * destination's current URL; each message then names when it was raised.
 */
export function NotificationFailedAlerts({ destinationID, destinationName, source, queryKey, onRedelivered }: { destinationID: string; destinationName: string; source: FailedAlertsSource; queryKey: readonly unknown[]; onRedelivered: () => void }) {
  const client = useQueryClient()
  const [before, setBefore] = useState<number | undefined>(undefined)
  const [busy, setBusy] = useState('')
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const key = [...queryKey, 'failed-alerts', destinationID, before ?? 0]
  const page = useQuery({ queryKey: key, queryFn: () => source.list(destinationID, before) })

  async function redeliver(deliveryIDs?: number[]) {
    setBusy(deliveryIDs ? `delivery:${deliveryIDs[0]}` : 'all')
    setMessage('')
    setError('')
    try {
      const result = await source.redeliver(destinationID, deliveryIDs)
      setMessage(result.redelivered === 0
        ? 'No failed alerts were left to redeliver.'
        : `${result.redelivered} alert${result.redelivered === 1 ? '' : 's'} queued for redelivery to ${destinationName}.`)
      await client.invalidateQueries({ queryKey: [...queryKey, 'failed-alerts', destinationID] })
      onRedelivered()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not redeliver the failed alerts.')
    } finally {
      setBusy('')
    }
  }

  const deliveries = page.data?.deliveries ?? []
  return <section className="notification-failed-alerts" aria-label={`Failed alerts for ${destinationName}`}>
    <p className="helper">These alerts were dropped after their retries ran out. Redelivering sends them to the destination’s current URL; each message names when it was raised.</p>
    {page.isLoading ? <div className="loading"><span className="spinner" />Loading failed alerts…</div>
      : page.error ? <ErrorNotice message="Could not load the failed alerts." onRetry={() => page.refetch()} />
        : deliveries.length === 0 ? <div className="inline-empty">No failed alerts are waiting for redelivery.</div>
          : <>
            <ul className="notification-failed-list">{deliveries.map(delivery => <FailedAlertRow key={delivery.id} delivery={delivery} busy={busy !== ''} redelivering={busy === `delivery:${delivery.id}`} onRedeliver={() => redeliver([delivery.id])} />)}</ul>
            <div className="notification-actions">
              <button className="button ghost" type="button" onClick={() => redeliver()} disabled={busy !== ''}><RotateCcw size={14} />{busy === 'all' ? 'Redelivering…' : 'Redeliver all'}</button>
              {before !== undefined && <button className="button ghost" type="button" onClick={() => setBefore(undefined)} disabled={busy !== ''}>Newest</button>}
              {page.data?.next_before != null && <button className="button ghost" type="button" onClick={() => setBefore(page.data?.next_before ?? undefined)} disabled={busy !== ''}>Older</button>}
            </div>
          </>}
    {message && <div className="success-banner destination-feedback save-feedback" role="status"><Check size={15} />{message}</div>}
    {error && <div className="form-error destination-feedback save-feedback" role="alert"><AlertTriangle size={15} />{error}</div>}
  </section>
}

function FailedAlertRow({ delivery, busy, redelivering, onRedeliver }: { delivery: TerminalDelivery; busy: boolean; redelivering: boolean; onRedeliver: () => void }) {
  const raised = delivery.event_at ? formatTime(delivery.event_at) : ''
  return <li className="notification-failed-row">
    <div className="notification-meta">
      <strong>{eventTypeLabel(delivery.event_type)}{delivery.job ? ` · ${delivery.job}` : ''}</strong>
      <span>{raised ? `Raised ${raised} · ` : ''}Dropped {formatTime(delivery.terminal_at)} · {delivery.attempts} attempt{delivery.attempts === 1 ? '' : 's'}{delivery.deferrals ? `, ${delivery.deferrals} deferral${delivery.deferrals === 1 ? '' : 's'}` : ''}{delivery.error_code ? ` · ${delivery.error_code}` : ''}</span>
    </div>
    <button className="button ghost" type="button" onClick={onRedeliver} disabled={busy} aria-label={`Redeliver ${eventTypeLabel(delivery.event_type)}${delivery.job ? ` for ${delivery.job}` : ''}`}>{redelivering ? 'Redelivering…' : 'Redeliver'}</button>
  </li>
}

function formatTime(value: string) {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? 'at an unknown time' : formatDateTime(date)
}
