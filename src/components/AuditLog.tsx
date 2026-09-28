import { useInfiniteQuery } from '@tanstack/react-query'
import { APIError } from '../api'
import type { AuditEntry, AuditPage } from '../api'
import { formatDateTime } from '../format'

/**
 * The server's explanation of a filter it refused, such as an action prefix
 * with characters that no action has, or nothing for another failure.
 */
function refusedFilter(error: unknown) {
  if (!(error instanceof APIError) || error.code !== 'validation_failed') return ''
  const details = Object.values(error.details ?? {}).filter((value): value is string => typeof value === 'string' && value !== '')
  return details.length ? details.join(' ') : error.message
}

const actorScopes: Record<string, { label: string; tone: string }> = {
  unit: { label: 'Unit', tone: 'blue' },
  platform: { label: 'Platform', tone: 'amber' },
  host: { label: 'Host', tone: 'gray' },
  system: { label: 'System', tone: 'gray' },
}

/**
 * A read-only audit list, newest first, with keyset pagination. Each "Load
 * older" request passes the previous page's next_before, so entries written
 * while the list is open never shift or repeat the entries already shown.
 */
export function AuditLog({ queryKey, load, showUnit = false, emptyMessage = 'No audit entries match.' }: { queryKey: readonly unknown[]; load: (before: number | null) => Promise<AuditPage>; showUnit?: boolean; emptyMessage?: string }) {
  const audit = useInfiniteQuery({
    queryKey,
    queryFn: ({ pageParam }) => load(pageParam),
    initialPageParam: null as number | null,
    getNextPageParam: last => last.next_before ?? undefined,
  })
  if (audit.isLoading) return <div className="loading"><span className="spinner" />Loading the audit log…</div>
  if (!audit.data) {
    // A refused filter fails the same way again, so it is explained instead
    // of offered for a retry.
    const refused = refusedFilter(audit.error)
    if (refused) return <div className="error-card" role="alert">The audit log could not be filtered: {refused}</div>
    return <div className="error-card" role="alert">Could not load the audit log. <button type="button" className="button ghost" onClick={() => void audit.refetch()}>Retry</button></div>
  }
  const entries = audit.data.pages.flatMap(page => page.entries)
  return <div className="panel audit-panel">
    {entries.length ? <ol className="audit-list" aria-label="Audit entries">{entries.map(entry => <AuditRow key={entry.id} entry={entry} showUnit={showUnit} />)}</ol> : <div className="inline-empty">{emptyMessage}</div>}
    {audit.isFetchNextPageError && <div className="form-error" role="alert">Could not load older entries. Try again.</div>}
    {audit.hasNextPage
      ? <div className="audit-more"><button type="button" className="button secondary" disabled={audit.isFetchingNextPage} onClick={() => void audit.fetchNextPage()}>{audit.isFetchingNextPage ? 'Loading…' : 'Load older'}</button></div>
      : entries.length ? <p className="muted audit-end">No older entries.</p> : null}
  </div>
}

function AuditRow({ entry, showUnit }: { entry: AuditEntry; showUnit: boolean }) {
  const scope = actorScopes[entry.actor.kind] ?? { label: 'Account', tone: 'gray' }
  const actor = entry.actor.display_name || entry.actor.username || (entry.actor.kind === 'host' ? 'Host command line' : 'EdgeWatch')
  return <li className="audit-row">
    <time dateTime={entry.created_at}>{formatDateTime(entry.created_at)}</time>
    <div className="audit-main"><code>{entry.action}</code><p>{entry.detail}</p>{entry.source_ip && <small>From {entry.source_ip}</small>}</div>
    <div className="audit-actor"><span className={`pill ${scope.tone}`} title={`${scope.label} actor`}>{scope.label}</span><span className="audit-actor-name">{actor}{entry.actor.username && entry.actor.display_name && entry.actor.display_name !== entry.actor.username ? <small> · {entry.actor.username}</small> : null}</span>{showUnit && <small className="audit-unit">{entry.unit ? entry.unit.name || 'Unknown unit' : 'Platform'}</small>}</div>
  </li>
}
