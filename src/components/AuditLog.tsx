import { useInfiniteQuery } from '@tanstack/react-query'
import type { AuditActorKind, AuditEntry, AuditPage } from '../api'
import { formatDateTime } from '../format'

const actorScopes: Record<AuditActorKind, { label: string; tone: string }> = {
  unit: { label: 'Unit', tone: 'blue' },
  platform: { label: 'Platform', tone: 'amber' },
  host: { label: 'Host', tone: 'gray' },
}

/**
 * A read-only, newest-first audit list with keyset pagination. Each "Load
 * older" request passes the previous page's next_before, so rows written while
 * the list is open never shift or repeat the rows already shown.
 */
export function AuditLog({ queryKey, load, showUnit = false, emptyMessage = 'No audit entries match.' }: { queryKey: readonly unknown[]; load: (before: number | null) => Promise<AuditPage>; showUnit?: boolean; emptyMessage?: string }) {
  const audit = useInfiniteQuery({
    queryKey,
    queryFn: ({ pageParam }) => load(pageParam),
    initialPageParam: null as number | null,
    getNextPageParam: last => last.next_before ?? undefined,
  })
  if (audit.isLoading) return <div className="loading"><span className="spinner" />Loading audit log…</div>
  if (!audit.data) return <div className="error-card" role="alert">Could not load the audit log. <button type="button" className="button ghost" onClick={() => void audit.refetch()}>Retry</button></div>
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
  const scope = actorScopes[entry.actor.kind] ?? { label: entry.actor.kind, tone: 'gray' }
  const actor = entry.actor.display_name || entry.actor.username || (entry.actor.kind === 'host' ? 'Host command line' : 'EdgeWatch')
  return <li className="audit-row">
    <time dateTime={entry.at}>{formatDateTime(entry.at)}</time>
    <div className="audit-main"><code>{entry.action}</code><p>{entry.detail}</p>{entry.target && entry.target !== entry.actor.username && <small>Target: {entry.target}</small>}</div>
    <div className="audit-actor"><span className={`pill ${scope.tone}`} title={`${scope.label} actor`}>{scope.label}</span><span className="audit-actor-name">{actor}{entry.actor.username && entry.actor.display_name ? <small> · {entry.actor.username}</small> : null}</span>{showUnit && <small className="audit-unit">{entry.unit ? entry.unit.name : 'No unit (platform)'}</small>}</div>
  </li>
}
