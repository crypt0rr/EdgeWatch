import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { ClipboardList, ExternalLink, X } from 'lucide-react'
import { useSearchParams } from 'react-router-dom'
import { APIError, acceptIncident, getSession, listIncidents, listJobs, suppressIncident, updateIncidentReview, type IncidentInboxQuery, type IncidentInboxView, type IncidentReviewUpdate } from '../api'
import type { Change, IncidentInboxItem, IncidentReview } from '../generated/api-types'
import type { Job } from '../types'
import { ActionDialog } from '../components/ActionDialog'
import { ErrorNotice } from '../components/ErrorNotice'
import { Pagination } from '../components/Pagination'
import { formatDateTime } from '../format'
import { useServerDraft, type ServerDraftSnapshot } from '../hooks/useServerDraft'
import { incidentDateTimeCandidates, incidentDateTimeInput, incidentTimeOffset, incidentTimeZone } from '../incident-time'
import { changeKindLabel, changeTargetLabel, severityLabel, severityTone } from '../status'

const pageSize = 20
const maxNoteBytes = 4096
const maxFollowUpMs = 30 * 24 * 60 * 60 * 1000
const views: { value: IncidentInboxView; label: string }[] = [
  { value: 'needs_review', label: 'Needs review' },
  { value: 'investigating', label: 'Investigating' },
  { value: 'follow_up_due', label: 'Follow-up due' },
  { value: 'all_active', label: 'All active' },
]
const severities = ['critical', 'warning', 'info'] as const
const kinds = ['port', 'port-address', 'service', 'host', 'dns-added', 'dns-removed'] as const
type ConflictRefresh = { token: string; status: 'loading' | 'found' | 'missing' | 'error'; expectedRevision: number | null; pageQueryID: string; pageDataUpdatedAt: number }
type ReviewDraft = { rebasedToRevision?: number; status: IncidentReviewUpdate['status']; note: string; dueLocal: string; ambiguousChoice: string }
type ReviewDraftSnapshot = ServerDraftSnapshot<ReviewDraft, number>
const statusLabels: Record<string, string> = {
  needs_review: 'Needs review',
  investigating: 'Investigating',
  follow_up_due: 'Follow-up due',
}
const kindLabels: Record<string, string> = {
  port: 'Port',
  'port-address': 'Port on address',
  service: 'Service',
  host: 'Host',
  'dns-added': 'DNS added',
  'dns-removed': 'DNS removed',
}
const uncertaintyReasons: Record<string, string> = {
  legacy_origin_unknown: 'This legacy incident has no reliable opening scan or time.',
  no_newer_observation: 'No newer observation is available to assess this incident.',
  latest_scan_unclassifiable: 'The latest observation does not contain enough evidence to assess this incident.',
  latest_scan_does_not_establish_recovery: 'The latest comparable scan does not establish that this incident has recovered.',
  latest_scan_failed: 'The newer scan failed, so it cannot establish whether this incident has recovered.',
  latest_scan_incomplete: 'The latest scan was incomplete.',
  latest_scan_not_compared: 'The latest scan was not compared with the baseline.',
  target_resolution_failed: 'The target could not be resolved in the latest scan.',
  target_observation_incomplete: 'The latest scan could not fully observe the relevant target. It may have timed out, been unreachable, or received an explicit network rejection; the finding remains unconfirmed.',
  target_host_down: 'The latest scan reported the relevant host as down or unreachable; its port or service state remains unconfirmed.',
  target_unobserved: 'The relevant target was not observed in the latest scan coverage.',
  protocol_unobserved: 'The relevant protocol was not observed in the latest scan coverage.',
}

function validView(value: string | null): value is IncidentInboxView {
  return views.some(item => item.value === value)
}
function validSeverity(value: string | null): value is NonNullable<IncidentInboxQuery['severity']> {
  return severities.some(item => item === value)
}
function validKind(value: string | null): value is NonNullable<IncidentInboxQuery['kind']> {
  return kinds.some(item => item === value)
}
function parseOffset(value: string | null) {
  if (!value || !/^\d+$/.test(value)) return 0
  const parsed = Number(value)
  if (!Number.isSafeInteger(parsed) || parsed < 0) return 0
  return Math.floor(parsed / pageSize) * pageSize
}
function normalizeSearch(search: URLSearchParams) {
  const next = new URLSearchParams()
  const view = search.get('view')
  const jobID = search.get('job_id')?.trim() ?? ''
  const severity = search.get('severity')
  const kind = search.get('kind')
  const occurrence = search.get('occurrence') ?? ''
  const lookupOccurrence = search.get('lookup_occurrence') ?? ''
  next.set('view', validView(view) ? view : 'needs_review')
  if (jobID && jobID.length <= 128) next.set('job_id', jobID)
  if (validSeverity(severity)) next.set('severity', severity)
  if (validKind(kind)) next.set('kind', kind)
  next.set('offset', String(parseOffset(search.get('offset'))))
  if (occurrence && occurrence.length <= 256) next.set('occurrence', occurrence)
  if (validView(view) && view === 'all_active' && jobID && jobID.length <= 128 && lookupOccurrence && lookupOccurrence.length <= 256) {
    next.set('lookup_occurrence', lookupOccurrence)
    next.set('offset', '0')
  }
  return next
}
function currentOffsetSearch(search: URLSearchParams, offset: number) {
  const next = new URLSearchParams(search)
  next.set('offset', String(offset))
  next.delete('occurrence')
  next.delete('lookup_occurrence')
  return next
}
function currentFilterSearch(search: URLSearchParams, name: string, value: string) {
  const next = new URLSearchParams(search)
  if (value) next.set(name, value)
  else next.delete(name)
  next.set('offset', '0')
  next.delete('occurrence')
  next.delete('lookup_occurrence')
  return next
}
function formatChange(change: Change) {
  return `${changeKindLabel(change.kind, change.old, change.new)}${change.port ? ` / ${change.protocol}:${change.port}` : ''}`
}
function changeValues(change: Change) {
  if (change.old || change.new) return `${change.old ?? '—'} → ${change.new ?? '—'}`
  return 'No before/after value recorded'
}
function safeTime(value: string | undefined) {
  if (!value || !Number.isFinite(Date.parse(value))) return 'Unknown'
  return formatDateTime(value)
}
function followUpTime(value: string) {
  const instant = Date.parse(value)
  if (!Number.isFinite(instant)) return 'Unknown'
  return `${formatDateTime(value)} (${incidentTimeZone()}) · UTC ${new Date(instant).toISOString()}`
}
function titleCase(value: string) {
  return value.replace(/[_-]+/g, ' ').replace(/\s+/g, ' ').replace(/^\w/, letter => letter.toUpperCase())
}
function openingTime(item: IncidentInboxItem) {
  return item.opening_time_known ? safeTime(item.incident.opened_at) : 'Unknown opening time'
}
function rowKey(item: IncidentInboxItem) {
  return item.occurrence_token
}
function reviewViewStatus(review: IncidentReview) {
  if (review.status === 'needs_review') return 'needs_review'
  if (review.follow_up_at && Date.parse(review.follow_up_at) <= Date.now()) return 'follow_up_due'
  return 'investigating'
}
function openEvidencePath(path: string, label: string) {
  return <a className="incident-evidence-link" href={path} target="_blank" rel="noopener noreferrer">{label} <span>(opens in new tab)</span><ExternalLink size={13} aria-hidden="true" /></a>
}
function isAddress(value: string) {
  return value.includes(':') || /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)
}

function Empty({ icon, title, body }: { icon: ReactNode; title: string; body: string }) {
  return <div className="empty"><div className="empty-icon">{icon}</div><h3>{title}</h3><p>{body}</p></div>
}

export function Incidents() {
  const [search, setSearch] = useSearchParams()
  const viewParam = search.get('view')
  const view: IncidentInboxView = validView(viewParam) ? viewParam : 'needs_review'
  const jobID = search.get('job_id')?.trim() ?? ''
  const severityParam = search.get('severity')
  const severity = validSeverity(severityParam) ? severityParam : ''
  const kindParam = search.get('kind')
  const kind = validKind(kindParam) ? kindParam : ''
  const offset = parseOffset(search.get('offset'))
  const selectedOccurrence = search.get('occurrence') ?? ''
  const lookupOccurrenceParam = search.get('lookup_occurrence') ?? ''
  const timezone = incidentTimeZone()
  const [pendingAction, setPendingAction] = useState<{ row: IncidentInboxItem; action: 'accept' | 'suppress' } | null>(null)
  const [selectedSnapshot, setSelectedSnapshot] = useState<IncidentInboxItem | null>(null)
  const [conflictRefreshes, setConflictRefreshes] = useState<Record<string, ConflictRefresh>>({})
  const [reviewDrafts, setReviewDrafts] = useState<Record<string, ReviewDraftSnapshot>>({})
  const conflictLookupGenerationRef = useRef<Record<string, number>>({})
  const [actionError, setActionError] = useState('')
  const actionErrorRef = useRef<HTMLDivElement>(null)
  const evidencePanelRef = useRef<HTMLElement>(null)
  const inboxHeadingRef = useRef<HTMLHeadingElement>(null)
  const evidenceOpenerRef = useRef<HTMLButtonElement | null>(null)
  const restoreEvidenceFocusRef = useRef(false)
  const lastFocusedOccurrenceRef = useRef('')
  const selectedTokenRef = useRef(selectedOccurrence)
  selectedTokenRef.current = selectedOccurrence
  const client = useQueryClient()
  const session = useQuery({ queryKey: ['session'], queryFn: getSession })
  const canRead = session.data?.permissions.includes('incidents.read') ?? false
  const canManage = session.data?.permissions.includes('incidents.manage') ?? false
  const jobs = useQuery({ queryKey: ['jobs', true], queryFn: () => listJobs(true), enabled: canRead })
  const exactLookup = lookupOccurrenceParam && jobID && view === 'all_active' ? lookupOccurrenceParam : ''
  const filters: IncidentInboxQuery = { view, limit: exactLookup ? 1 : pageSize, offset: exactLookup ? 0 : offset, ...(jobID ? { job_id: jobID } : {}), ...(exactLookup ? { occurrence_token: exactLookup } : {}), ...(severity ? { severity } : {}), ...(kind ? { kind } : {}) }
  const pageQueryKey = ['incidents', 'inbox', view, jobID, exactLookup, severity, kind, offset] as const
  const pageQueryID = JSON.stringify(pageQueryKey)
  const incidents = useQuery({
    queryKey: pageQueryKey,
    queryFn: () => listIncidents(filters),
    enabled: canRead,
  })
  const rows = incidents.data?.incidents ?? []
  const selectedRow = rows.find(row => row.occurrence_token === selectedOccurrence)
  const conflictRefresh = conflictRefreshes[selectedOccurrence] ?? null
  const hasConflictRefresh = !!conflictRefresh
  const refreshedSnapshot = conflictRefresh?.status === 'found' && selectedSnapshot?.occurrence_token === selectedOccurrence ? selectedSnapshot : undefined
  const staleSelectedRow = !!refreshedSnapshot && !!selectedRow && refreshedSnapshot.review.revision !== selectedRow.review.revision
  const evidenceItem = refreshedSnapshot ?? selectedRow ?? (selectedSnapshot?.occurrence_token === selectedOccurrence ? selectedSnapshot : undefined)
  const selectionOutOfResults = !!selectedOccurrence && incidents.isSuccess && (!selectedRow || staleSelectedRow)
  const activeCount = incidents.data?.active_count ?? incidents.data?.pagination.total ?? 0
  const selectedJobUnavailable = !!jobID && !!jobs.data && !jobs.data.jobs.some(job => job.id === jobID)

  const lookupOccurrence = useCallback(async (token: string, selectedJobID: string, expectedRevision: number | null) => {
    const generation = (conflictLookupGenerationRef.current[token] ?? 0) + 1
    conflictLookupGenerationRef.current[token] = generation
    const pageQueryID = JSON.stringify(['incidents', 'inbox', view, jobID, exactLookup, severity, kind, offset])
    const pageDataUpdatedAt = incidents.dataUpdatedAt
    setConflictRefreshes(current => ({ ...current, [token]: { token, status: 'loading', expectedRevision, pageQueryID, pageDataUpdatedAt } }))
    try {
      const result = await listIncidents({ view: 'all_active', job_id: selectedJobID, occurrence_token: token, limit: 1, offset: 0 })
      if (conflictLookupGenerationRef.current[token] !== generation) return
      const current = result.incidents.find(row => row.occurrence_token === token)
      if (current && selectedTokenRef.current === token) setSelectedSnapshot(current)
      setConflictRefreshes(refreshes => ({ ...refreshes, [token]: { token, status: current ? 'found' : 'missing', expectedRevision, pageQueryID, pageDataUpdatedAt } }))
    } catch {
      if (conflictLookupGenerationRef.current[token] !== generation) return
      setConflictRefreshes(refreshes => ({ ...refreshes, [token]: { token, status: 'error', expectedRevision, pageQueryID, pageDataUpdatedAt } }))
    }
  }, [incidents.dataUpdatedAt, view, jobID, exactLookup, severity, kind, offset])

  useEffect(() => {
    const normalized = normalizeSearch(search)
    if (normalized.toString() !== search.toString()) setSearch(normalized, { replace: true })
  }, [search, setSearch])
  useEffect(() => {
    if (selectedRow) setSelectedSnapshot(selectedRow)
  }, [selectedRow])
  useEffect(() => {
    const token = selectedOccurrence
    if (!token || !selectedSnapshot || selectedSnapshot.occurrence_token !== token || selectedRow || !incidents.isSuccess || incidents.isFetching) return
    if (conflictRefresh?.pageQueryID === pageQueryID && conflictRefresh.pageDataUpdatedAt === incidents.dataUpdatedAt) return
    void lookupOccurrence(token, selectedSnapshot.job_id, conflictRefresh?.expectedRevision ?? null)
  }, [selectedOccurrence, selectedSnapshot?.occurrence_token, selectedSnapshot?.job_id, selectedRow, incidents.isSuccess, incidents.isFetching, incidents.dataUpdatedAt, pageQueryID, conflictRefresh?.pageQueryID, conflictRefresh?.pageDataUpdatedAt, conflictRefresh?.expectedRevision, lookupOccurrence])
  useEffect(() => {
    if (selectedOccurrence && selectedRow) {
      if (lastFocusedOccurrenceRef.current !== selectedOccurrence) {
        lastFocusedOccurrenceRef.current = selectedOccurrence
        if (!evidencePanelRef.current?.contains(document.activeElement)) evidencePanelRef.current?.focus()
      }
    } else if (!selectedOccurrence && restoreEvidenceFocusRef.current) {
      lastFocusedOccurrenceRef.current = ''
      restoreEvidenceFocusRef.current = false
      if (evidenceOpenerRef.current?.isConnected) evidenceOpenerRef.current.focus()
      else inboxHeadingRef.current?.focus()
    } else if (!selectedOccurrence) {
      lastFocusedOccurrenceRef.current = ''
    }
  }, [selectedOccurrence, selectedRow])
  useEffect(() => {
    if (!actionError || pendingAction) return
    const alert = actionErrorRef.current
    if (!alert) return
    alert.scrollIntoView?.({ block: 'nearest' })
    alert.focus({ preventScroll: true })
  }, [actionError, pendingAction])
  useEffect(() => {
    const page = incidents.data?.pagination
    if (!page || incidents.isFetching || rows.length || !page.total || offset === 0) return
    const lastPage = Math.floor((page.total - 1) / page.limit) * page.limit
    setSearch(currentOffsetSearch(search, Math.max(0, Math.min(lastPage, offset - page.limit))), { replace: true })
  }, [incidents.data, incidents.isFetching, offset, rows.length, search, setSearch])

  function changeFilter(name: string, value: string) {
    setActionError('')
    setSearch(currentFilterSearch(search, name, value))
  }
  function selectOccurrence(item: IncidentInboxItem, trigger: HTMLButtonElement) {
    evidenceOpenerRef.current = trigger
    setSelectedSnapshot(item)
    const next = new URLSearchParams(search)
    next.set('occurrence', item.occurrence_token)
    setSearch(next)
  }
  function closeEvidence() {
    restoreEvidenceFocusRef.current = true
    setSelectedSnapshot(null)
    const next = new URLSearchParams(search)
    next.delete('occurrence')
    setSearch(next)
  }
  function changePage(nextOffset: number) {
    setSearch(currentOffsetSearch(search, nextOffset))
  }
  function clearConflict(token: string) {
    conflictLookupGenerationRef.current[token] = (conflictLookupGenerationRef.current[token] ?? 0) + 1
    setConflictRefreshes(current => {
      if (!(token in current)) return current
      const next = { ...current }
      delete next[token]
      return next
    })
  }
  function updateReviewDraft(token: string, draft: ReviewDraftSnapshot | null) {
    setReviewDrafts(current => {
      if (!draft) {
        if (!(token in current)) return current
        const next = { ...current }
        delete next[token]
        return next
      }
      return { ...current, [token]: draft }
    })
  }
  function showRefreshedOccurrence(item: IncidentInboxItem) {
    const next = new URLSearchParams(search)
    next.set('view', 'all_active')
    next.set('job_id', item.job_id)
    next.set('lookup_occurrence', item.occurrence_token)
    next.set('occurrence', item.occurrence_token)
    next.set('offset', '0')
    next.delete('severity')
    next.delete('kind')
    setSearch(next)
  }
  async function act(row: IncidentInboxItem, action: 'accept' | 'suppress') {
    const key = row.incident.change.key
    if (!key) {
      setActionError('This legacy incident has no actionable key. Run a newer scan before changing it.')
      setPendingAction(null)
      return
    }
    setActionError('')
    try {
      if (action === 'accept') await acceptIncident(row.job_id, key, row.incident.change)
      else await suppressIncident(row.job_id, key, row.incident.change)
      setPendingAction(null)
      await client.invalidateQueries({ queryKey: ['incidents'] })
      await client.invalidateQueries({ queryKey: ['job', row.job_id] })
      if (action === 'accept') {
        await client.invalidateQueries({ queryKey: ['baseline-hosts', row.job_id] })
        await client.invalidateQueries({ queryKey: ['host-detail'] })
      }
    } catch (error) {
      setPendingAction(null)
      await client.invalidateQueries({ queryKey: ['incidents'] })
      await client.invalidateQueries({ queryKey: ['job', row.job_id] })
      if (error instanceof APIError && (error.code === 'incident_conflict' || error.code === 'incident_not_found')) {
        setActionError(error.code === 'incident_not_found'
          ? 'This incident is no longer active. The incident list was refreshed.'
          : 'This incident changed while it was open. The incident list was refreshed; review the new evidence before retrying.')
      } else {
        setActionError(error instanceof Error ? error.message : 'The incident action could not be completed.')
      }
    }
  }
  const actionFor = (row: IncidentInboxItem, action: 'accept' | 'suppress') => {
    setActionError('')
    setPendingAction({ row, action })
  }

  return <section className="page incident-inbox-page">
    <div className="page-heading incident-inbox-heading">
      <div><p className="eyebrow">Change tracking</p><h1 ref={inboxHeadingRef} tabIndex={-1}>Investigation inbox</h1><p className="muted">Review confirmed changes, share investigation notes, and set follow-up times.</p></div>
      <div className="incident-inbox-active-count"><strong>{activeCount}</strong><span>active incident{activeCount === 1 ? '' : 's'} across all views</span></div>
    </div>

    {actionError && !pendingAction && <div ref={actionErrorRef} className="form-error banner" role="alert" tabIndex={-1}>{actionError}</div>}
    {session.isError ? <ErrorNotice message="Could not read your incident permissions." onRetry={() => session.refetch()} /> : !session.isSuccess ? <div className="skeleton-list" aria-label="Loading session" /> : !canRead ? <Empty icon={<ClipboardList />} title="Incident access required" body="Your account does not have permission to read incidents." /> : <>
      <div className="incident-inbox-filters" role="group" aria-label="Filter investigation inbox">
        <label>View<select aria-label="Filter by review view" value={view} onChange={event => changeFilter('view', event.target.value)}>
          {views.map(option => <option key={option.value} value={option.value}>{option.label}</option>)}
        </select></label>
        <label>Job<select aria-label="Filter by job" value={jobID} onChange={event => changeFilter('job_id', event.target.value)}>
          <option value="">All jobs</option>
          {selectedJobUnavailable && <option value={jobID}>Unavailable or inaccessible job</option>}
          {jobs.data?.jobs.map((job: Job) => <option key={job.id} value={job.id}>{job.job.name}{job.archived ? ' (archived)' : ''}</option>)}
        </select></label>
        <label>Severity<select aria-label="Filter by severity" value={severity} onChange={event => changeFilter('severity', event.target.value)}>
          <option value="">All severities</option>
          {severities.map(value => <option key={value} value={value}>{severityLabel(value)}</option>)}
        </select></label>
        <label>Change kind<select aria-label="Filter by change kind" value={kind} onChange={event => changeFilter('kind', event.target.value)}>
          <option value="">All change kinds</option>
          {kinds.map(value => <option key={value} value={value}>{kindLabels[value]}</option>)}
        </select></label>
      </div>
      {jobs.error && <ErrorNotice message="Could not load job filters. You can still filter by view, severity, and change kind." onRetry={() => jobs.refetch()} />}
      {incidents.isLoading ? <div className="skeleton-list" aria-label="Loading incidents" /> : incidents.error ? <ErrorNotice message="Could not load investigation inbox items." onRetry={() => incidents.refetch()} /> : <>
        {incidents.data?.truncated && <p className="notice" role="status">The server limited this result. Narrow the filters to review the matching incidents.</p>}
        <p className="incident-inbox-result-count">{incidents.data?.pagination.total ?? 0} matching incident{incidents.data?.pagination.total === 1 ? '' : 's'} · sorted by severity, opening time, then stable tie-breakers</p>
    {exactLookup && <p className="notice" role="status">Showing the exact refreshed occurrence for {selectedJobUnavailable ? 'the selected job' : jobs.data?.jobs.find(job => job.id === jobID)?.job.name ?? 'the selected job'}.</p>}
    <div className={`incident-inbox-layout${selectedOccurrence ? ' has-selection' : ''}`}>
          <div className="incident-inbox-results">
            {rows.length ? <>
              <div className="table-card inbox-table-card">
                <div className="inbox-desktop-table"><table>
                  <thead><tr><th scope="col">Review state</th><th scope="col">Severity</th><th scope="col">Job</th><th scope="col">Target</th><th scope="col">Change</th><th scope="col">Opened</th><th scope="col">Evidence</th></tr></thead>
                  <tbody>{rows.map(item => <IncidentTableRow key={rowKey(item)} item={item} selected={selectedOccurrence === item.occurrence_token} onOpen={selectOccurrence} />)}</tbody>
                </table></div>
                <div className="inbox-mobile-list" aria-label="Active incidents">{rows.map(item => <IncidentCard key={rowKey(item)} item={item} selected={selectedOccurrence === item.occurrence_token} onOpen={selectOccurrence} />)}</div>
              </div>
              <Pagination page={incidents.data?.pagination} onChange={changePage} label="Investigation inbox pagination" />
            </> : incidents.data?.pagination.total ? <><div className="inline-empty">No incidents on this page.</div><Pagination page={incidents.data.pagination} onChange={changePage} label="Investigation inbox pagination" /></> : <Empty icon={<ClipboardList />} title="No matching incidents" body={view === 'needs_review' ? 'New confirmed changes will appear here for review.' : 'Change the view or filters to see other active incidents.'} />}
          </div>
          {selectedOccurrence && <aside ref={evidencePanelRef} className="incident-evidence-panel" tabIndex={-1} aria-labelledby="incident-evidence-title">
            <div className="incident-evidence-heading"><div><p className="eyebrow">Selected occurrence</p><h2 id="incident-evidence-title">Evidence and review</h2></div><button className="icon-button" type="button" aria-label="Close evidence panel" onClick={closeEvidence}><X size={18} aria-hidden="true" /></button></div>
            {evidenceItem ? <>
              {hasConflictRefresh && conflictRefresh.status === 'loading' && <p className="incident-context-notice" role="status">Checking this exact occurrence in the active job while keeping your draft.</p>}
              {selectionOutOfResults && hasConflictRefresh && conflictRefresh.status === 'found' && <div className="incident-context-notice" role="status"><p>This occurrence is active, but it no longer matches the current view or page. Your draft is kept here.</p><button className="button secondary" type="button" onClick={() => showRefreshedOccurrence(evidenceItem)}>Show refreshed occurrence</button></div>}
              {hasConflictRefresh && conflictRefresh.status === 'missing' && <p className="incident-context-notice" role="status">This occurrence is no longer active. Your draft is kept for reference, but it cannot be saved because the active occurrence has changed or closed.</p>}
              {hasConflictRefresh && conflictRefresh.status === 'error' && <div className="incident-context-notice" role="status"><p>Could not verify the latest active occurrence. Your draft is kept, and saving is disabled until the exact lookup succeeds.</p><button className="button secondary" type="button" onClick={() => evidenceItem && void lookupOccurrence(evidenceItem.occurrence_token, evidenceItem.job_id, conflictRefresh.expectedRevision)}>Retry exact occurrence check</button></div>}
              {selectionOutOfResults && !hasConflictRefresh && <p className="incident-context-notice" role="status">This incident is no longer in the selected view or page. Its evidence stays open here; close the panel to keep your filters and page, or use All active to locate it again.</p>}
              <EvidencePanel item={evidenceItem} canManage={canManage} readOnly={selectionOutOfResults || (!!conflictRefresh && conflictRefresh.status !== 'found')} draft={reviewDrafts[evidenceItem.occurrence_token]} onDraftChange={updateReviewDraft} conflictRefresh={conflictRefresh} onConflictCheck={lookupOccurrence} onClearConflict={clearConflict} onAction={actionFor} onSaved={review => setSelectedSnapshot(current => current?.occurrence_token === evidenceItem.occurrence_token ? { ...current, review, view_status: reviewViewStatus(review) } : current)} />
            </> : <div className="inline-empty" role="status">This occurrence is not available in the selected view or page. Close the panel or use All active to locate it again.</div>}
          </aside>}
        </div>
      </>}
    </>}
    {pendingAction && <ActionDialog title={pendingAction.action === 'accept' ? 'Accept this change?' : 'Suppress this incident for one scan?'} description={pendingAction.action === 'accept' ? `Accept this change into the baseline for “${pendingAction.row.job}”? Future scans will treat it as expected.` : 'The incident will be suppressed for the next successful scan. If it is still present after that scan, it will be reported again.'} confirmLabel={pendingAction.action === 'accept' ? 'Accept change' : 'Suppress 1 scan'} destructive={pendingAction.action === 'suppress'} onConfirm={() => act(pendingAction.row, pendingAction.action)} onCancel={() => { setPendingAction(null); setActionError('') }} error={actionError} />}
  </section>
}

function IncidentTableRow({ item, selected, onOpen }: { item: IncidentInboxItem; selected: boolean; onOpen: (item: IncidentInboxItem, trigger: HTMLButtonElement) => void }) {
  const change = item.incident.change
  return <tr className={selected ? 'selected' : undefined}>
    <td><span className={`pill ${item.view_status === 'follow_up_due' ? 'red' : item.view_status === 'investigating' ? 'blue' : 'amber'}`}>{statusLabels[item.view_status] ?? titleCase(item.view_status)}</span></td>
    <td><span className={`pill ${severityTone(change.severity)}`}>{severityLabel(change.severity)}</span></td>
    <td><strong>{item.job}</strong></td>
    <td>{changeTargetLabel(change)}</td>
    <td><strong>{formatChange(change)}</strong><br /><span className="muted">{changeValues(change)}</span></td>
    <td>{openingTime(item)}</td>
    <td><button className="button ghost" type="button" aria-expanded={selected} onClick={event => onOpen(item, event.currentTarget)}>Review evidence</button></td>
  </tr>
}

function IncidentCard({ item, selected, onOpen }: { item: IncidentInboxItem; selected: boolean; onOpen: (item: IncidentInboxItem, trigger: HTMLButtonElement) => void }) {
  const change = item.incident.change
  return <article className={`inbox-incident-card${selected ? ' selected' : ''}`} aria-label={`Incident for ${item.job}`}>
    <div className="inbox-card-heading"><strong>{item.job}</strong><span className={`pill ${severityTone(change.severity)}`}>{severityLabel(change.severity)}</span></div>
    <span className={`pill ${item.view_status === 'follow_up_due' ? 'red' : item.view_status === 'investigating' ? 'blue' : 'amber'}`}>{statusLabels[item.view_status] ?? titleCase(item.view_status)}</span>
    <dl className="incident-facts"><div><dt>Target</dt><dd>{changeTargetLabel(change)}</dd></div><div><dt>Change</dt><dd><strong>{formatChange(change)}</strong><br /><span className="muted">{changeValues(change)}</span></dd></div><div><dt>Opened</dt><dd>{openingTime(item)}</dd></div></dl>
    <button className="button secondary" type="button" aria-expanded={selected} onClick={event => onOpen(item, event.currentTarget)}>Review evidence</button>
  </article>
}

function EvidencePanel({ item, canManage, readOnly, draft, onDraftChange, conflictRefresh, onConflictCheck, onClearConflict, onAction, onSaved }: { item: IncidentInboxItem; canManage: boolean; readOnly: boolean; draft?: ReviewDraftSnapshot; onDraftChange: (token: string, draft: ReviewDraftSnapshot | null) => void; conflictRefresh: ConflictRefresh | null; onConflictCheck: (token: string, jobID: string, expectedRevision: number | null) => Promise<void>; onClearConflict: (token: string) => void; onAction: (item: IncidentInboxItem, action: 'accept' | 'suppress') => void; onSaved: (review: IncidentReview) => void }) {
  const change = item.incident.change
  const sourceScan = item.incident.scan_id
  const sourceScanAvailable = !!sourceScan && item.opening_scan_available
  const base = `/jobs/${encodeURIComponent(item.job_id)}`
  const address = change.address || (isAddress(change.target) ? change.target : '')
  const uncertainty = item.observation_uncertainty
  const uncertaintyText = uncertaintyReasons[uncertainty.reason ?? ''] ?? (uncertainty.status === 'unknown'
    ? 'Current observation is unknown. This does not show that the incident has recovered.'
    : `The current observation is ${titleCase(uncertainty.status)}; it does not confirm recovery.`)
  return <>
    <section className="incident-evidence-section" aria-labelledby="evidence-change-title">
      <div className="incident-evidence-status"><span className={`pill ${item.view_status === 'follow_up_due' ? 'red' : item.view_status === 'investigating' ? 'blue' : 'amber'}`}>{statusLabels[item.view_status] ?? titleCase(item.view_status)}</span><span className={`pill ${severityTone(change.severity)}`}>{severityLabel(change.severity)}</span></div>
      <h3 id="evidence-change-title">{item.job} · {changeTargetLabel(change)}</h3>
      <p><strong>{formatChange(change)}</strong><br /><span className="muted">{changeValues(change)}</span></p>
      <dl className="incident-evidence-facts">
        <div><dt>Opening time</dt><dd>{openingTime(item)}</dd></div>
        <div><dt>Last seen</dt><dd>{safeTime(item.incident.last_seen_at)}</dd></div>
        <div><dt>Recovery observations</dt><dd>{item.incident.recovery_count}</dd></div>
        {item.review.reviewer_label && <div><dt>Last reviewer</dt><dd>{item.review.reviewer_label}</dd></div>}
        {item.review.reviewed_at && <div><dt>Last reviewed</dt><dd>{safeTime(item.review.reviewed_at)}</dd></div>}
        {item.review.follow_up_at && <div><dt>Follow-up time</dt><dd>{followUpTime(item.review.follow_up_at)}</dd></div>}
      </dl>
      <div className={`incident-uncertainty uncertainty-${uncertainty.status}`} role="note"><strong>Observation uncertainty: {uncertainty.status === 'unknown' ? 'Unknown' : titleCase(uncertainty.status)}</strong><p>{uncertaintyText}</p>{uncertainty.observed_at && <p className="muted">Evidence observed {safeTime(uncertainty.observed_at)}{uncertainty.scan_id ? ` · scan ${uncertainty.scan_id}` : ''}</p>}{uncertainty.scan_status && <p className="muted">Latest scan status: {titleCase(uncertainty.scan_status)}</p>}{uncertainty.comparison && <p className="muted">Baseline comparison: {titleCase(uncertainty.comparison)}</p>}</div>
      <nav className="incident-evidence-links" aria-label="Incident evidence links">
        {openEvidencePath(base, 'Open job details')}
        {openEvidencePath(`${base}/baseline`, 'Open baseline evidence')}
        {sourceScanAvailable && openEvidencePath(`${base}/scans/${encodeURIComponent(sourceScan!)}`, 'Open source scan')}
        {sourceScanAvailable && address && openEvidencePath(`${base}/scans/${encodeURIComponent(sourceScan!)}/hosts/${encodeURIComponent(address)}`, `Open ${address} in source scan`)}
        {sourceScan && !item.opening_scan_available && <span className="incident-evidence-unavailable" role="status">Opening scan {sourceScan} is no longer available.</span>}
        {address && openEvidencePath(`${base}/baseline/hosts/${encodeURIComponent(address)}`, `Open ${address} in baseline`)}
      </nav>
      {item.review.note && <section className="incident-shared-note" aria-labelledby="current-review-note"><h3 id="current-review-note">Shared reviewer note</h3><p>{item.review.note}</p></section>}
    </section>
    {canManage ? <ReviewEditor key={item.occurrence_token} item={item} readOnly={readOnly} draft={draft} onDraftChange={onDraftChange} conflictRefresh={conflictRefresh} onConflictCheck={onConflictCheck} onClearConflict={onClearConflict} onSaved={onSaved} /> : <p className="muted">You can read this review. Saving review status, notes, or follow-up times requires incident management permission.</p>}
    {canManage && !readOnly && <div className="incident-resolution-actions"><p className="eyebrow">Baseline actions</p><p className="muted">Accepting or suppressing changes remains a separate decision from investigation status.</p><button className="button secondary" type="button" disabled={!change.key} onClick={() => onAction(item, 'accept')}>Accept change</button><button className="button ghost" type="button" disabled={!change.key} onClick={() => onAction(item, 'suppress')}>Suppress 1 scan</button>{!change.key && <p className="muted">This legacy incident has no actionable key. A newer scan is needed before accepting or suppressing it.</p>}</div>}
  </>
}

function ReviewEditor({ item, readOnly, draft: draftSnapshot, onDraftChange, conflictRefresh, onConflictCheck, onClearConflict, onSaved }: { item: IncidentInboxItem; readOnly: boolean; draft?: ReviewDraftSnapshot; onDraftChange: (token: string, draft: ReviewDraftSnapshot | null) => void; conflictRefresh: ConflictRefresh | null; onConflictCheck: (token: string, jobID: string, expectedRevision: number | null) => Promise<void>; onClearConflict: (token: string) => void; onSaved: (review: IncidentReview) => void }) {
  const client = useQueryClient()
  const timezone = incidentTimeZone()
  const initialDraft: ReviewDraft = {
    status: item.review.status === 'investigating' ? 'investigating' : 'needs_review',
    note: item.review.note,
    dueLocal: incidentDateTimeInput(item.review.follow_up_at, timezone),
    ambiguousChoice: '',
  }
  const { draft, setDraft, baseRevision, remoteChanged, hasDraft, rebase, discard, markSaved } = useServerDraft(
    initialDraft,
    item.review.revision,
    { controlled: { snapshot: draftSnapshot, onChange: snapshot => onDraftChange(item.occurrence_token, snapshot) } },
  )
  const { status, note, dueLocal, ambiguousChoice } = draft
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [saved, setSaved] = useState('')
  const bytes = new TextEncoder().encode(note).length
  const dueCandidates = dueLocal ? incidentDateTimeCandidates(dueLocal, timezone) : []
  const selectedDue = dueCandidates.length === 1 ? dueCandidates[0] : dueCandidates.includes(ambiguousChoice) ? ambiguousChoice : ''
  const tooFarAhead = !!selectedDue && Date.parse(selectedDue) > Date.now() + maxFollowUpMs
  const dueError = dueLocal && dueCandidates.length === 0
    ? `This local time does not exist in ${timezone} because the clock changes. Choose another time.`
    : dueCandidates.length > 1 && !selectedDue
      ? `This local time occurs twice in ${timezone}. Choose the displayed UTC offset.`
        : tooFarAhead
          ? 'Follow-up must be no more than 30 days ahead.'
          : ''
  const conflict = remoteChanged
  const draftBaseRevision = baseRevision
  const conflictRefreshed = conflictRefresh === null || (conflictRefresh.status === 'found' && (conflictRefresh.expectedRevision === null || item.review.revision !== conflictRefresh.expectedRevision))
  const canSave = !!item.incident.change.key && !readOnly && !saving && bytes <= maxNoteBytes && !dueError && conflictRefreshed
  const queryKey = ['incidents', 'inbox']

  function patchDraft(patch: Partial<ReviewDraft>) {
    setDraft(current => ({ ...current, ...patch }))
    setSaved('')
    setError('')
  }
  function rebaseDraft() {
    if (!hasDraft || !remoteChanged || readOnly || saving) return
    setDraft(current => ({ ...current, rebasedToRevision: item.review.revision }))
    rebase(item.review.revision)
    setError('')
    setSaved('')
  }
  async function resetDraft() {
    discard()
    setError('')
    setSaved('')
    onClearConflict(item.occurrence_token)
  }
  async function save(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!canSave) return
    const expectedRevision = baseRevision
    if (!hasDraft) setDraft(draft)
    const update: IncidentReviewUpdate = {
      key: item.incident.change.key,
      occurrence_token: item.occurrence_token,
      expected_revision: expectedRevision,
      status,
      note,
      follow_up_at: status === 'investigating' && selectedDue ? selectedDue : null,
    }
    setSaving(true)
    setError('')
    setSaved('')
    try {
      const savedReview = await updateIncidentReview(item.job_id, update)
      onSaved(savedReview)
      markSaved()
      onClearConflict(item.occurrence_token)
      setSaved('Review saved. Notes and follow-up times do not change notifications or reminders.')
      await client.invalidateQueries({ queryKey: ['incidents'] })
    } catch (cause) {
      if (cause instanceof APIError && (cause.code === 'incident_occurrence_conflict' || cause.code === 'incident_review_revision_conflict')) {
        setError(cause.code === 'incident_occurrence_conflict'
          ? 'This incident occurrence changed or closed while you were editing. The list was refreshed; your draft remains here if the occurrence is still available.'
          : 'Another reviewer saved an update first. The current review is refreshing; your draft remains here.')
        await onConflictCheck(item.occurrence_token, item.job_id, update.expected_revision)
        await client.invalidateQueries({ queryKey })
      } else if (cause instanceof APIError && cause.code === 'incident_review_invalid') {
        setError(cause.message || 'The review could not be saved. Check the note and follow-up time.')
      } else {
        setError(cause instanceof Error ? cause.message : 'The review could not be saved.')
      }
    } finally {
      setSaving(false)
    }
  }

  return <form className={`incident-review-form${readOnly ? ' read-only' : ''}`} onSubmit={save} aria-label={`Review ${item.job} incident`}>
    <div className="incident-review-form-heading"><h3>Shared investigation review</h3><span className="revision">Revision {item.review.revision}</span></div>
    {readOnly && <p className="incident-context-notice">Review fields are read-only because this occurrence is outside the current results.</p>}
    {conflict && <div className="incident-review-conflict" role="status"><strong>Latest saved review</strong><p>Status: {item.review.status === 'investigating' ? 'Investigating' : 'Needs review'} · Revision {item.review.revision}{item.review.reviewer_label ? ` · ${item.review.reviewer_label}` : ''}{item.review.reviewed_at ? ` · ${safeTime(item.review.reviewed_at)}` : ''}</p><p>Shared note:</p>{item.review.note ? <blockquote>{item.review.note}</blockquote> : <p>No saved note.</p>}<p>Follow-up: {item.review.follow_up_at ? followUpTime(item.review.follow_up_at) : 'None'}</p><p>Your draft remains based on revision {draftBaseRevision}. Rebase keeps your edits and changes the revision used when you save.</p><button className="button secondary" type="button" disabled={readOnly || saving} onClick={rebaseDraft}>Rebase my draft to revision {item.review.revision}</button></div>}
    {draft.rebasedToRevision === item.review.revision && <p className="success-message" role="status">Your draft is based on revision {item.review.revision}. Save it to share your changes.</p>}
    <label>Review status<select disabled={readOnly} value={status} onChange={event => { const value = event.target.value as IncidentReviewUpdate['status']; patchDraft(value === 'needs_review' ? { status: value, dueLocal: '', ambiguousChoice: '' } : { status: value }) }}>
      <option value="needs_review">Needs review</option><option value="investigating">Investigating</option>
    </select></label>
    <label>Shared reviewer note<textarea disabled={readOnly} value={note} rows={4} onChange={event => patchDraft({ note: event.target.value })} aria-describedby="incident-note-help incident-note-count" /></label>
    <div className="incident-note-meta"><small id="incident-note-help">Plain text shared with other reviewers. Maximum {maxNoteBytes} UTF-8 bytes.</small><small id="incident-note-count" aria-live="polite" className={bytes > maxNoteBytes ? 'over-limit' : ''}>{bytes} / {maxNoteBytes} bytes</small></div>
    <label>Optional follow-up time <span className="incident-timezone-label">({timezone})</span><input type="datetime-local" value={dueLocal} disabled={readOnly || status === 'needs_review'} onChange={event => patchDraft({ dueLocal: event.target.value, ambiguousChoice: '' })} aria-describedby="incident-follow-up-help incident-follow-up-feedback" /></label>
    <small id="incident-follow-up-help">Enter local wall time in {timezone}. Past times are allowed; future times are limited to 30 days. Returning to Needs review clears the follow-up and keeps the note.</small>
    {dueCandidates.length > 1 && <label>Choose the matching local-time occurrence<select disabled={readOnly} value={selectedDue} onChange={event => patchDraft({ ambiguousChoice: event.target.value })}>
      <option value="">Choose UTC offset</option>{dueCandidates.map(candidate => <option key={candidate} value={candidate}>{formatDateTime(candidate, { dateStyle: 'medium', timeStyle: 'short' })} · {incidentTimeOffset(candidate, timezone)} ({candidate})</option>)}
    </select></label>}
    <div id="incident-follow-up-feedback" className="incident-follow-up-feedback" aria-live="polite">
      {dueError ? <p className="form-error" role="alert">{dueError}</p> : selectedDue ? <p>Will be saved as <strong>{formatDateTime(selectedDue, { dateStyle: 'medium', timeStyle: 'short' })}</strong> in {timezone}; exact UTC instant <code>{selectedDue}</code>.</p> : status === 'investigating' ? <p>No follow-up time set.</p> : null}
    </div>
    {item.review.status === 'needs_review' && status === 'needs_review' && item.review.note && <p className="muted">This incident is in Needs review. Its existing note stays shared and is retained when you save or change the status.</p>}
    {error && <div className="form-error" role="alert">{error}</div>}{saved && <p className="success-message" role="status">{saved}</p>}
    <div className="incident-review-actions"><button className="button primary" type="submit" disabled={!canSave}>{saving ? 'Saving…' : 'Save review'}</button><button className="button ghost" type="button" disabled={saving || readOnly} onClick={() => void resetDraft()}>Reset draft</button></div>
  </form>
}
