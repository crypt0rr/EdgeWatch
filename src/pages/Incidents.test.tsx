/** @vitest-environment jsdom */

import { act, cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { useQueryClient } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { useLocation } from 'react-router-dom'
import { APIError, acceptIncident, getSession, listIncidents, listJobs, suppressIncident, updateIncidentReview } from '../api'
import type { IncidentInboxItem, IncidentInboxPage, IncidentReview } from '../generated/api-types'
import { formatDateTime, setDisplayTimeZone } from '../format'
import { incidentDateTimeInput } from '../incident-time'
import { renderWithProviders } from '../test/test-utils'
import { Incidents } from './Incidents'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return { ...actual, acceptIncident: vi.fn(), getSession: vi.fn(), listIncidents: vi.fn(), listJobs: vi.fn(), suppressIncident: vi.fn(), updateIncidentReview: vi.fn() }
})

const review: IncidentReview = { status: 'needs_review', reviewer_label: null, reviewed_at: null, note: '', follow_up_at: null, revision: 0 }
const item: IncidentInboxItem = {
  job_id: 'job-1', job: 'Production', occurrence_token: 'occurrence-1', opening_time_known: true, opening_scan_available: true,
  view_status: 'needs_review',
  incident: { change: { key: 'port|192.0.2.10|tcp|443', kind: 'port', target: '192.0.2.10', protocol: 'tcp', port: 443, old: 'not-open', new: 'open', severity: 'critical' }, scan_id: 'scan-1', opened_at: '2026-10-10T08:00:00Z', last_seen_at: '2026-10-11T08:00:00Z', recovery_count: 0 },
  review,
  observation_uncertainty: { status: 'unknown', reason: 'legacy_origin_unknown' },
}
const pagination = { limit: 20, offset: 0, total: 1, has_more: false, next_offset: null }
const page = (items: IncidentInboxItem[] = [item], total = items.length, offset = 0, activeCount = items.length, schedule: { serverNow?: string; nextFollowUpAt?: string | null } = {}): IncidentInboxPage & { incidents: IncidentInboxItem[] } => {
  const serverNow = schedule.serverNow ?? new Date().toISOString()
  const upcoming = items.map(row => row.review.status === 'investigating' ? row.review.follow_up_at : null)
    .filter((value): value is string => !!value && Date.parse(value) > Date.parse(serverNow))
    .sort((left, right) => Date.parse(left) - Date.parse(right))[0] ?? null
  return {
    incidents: items,
    pagination: { ...pagination, offset, total, has_more: offset + items.length < total, next_offset: offset + items.length < total ? offset + 20 : null },
    truncated: false,
    active_count: activeCount,
    server_now: serverNow,
    next_follow_up_at: schedule.nextFollowUpAt === undefined ? upcoming : schedule.nextFollowUpAt,
  }
}
const job = { id: 'job-1', revision: 1, enabled: true, archived: false, security_hash: '', created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z', job: { name: 'Production', schedule: '', timezone: 'UTC', targets: ['192.0.2.10'], max_expanded_hosts: 1, timing: 'balanced', timeout: '1h', baseline_samples: 1, change_confirmations: 1 }, baseline: { status: 'complete' } }
const administrator = { user_id: 'admin-1', username: 'admin', display_name: 'Riley Reviewer', role: 'administrator', permissions: ['incidents.read', 'incidents.manage'], csrf_token: '', totp_enabled: true, password_requirements: { minimum_length: 12 }, scope: 'unit', unit: { id: 'unit-1', name: 'Default', slug: 'default' }, multi_unit: false }
const dayMs = 24 * 60 * 60 * 1000
const nativeTimeoutMax = 2_147_483_647
const dueRefreshSafetyMarginForTest = 250

function investigatingItem(followUpAt: string, viewStatus: IncidentInboxItem['view_status'] = 'investigating'): IncidentInboxItem {
  return {
    ...item,
    view_status: viewStatus,
    review: { ...review, status: 'investigating', reviewer_label: 'Riley Reviewer', reviewed_at: '2026-10-13T11:00:00Z', follow_up_at: followUpAt, revision: 1 },
  }
}

function LocationOutput() {
  const location = useLocation()
  return <output data-testid="location">{location.pathname}{location.search}</output>
}
function RefreshIncidentsButton() {
  const client = useQueryClient()
  return <button type="button" onClick={() => void client.invalidateQueries({ queryKey: ['incidents'] })}>Refresh incidents</button>
}
function RefreshSessionButton() {
  const client = useQueryClient()
  return <button type="button" onClick={() => void client.invalidateQueries({ queryKey: ['session'] })}>Refresh session</button>
}
function renderInbox(route = ['/incidents'], includeRefresh = false, includeSessionRefresh = false) {
  return renderWithProviders(<><Incidents />{includeRefresh && <RefreshIncidentsButton />}{includeSessionRefresh && <RefreshSessionButton />}<LocationOutput /></>, { route })
}
function locationSearch() {
  return new URL(screen.getByTestId('location').textContent || '/incidents', 'http://example.test').searchParams
}
function openFirstEvidence() {
  fireEvent.click(screen.getAllByRole('button', { name: 'Review evidence' })[0])
}
async function waitForInbox() {
  await screen.findByRole('heading', { name: 'Investigation inbox' })
  await screen.findAllByRole('button', { name: 'Review evidence' })
}

beforeEach(() => {
  vi.mocked(getSession).mockResolvedValue(administrator as never)
  vi.mocked(listJobs).mockResolvedValue({ jobs: [job] } as never)
  vi.mocked(listIncidents).mockResolvedValue(page() as never)
  vi.mocked(acceptIncident).mockResolvedValue(undefined)
  vi.mocked(suppressIncident).mockResolvedValue(undefined)
  vi.mocked(updateIncidentReview).mockResolvedValue({ ...review, status: 'investigating', reviewer_label: 'Riley Reviewer', reviewed_at: '2026-10-11T12:00:00Z', revision: 1 } as never)
})
afterEach(() => {
  cleanup()
  vi.useRealTimers()
  vi.clearAllMocks()
  setDisplayTimeZone(null)
})

describe('investigation inbox filters and context', () => {
  it('defaults explicitly to Needs review and uses URL-backed filters and pagination', async () => {
    renderInbox()
    await waitForInbox()
    await waitFor(() => expect(listIncidents).toHaveBeenCalledWith({ view: 'needs_review', limit: 20, offset: 0 }))
    await waitFor(() => expect(locationSearch().get('view')).toBe('needs_review'))

    fireEvent.change(screen.getByRole('combobox', { name: 'Filter by job' }), { target: { value: 'job-1' } })
    fireEvent.change(screen.getByRole('combobox', { name: 'Filter by severity' }), { target: { value: 'critical' } })
    fireEvent.change(screen.getByRole('combobox', { name: 'Filter by change kind' }), { target: { value: 'port' } })
    fireEvent.change(screen.getByRole('combobox', { name: 'Filter by review view' }), { target: { value: 'all_active' } })

    await waitFor(() => expect(listIncidents).toHaveBeenLastCalledWith({ view: 'all_active', limit: 20, offset: 0, job_id: 'job-1', severity: 'critical', kind: 'port' }))
    expect(locationSearch().get('view')).toBe('all_active')
    expect(locationSearch().get('job_id')).toBe('job-1')
    expect(locationSearch().get('severity')).toBe('critical')
    expect(locationSearch().get('kind')).toBe('port')
    expect(locationSearch().get('offset')).toBe('0')
  })

  it('normalizes invalid filter, job, and offset values without echoing unknown IDs', async () => {
    vi.mocked(listIncidents).mockResolvedValue(page([], 0, 0, 4) as never)
    renderInbox(['/incidents?view=all&job_id=unknown-foreign-id&severity=urgent&kind=bogus&offset=-2'])
    await screen.findByText('No matching incidents')
    await waitFor(() => expect(listIncidents).toHaveBeenCalledWith({ view: 'needs_review', limit: 20, offset: 0, job_id: 'unknown-foreign-id' }))
    await waitFor(() => expect(locationSearch().toString()).toBe('view=needs_review&job_id=unknown-foreign-id&offset=0'))
    expect(screen.getByRole('option', { name: 'Unavailable or inaccessible job' })).toBeInTheDocument()
    expect(screen.getByText('4').closest('.incident-inbox-active-count')).toHaveTextContent(/active incidents across all views/)
  })

  it('opens evidence from a direct URL and closes without changing filters or page', async () => {
    renderInbox(['/incidents?view=all_active&job_id=job-1&severity=critical&kind=port&offset=0&occurrence=occurrence-1'])
    const panel = await screen.findByRole('complementary', { name: 'Evidence and review' })
    expect(panel).toBeInTheDocument()
    expect(within(panel).getByText('Observation uncertainty: Unknown')).toBeInTheDocument()
    expect(within(panel).getByText(/no reliable opening scan or time/)).toBeInTheDocument()
    expect(within(panel).queryByText('Unknown opening time')).not.toBeInTheDocument()
    const scanLink = within(panel).getByRole('link', { name: /Open source scan/ })
    expect(scanLink).toHaveAttribute('href', '/jobs/job-1/scans/scan-1')
    expect(scanLink).toHaveAttribute('target', '_blank')
    expect(scanLink).toHaveAccessibleName(/opens in new tab/i)

    fireEvent.click(within(panel).getByRole('button', { name: 'Close evidence panel' }))
    await waitFor(() => expect(screen.queryByRole('complementary', { name: 'Evidence and review' })).not.toBeInTheDocument())
    expect(locationSearch().toString()).toBe('view=all_active&job_id=job-1&severity=critical&kind=port&offset=0')
  })

  it('shows unknown legacy opening time explicitly and preserves the review panel across reload state', async () => {
    const legacy = { ...item, opening_time_known: false, incident: { ...item.incident, opened_at: '0001-01-01T00:00:00Z', scan_id: undefined } }
    vi.mocked(listIncidents).mockResolvedValue(page([legacy]) as never)
    renderInbox(['/incidents?view=needs_review&occurrence=occurrence-1'])
    await waitFor(() => expect(screen.getAllByText('Unknown opening time').length).toBeGreaterThan(0))
    expect(screen.getByRole('complementary', { name: 'Evidence and review' })).toBeInTheDocument()
  })
})

describe('shared review workflow', () => {
  it('pins a draft to its starting revision across an in-view refresh and rebases only by explicit choice', async () => {
    const latest = {
      ...item,
      review: { status: 'investigating', reviewer_label: 'Sam', reviewed_at: '2026-10-12T10:00:00Z', note: 'Saved by another reviewer', follow_up_at: '2026-10-13T10:00:00Z', revision: 1 },
      view_status: 'investigating',
    }
    vi.mocked(listIncidents).mockResolvedValueOnce(page() as never).mockResolvedValue(page([latest]) as never)
    vi.mocked(updateIncidentReview)
      .mockRejectedValueOnce(new APIError('review changed', 'incident_review_revision_conflict', undefined, 409))
      .mockResolvedValueOnce({ ...latest.review, note: 'My draft', reviewer_label: 'Riley Reviewer', revision: 2 } as never)
    renderInbox(['/incidents?view=all_active'], true)
    await waitForInbox()
    openFirstEvidence()
    const panel = await screen.findByRole('complementary', { name: 'Evidence and review' })
    const note = within(panel).getByRole('textbox', { name: 'Shared reviewer note' })
    fireEvent.change(note, { target: { value: 'My draft' } })

    fireEvent.click(screen.getByRole('button', { name: 'Refresh incidents' }))
    await within(panel).findAllByText('Saved by another reviewer')
    expect(note).toHaveValue('My draft')
    fireEvent.click(within(panel).getByRole('button', { name: 'Save review' }))
    await waitFor(() => expect(updateIncidentReview).toHaveBeenNthCalledWith(1, 'job-1', expect.objectContaining({ expected_revision: 0, note: 'My draft' })))
    await within(panel).findByText(/Another reviewer saved an update first/)
    await within(panel).findByText('Latest saved review')
    expect(within(panel).getAllByText('Saved by another reviewer').length).toBeGreaterThan(0)
    expect(within(panel).getByText(/Follow-up:/)).toHaveTextContent('2026-10-13T10:00:00.000Z')

    fireEvent.click(within(panel).getByRole('button', { name: 'Rebase my draft to revision 1' }))
    expect(note).toHaveValue('My draft')
    expect(updateIncidentReview).toHaveBeenCalledTimes(1)
    await within(panel).findByText(/Your draft is based on revision 1/)
    fireEvent.click(within(panel).getByRole('button', { name: 'Save review' }))
    await waitFor(() => expect(updateIncidentReview).toHaveBeenNthCalledWith(2, 'job-1', expect.objectContaining({ expected_revision: 1, note: 'My draft' })))
  })

  it('keeps a review draft by occurrence when its evidence panel closes and reopens', async () => {
    renderInbox(['/incidents?view=all_active'])
    await waitForInbox()
    openFirstEvidence()
    let panel = await screen.findByRole('complementary', { name: 'Evidence and review' })
    fireEvent.change(within(panel).getByRole('textbox', { name: 'Shared reviewer note' }), { target: { value: 'Keep this draft' } })
    fireEvent.click(within(panel).getByRole('button', { name: 'Close evidence panel' }))
    await waitFor(() => expect(screen.queryByRole('complementary', { name: 'Evidence and review' })).not.toBeInTheDocument())

    openFirstEvidence()
    panel = await screen.findByRole('complementary', { name: 'Evidence and review' })
    expect(within(panel).getByRole('textbox', { name: 'Shared reviewer note' })).toHaveValue('Keep this draft')
    fireEvent.click(within(panel).getByRole('button', { name: 'Reset draft' }))
    expect(within(panel).getByRole('textbox', { name: 'Shared reviewer note' })).toHaveValue('')
  })

  it('keeps keyboard focus in the note when an in-view refetch replaces the selected row', async () => {
    const latestObservation = { ...item, incident: { ...item.incident, last_seen_at: '2026-10-12T08:00:00Z' } }
    vi.mocked(listIncidents).mockResolvedValueOnce(page() as never).mockResolvedValue(page([latestObservation]) as never)
    renderInbox(['/incidents?view=all_active'], true)
    await waitForInbox()
    openFirstEvidence()
    const panel = await screen.findByRole('complementary', { name: 'Evidence and review' })
    const note = within(panel).getByRole('textbox', { name: 'Shared reviewer note' })
    note.focus()
    expect(note).toHaveFocus()

    fireEvent.click(screen.getByRole('button', { name: 'Refresh incidents' }))
    await within(panel).findByText(formatDateTime('2026-10-12T08:00:00Z'))
    expect(note).toHaveFocus()
  })

  it('keeps the evidence panel, review draft and focus after a background refetch fails', async () => {
    vi.mocked(listIncidents).mockResolvedValueOnce(page() as never).mockRejectedValueOnce(new Error('temporary inbox failure'))
    const { client } = renderInbox(['/incidents?view=all_active'])
    await waitForInbox()
    openFirstEvidence()
    const panel = await screen.findByRole('complementary', { name: 'Evidence and review' })
    const note = within(panel).getByRole('textbox', { name: 'Shared reviewer note' })
    fireEvent.change(note, { target: { value: 'Unsaved reviewer context' } })
    note.focus()

    await act(async () => { await client.invalidateQueries({ queryKey: ['incidents'] }) })
    await waitFor(() => expect(listIncidents).toHaveBeenCalledTimes(2))

    expect(screen.getByRole('complementary', { name: 'Evidence and review' })).toBeInTheDocument()
    expect(within(panel).getByRole('textbox', { name: 'Shared reviewer note' })).toHaveValue('Unsaved reviewer context')
    expect(note).toHaveFocus()
    expect(await screen.findByText(/Could not refresh the investigation inbox\. Showing the last loaded results\./)).toBeInTheDocument()
  })

  it('shows the saved review revision while the post-save refetch is pending and disables edits during save', async () => {
    let finishSave!: (value: IncidentReview) => void
    let finishRefetch!: (value: IncidentInboxPage & { incidents: IncidentInboxItem[] }) => void
    const savedReview: IncidentReview = { ...review, status: 'investigating', reviewer_label: 'Riley Reviewer', reviewed_at: '2026-10-12T10:00:00Z', note: 'Saved note', revision: 1 }
    vi.mocked(listIncidents).mockResolvedValueOnce(page() as never).mockReturnValueOnce(new Promise(resolve => { finishRefetch = resolve }) as never)
    vi.mocked(updateIncidentReview).mockReturnValueOnce(new Promise(resolve => { finishSave = resolve }) as never)
    renderInbox(['/incidents?view=all_active'])
    await waitForInbox()
    openFirstEvidence()
    const panel = await screen.findByRole('complementary', { name: 'Evidence and review' })
    const note = within(panel).getByRole('textbox', { name: 'Shared reviewer note' })
    fireEvent.change(note, { target: { value: 'Saved note' } })
    const save = within(panel).getByRole('button', { name: 'Save review' })
    fireEvent.click(save)
    expect(note).toBeDisabled()
    expect(within(panel).getByRole('combobox', { name: 'Review status' })).toBeDisabled()

    await act(async () => { finishSave(savedReview) })
    expect(await within(panel).findByText(/Review saved/)).toBeInTheDocument()
    expect(note).toHaveValue('Saved note')
    expect(within(panel).getByText('Revision 1')).toBeInTheDocument()
    expect(note).toBeDisabled()

    await act(async () => { finishRefetch(page([{ ...item, review: savedReview, view_status: 'investigating' }]) as never) })
    await waitFor(() => expect(note).not.toBeDisabled())
    expect(note).toHaveValue('Saved note')
  })

  it('keeps focus on Save after a successful save refreshes the selected row', async () => {
    const savedReview = { ...review, status: 'investigating', reviewer_label: 'Riley Reviewer', reviewed_at: '2026-10-12T10:00:00Z', note: 'My draft', revision: 1 }
    const refreshed = { ...item, review: savedReview, incident: { ...item.incident, last_seen_at: '2026-10-12T08:00:00Z' }, view_status: 'investigating' }
    vi.mocked(listIncidents).mockResolvedValueOnce(page() as never).mockResolvedValue(page([refreshed]) as never)
    vi.mocked(updateIncidentReview).mockResolvedValue(savedReview as never)
    renderInbox(['/incidents?view=all_active'])
    await waitForInbox()
    openFirstEvidence()
    const panel = await screen.findByRole('complementary', { name: 'Evidence and review' })
    fireEvent.change(within(panel).getByRole('textbox', { name: 'Shared reviewer note' }), { target: { value: 'My draft' } })
    const save = within(panel).getByRole('button', { name: 'Save review' })
    save.focus()
    fireEvent.click(save)

    await within(panel).findByText(/Review saved/)
    await waitFor(() => expect(listIncidents).toHaveBeenCalledTimes(2))
    expect(save).toHaveFocus()
  })

  it('labels a saved follow-up with the displayed timezone and exact UTC instant', async () => {
    setDisplayTimeZone('Europe/Amsterdam')
    const current = { ...item, review: { status: 'investigating', reviewer_label: 'Sam', reviewed_at: '2026-10-10T00:00:00Z', note: '', follow_up_at: '2026-10-12T08:00:00Z', revision: 4 }, view_status: 'investigating' }
    vi.mocked(listIncidents).mockResolvedValue(page([current]) as never)
    renderInbox(['/incidents?view=all_active&occurrence=occurrence-1'])
    const panel = await screen.findByRole('complementary', { name: 'Evidence and review' })

    expect(within(panel).getByText(`${formatDateTime('2026-10-12T08:00:00Z')} (Europe/Amsterdam) · UTC 2026-10-12T08:00:00.000Z`)).toBeInTheDocument()
  })

  it('saves a note and a local follow-up as an exact UTC instant', async () => {
    setDisplayTimeZone('Europe/Amsterdam')
    renderInbox()
    await waitForInbox()
    openFirstEvidence()
    const panel = await screen.findByRole('complementary', { name: 'Evidence and review' })
    fireEvent.change(within(panel).getByRole('combobox', { name: 'Review status' }), { target: { value: 'investigating' } })
    fireEvent.change(within(panel).getByRole('textbox', { name: 'Shared reviewer note' }), { target: { value: 'Check the service on the next scan.' } })
    fireEvent.change(within(panel).getByLabelText(/Optional follow-up time/), { target: { value: '2026-01-15T12:30' } })
    expect(within(panel).getByText('2026-01-15T11:30:00.000Z')).toBeInTheDocument()
    fireEvent.click(within(panel).getByRole('button', { name: 'Save review' }))

    await waitFor(() => expect(updateIncidentReview).toHaveBeenCalledWith('job-1', {
      key: item.incident.change.key,
      occurrence_token: 'occurrence-1',
      expected_revision: 0,
      status: 'investigating',
      note: 'Check the service on the next scan.',
      follow_up_at: '2026-01-15T11:30:00.000Z',
    }))
    expect(await within(panel).findByRole('status')).toHaveTextContent(/Review saved/)
  })

  it('keeps notes when returning to Needs review and clears the follow-up', async () => {
    const current = { ...item, review: { status: 'investigating', reviewer_label: 'Sam', reviewed_at: '2026-10-10T00:00:00Z', note: 'Keep this context', follow_up_at: '2026-10-12T08:00:00Z', revision: 4 }, view_status: 'investigating' }
    vi.mocked(listIncidents).mockResolvedValue(page([current]) as never)
    renderInbox(['/incidents?view=all_active&occurrence=occurrence-1'])
    const panel = await screen.findByRole('complementary', { name: 'Evidence and review' })
    const note = within(panel).getByRole('textbox', { name: 'Shared reviewer note' })
    expect(note).toHaveValue('Keep this context')
    fireEvent.change(within(panel).getByRole('combobox', { name: 'Review status' }), { target: { value: 'needs_review' } })
    expect(note).toHaveValue('Keep this context')
    expect(within(panel).getByLabelText(/Optional follow-up time/)).toBeDisabled()
    fireEvent.click(within(panel).getByRole('button', { name: 'Save review' }))
    await waitFor(() => expect(updateIncidentReview).toHaveBeenCalledWith('job-1', expect.objectContaining({ expected_revision: 4, status: 'needs_review', note: 'Keep this context', follow_up_at: null })))
  })

  it('limits notes by UTF-8 bytes and rejects a future time beyond 30 days', async () => {
    setDisplayTimeZone('Europe/Amsterdam')
    renderInbox()
    await waitForInbox()
    openFirstEvidence()
    const panel = await screen.findByRole('complementary', { name: 'Evidence and review' })
    const note = within(panel).getByRole('textbox', { name: 'Shared reviewer note' })
    fireEvent.change(note, { target: { value: 'é'.repeat(2049) } })
    expect(within(panel).getByText('4098 / 4096 bytes')).toBeInTheDocument()
    expect(within(panel).getByRole('button', { name: 'Save review' })).toBeDisabled()
    fireEvent.change(note, { target: { value: '' } })
    fireEvent.change(within(panel).getByRole('combobox', { name: 'Review status' }), { target: { value: 'investigating' } })
    const tooFar = incidentDateTimeInput(new Date(Date.now() + 31 * 24 * 60 * 60 * 1000).toISOString(), 'Europe/Amsterdam')
    fireEvent.change(within(panel).getByLabelText(/Optional follow-up time/), { target: { value: tooFar } })
    expect(within(panel).getByText('Follow-up must be no more than 30 days ahead.')).toBeInTheDocument()
    expect(within(panel).getByRole('button', { name: 'Save review' })).toBeDisabled()
  })

  it('rejects nonexistent DST times and requires an explicit offset for a repeated local time', async () => {
    setDisplayTimeZone('Europe/Amsterdam')
    renderInbox()
    await waitForInbox()
    openFirstEvidence()
    const panel = await screen.findByRole('complementary', { name: 'Evidence and review' })
    fireEvent.change(within(panel).getByRole('combobox', { name: 'Review status' }), { target: { value: 'investigating' } })
    const due = within(panel).getByLabelText(/Optional follow-up time/)
    fireEvent.change(due, { target: { value: '2026-03-29T02:30' } })
    expect(within(panel).getByText(/does not exist in Europe\/Amsterdam/)).toBeInTheDocument()
    fireEvent.change(due, { target: { value: '2026-10-25T02:30' } })
    expect(within(panel).getByText(/occurs twice in Europe\/Amsterdam/)).toBeInTheDocument()
    expect(within(panel).getByRole('button', { name: 'Save review' })).toBeDisabled()
    fireEvent.change(within(panel).getByRole('combobox', { name: 'Choose the matching local-time occurrence' }), { target: { value: '2026-10-25T00:30:00.000Z' } })
    expect(within(panel).getByText('2026-10-25T00:30:00.000Z')).toBeInTheDocument()
    fireEvent.click(within(panel).getByRole('button', { name: 'Save review' }))
    await waitFor(() => expect(updateIncidentReview).toHaveBeenCalledWith('job-1', expect.objectContaining({ follow_up_at: '2026-10-25T00:30:00.000Z' })))
  })

  it('refreshes a racing revision conflict and keeps the draft pinned until it is rebased', async () => {
    const latest = { ...item, review: { status: 'needs_review', reviewer_label: 'Sam', reviewed_at: '2026-10-11T10:00:00Z', note: 'Saved by another reviewer', follow_up_at: null, revision: 2 } }
    vi.mocked(listIncidents).mockResolvedValueOnce(page()).mockResolvedValue(page([latest]))
    vi.mocked(updateIncidentReview)
      .mockRejectedValueOnce(new APIError('review changed', 'incident_review_revision_conflict', undefined, 409))
      .mockResolvedValueOnce({ ...latest.review, note: 'My draft', reviewer_label: 'Riley Reviewer', revision: 3 } as never)
    renderInbox()
    await waitForInbox()
    openFirstEvidence()
    const panel = await screen.findByRole('complementary', { name: 'Evidence and review' })
    const note = within(panel).getByRole('textbox', { name: 'Shared reviewer note' })
    fireEvent.change(note, { target: { value: 'My draft' } })
    fireEvent.click(within(panel).getByRole('button', { name: 'Save review' }))
    await within(panel).findByText(/Another reviewer saved an update first/)
    await waitFor(() => expect(within(panel).getByRole('textbox', { name: 'Shared reviewer note' })).toHaveValue('My draft'))
    expect(within(panel).getAllByText('Saved by another reviewer').length).toBeGreaterThan(0)
    fireEvent.click(within(panel).getByRole('button', { name: 'Rebase my draft to revision 2' }))
    expect(updateIncidentReview).toHaveBeenCalledTimes(1)
    expect(note).toHaveValue('My draft')
    fireEvent.click(within(panel).getByRole('button', { name: 'Save review' }))
    await waitFor(() => expect(updateIncidentReview).toHaveBeenLastCalledWith('job-1', expect.objectContaining({ expected_revision: 2, note: 'My draft' })))
  })
})

describe('follow-up due refresh', () => {
  const start = new Date('2026-10-14T12:00:00.000Z')

  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    vi.setSystemTime(start)
  })

  it('refreshes an empty due view when its upcoming follow-up becomes due', async () => {
    const dueAt = start.getTime() + 60_000
    const dueAtISO = new Date(dueAt).toISOString()
    const due = investigatingItem(dueAtISO, 'follow_up_due')
    vi.mocked(listIncidents).mockResolvedValueOnce(page([], 0, 0, 0, { serverNow: start.toISOString(), nextFollowUpAt: dueAtISO }) as never)
      .mockResolvedValue(page([due], 1, 0, 1, { serverNow: new Date(dueAt + 250).toISOString() }) as never)
    renderInbox(['/incidents?view=follow_up_due'])
    // The empty state sits under the page's level-one heading (#1680).
    await screen.findByRole('heading', { level: 2, name: 'No matching incidents' })
    expect(listIncidents).toHaveBeenCalledTimes(1)

    await act(async () => { await vi.advanceTimersByTimeAsync(59_000) })
    expect(listIncidents).toHaveBeenCalledTimes(1)
    await act(async () => { await vi.advanceTimersByTimeAsync(1_250) })
    await waitFor(() => expect(listIncidents).toHaveBeenCalledTimes(2))
    expect(await screen.findByRole('cell', { name: 'Follow-up due' })).toBeInTheDocument()
  })

  it.each([1, 30])('uses server time when the browser clock is %i seconds ahead', async skewSeconds => {
    const serverNow = start
    const dueAt = serverNow.getTime() + 60_000
    vi.setSystemTime(new Date(serverNow.getTime() + skewSeconds * 1000))
    const future = investigatingItem(new Date(dueAt).toISOString())
    const due = investigatingItem(new Date(dueAt).toISOString(), 'follow_up_due')
    vi.mocked(listIncidents).mockResolvedValueOnce(page([future], 1, 0, 1, { serverNow: serverNow.toISOString(), nextFollowUpAt: future.review.follow_up_at }) as never)
      .mockResolvedValue(page([due], 1, 0, 1, { serverNow: new Date(dueAt + 250).toISOString() }) as never)
    renderInbox(['/incidents?view=all_active'])
    await waitForInbox()

    await act(async () => { await vi.advanceTimersByTimeAsync(60_000 - skewSeconds * 1000) })
    expect(listIncidents).toHaveBeenCalledTimes(1)
    await act(async () => { await vi.advanceTimersByTimeAsync(skewSeconds * 1000 + dueRefreshSafetyMarginForTest) })
    await waitFor(() => expect(listIncidents).toHaveBeenCalledTimes(2))
    expect(await screen.findByRole('cell', { name: 'Follow-up due' })).toBeInTheDocument()
  })

  it('retries an overdue refresh on tab return after one request fails', async () => {
    const descriptor = Object.getOwnPropertyDescriptor(document, 'visibilityState')
    const dueAt = start.getTime() + 5 * 60_000
    const dueAtISO = new Date(dueAt).toISOString()
    const future = investigatingItem(new Date(dueAt).toISOString())
    const due = investigatingItem(new Date(dueAt).toISOString(), 'follow_up_due')
    vi.mocked(listIncidents).mockResolvedValueOnce(page([future], 1, 0, 1, { serverNow: start.toISOString(), nextFollowUpAt: dueAtISO }) as never)
      .mockRejectedValueOnce(new Error('temporary inbox failure'))
      .mockResolvedValue(page([due], 1, 0, 1, { serverNow: new Date(dueAt + 250).toISOString() }) as never)
    try {
      renderInbox(['/incidents?view=all_active'])
      await waitForInbox()
      await act(async () => { await vi.advanceTimersByTimeAsync(dueAt - start.getTime() + 250) })
      await waitFor(() => expect(listIncidents).toHaveBeenCalledTimes(2))
      expect(await screen.findByText(/Could not refresh the investigation inbox\. Showing the last loaded results\./)).toBeInTheDocument()
      expect(screen.getByRole('cell', { name: 'Follow-up due' })).toBeInTheDocument()

      Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' })
      await act(async () => { window.dispatchEvent(new Event('visibilitychange')) })
      Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' })
      await act(async () => { window.dispatchEvent(new Event('visibilitychange')) })
      await waitFor(() => expect(listIncidents).toHaveBeenCalledTimes(3))
      expect(await screen.findByRole('cell', { name: 'Follow-up due' })).toBeInTheDocument()
      await act(async () => { await vi.advanceTimersByTimeAsync(dayMs) })
      expect(listIncidents).toHaveBeenCalledTimes(3)
    } finally {
      if (descriptor) Object.defineProperty(document, 'visibilityState', descriptor)
      else Reflect.deleteProperty(document, 'visibilityState')
    }
  })

  it('re-arms at the native timeout cap without polling for a far-future follow-up', async () => {
    const dueAt = start.getTime() + 30 * dayMs
    const dueAtISO = new Date(dueAt).toISOString()
    const future = investigatingItem(dueAtISO)
    const due = investigatingItem(dueAtISO, 'follow_up_due')
    vi.mocked(listIncidents).mockResolvedValueOnce(page([future], 1, 0, 1, { serverNow: start.toISOString(), nextFollowUpAt: dueAtISO }) as never)
      .mockResolvedValue(page([due], 1, 0, 1, { serverNow: new Date(dueAt + 250).toISOString() }) as never)
    const rendered = renderInbox(['/incidents?view=all_active'])
    await waitForInbox()

    await act(async () => { await vi.advanceTimersByTimeAsync(nativeTimeoutMax + 5_000) })
    expect(listIncidents).toHaveBeenCalledTimes(1)
    const untilDue = dueAt - start.getTime() + dueRefreshSafetyMarginForTest - (nativeTimeoutMax + 5_000)
    await act(async () => { await vi.advanceTimersByTimeAsync(untilDue - 1_000) })
    expect(listIncidents).toHaveBeenCalledTimes(1)
    await act(async () => { await vi.advanceTimersByTimeAsync(1_000) })
    await waitFor(() => expect(listIncidents).toHaveBeenCalledTimes(2))
    rendered.unmount()
    await act(async () => { await vi.advanceTimersByTimeAsync(6 * dayMs) })
    expect(listIncidents).toHaveBeenCalledTimes(2)
  })

  it('refreshes a due row once when the page becomes visible again', async () => {
    const descriptor = Object.getOwnPropertyDescriptor(document, 'visibilityState')
    const dueAt = start.getTime() + 5 * 60_000
    const future = investigatingItem(new Date(dueAt).toISOString())
    const due = investigatingItem(new Date(dueAt).toISOString(), 'follow_up_due')
    vi.mocked(listIncidents).mockResolvedValueOnce(page([future]) as never).mockResolvedValue(page([due]) as never)
    Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' })
    try {
      renderInbox(['/incidents?view=all_active'])
      await waitForInbox()
      await act(async () => { await vi.advanceTimersByTimeAsync(dueAt - Date.now() + dueRefreshSafetyMarginForTest) })
      expect(listIncidents).toHaveBeenCalledTimes(1)

      Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' })
      await act(async () => { window.dispatchEvent(new Event('visibilitychange')) })
      await waitFor(() => expect(listIncidents).toHaveBeenCalledTimes(2))
      expect(await screen.findByRole('cell', { name: 'Follow-up due' })).toBeInTheDocument()
    } finally {
      if (descriptor) Object.defineProperty(document, 'visibilityState', descriptor)
      else Reflect.deleteProperty(document, 'visibilityState')
    }
  })

  it('arms the next upcoming follow-up after the current one becomes due', async () => {
    const firstDueAt = start.getTime() + 60_000
    const secondDueAt = start.getTime() + 2 * 60_000
    const firstFuture = investigatingItem(new Date(firstDueAt).toISOString())
    const secondFuture = { ...investigatingItem(new Date(secondDueAt).toISOString()), incident: { ...item.incident, change: { ...item.incident.change, key: 'port|192.0.2.11|tcp|8443', target: '192.0.2.11', port: 8443 } }, occurrence_token: 'occurrence-2' }
    const firstDue = { ...firstFuture, view_status: 'follow_up_due' as const }
    const secondDue = { ...secondFuture, view_status: 'follow_up_due' as const }
    vi.mocked(listIncidents)
      .mockResolvedValueOnce(page([firstFuture, secondFuture], 2, 0, 2, { serverNow: start.toISOString(), nextFollowUpAt: new Date(firstDueAt).toISOString() }) as never)
      .mockResolvedValueOnce(page([firstDue, secondFuture], 2, 0, 2, { serverNow: new Date(firstDueAt + dueRefreshSafetyMarginForTest).toISOString(), nextFollowUpAt: new Date(secondDueAt).toISOString() }) as never)
      .mockResolvedValue(page([firstDue, secondDue], 2, 0, 2, { serverNow: new Date(secondDueAt + dueRefreshSafetyMarginForTest).toISOString(), nextFollowUpAt: null }) as never)
    renderInbox(['/incidents?view=all_active'])
    await waitForInbox()
    await act(async () => { await vi.advanceTimersByTimeAsync(firstDueAt - start.getTime() + dueRefreshSafetyMarginForTest) })
    await waitFor(() => expect(listIncidents).toHaveBeenCalledTimes(2))
    expect(await screen.findByRole('cell', { name: 'Follow-up due' })).toBeInTheDocument()

    await act(async () => { await vi.advanceTimersByTimeAsync(secondDueAt - firstDueAt) })
    await waitFor(() => expect(listIncidents).toHaveBeenCalledTimes(3))
    expect(await screen.findAllByRole('cell', { name: 'Follow-up due' })).toHaveLength(2)
  })

  it('cancels a stale due timer when filters change and when the inbox unmounts', async () => {
    const firstDueAt = start.getTime() + 5 * 60_000
    const future = investigatingItem(new Date(firstDueAt).toISOString())
    vi.mocked(listIncidents).mockResolvedValueOnce(page([future]) as never).mockResolvedValue(page([]) as never)
    const rendered = renderInbox(['/incidents?view=all_active'])
    await waitForInbox()
    fireEvent.change(screen.getByRole('combobox', { name: 'Filter by review view' }), { target: { value: 'needs_review' } })
    await waitFor(() => expect(listIncidents).toHaveBeenCalledTimes(2))
    await act(async () => { await vi.advanceTimersByTimeAsync(firstDueAt - Date.now()) })
    expect(listIncidents).toHaveBeenCalledTimes(2)

    const unmountDueAt = Date.now() + 60_000
    const withDue = investigatingItem(new Date(unmountDueAt).toISOString())
    vi.mocked(listIncidents).mockResolvedValue(page([withDue]) as never)
    fireEvent.change(screen.getByRole('combobox', { name: 'Filter by review view' }), { target: { value: 'all_active' } })
    await waitFor(() => expect(listIncidents).toHaveBeenCalledTimes(3))
    rendered.unmount()
    await act(async () => { await vi.advanceTimersByTimeAsync(unmountDueAt - Date.now()) })
    expect(listIncidents).toHaveBeenCalledTimes(3)
  })

  it('does not poll an already-due row', async () => {
    const alreadyDue = investigatingItem(new Date(start.getTime() - 60_000).toISOString(), 'follow_up_due')
    vi.mocked(listIncidents).mockResolvedValue(page([alreadyDue]) as never)
    const alreadyDueView = renderInbox(['/incidents?view=all_active'])
    await waitForInbox()
    await act(async () => { await vi.advanceTimersByTimeAsync(dayMs) })
    expect(listIncidents).toHaveBeenCalledTimes(1)
    alreadyDueView.unmount()
  })

  it('cancels a pending due timer when the authenticated tenant changes', async () => {
    const dueAt = start.getTime() + 60_000
    const dueAtISO = new Date(dueAt).toISOString()
    const future = investigatingItem(dueAtISO)
    vi.mocked(getSession)
      .mockResolvedValueOnce(administrator as never)
      .mockResolvedValueOnce({ ...administrator, unit: { id: 'unit-2', name: 'Second', slug: 'second' } } as never)
    vi.mocked(listIncidents)
      .mockResolvedValueOnce(page([future], 1, 0, 1, { serverNow: start.toISOString(), nextFollowUpAt: dueAtISO }) as never)
      .mockResolvedValue(page([]) as never)
    renderInbox(['/incidents?view=all_active'], false, true)
    await waitForInbox()
    fireEvent.click(screen.getByRole('button', { name: 'Refresh session' }))
    await waitFor(() => expect(listIncidents).toHaveBeenCalledTimes(2))
    await act(async () => { await vi.advanceTimersByTimeAsync(dueAt - start.getTime() + dueRefreshSafetyMarginForTest) })
    expect(listIncidents).toHaveBeenCalledTimes(2)
  })
})

describe('incident access and preserved baseline actions', () => {
  it('shows evidence to readers but reserves editing and baseline actions for managers', async () => {
    vi.mocked(getSession).mockResolvedValue({ ...administrator, role: 'viewer', permissions: ['incidents.read'] } as never)
    renderInbox()
    await waitForInbox()
    openFirstEvidence()
    const panel = await screen.findByRole('complementary', { name: 'Evidence and review' })
    expect(within(panel).getByText(/requires incident management permission/)).toBeInTheDocument()
    expect(within(panel).queryByRole('textbox', { name: 'Shared reviewer note' })).not.toBeInTheDocument()
    expect(within(panel).queryByRole('button', { name: 'Accept change' })).not.toBeInTheDocument()
    expect(within(panel).queryByRole('button', { name: 'Suppress 1 scan' })).not.toBeInTheDocument()
  })

  it('keeps accept and suppress as separate, individually confirmed actions', async () => {
    renderInbox()
    await waitForInbox()
    openFirstEvidence()
    const panel = await screen.findByRole('complementary', { name: 'Evidence and review' })
    fireEvent.click(within(panel).getByRole('button', { name: 'Accept change' }))
    const dialog = screen.getByRole('dialog')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Accept change' }))
    await waitFor(() => expect(acceptIncident).toHaveBeenCalledWith('job-1', item.incident.change.key, item.incident.change))

    fireEvent.click(within(panel).getByRole('button', { name: 'Suppress 1 scan' }))
    const suppressDialog = screen.getByRole('dialog')
    fireEvent.click(within(suppressDialog).getByRole('button', { name: 'Suppress 1 scan' }))
    await waitFor(() => expect(suppressIncident).toHaveBeenCalledWith('job-1', item.incident.change.key, item.incident.change))
  })
})
