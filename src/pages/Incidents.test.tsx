/** @vitest-environment jsdom */

import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react'
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
const page = (items: IncidentInboxItem[] = [item], total = items.length, offset = 0, activeCount = items.length): Omit<IncidentInboxPage, 'incidents'> & { incidents: IncidentInboxItem[] } => ({ incidents: items, pagination: { ...pagination, offset, total, has_more: offset + items.length < total, next_offset: offset + items.length < total ? offset + 20 : null }, truncated: false, active_count: activeCount })
const job = { id: 'job-1', revision: 1, enabled: true, archived: false, security_hash: '', created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z', job: { name: 'Production', schedule: '', timezone: 'UTC', targets: ['192.0.2.10'], max_expanded_hosts: 1, timing: 'balanced', timeout: '1h', baseline_samples: 1, change_confirmations: 1 }, baseline: { status: 'complete' } }
const administrator = { user_id: 'admin-1', username: 'admin', display_name: 'Riley Reviewer', role: 'administrator', permissions: ['incidents.read', 'incidents.manage'], csrf_token: '', totp_enabled: true, password_requirements: { minimum_length: 12 }, scope: 'unit', unit: { id: 'unit-1', name: 'Default', slug: 'default' }, multi_unit: false }

function LocationOutput() {
  const location = useLocation()
  return <output data-testid="location">{location.pathname}{location.search}</output>
}
function renderInbox(route = ['/incidents']) {
  return renderWithProviders(<><Incidents /><LocationOutput /></>, { route })
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

  it('refreshes a stale revision while preserving the draft for an explicit retry', async () => {
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
    fireEvent.click(within(panel).getByRole('button', { name: 'Save draft to latest review' }))
    await waitFor(() => expect(updateIncidentReview).toHaveBeenLastCalledWith('job-1', expect.objectContaining({ expected_revision: 2, note: 'My draft' })))
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
