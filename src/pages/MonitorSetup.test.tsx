/** @vitest-environment jsdom */

import { fireEvent, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { act, StrictMode, useEffect, type ReactNode } from 'react'
import { Link, Route, Routes, useLocation } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { APIError, BUILTIN_NAABU_PROFILE_ID, createJob, createNotificationDestination, getJob, getSession, listNotificationDestinations, listScannerProfiles, previewJob, scannerCapabilities, scheduleSuggestion, testNotificationDestination, updateJob } from '../api'
import type { NotificationDestination } from '../api'
import type { Job, JobForm, JobPreview } from '../types'
import type { PerimeterProtocol, PerimeterSuggestion } from '../generated/api-types'
import { setDisplayTimeZone } from '../format'
import { defaultTCP, type JobCreationDraft } from '../job-form'
import { JobCreationDraftProvider, useOptionalJobCreationDraft } from '../job-creation-draft'
import { consumeFirstScanIntent } from '../firstScanIntent'
import { buildPerimeterPrefill } from '../perimeter-prefill'
import { renderWithProviders } from '../test/test-utils'
import { JobEditor } from './JobEditor'
import { MonitorSetup } from './MonitorSetup'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return {
    ...actual,
    createJob: vi.fn(),
    createNotificationDestination: vi.fn(),
    getJob: vi.fn(),
    getSession: vi.fn(),
    listNotificationDestinations: vi.fn(),
    listScannerProfiles: vi.fn(),
    previewJob: vi.fn(),
    scannerCapabilities: vi.fn(),
    scheduleSuggestion: vi.fn(),
    testNotificationDestination: vi.fn(),
    updateJob: vi.fn(),
  }
})

// The markDirty argument of each draft update that the guided setup makes,
// so a test can count them. The hook below passes every update through.
const guidedDraftUpdates = vi.hoisted(() => [] as Array<boolean | undefined>)

vi.mock('../job-creation-draft', async () => {
  const actual = await vi.importActual<typeof import('../job-creation-draft')>('../job-creation-draft')
  const { useCallback } = await vi.importActual<typeof import('react')>('react')
  return {
    ...actual,
    useJobCreationDraft: () => {
      const value = actual.useJobCreationDraft()
      const { updateDraft } = value
      const recordedUpdateDraft = useCallback<typeof updateDraft>((updater, markDirty) => {
        guidedDraftUpdates.push(markDirty)
        updateDraft(updater, markDirty)
      }, [updateDraft])
      return { ...value, updateDraft: recordedUpdateDraft }
    },
  }
})

const destination: NotificationDestination = { id: 'destination-1', name: 'Operations', provider: 'smtp', source: 'web', enabled: true, locked: false, read_only: false, revision: 1 }
const session = { role: 'administrator' as const, user_id: 'admin', username: 'admin', permissions: ['jobs.write', 'jobs.read', 'users.manage', 'notifications.manage'], high_cost_override: true, csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 }, scope: 'unit' as const, unit: { id: 'unit-1', name: 'Unit', slug: 'unit' }, multi_unit: false }
const operatorSession = { ...session, role: 'operator' as const, user_id: 'operator', username: 'operator', permissions: ['jobs.read', 'jobs.write'], high_cost_override: false }
const profile = { id: 'profile-advanced', name: 'Tuned discovery', description: '', built_in: false, archived: false, revision: 7, definition: { engine: 'naabu_nmap', naabu: { scan_type: 'connect', rate: 1800, workers: 20, retries: 2, timeout_ms: 1200, warm_up_seconds: 2, verify: true, address_batch_size: 16 }, nmap_args: ['-sV'], naabu_args: [], enrichment_args: [] } }
const capabilities = { engines: ['nmap', 'naabu_nmap'], nmap: { available: true, path: '/usr/bin/nmap', version: '7.99' }, naabu: { available: true, path: '/usr/bin/naabu', version: '2.6.1', syn_supported: false } }

function previewResponse(value: JobForm, probes = 300, budget: JobPreview['scan_budget'] = { exceeded: false, estimated_probes: probes, limit: 10_000 }, profileRevision = 9): JobPreview {
  return {
    job: { ...value, tcp: value.tcp ? { ...value.tcp, profile_revision: value.tcp.profile_revision ?? (value.tcp.profile_id ? profileRevision : undefined) } : undefined },
    scan_estimate: { hosts: 2, tcp_ports: value.tcp?.engine === 'naabu_nmap' ? 65_535 : value.tcp ? 2 : 0, udp_ports: value.udp ? 1 : 0, probes, naabu_probes: value.tcp?.engine === 'naabu_nmap' ? 131_070 : 0, nmap_probes: probes, naabu_invocations: value.tcp?.engine === 'naabu_nmap' ? 1 : 0, nmap_invocations: 1, unknown_dns: 0 },
    scan_budget: budget,
    warnings: [],
  }
}

function returnedJob(value: JobForm): Job {
  return { id: 'job-created', revision: 1, enabled: value.enabled ?? true, archived: false, security_hash: 'scope', created_at: '2026-10-09T08:00:00Z', updated_at: '2026-10-09T08:00:00Z', job: value, baseline: { status: 'pending', samples: 0, attempts: 0 } }
}

function CreationRoutes({ editedDraft = false }: { editedDraft?: boolean }) {
  const routes = <Routes>
    <Route index element={<MonitorSetup />} />
    <Route path="advanced" element={<JobEditor />} />
    <Route path="*" element={<div>Unknown creation path</div>} />
  </Routes>
  return <JobCreationDraftProvider><DraftProbe />{editedDraft ? <EditBeforeSetup>{routes}</EditBeforeSetup> : routes}</JobCreationDraftProvider>
}

// Edits the creation draft, as a person would have, before the guided setup
// mounts.
function EditBeforeSetup({ children }: { children: ReactNode }) {
  const { dirty, updateDraft } = useOptionalJobCreationDraft()!
  useEffect(() => {
    updateDraft(draft => ({ ...draft, fields: { ...draft.fields, name: 'Hand-edited monitor' }, targets: ['198.51.100.7'] }))
  }, [updateDraft])
  return dirty ? children : null
}

function DraftProbe() {
  const context = useOptionalJobCreationDraft()
  return <>
    <output data-testid="creation-draft">{context ? JSON.stringify(context.draft) : 'no draft'}</output>
    {context && <button type="button" onClick={() => context.updateDraft(draft => ({ ...draft, notificationIDs: ['missing-destination'], notificationSelectionTouched: true }))}>Seed missing destination</button>}
  </>
}

function PathProbe() {
  const location = useLocation()
  return <output data-testid="route-location">{JSON.stringify({ path: location.pathname, state: location.state ?? null })}</output>
}

function TestJourney({ editedDraft = false }: { editedDraft?: boolean }) {
  return <>
    <PathProbe />
    <Routes>
      <Route path="/jobs/new/*" element={<CreationRoutes editedDraft={editedDraft} />} />
      <Route path="/jobs/:id" element={<div data-testid="created-job">Created job</div>} />
      <Route path="/jobs" element={<div>Jobs list <Link to="/jobs/new">New monitor</Link></div>} />
    </Routes>
  </>
}

function renderJourney(route = '/jobs/new') {
  return renderWithProviders(<TestJourney />, { route: [route] })
}

async function waitForInAct(assertion: () => unknown) {
  await act(async () => {
    await vi.waitFor(assertion, { timeout: 1000 })
  })
}

function creationDraft(): JobCreationDraft {
  return JSON.parse(screen.getByTestId('creation-draft').textContent ?? '{}')
}

function routeLocation(): { path: string; state: unknown } {
  return JSON.parse(screen.getByTestId('route-location').textContent ?? '{}')
}

// The job protocol settings of a Perimeter protocol: all but its protocol key.
function jobSettings(value: PerimeterProtocol) {
  const { protocol: _kind, ...settings } = value
  return settings
}

// Protocol settings that differ from the console's own defaults, so a test
// can tell the returned settings from a preset.
const perimeterFullTCP: PerimeterProtocol = { protocol: 'tcp', engine: 'naabu_nmap', ports: '1-65535', mode: 'connect', service_detection: false, profile_id: 'perimeter-naabu-profile' }
const perimeterSelectedTCP: PerimeterProtocol = { protocol: 'tcp', engine: 'nmap', ports: '22,80,443', mode: 'connect', service_detection: true }
const perimeterUDP: PerimeterProtocol = { protocol: 'udp', engine: 'nmap', ports: '53,123,161,500,1194,4500', service_detection: true }

function perimeterSuggestion(overrides: Partial<PerimeterSuggestion> = {}): PerimeterSuggestion {
  return { mode: 'full_tcp', targets: ['203.0.112.0/24', '203.0.113.64/27'], addresses: 288, already_covered_addresses: 0, estimated_probes: 18_874_080, protocol: perimeterFullTCP, ...overrides }
}

function perimeterRoute(state: unknown) {
  return [{ pathname: '/jobs/new', state }]
}

async function goToSchedule() {
  await waitForInAct(() => expect(screen.getByRole('heading', { name: 'Choose targets' })).toBeInTheDocument())
  fireEvent.change(screen.getByLabelText(/^Monitor name/), { target: { value: 'Public edge' } })
  fireEvent.change(screen.getByLabelText('Target 1'), { target: { value: '198.51.100.20' } })
  fireEvent.click(screen.getByRole('button', { name: /Continue to coverage/ }))
  await waitForInAct(() => expect(screen.getByRole('heading', { name: 'Set scan coverage' })).toBeInTheDocument())
  fireEvent.click(screen.getByRole('button', { name: /Continue to schedule/ }))
  await waitForInAct(() => expect(screen.getByRole('heading', { name: 'Set schedule and alerts' })).toBeInTheDocument())
}

async function goToReview() {
  await goToSchedule()
  fireEvent.click(screen.getByRole('button', { name: 'Use no alerts' }))
  fireEvent.click(screen.getByRole('button', { name: /Review monitor/ }))
  await screen.findByRole('heading', { name: 'Review and create' })
  await waitFor(() => expect(previewJob).toHaveBeenCalled())
  await waitFor(() => expect(screen.getByText('300', { exact: true })).toBeInTheDocument())
}

describe('guided monitor creation', () => {
  beforeEach(() => {
    vi.mocked(createJob).mockImplementation(async value => returnedJob(value))
    vi.mocked(createNotificationDestination).mockResolvedValue(destination)
    vi.mocked(getJob).mockRejectedValue(new Error('not used'))
    vi.mocked(getSession).mockResolvedValue(session)
    vi.mocked(listNotificationDestinations).mockResolvedValue({ destinations: [], status: { deployment: 0, managed: 0, active: 0, locked: 0, key_state: 'not_required' } })
    vi.mocked(listScannerProfiles).mockResolvedValue({ profiles: [profile] })
    vi.mocked(previewJob).mockImplementation(async value => previewResponse(value))
    vi.mocked(scannerCapabilities).mockResolvedValue(capabilities)
    vi.mocked(scheduleSuggestion).mockResolvedValue({ suggested: false, draft_next_run: '2026-10-09T12:00:00Z', gap_minutes: 120 })
    vi.mocked(testNotificationDestination).mockResolvedValue({ sent: 1 })
    vi.mocked(updateJob).mockResolvedValue(returnedJob({} as JobForm))
  })

  afterEach(() => {
    vi.clearAllMocks()
    setDisplayTimeZone(undefined)
    window.history.replaceState(null, '', '/')
    guidedDraftUpdates.length = 0
  })

  it('labels browser-zone fallback times with the zone used in both schedule notices', async () => {
    setDisplayTimeZone(undefined)
    const runAt = '2026-10-13T07:00:00Z'
    const unsupportedZone = 'Factory'
    expect(() => new Intl.DateTimeFormat(undefined, { timeZone: unsupportedZone })).toThrow()
    vi.mocked(scheduleSuggestion).mockResolvedValue({
      suggested: true,
      suggested_schedule: '0 4 * * *',
      offset_minutes: 60,
      nearest: { id: 'job-neighbour', name: 'Factory neighbour', schedule: '0 3 * * *', timezone: unsupportedZone, next_run: runAt },
      draft_next_run: runAt,
      gap_minutes: 60,
    })

    renderJourney()
    fireEvent.change(screen.getByLabelText(/^Monitor name/), { target: { value: 'Public edge' } })
    fireEvent.change(screen.getByLabelText('Target 1'), { target: { value: '198.51.100.20' } })
    fireEvent.click(screen.getByRole('button', { name: /Continue to coverage/ }))
    expect(screen.getByRole('heading', { name: 'Set scan coverage' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /Continue to schedule/ }))
    expect(screen.getByRole('heading', { name: 'Set schedule and alerts' })).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText(/^Timezone/), { target: { value: unsupportedZone } })

    const browserZone = Intl.DateTimeFormat().resolvedOptions().timeZone
    const firstRunLocal = new Date(runAt).toLocaleString(undefined, { timeZone: browserZone })
    await act(async () => {
      await new Promise(resolve => window.setTimeout(resolve, 400))
    })
    await waitFor(() => {
      expect(screen.getByText(/first scheduled scan is expected at/)).toHaveTextContent(`${firstRunLocal} (${browserZone})`)
      expect(screen.getByText(/Factory neighbour is next at/)).toHaveTextContent(`${firstRunLocal} (${browserZone})`)
    })
  })

  it('counts guided monitor names by Unicode code point', async () => {
    renderJourney()
    await screen.findByRole('heading', { name: 'Choose targets' })
    const name = screen.getByLabelText(/^Monitor name/)
    const target = screen.getByLabelText('Target 1')
    fireEvent.change(target, { target: { value: '198.51.100.20' } })

    fireEvent.change(name, { target: { value: '🙂'.repeat(201) } })
    expect(name).toHaveValue('🙂'.repeat(201))
    fireEvent.click(screen.getByRole('button', { name: /Continue to coverage/ }))
    expect(screen.getByRole('alert')).toHaveTextContent('Use a name of up to 200 characters without control characters.')

    fireEvent.change(name, { target: { value: '🙂'.repeat(200) } })
    fireEvent.click(screen.getByRole('button', { name: /Continue to coverage/ }))
    await screen.findByRole('heading', { name: 'Set scan coverage' })
  })

  it('warns when the targets expand beyond the deployment host ceiling', async () => {
    vi.mocked(scannerCapabilities).mockResolvedValue({ ...capabilities, max_job_hosts: 1024 })
    renderJourney()
    await screen.findByRole('heading', { name: 'Choose targets' })
    fireEvent.change(screen.getByLabelText(/^Monitor name/), { target: { value: 'Campus' } })
    fireEvent.change(screen.getByLabelText('Target 1'), { target: { value: '10.20.0.0/16' } })
    await waitFor(() => expect(screen.getByText(/more than the 1,024 hosts that one job may scan in this deployment/)).toBeInTheDocument())
    const limit = screen.getByLabelText(/^Maximum expanded hosts/)
    expect(limit).toHaveAttribute('max', '1000000')
    fireEvent.change(limit, { target: { value: '65536' } })
    expect(limit).toHaveValue(65536)
    fireEvent.change(screen.getByLabelText('Target 1'), { target: { value: '10.20.0.0/24' } })
    expect(screen.queryByText(/that one job may scan in this deployment/)).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /Continue to coverage/ }))
    await screen.findByRole('heading', { name: 'Set scan coverage' })
  })

  it('offers full TCP discovery by default, and makes selected TCP ports an explicit Nmap scope', async () => {
    renderJourney()
    await screen.findByRole('heading', { name: 'Choose targets' })
    fireEvent.change(screen.getByLabelText(/^Monitor name/), { target: { value: 'Public edge' } })
    fireEvent.change(screen.getByLabelText('Target 1'), { target: { value: '198.51.100.20' } })
    fireEvent.click(screen.getByRole('button', { name: /Continue to coverage/ }))
    await screen.findByRole('heading', { name: 'Set scan coverage' })

    expect(screen.getByRole('radio', { name: /Full TCP range/ })).toBeChecked()
    expect(screen.getByRole('checkbox', { name: /Include UDP/ })).not.toBeChecked()
    fireEvent.click(screen.getByRole('radio', { name: /Selected TCP ports/ }))
    const ports = screen.getByLabelText(/^TCP ports/)
    expect(ports).toHaveValue('22,443')
    fireEvent.change(ports, { target: { value: '8443' } })
    fireEvent.click(screen.getByRole('radio', { name: /Full TCP range/ }))
    fireEvent.click(screen.getByRole('radio', { name: /Selected TCP ports/ }))
    expect(screen.getByLabelText(/^TCP ports/)).toHaveValue('8443')
    fireEvent.click(screen.getByRole('checkbox', { name: /Include UDP/ }))
    expect(screen.getByLabelText(/^UDP ports/)).toHaveValue('53')
    expect(screen.getByRole('heading', { name: 'Set scan coverage' })).toHaveFocus()
  })

  it('previews selected TCP and optional UDP, sends an explicit no-alert choice, then creates exactly once', async () => {
    const { client } = renderJourney()
    client.setQueryDefaults(['job'], { gcTime: 30_000 })
    await goToSchedule()
    fireEvent.click(screen.getByRole('button', { name: 'Previous step' }))
    await screen.findByRole('heading', { name: 'Set scan coverage' })
    fireEvent.click(screen.getByRole('radio', { name: /Selected TCP ports/ }))
    fireEvent.change(screen.getByLabelText(/^TCP ports/), { target: { value: '8443,9443' } })
    fireEvent.click(screen.getByRole('checkbox', { name: /Include UDP/ }))
    fireEvent.change(screen.getByLabelText(/^UDP ports/), { target: { value: '53,123' } })
    fireEvent.click(screen.getByRole('button', { name: /Continue to schedule/ }))
    await screen.findByRole('heading', { name: 'Set schedule and alerts' })
    fireEvent.click(screen.getByRole('button', { name: 'Use no alerts' }))
    fireEvent.click(screen.getByRole('button', { name: /Review monitor/ }))
    await screen.findByRole('heading', { name: 'Review and create' })
    await waitFor(() => expect(previewJob).toHaveBeenCalled())
    await waitFor(() => expect(screen.getByRole('button', { name: 'Create without starting' })).toBeEnabled())

    const previewPayload = vi.mocked(previewJob).mock.calls.at(-1)![0]
    expect(previewPayload).toMatchObject({
      name: 'Public edge',
      targets: ['198.51.100.20'],
      tcp: { engine: 'nmap', ports: '8443,9443' },
      udp: { engine: 'nmap', ports: '53,123' },
      notification_destinations: [],
    })
    expect(screen.getByText(/partial TCP coverage/i)).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Create without starting' }))
    await screen.findByTestId('created-job')
    expect(createJob).toHaveBeenCalledTimes(1)
    expect(client.getQueryData(['job', 'job-created'])).toMatchObject({ id: 'job-created' })
    expect(screen.getByTestId('route-location')).toHaveTextContent('"path":"/jobs/job-created","state":null')
  })

  it('accepts the visible active default destination when continuing to review', async () => {
    vi.mocked(listNotificationDestinations).mockResolvedValue({ destinations: [destination], status: { deployment: 0, managed: 1, active: 1, locked: 0, key_state: 'ready' } })
    renderJourney()
    await goToSchedule()
    await waitFor(() => expect(screen.getByRole('checkbox', { name: /Operations/ })).toBeChecked())
    fireEvent.click(screen.getByRole('button', { name: /Review monitor/ }))
    await screen.findByRole('heading', { name: 'Review and create' })
    await waitFor(() => expect(screen.getByRole('button', { name: 'Create without starting' })).toBeEnabled())
    expect(vi.mocked(previewJob).mock.calls.at(-1)![0].notification_destinations).toEqual([destination.id])
    fireEvent.click(screen.getByRole('button', { name: 'Create without starting' }))
    await screen.findByTestId('created-job')
    expect(vi.mocked(createJob).mock.calls[0][0].notification_destinations).toEqual([destination.id])
  })

  it('hands create-and-start to the created job with a one-shot job-bound token', async () => {
    renderJourney()
    await goToReview()
    fireEvent.click(screen.getByRole('button', { name: 'Create and start first scan' }))
    await screen.findByTestId('created-job')
    expect(createJob).toHaveBeenCalledTimes(1)
    const route = JSON.parse(screen.getByTestId('route-location').textContent ?? '{}')
    expect(route.path).toBe('/jobs/job-created')
    expect(route.state.startFirstScanToken).toEqual(expect.any(String))
    expect(route.state.startFirstScanToken).not.toBe('')
    expect(consumeFirstScanIntent('another-job', route.state.startFirstScanToken)).toBe(false)
    expect(consumeFirstScanIntent('job-created', route.state.startFirstScanToken)).toBe(true)
    expect(consumeFirstScanIntent('job-created', route.state.startFirstScanToken)).toBe(false)
  })

  it('saves the exact normalized preview profile revision and refreshes after a profile conflict', async () => {
    let previewCount = 0
    vi.mocked(previewJob).mockImplementation(async value => previewResponse(value, 300, undefined, previewCount++ === 0 ? 9 : 10))
    vi.mocked(createJob).mockRejectedValueOnce(new APIError('Profile revision changed', 'profile_conflict', {}, 409)).mockImplementation(async value => returnedJob(value))
    renderJourney()
    await goToReview()
    expect(await screen.findByText(/revision 9 \(resolved for this preview\)/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Create without starting' }))
    await waitFor(() => expect(previewJob).toHaveBeenCalledTimes(2))
    expect(createJob).toHaveBeenCalledTimes(1)
    expect(vi.mocked(createJob).mock.calls[0][0].tcp?.profile_revision).toBe(9)

    await waitFor(() => expect(screen.getByRole('button', { name: 'Create without starting' })).toBeEnabled())
    expect(await screen.findByText(/revision 10 \(resolved for this preview\)/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Create without starting' }))
    await screen.findByTestId('created-job')
    expect(createJob).toHaveBeenCalledTimes(2)
    expect(vi.mocked(createJob).mock.calls[1][0].tcp?.profile_revision).toBe(10)
  })

  it('keeps preview values unavailable until retry succeeds', async () => {
    vi.mocked(previewJob).mockRejectedValueOnce(new APIError('Probe budget unavailable', 'preview_unavailable', { reason: 'scan_budget_unavailable' }, 503)).mockImplementationOnce(async value => previewResponse(value))
    renderJourney()
    await goToSchedule()
    fireEvent.click(screen.getByRole('button', { name: 'Use no alerts' }))
    fireEvent.click(screen.getByRole('button', { name: /Review monitor/ }))
    await screen.findByRole('heading', { name: 'Review and create' })
    expect(await screen.findByRole('button', { name: 'Retry' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Create without starting' })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    await waitFor(() => expect(screen.getByRole('button', { name: 'Create without starting' })).toBeEnabled())
  })

  it('removes unavailable destination IDs before creating the monitor', async () => {
    vi.mocked(listNotificationDestinations).mockResolvedValue({ destinations: [destination], status: { deployment: 0, managed: 1, active: 1, locked: 0, key_state: 'ready' } })
    renderJourney()
    fireEvent.click(screen.getByRole('button', { name: 'Seed missing destination' }))
    await goToSchedule()
    expect(screen.getByText(/These saved destination IDs are unavailable/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Remove missing selections' }))
    expect(screen.getByText(/This monitor will not send notifications/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /Review monitor/ }))
    await screen.findByRole('heading', { name: 'Review and create' })
    await waitFor(() => expect(previewJob).toHaveBeenCalled())
    expect(vi.mocked(previewJob).mock.calls.at(-1)![0].notification_destinations).toEqual([])
  })

  it('explains paused and locked destinations and supports an explicit no-alert choice', async () => {
    const paused = { ...destination, id: 'destination-paused', name: 'Paused alerts', enabled: false }
    const locked = { ...destination, id: 'destination-locked', name: 'Locked alerts', locked: true }
    vi.mocked(listNotificationDestinations).mockResolvedValue({ destinations: [paused, locked], status: { deployment: 0, managed: 2, active: 0, locked: 1, key_state: 'locked' } })
    renderJourney()
    await goToSchedule()
    fireEvent.click(screen.getByRole('checkbox', { name: /Paused alerts/ }))
    fireEvent.click(screen.getByRole('checkbox', { name: /Locked alerts/ }))
    expect(screen.getByText(/A selected destination is paused or locked/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Use no alerts' }))
    expect(screen.getByText(/This monitor will not send notifications/)).toBeInTheDocument()
    expect(screen.queryByText(/A selected destination is paused or locked/)).not.toBeInTheDocument()
  })

  it('requires an explicit no-alert choice before reviewing an empty destination selection', async () => {
    renderJourney()
    await goToSchedule()

    fireEvent.click(screen.getByRole('button', { name: 'Review monitor' }))
    expect(screen.getByRole('alert')).toHaveTextContent('Select notification destinations or choose Use no alerts.')
    expect(screen.getByRole('heading', { name: 'Set schedule and alerts' })).toBeInTheDocument()
    expect(previewJob).not.toHaveBeenCalled()

    fireEvent.click(screen.getByRole('button', { name: 'Use no alerts' }))
    expect(screen.getByText('This monitor will not send notifications.')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Review monitor' }))
    await screen.findByRole('heading', { name: 'Review and create' })
    await waitFor(() => expect(previewJob).toHaveBeenCalled())
    expect(vi.mocked(previewJob).mock.calls.at(-1)![0].notification_destinations).toEqual([])
    expect(createJob).not.toHaveBeenCalled()
  })

  it('offers a no-alert review when notification destinations cannot be loaded', async () => {
    vi.mocked(listNotificationDestinations).mockRejectedValueOnce(new Error('offline'))
    renderJourney()
    await goToSchedule()

    await waitForInAct(() => expect(screen.getByText(/Notification destinations could not be loaded\. Retry to select a destination, or choose Use no alerts\./)).toBeInTheDocument())
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Use no alerts' }))
    expect(screen.getByText('This monitor will not send notifications.')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Review monitor' }))
    await screen.findByRole('heading', { name: 'Review and create' })
    await waitForInAct(() => expect(previewJob).toHaveBeenCalled())
    expect(vi.mocked(previewJob).mock.calls.at(-1)![0].notification_destinations).toEqual([])
    expect(createJob).not.toHaveBeenCalled()
  })

  it('restores available destination choices after Retry recovers a failed load', async () => {
    vi.mocked(listNotificationDestinations)
      .mockRejectedValueOnce(new Error('offline'))
      .mockResolvedValueOnce({ destinations: [destination], status: { deployment: 0, managed: 1, active: 1, locked: 0, key_state: 'ready' } })
    renderJourney()
    await goToSchedule()

    await waitForInAct(() => expect(screen.getByText(/Notification destinations could not be loaded\. Retry to select a destination, or choose Use no alerts\./)).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    let operations!: HTMLInputElement
    await waitForInAct(() => {
      operations = screen.getByRole('checkbox', { name: /Operations/ })
      expect(operations).toBeInTheDocument()
    })
    if (!operations.checked) fireEvent.click(operations)
    await waitForInAct(() => expect(operations).toBeChecked())
    fireEvent.click(screen.getByRole('button', { name: 'Review monitor' }))
    await waitForInAct(() => expect(screen.getByRole('heading', { name: 'Review and create' })).toBeInTheDocument())
    await waitForInAct(() => expect(previewJob).toHaveBeenCalled())
    expect(vi.mocked(previewJob).mock.calls.at(-1)![0].notification_destinations).toEqual([destination.id])
    expect(createJob).not.toHaveBeenCalled()
  })

  it.each([
    { role: 'administrator', userSession: session, canManageDestinations: true },
    { role: 'operator', userSession: operatorSession, canManageDestinations: false },
  ])('$role can select no alerts by keyboard and review the unchanged draft', async ({ userSession, canManageDestinations }) => {
    vi.mocked(getSession).mockResolvedValue(userSession)
    renderJourney()
    await goToSchedule()

    const noAlerts = screen.getByRole('button', { name: 'Use no alerts' })
    if (canManageDestinations) {
      expect(screen.getByRole('button', { name: 'Add destination' })).toBeInTheDocument()
    } else {
      expect(screen.queryByRole('button', { name: 'Add destination' })).not.toBeInTheDocument()
      expect(screen.getByText(/An administrator can add destinations/i)).toBeInTheDocument()
    }

    const user = userEvent.setup()
    noAlerts.focus()
    await user.keyboard('{Enter}')

    expect(noAlerts).toHaveFocus()
    expect(screen.getByText('This monitor will not send notifications.')).toHaveAttribute('role', 'status')
    expect(screen.getByRole('heading', { name: 'Set schedule and alerts' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Review monitor' })).toBeInTheDocument()
    expect(creationDraft()).toMatchObject({ fields: { name: 'Public edge' }, targets: ['198.51.100.20'], notificationIDs: [], notificationSelectionTouched: true })
    expect(previewJob).not.toHaveBeenCalled()
    expect(createJob).not.toHaveBeenCalled()
  })

  it('keeps a destination created before cancellation and starts a fresh monitor draft on the next journey', async () => {
    let configuredDestinations: NotificationDestination[] = []
    vi.mocked(listNotificationDestinations).mockImplementation(async () => ({ destinations: configuredDestinations, status: { deployment: 0, managed: configuredDestinations.length, active: configuredDestinations.filter(item => item.enabled && !item.locked).length, locked: configuredDestinations.filter(item => item.locked).length, key_state: 'ready' } }))
    vi.mocked(createNotificationDestination).mockImplementation(async () => {
      configuredDestinations = [destination]
      return destination
    })
    renderJourney()
    await goToSchedule()
    fireEvent.click(screen.getByRole('button', { name: 'Add destination' }))
    fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'Operations' } })
    fireEvent.change(screen.getByLabelText('SMTP server'), { target: { value: 'smtp.example.test' } })
    fireEvent.change(screen.getByLabelText('From address'), { target: { value: 'edge@example.test' } })
    fireEvent.change(screen.getByLabelText(/^Recipients/), { target: { value: 'ops@example.test' } })
    fireEvent.change(screen.getByLabelText(/^Password confirmation/), { target: { value: 'account-password-value' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save and select destination' }))
    await screen.findByText(/will remain in Notifications if you cancel this monitor/)
    expect(screen.getByTestId('creation-draft').textContent).not.toContain('account-password-value')

    fireEvent.click(screen.getByRole('button', { name: 'Previous step' }))
    fireEvent.click(screen.getByRole('button', { name: 'Previous step' }))
    fireEvent.click(screen.getByRole('link', { name: /Back to jobs/ }))
    expect(await screen.findByRole('dialog')).toHaveTextContent('A destination created from this flow is a separate resource')
    fireEvent.click(screen.getByRole('button', { name: 'Discard changes' }))
    await screen.findByText('Jobs list')
    fireEvent.click(screen.getByRole('link', { name: 'New monitor' }))
    await screen.findByRole('heading', { name: 'Choose targets' })
    expect(screen.getByLabelText(/^Monitor name/)).toHaveValue('')
    await goToSchedule()
    await waitFor(() => expect(screen.getByRole('checkbox', { name: /Operations/ })).toBeChecked())
  })

  it('keeps duplicate-name conflicts actionable without retrying the preview', async () => {
    vi.mocked(createJob).mockRejectedValueOnce(new APIError('Job name is already in use', 'conflict', {}, 409))
    renderJourney()
    await goToReview()
    fireEvent.click(screen.getByRole('button', { name: 'Create without starting' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Job name is already in use')
    expect(previewJob).toHaveBeenCalledTimes(1)
    expect(createJob).toHaveBeenCalledTimes(1)
    expect(screen.getByTestId('creation-draft').textContent).toContain('Public edge')
    expect(screen.getByRole('button', { name: 'Create without starting' })).toBeEnabled()
  })

  it('locks all draft edits and mode navigation while create is pending', async () => {
    let resolveCreate!: (value: Job) => void
    vi.mocked(createJob).mockImplementation(() => new Promise(resolve => { resolveCreate = resolve }))
    renderJourney()
    await goToReview()
    const submittedDraft = screen.getByTestId('creation-draft').textContent
    const submittedPayload = vi.mocked(previewJob).mock.calls.at(-1)![0]

    fireEvent.click(screen.getByRole('button', { name: 'Create without starting' }))
    await screen.findAllByRole('button', { name: 'Creating…' })
    expect(screen.getByRole('group', { name: 'Current monitor setup fields' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Schedule and alerts' })).toBeDisabled()
    fireEvent.click(screen.getByRole('link', { name: /Open full editor/ }))
    expect(screen.getByRole('heading', { name: 'Review and create' })).toBeInTheDocument()
    expect(screen.getByTestId('route-location')).toHaveTextContent('"path":"/jobs/new"')
    expect(screen.getByTestId('creation-draft').textContent).toBe(submittedDraft)
    expect(createJob).toHaveBeenCalledTimes(1)

    resolveCreate(returnedJob(submittedPayload))
    await screen.findByTestId('created-job')
    expect(createJob).toHaveBeenCalledTimes(1)
  })

  it('keeps an unknown guided create locked when switching to the advanced editor', async () => {
    let rejectCreate!: (error: unknown) => void
    vi.mocked(createJob).mockImplementationOnce(() => new Promise<Job>((_resolve, reject) => { rejectCreate = reject }))
    renderJourney()
    await goToReview()
    fireEvent.click(screen.getByRole('button', { name: 'Create without starting' }))
    await screen.findAllByRole('button', { name: 'Creating…' })
    const advancedLink = screen.getByRole('link', { name: /Open full editor/ })
    expect(advancedLink).toHaveAttribute('aria-disabled', 'true')
    fireEvent.click(advancedLink)
    expect(screen.getByTestId('route-location')).toHaveTextContent('"path":"/jobs/new"')

    rejectCreate(new TypeError('connection lost'))
    expect(await screen.findByText(/did not confirm whether this monitor was created/)).toBeInTheDocument()
    expect(createJob).toHaveBeenCalledTimes(1)
    await waitFor(() => expect(advancedLink).toHaveAttribute('aria-disabled', 'false'))

    fireEvent.click(advancedLink)
    await screen.findByRole('heading', { name: 'Create a monitoring job' })
    expect(screen.getByRole('button', { name: 'Create job' })).toBeDisabled()
    expect(screen.getByText(/create result is still unknown/)).toBeInTheDocument()
    expect(screen.getByTestId('creation-draft').textContent).toContain('Public edge')
    expect(createJob).toHaveBeenCalledTimes(1)
  })

  it('keeps an unknown advanced create locked when returning to guided setup', async () => {
    vi.mocked(createJob).mockRejectedValueOnce(new TypeError('connection lost'))
    renderJourney('/jobs/new/advanced')
    await screen.findByRole('heading', { name: 'Create a monitoring job' })
    fireEvent.change(screen.getByLabelText('Job name'), { target: { value: 'Advanced monitor' } })
    fireEvent.change(screen.getByLabelText('Target 1'), { target: { value: '198.51.100.20' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create job' }))
    expect(await screen.findByText(/did not confirm whether this job was created/)).toBeInTheDocument()
    expect(createJob).toHaveBeenCalledTimes(1)

    fireEvent.click(screen.getByRole('link', { name: /Back to guided setup/ }))
    await screen.findByRole('heading', { name: 'Choose targets' })
    await goToReview()
    expect(screen.getByText(/did not confirm whether this monitor was created/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Create without starting' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Create and start first scan' })).toBeDisabled()
    expect(createJob).toHaveBeenCalledTimes(1)
  })

  it('locks both modes when a successful create response has no job ID', async () => {
    vi.mocked(createJob).mockResolvedValueOnce({} as never)
    renderJourney('/jobs/new/advanced')
    await screen.findByRole('heading', { name: 'Create a monitoring job' })
    fireEvent.change(screen.getByLabelText('Job name'), { target: { value: 'Advanced monitor' } })
    fireEvent.change(screen.getByLabelText('Target 1'), { target: { value: '198.51.100.20' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create job' }))
    expect(await screen.findByText(/create response did not include a job ID/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Create job' })).toBeDisabled()
    expect(screen.getByTestId('creation-draft').textContent).toContain('Advanced monitor')
    expect(createJob).toHaveBeenCalledTimes(1)

    fireEvent.click(screen.getByRole('link', { name: /Back to guided setup/ }))
    await screen.findByRole('heading', { name: 'Choose targets' })
    await goToReview()
    expect(screen.getByText(/did not confirm whether this monitor was created/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Create without starting' })).toBeDisabled()
    expect(createJob).toHaveBeenCalledTimes(1)
  })

  it('allows saving an over-budget monitor without starting and disables first-scan dispatch', async () => {
    vi.mocked(previewJob).mockImplementation(async value => previewResponse(value, 40_000, { exceeded: true, estimated_probes: 40_000, limit: 10_000, approval_would_fit: true }))
    renderJourney()
    await goToSchedule()
    fireEvent.click(screen.getByRole('button', { name: 'Use no alerts' }))
    fireEvent.click(screen.getByRole('button', { name: /Review monitor/ }))
    await screen.findByRole('heading', { name: 'Review and create' })
    await waitFor(() => expect(screen.getByRole('button', { name: 'Create without starting' })).toBeEnabled())
    expect(screen.getByRole('button', { name: 'Create and start first scan' })).toBeDisabled()
    expect(screen.getByText(/administrator’s high-cost approval would allow the scan/i)).toBeInTheDocument()
  })

  it('disables first-scan dispatch when a current preview has no usable budget result', async () => {
    vi.mocked(previewJob).mockImplementation(async value => ({ ...previewResponse(value), scan_budget: undefined as unknown as JobPreview['scan_budget'] }))
    renderJourney()
    await goToReview()
    expect(screen.getByRole('button', { name: 'Create without starting' })).toBeEnabled()
    expect(screen.getByRole('button', { name: 'Create and start first scan' })).toBeDisabled()
    expect(screen.getByText(/did not confirm a scan budget/)).toBeInTheDocument()
  })

  it('ignores a superseded preview that finishes after the current draft preview', async () => {
    const pending: Array<{ resolve: (value: JobPreview) => void; payload: JobForm }> = []
    vi.mocked(previewJob).mockImplementation(value => new Promise(resolve => pending.push({ resolve, payload: value })) as Promise<JobPreview>)
    renderJourney()
    await goToSchedule()
    fireEvent.click(screen.getByRole('button', { name: 'Use no alerts' }))
    fireEvent.click(screen.getByRole('button', { name: /Review monitor/ }))
    await screen.findByRole('heading', { name: 'Review and create' })
    await waitFor(() => expect(pending).toHaveLength(1))

    fireEvent.click(screen.getByRole('button', { name: 'Schedule and alerts' }))
    fireEvent.change(screen.getByLabelText('Five-field cron'), { target: { value: '5 */4 * * *' } })
    fireEvent.click(screen.getByRole('button', { name: /Review monitor/ }))
    await waitFor(() => expect(pending).toHaveLength(2))
    pending[1].resolve(previewResponse(pending[1].payload, 222))
    await waitFor(() => expect(screen.getByText('222', { exact: true })).toBeInTheDocument())
    pending[0].resolve(previewResponse(pending[0].payload, 111))
    await waitFor(() => expect(screen.getByText('222', { exact: true })).toBeInTheDocument())
    expect(screen.queryByText('111', { exact: true })).not.toBeInTheDocument()
  })

  it('round-trips the whole draft through advanced mode, including profile revision and advanced-only fields', async () => {
    vi.mocked(listNotificationDestinations).mockResolvedValue({ destinations: [destination], status: { deployment: 0, managed: 1, active: 1, locked: 0, key_state: 'ready' } })
    renderJourney()
    await screen.findByRole('heading', { name: 'Choose targets' })
    fireEvent.change(screen.getByLabelText(/^Monitor name/), { target: { value: 'Keep every setting' } })
    fireEvent.change(screen.getByLabelText('Target 1'), { target: { value: 'edge.example' } })
    fireEvent.click(screen.getByRole('link', { name: /Open full editor/ }))
    await screen.findByRole('heading', { name: 'Create a monitoring job' })
    expect(screen.getByLabelText('Job name')).toHaveValue('Keep every setting')
    expect(screen.getByLabelText('Target 1')).toHaveValue('edge.example')

    fireEvent.change(screen.getByLabelText('Scanner profile'), { target: { value: 'profile-advanced' } })
    fireEvent.change(screen.getByLabelText('DNS comparison'), { target: { value: 'aggregate' } })
    fireEvent.change(screen.getByLabelText(/^Maximum expanded hosts/), { target: { value: '512' } })
    fireEvent.change(screen.getByLabelText(/^Timing profile/), { target: { value: 'fast' } })
    fireEvent.change(screen.getByLabelText(/^Scan timeout/), { target: { value: '2h' } })
    fireEvent.change(screen.getByLabelText(/^Resume window/), { target: { value: '12h' } })
    fireEvent.change(screen.getByLabelText(/^Baseline samples/), { target: { value: '3' } })
    fireEvent.change(screen.getByLabelText(/^Change confirmations/), { target: { value: '2' } })
    fireEvent.click(screen.getByLabelText(/Run on startup/))
    fireEvent.click(screen.getByLabelText(/Assume targets are alive/))
    fireEvent.click(screen.getByLabelText(/Allow high-cost scans/))
    fireEvent.click(screen.getByRole('link', { name: /Back to guided setup/ }))
    await screen.findByRole('heading', { name: 'Choose targets' })
    fireEvent.click(screen.getByRole('button', { name: /Continue to coverage/ }))
    fireEvent.click(screen.getByRole('radio', { name: /Selected TCP ports/ }))
    fireEvent.click(screen.getByRole('radio', { name: /Full TCP range/ }))
    expect(screen.getByText(/revision 7 is pinned/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /Continue to schedule/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Use no alerts' }))
    fireEvent.click(screen.getByRole('button', { name: /Review monitor/ }))
    await screen.findByRole('heading', { name: 'Review and create' })
    await waitFor(() => expect(previewJob).toHaveBeenCalled())

    const payload = vi.mocked(previewJob).mock.calls.at(-1)![0]
    expect(payload).toMatchObject({
      name: 'Keep every setting',
      targets: ['edge.example'],
      dns_comparison_mode: 'aggregate',
      max_expanded_hosts: 512,
      timing: 'fast',
      timeout: '2h',
      resume_window: '12h',
      baseline_samples: 3,
      change_confirmations: 2,
      run_on_start: true,
      assume_alive: false,
      allow_high_cost: true,
      tcp: { profile_id: 'profile-advanced', profile_revision: 7, engine: 'naabu_nmap', naabu: { rate: 1800 } },
      notification_destinations: [],
    })
    expect(screen.getByTestId('creation-draft').textContent).not.toContain('password')
    expect(screen.getByTestId('creation-draft').textContent).not.toContain('smtp')
  })

  it('creates and tests a destination in transient form state, then selects its ID', async () => {
    renderJourney()
    await goToSchedule()
    fireEvent.click(screen.getByRole('button', { name: 'Add destination' }))
    fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'New alerts' } })
    fireEvent.change(screen.getByLabelText('SMTP server'), { target: { value: 'smtp.example.test' } })
    fireEvent.change(screen.getByLabelText('From address'), { target: { value: 'edge@example.test' } })
    fireEvent.change(screen.getByLabelText(/^Recipients/), { target: { value: 'ops@example.test' } })
    fireEvent.change(screen.getByLabelText(/^Password confirmation/), { target: { value: 'correct horse battery staple' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save and select destination' }))
    await waitFor(() => expect(createNotificationDestination).toHaveBeenCalledWith('New alerts', expect.objectContaining({ provider: 'smtp' }), 'correct horse battery staple', true))
    await screen.findByText(/will remain in Notifications if you cancel this monitor/)
    expect(screen.getByLabelText(/^Password confirmation/)).toHaveValue('')
    expect(screen.getByLabelText(/^Name/)).toHaveValue('')
    expect(screen.getByTestId('creation-draft').textContent).toContain(destination.id)
    expect(screen.getByTestId('creation-draft').textContent).not.toContain('correct horse battery staple')

    fireEvent.click(screen.getByRole('button', { name: 'Test destination' }))
    await waitFor(() => expect(testNotificationDestination).toHaveBeenCalledWith(destination.id))
    expect(await screen.findByText(/Check that the message arrived/)).toBeInTheDocument()
  })

  it('does not offer first-scan start until the capability check succeeds', async () => {
    vi.mocked(scannerCapabilities).mockRejectedValue(new Error('capabilities unavailable'))
    renderJourney()
    await goToReview()
    expect(screen.getByRole('button', { name: 'Create without starting' })).toBeEnabled()
    expect(screen.getByRole('button', { name: 'Create and start first scan' })).toBeDisabled()
    expect(screen.getByText(/Scanner availability is unverified/)).toBeInTheDocument()
  })

  describe('Perimeter prefill', () => {
    it('applies a suggestion once under StrictMode, clears the router state, and marks the draft dirty', async () => {
      const perimeterPrefill = buildPerimeterPrefill(perimeterSuggestion(), '203.0.112.0/23', 0, 1)
      renderWithProviders(<StrictMode><TestJourney /></StrictMode>, { route: perimeterRoute({ perimeterPrefill }) })
      await screen.findByRole('heading', { name: 'Choose targets' })

      expect(await screen.findByText('Prefilled from Perimeter (203.0.112.0/23). A declared range is not an authorization: confirm you may scan these addresses.')).toBeInTheDocument()
      expect(screen.getByText(/Only add targets that you are authorized to scan/)).toBeInTheDocument()
      expect(screen.queryByText(/was not applied/)).not.toBeInTheDocument()
      expect(screen.getByLabelText(/^Monitor name/)).toHaveValue('Perimeter 203.0.112.0/24 +1 more · full TCP')
      expect(screen.getByLabelText('Target 1')).toHaveValue('203.0.112.0/24')
      expect(screen.getByLabelText('Target 2')).toHaveValue('203.0.113.64/27')
      expect(screen.getByLabelText(/^Maximum expanded hosts/)).toHaveValue(288)

      // One update, which marks the draft dirty, and the handoff is gone from
      // the history entry.
      await waitFor(() => expect(routeLocation()).toEqual({ path: '/jobs/new', state: null }))
      expect(guidedDraftUpdates).toEqual([undefined])
      const draft = creationDraft()
      expect(draft.fields.allow_high_cost).toBe(false)
      expect(draft.tcp).toStrictEqual(jobSettings(perimeterFullTCP))
      expect(draft.tcpFullSnapshot).toStrictEqual(jobSettings(perimeterFullTCP))
      expect(draft.tcpSelectedSnapshot).toBeUndefined()
      expect(draft.lastTCP).toBeUndefined()
      expect(draft.udp).toBeUndefined()
      expect(draft.lastUDP).toBeUndefined()

      // The leave guard protects the prefilled monitor, and an edit survives
      // the guided setup mounting again.
      fireEvent.click(screen.getByRole('link', { name: /Back to jobs/ }))
      expect(await screen.findByRole('dialog')).toHaveTextContent('Discard monitor changes?')
      fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
      fireEvent.change(screen.getByLabelText(/^Monitor name/), { target: { value: 'Edited perimeter monitor' } })
      fireEvent.click(screen.getByRole('link', { name: /Open full editor/ }))
      await screen.findByRole('heading', { name: 'Create a monitoring job' })
      // The full editor keeps the authorization warning of the prefill.
      expect(screen.getByText(/^Prefilled from Perimeter \(203\.0\.112\.0\/23\)/).closest('[role="status"]')).toBeInTheDocument()
      fireEvent.click(screen.getByRole('link', { name: /Back to guided setup/ }))
      await screen.findByRole('heading', { name: 'Choose targets' })
      expect(screen.getByLabelText(/^Monitor name/)).toHaveValue('Edited perimeter monitor')
      // The outcome lives with the draft, so the targets step still shows it.
      expect(screen.getByText(/^Prefilled from Perimeter \(203\.0\.112\.0\/23\)/)).toBeInTheDocument()
      expect(screen.queryByText(/was not applied/)).not.toBeInTheDocument()
    })

    it.each([
      {
        mode: 'full_tcp' as const,
        source: '203.0.112.0/23',
        suggestion: perimeterSuggestion(),
        maxExpandedHosts: 288,
        draft: { tcp: jobSettings(perimeterFullTCP), tcpFullSnapshot: jobSettings(perimeterFullTCP), tcpSelectedSnapshot: undefined, lastTCP: undefined, udp: undefined, lastUDP: undefined },
      },
      {
        mode: 'selected_tcp' as const,
        source: '198.18.0.0/15',
        suggestion: perimeterSuggestion({ mode: 'selected_tcp', targets: ['198.18.0.0/20'], addresses: 4096, estimated_probes: 24_576, protocol: perimeterSelectedTCP }),
        maxExpandedHosts: 4096,
        draft: { tcp: jobSettings(perimeterSelectedTCP), tcpFullSnapshot: defaultTCP(), tcpSelectedSnapshot: jobSettings(perimeterSelectedTCP), lastTCP: undefined, udp: undefined, lastUDP: undefined },
      },
      {
        // A suggestion smaller than the default expansion limit keeps it.
        mode: 'udp' as const,
        source: '192.0.2.0/24',
        suggestion: perimeterSuggestion({ mode: 'udp', targets: ['192.0.2.64/26'], addresses: 64, estimated_probes: 768, protocol: perimeterUDP }),
        maxExpandedHosts: 256,
        draft: { tcp: undefined, tcpFullSnapshot: defaultTCP(), tcpSelectedSnapshot: undefined, lastTCP: defaultTCP(), udp: jobSettings(perimeterUDP), lastUDP: undefined },
      },
    ])('applies the returned $mode protocol verbatim and previews it unchanged', async ({ mode, source, suggestion, maxExpandedHosts, draft: expected }) => {
      const perimeterPrefill = buildPerimeterPrefill(suggestion, source, 0, 1)
      renderWithProviders(<TestJourney />, { route: perimeterRoute({ perimeterPrefill }) })
      await screen.findByText(`Prefilled from Perimeter (${source}). A declared range is not an authorization: confirm you may scan these addresses.`)
      await waitFor(() => expect(routeLocation().state).toBeNull())

      const draft = creationDraft()
      expect(draft.fields.name).toBe(perimeterPrefill.name)
      expect(draft.targets).toEqual(suggestion.targets)
      expect(draft.fields.max_expanded_hosts).toBe(maxExpandedHosts)
      expect(draft.fields.allow_high_cost).toBe(false)
      for (const field of ['tcp', 'tcpFullSnapshot', 'tcpSelectedSnapshot', 'lastTCP', 'udp', 'lastUDP'] as const) {
        expect(draft[field], field).toStrictEqual(expected[field])
      }

      fireEvent.click(screen.getByRole('button', { name: /Continue to coverage/ }))
      await screen.findByRole('heading', { name: 'Set scan coverage' })
      if (mode === 'udp') {
        expect(screen.getByRole('checkbox', { name: /Include TCP/ })).not.toBeChecked()
        expect(screen.getByLabelText(/^UDP ports/)).toHaveValue(perimeterUDP.ports)
        // TCP comes back as a new draft's full range, and leaves again.
        fireEvent.click(screen.getByRole('checkbox', { name: /Include TCP/ }))
        expect(screen.getByRole('radio', { name: /Full TCP range/ })).toBeChecked()
        fireEvent.click(screen.getByRole('checkbox', { name: /Include TCP/ }))
      } else {
        expect(screen.getByRole('checkbox', { name: /Include UDP/ })).not.toBeChecked()
        if (mode === 'selected_tcp') {
          expect(screen.getByLabelText(/^TCP ports/)).toHaveValue(perimeterSelectedTCP.ports)
          fireEvent.click(screen.getByRole('radio', { name: /Full TCP range/ }))
          expect(creationDraft().tcp).toStrictEqual(defaultTCP())
          fireEvent.click(screen.getByRole('radio', { name: /Selected TCP ports/ }))
          expect(screen.getByLabelText(/^TCP ports/)).toHaveValue(perimeterSelectedTCP.ports)
        } else {
          expect(screen.getByRole('radio', { name: /Full TCP range/ })).toBeChecked()
        }
      }
      fireEvent.click(screen.getByRole('button', { name: /Continue to schedule/ }))
      await screen.findByRole('heading', { name: 'Set schedule and alerts' })
      fireEvent.click(screen.getByRole('button', { name: 'Use no alerts' }))
      fireEvent.click(screen.getByRole('button', { name: /Review monitor/ }))
      await screen.findByRole('heading', { name: 'Review and create' })
      await waitFor(() => expect(previewJob).toHaveBeenCalled())

      const payload = vi.mocked(previewJob).mock.calls.at(-1)![0]
      expect(payload).toMatchObject({ name: perimeterPrefill.name, targets: suggestion.targets, max_expanded_hosts: maxExpandedHosts, allow_high_cost: false })
      expect(payload.tcp).toEqual(expected.tcp)
      expect(payload.udp).toEqual(expected.udp)
      expect(createJob).not.toHaveBeenCalled()
    })

    it('raises the Full TCP setup timeout to its probe-rate lower bound when it fits the resume window', async () => {
      const suggestion = perimeterSuggestion({
        targets: ['198.51.100.0/24'],
        addresses: 256,
        estimated_probes: 16_776_960,
        minimum_duration_seconds: 16_777,
      })
      const perimeterPrefill = buildPerimeterPrefill(suggestion, '198.51.100.0/24', 0, 1)
      renderWithProviders(<TestJourney />, { route: perimeterRoute({ perimeterPrefill }) })
      await screen.findByRole('heading', { name: 'Choose targets' })

      expect(creationDraft().fields.timeout).toBe('4h40m')
      expect(creationDraft().fields.resume_window).toBe('8d')
    })

    it('keeps the current timeout when the Full TCP lower bound exceeds the configured resume window', async () => {
      const suggestion = perimeterSuggestion({
        targets: ['198.51.100.0/24'],
        addresses: 256,
        estimated_probes: 256 * 65_535,
        minimum_duration_seconds: 700_000,
      })
      const perimeterPrefill = buildPerimeterPrefill(suggestion, '198.51.100.0/24', 0, 1)
      renderWithProviders(<TestJourney />, { route: perimeterRoute({ perimeterPrefill }) })
      await screen.findByRole('heading', { name: 'Choose targets' })

      expect(creationDraft().fields.timeout).toBe('1h')
      expect(creationDraft().fields.resume_window).toBe('8d')
    })

    it('never overwrites a draft that already has changes, and says why', async () => {
      const perimeterPrefill = buildPerimeterPrefill(perimeterSuggestion(), '203.0.112.0/23', 0, 1)
      renderWithProviders(<TestJourney editedDraft />, { route: perimeterRoute({ perimeterPrefill }) })
      await screen.findByRole('heading', { name: 'Choose targets' })

      expect(await screen.findByText('The Perimeter suggestion for 203.0.112.0/23 was not applied, because this monitor draft already has changes. Finish or discard this draft, then choose Create monitor again.')).toBeInTheDocument()
      expect(screen.queryByText(/Prefilled from Perimeter/)).not.toBeInTheDocument()
      expect(screen.getByLabelText(/^Monitor name/)).toHaveValue('Hand-edited monitor')
      expect(screen.getByLabelText('Target 1')).toHaveValue('198.51.100.7')
      expect(screen.getByLabelText(/^Maximum expanded hosts/)).toHaveValue(256)
      await waitFor(() => expect(routeLocation()).toEqual({ path: '/jobs/new', state: null }))
      expect(guidedDraftUpdates).toEqual([])
      expect(creationDraft().tcp).toStrictEqual(defaultTCP())
    })

    it.each([
      { label: 'a protocol of the wrong kind for its mode', state: { perimeterPrefill: { ...buildPerimeterPrefill(perimeterSuggestion(), '203.0.112.0/23', 0, 1), protocol: perimeterUDP } } },
      { label: 'no targets', state: { perimeterPrefill: { ...buildPerimeterPrefill(perimeterSuggestion(), '203.0.112.0/23', 0, 1), targets: [] } } },
      { label: 'a name that is not a job name', state: { perimeterPrefill: { ...buildPerimeterPrefill(perimeterSuggestion(), '203.0.112.0/23', 0, 1), name: 'Perimeter\tedge' } } },
      { label: 'unrelated state', state: { from: '/perimeter' } },
    ])('ignores router state with $label', async ({ state }) => {
      renderWithProviders(<TestJourney />, { route: perimeterRoute(state) })
      await screen.findByRole('heading', { name: 'Choose targets' })

      expect(screen.getByLabelText(/^Monitor name/)).toHaveValue('')
      expect(screen.getByLabelText('Target 1')).toHaveValue('')
      expect(screen.queryByText(/Prefilled from Perimeter|was not applied/)).not.toBeInTheDocument()
      expect(guidedDraftUpdates).toEqual([])
      expect(routeLocation()).toEqual({ path: '/jobs/new', state })
      // The draft is still clean, so leaving needs no confirmation.
      fireEvent.click(screen.getByRole('link', { name: /Back to jobs/ }))
      await screen.findByText('Jobs list')
    })
  })
})
