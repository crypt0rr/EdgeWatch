/** @vitest-environment jsdom */

import { fireEvent, screen, waitFor } from '@testing-library/react'
import { Link, Route, Routes, useLocation } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { APIError, BUILTIN_NAABU_PROFILE_ID, createJob, createNotificationDestination, getJob, getSession, listNotificationDestinations, listScannerProfiles, previewJob, scannerCapabilities, scheduleSuggestion, testNotificationDestination, updateJob } from '../api'
import type { NotificationDestination } from '../api'
import type { Job, JobForm, JobPreview } from '../types'
import { JobCreationDraftProvider, useOptionalJobCreationDraft } from '../job-creation-draft'
import { consumeFirstScanIntent } from '../firstScanIntent'
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

const destination: NotificationDestination = { id: 'destination-1', name: 'Operations', provider: 'smtp', source: 'web', enabled: true, locked: false, read_only: false, revision: 1 }
const session = { role: 'administrator' as const, user_id: 'admin', username: 'admin', permissions: ['jobs.write', 'jobs.read', 'users.manage', 'notifications.manage'], high_cost_override: true, csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 }, scope: 'unit' as const, unit: { id: 'unit-1', name: 'Unit', slug: 'unit' }, multi_unit: false }
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

function CreationRoutes() {
  return <JobCreationDraftProvider><DraftProbe /><Routes>
    <Route index element={<MonitorSetup />} />
    <Route path="advanced" element={<JobEditor />} />
    <Route path="*" element={<div>Unknown creation path</div>} />
  </Routes></JobCreationDraftProvider>
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

function TestJourney() {
  return <>
    <PathProbe />
    <Routes>
      <Route path="/jobs/new/*" element={<CreationRoutes />} />
      <Route path="/jobs/:id" element={<div data-testid="created-job">Created job</div>} />
      <Route path="/jobs" element={<div>Jobs list <Link to="/jobs/new">New monitor</Link></div>} />
    </Routes>
  </>
}

function renderJourney(route = '/jobs/new') {
  return renderWithProviders(<TestJourney />, { route: [route] })
}

async function goToSchedule() {
  await screen.findByRole('heading', { name: 'Choose targets' })
  fireEvent.change(screen.getByLabelText(/^Monitor name/), { target: { value: 'Public edge' } })
  fireEvent.change(screen.getByLabelText('Target 1'), { target: { value: '198.51.100.20' } })
  fireEvent.click(screen.getByRole('button', { name: /Continue to coverage/ }))
  await screen.findByRole('heading', { name: 'Set scan coverage' })
  fireEvent.click(screen.getByRole('button', { name: /Continue to schedule/ }))
  await screen.findByRole('heading', { name: 'Set schedule and alerts' })
}

async function goToReview() {
  await goToSchedule()
  fireEvent.click(screen.getByRole('button', { name: 'Continue without alerts' }))
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
    window.history.replaceState(null, '', '/')
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
    fireEvent.click(screen.getByRole('button', { name: 'Continue without alerts' }))
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
    fireEvent.click(screen.getByRole('button', { name: 'Continue without alerts' }))
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
    fireEvent.click(screen.getByRole('button', { name: 'Continue without alerts' }))
    expect(screen.getByText(/This monitor will not send notifications/)).toBeInTheDocument()
    expect(screen.queryByText(/A selected destination is paused or locked/)).not.toBeInTheDocument()
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
    vi.mocked(createJob).mockRejectedValueOnce(new TypeError('connection lost'))
    renderJourney()
    await goToReview()
    fireEvent.click(screen.getByRole('button', { name: 'Create without starting' }))
    expect(await screen.findByText(/did not confirm whether this monitor was created/)).toBeInTheDocument()
    expect(createJob).toHaveBeenCalledTimes(1)

    fireEvent.click(screen.getByRole('link', { name: /Open full editor/ }))
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
    fireEvent.click(screen.getByRole('button', { name: 'Continue without alerts' }))
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
    fireEvent.click(screen.getByRole('button', { name: 'Continue without alerts' }))
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
    fireEvent.click(screen.getByRole('button', { name: 'Continue without alerts' }))
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
})
