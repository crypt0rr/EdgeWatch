/** @vitest-environment jsdom */

import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { act } from 'react'
import { BrowserRouter, Link, Route, Routes } from 'react-router-dom'
import { QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { APIError, BUILTIN_NAABU_PROFILE_ID, createJob, getJob, getSession, listNotificationDestinations, listScannerProfiles, scannerCapabilities, scheduleSuggestion, updateJob } from '../api'
import { createTestClient, renderWithProviders, defaultUnitScope } from '../test/test-utils'
import { setDisplayTimeZone } from '../format'
import { JobEditor } from './JobEditor'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return { ...actual, createJob: vi.fn(), getJob: vi.fn(), getSession: vi.fn(), listNotificationDestinations: vi.fn(), listScannerProfiles: vi.fn(), scannerCapabilities: vi.fn(), scheduleSuggestion: vi.fn(), updateJob: vi.fn() }
})

const destinationResponse = {
  destinations: [{ id: 'notify-1', name: 'Mattermost', provider: 'mattermost', source: 'web', enabled: true, locked: false, revision: 1 }],
  status: { deployment: 0, managed: 1, active: 1, locked: 0, key_state: 'ready' },
}
const capabilities = { engines: ['nmap', 'naabu_nmap'], nmap: { available: true, path: '/usr/bin/nmap', version: '7.99' }, naabu: { available: true, path: '/usr/local/bin/naabu', version: '2.6.1', syn_supported: false } }
const administrator = { role: 'administrator' as const, user_id: 'admin', username: 'admin', permissions: ['jobs.write', 'jobs.delete', 'users.manage'], csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 }, ...defaultUnitScope }
const operator = { ...administrator, role: 'operator' as const, user_id: 'operator', username: 'operator', permissions: ['jobs.write'] }
const approvedJob = { id: 'job-1', revision: 4, enabled: true, archived: false, security_hash: 'old', job: { name: 'Broad edge', schedule: '0 */6 * * *', timezone: 'UTC', targets: ['198.51.100.0/16'], max_expanded_hosts: 65536, tcp: { ports: '1-65535', mode: 'connect', service_detection: false, engine: 'nmap' }, timing: 'balanced', timeout: '1h', resume_window: '8d', baseline_samples: 1, change_confirmations: 1, allow_high_cost: true }, baseline: { status: 'complete', samples: 1, attempts: 1 } }
const profile = { id: 'profile-1', name: 'Naabu default', description: '', built_in: true, archived: false, revision: 1, definition: { engine: 'naabu_nmap', naabu: { scan_type: 'connect', rate: 1000, workers: 25, retries: 3, timeout_ms: 1000, warm_up_seconds: 2, verify: true, address_batch_size: 16 }, nmap_args: [], naabu_args: [], enrichment_args: [] } }

describe('job editor workflow coverage', () => {
  beforeEach(() => {
    vi.mocked(listNotificationDestinations).mockResolvedValue(destinationResponse as never)
    vi.mocked(listScannerProfiles).mockResolvedValue({ profiles: [profile] } as never)
    vi.mocked(scannerCapabilities).mockResolvedValue(capabilities as never)
    vi.mocked(createJob).mockResolvedValue({} as never)
    vi.mocked(updateJob).mockResolvedValue({} as never)
    vi.mocked(scheduleSuggestion).mockResolvedValue({ suggested: false, gap_minutes: 60 })
    vi.mocked(getSession).mockResolvedValue(administrator)
  })
  afterEach(() => {
    vi.clearAllMocks()
    window.history.replaceState(null, '', '/')
  })

  it('retries notification-destination loading without changing the new-job form', async () => {
    vi.mocked(listNotificationDestinations).mockRejectedValueOnce(new Error('notification store unavailable'))
    renderWithProviders(<JobEditor />, { route: ['/jobs/new'] })
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Create a monitoring job' })).toBeInTheDocument())
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Notification destinations could not be loaded.'))
    expect(screen.getByLabelText('Job name')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    await waitFor(() => expect(screen.getByRole('checkbox', { name: /Mattermost/ })).toBeInTheDocument())
    expect(screen.getByLabelText('Job name')).toBeInTheDocument()
  })

  it('does not replace notification routing with an empty selection when destinations fail to load', async () => {
    vi.mocked(listNotificationDestinations).mockRejectedValue(new Error('notification store unavailable'))
    renderWithProviders(<JobEditor />, { route: ['/jobs/new'] })
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Create a monitoring job' })).toBeInTheDocument())
    fireEvent.change(screen.getByLabelText('Job name'), { target: { value: 'Preserve routing' } })
    fireEvent.change(screen.getByLabelText('Target 1'), { target: { value: '198.51.100.10' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create job' }))
    await waitFor(() => expect(createJob).toHaveBeenCalled())
    expect(vi.mocked(createJob).mock.calls[0][0].notification_destinations).toBeUndefined()
  })

  it('shows the server rejection of host discovery with Naabu connect discovery next to the toggle', async () => {
    const message = 'job Public edge: Naabu connect discovery cannot use host discovery; keep assume_alive enabled, choose a Naabu SYN profile, or use Nmap only'
    vi.mocked(createJob).mockRejectedValueOnce(new APIError(message, 'validation_failed', { assume_alive: message }, 400))
    renderWithProviders(<JobEditor />, { route: ['/jobs/new'] })
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Create a monitoring job' })).toBeInTheDocument())
    fireEvent.change(screen.getByLabelText('Job name'), { target: { value: 'Public edge' } })
    fireEvent.change(screen.getByLabelText('Target 1'), { target: { value: '198.51.100.10' } })
    const toggle = screen.getByLabelText(/Assume targets are alive/)
    fireEvent.click(toggle)
    fireEvent.click(screen.getByRole('button', { name: 'Create job' }))
    await waitFor(() => expect(createJob).toHaveBeenCalled())
    expect(vi.mocked(createJob).mock.calls[0][0].assume_alive).toBe(false)
    const label = toggle.closest('label') as HTMLElement
    await waitFor(() => expect(within(label).getByText(message)).toHaveClass('field-error'))
  })

  it('creates a Naabu job with startup disabled and explicit empty notification routing', async () => {
    renderWithProviders(<JobEditor />, { route: ['/jobs/new'] })
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Create a monitoring job' })).toBeInTheDocument())
    fireEvent.change(screen.getByLabelText('Job name'), { target: { value: 'Public edge' } })
    fireEvent.change(screen.getByLabelText('Target 1'), { target: { value: '198.51.100.10' } })
    expect(screen.getByLabelText(/Run on startup/)).not.toBeChecked()
    expect(screen.getByLabelText('DNS comparison')).toHaveValue('address_sensitive')
    expect(screen.getByLabelText(/^TCP engine/)).toHaveValue('naabu_nmap')
    expect(screen.getByLabelText(/^Ports/)).toHaveValue('1-65535')
    const notification = screen.getByRole('checkbox', { name: /Mattermost/ }) as HTMLInputElement
    expect(notification).toBeChecked()
    fireEvent.click(notification)
    expect(notification).not.toBeChecked()
    fireEvent.click(screen.getByRole('button', { name: 'Create job' }))
    await waitFor(() => expect(createJob).toHaveBeenCalled())
    const payload = vi.mocked(createJob).mock.calls[0][0]
    expect(payload).toMatchObject({ name: 'Public edge', targets: ['198.51.100.10'], run_on_start: false, notification_destinations: [], tcp: { engine: 'naabu_nmap', ports: '1-65535' } })
  })

  it('submits aggregate DNS comparison explicitly and explains its reduced alert coverage', async () => {
    renderWithProviders(<JobEditor />, { route: ['/jobs/new'] })
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Create a monitoring job' })).toBeInTheDocument())
    fireEvent.change(screen.getByLabelText('Job name'), { target: { value: 'Rotating DNS service' } })
    fireEvent.change(screen.getByLabelText('Target 1'), { target: { value: 'edge.example' } })
    expect(screen.getByText(/a port that opens or closes on one address alerts even while another address exposes it/)).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('DNS comparison'), { target: { value: 'aggregate' } })
    expect(screen.getByText(/Address rotation, individual backend reachability, and a port that opens or closes on one address while another address exposes it will not alert/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Create job' }))

    await waitFor(() => expect(createJob).toHaveBeenCalled())
    expect(vi.mocked(createJob).mock.calls[0][0]).toMatchObject({
      targets: ['edge.example'],
      dns_comparison_mode: 'aggregate',
    })
  })

  it('keeps the built-in Naabu profile selectable when profile listing is unavailable', async () => {
    vi.mocked(listScannerProfiles).mockRejectedValue(new Error('profile service unavailable'))
    const { client } = renderWithProviders(<JobEditor />, { route: ['/jobs/new'] })
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Create a monitoring job' })).toBeInTheDocument())
    await waitFor(() => expect(client.getQueryState(['scanner-profiles'])?.status).toBe('error'))

    fireEvent.change(screen.getByLabelText(/^TCP engine/), { target: { value: 'nmap' } })
    fireEvent.change(screen.getByLabelText(/^TCP engine/), { target: { value: 'naabu_nmap' } })
    fireEvent.change(screen.getByLabelText('Job name'), { target: { value: 'Fallback profile' } })
    fireEvent.change(screen.getByLabelText('Target 1'), { target: { value: '198.51.100.10' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create job' }))

    await waitFor(() => expect(createJob).toHaveBeenCalled())
    expect(vi.mocked(createJob).mock.calls[0][0].tcp).toMatchObject({ engine: 'naabu_nmap', profile_id: BUILTIN_NAABU_PROFILE_ID })
    expect(vi.mocked(createJob).mock.calls[0][0].tcp?.profile_revision).toBeUndefined()
  })

  it('limits job-level scanner tuning to fields enabled by the selected profile', async () => {
    vi.mocked(listScannerProfiles).mockResolvedValue({ profiles: [{
      ...profile,
      id: BUILTIN_NAABU_PROFILE_ID,
      definition: { ...profile.definition, operator_adjustable: ['rate'], operator_bounds: { rate: { min: 100, max: 2000 } } },
    }] } as never)
    renderWithProviders(<JobEditor />, { route: ['/jobs/new'] })
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Create a monitoring job' })).toBeInTheDocument())
    await waitFor(() => expect(screen.getByLabelText(/^Rate/)).toBeEnabled())

    expect(screen.getByLabelText(/^Workers/)).toBeDisabled()
    expect(screen.getByRole('checkbox', { name: /Verify discoveries/ })).toBeDisabled()
    fireEvent.change(screen.getByLabelText(/^Rate/), { target: { value: '1500' } })
    fireEvent.change(screen.getByLabelText('Job name'), { target: { value: 'Bounded operator tuning' } })
    fireEvent.change(screen.getByLabelText('Target 1'), { target: { value: '198.51.100.10' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create job' }))

    await waitFor(() => expect(createJob).toHaveBeenCalled())
    expect(vi.mocked(createJob).mock.calls[0][0].tcp).toMatchObject({ profile_id: BUILTIN_NAABU_PROFILE_ID, naabu: { rate: 1500, workers: 25, verify: true } })
  })

  it('uses the selected profile bounds and shows a rejected value next to its field', async () => {
    vi.mocked(listScannerProfiles).mockResolvedValue({ profiles: [{
      ...profile,
      id: BUILTIN_NAABU_PROFILE_ID,
      definition: { ...profile.definition, operator_adjustable: ['rate'], operator_bounds: { rate: { min: 100, max: 2000 } } },
    }] } as never)
    const message = 'naabu rate must be between 100 and 2000'
    vi.mocked(createJob).mockRejectedValueOnce(new APIError(message, 'validation_failed', { rate: message }, 400))
    renderWithProviders(<JobEditor />, { route: ['/jobs/new'] })
    await waitFor(() => expect(screen.getByLabelText(/^Rate/)).toBeEnabled())
    const rate = screen.getByLabelText(/^Rate/)
    expect(rate).toHaveAttribute('min', '100')
    expect(rate).toHaveAttribute('max', '2000')
    expect(rate.closest('label')).toHaveTextContent('100–2000')

    // The browser refuses values outside min/max before submitting. The
    // server still has the final say, for example for a pinned revision.
    fireEvent.change(rate, { target: { value: '1500' } })
    fireEvent.change(screen.getByLabelText('Job name'), { target: { value: 'Out of bounds' } })
    fireEvent.change(screen.getByLabelText('Target 1'), { target: { value: '198.51.100.10' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create job' }))
    await waitFor(() => expect(rate.closest('label')?.querySelector('.field-error')).toHaveTextContent(message))
  })

  it('keeps discovery tuning disabled until the scanner profiles load', async () => {
    let resolveProfiles: (value: unknown) => void = () => {}
    vi.mocked(listScannerProfiles).mockReturnValue(new Promise(resolve => { resolveProfiles = resolve }) as never)
    renderWithProviders(<JobEditor />, { route: ['/jobs/new'] })
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Create a monitoring job' })).toBeInTheDocument())
    expect(screen.getByLabelText(/^Rate/)).toBeDisabled()
    expect(screen.getByLabelText('Discovery type')).toBeDisabled()
    expect(screen.getByText(/Loading scanner profiles/)).toBeInTheDocument()

    await act(async () => resolveProfiles({ profiles: [{ ...profile, id: BUILTIN_NAABU_PROFILE_ID, definition: { ...profile.definition, operator_adjustable: ['rate'], operator_bounds: { rate: { min: 100, max: 2000 } } } }] }))
    await waitFor(() => expect(screen.getByLabelText(/^Rate/)).toBeEnabled())
    expect(screen.getByLabelText(/^Workers/)).toBeDisabled()
  })

  it('keeps discovery tuning disabled and offers a retry when the scanner profiles fail to load', async () => {
    vi.mocked(listScannerProfiles).mockRejectedValueOnce(new Error('profiles unavailable'))
    renderWithProviders(<JobEditor />, { route: ['/jobs/new'] })
    const retry = await screen.findByRole('button', { name: 'Retry' })
    expect(screen.getByText(/Scanner profiles could not be loaded/)).toBeInTheDocument()
    for (const label of [/^Rate/, /^Workers/, /^Retries/]) expect(screen.getByLabelText(label)).toBeDisabled()

    vi.mocked(listScannerProfiles).mockResolvedValue({ profiles: [{ ...profile, id: BUILTIN_NAABU_PROFILE_ID, definition: { ...profile.definition, operator_adjustable: ['rate'], operator_bounds: { rate: { min: 100, max: 2000 } } } }] } as never)
    fireEvent.click(retry)
    await waitFor(() => expect(screen.getByLabelText(/^Rate/)).toBeEnabled())
  })

  it('restores a protocol’s settings when it is switched off and on again', async () => {
    renderWithProviders(<JobEditor />, { route: ['/jobs/new'] })
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Create a monitoring job' })).toBeInTheDocument())
    fireEvent.change(screen.getByLabelText(/^TCP engine/), { target: { value: 'nmap' } })
    fireEvent.change(screen.getByLabelText(/^Ports/), { target: { value: '22,443' } })
    fireEvent.click(screen.getByLabelText(/TCP scan/))
    expect(screen.queryByLabelText(/^TCP engine/)).not.toBeInTheDocument()
    fireEvent.click(screen.getByLabelText(/TCP scan/))
    expect(screen.getByLabelText(/^TCP engine/)).toHaveValue('nmap')
    expect(screen.getByLabelText(/^Ports/)).toHaveValue('22,443')
  })

  it('shows saved durations in the units the editor suggests and saves them unchanged', async () => {
    vi.mocked(getJob).mockResolvedValue({ ...approvedJob, job: { ...approvedJob.job, timeout: '1h30m0s', resume_window: '192h0m0s' } } as never)
    vi.mocked(updateJob).mockResolvedValue({ ...approvedJob, revision: 5 } as never)
    renderWithProviders(<Routes><Route path="/jobs/:id/edit" element={<JobEditor />} /><Route path="/jobs/:id" element={<p>Job page</p>} /></Routes>, { route: ['/jobs/job-1/edit'] })
    await waitFor(() => expect(screen.getByLabelText(/^Scan timeout/)).toHaveValue('1h30m'))
    expect(screen.getByLabelText(/^Resume window/)).toHaveValue('8d')

    fireEvent.click(screen.getByRole('button', { name: 'Save changes' }))
    await waitFor(() => expect(updateJob).toHaveBeenCalled())
    expect(vi.mocked(updateJob).mock.calls[0][2]).toMatchObject({ timeout: '1h30m', resume_window: '8d' })
  })

  it('applies a newer scanner-profile revision only after an explicit choice', async () => {
    const currentProfile = {
      ...profile,
      id: BUILTIN_NAABU_PROFILE_ID,
      revision: 2,
      definition: { ...profile.definition, naabu: { ...profile.definition.naabu, rate: 2500 }, operator_adjustable: ['rate'] },
    }
    const saved = {
      ...approvedJob,
      job: {
        ...approvedJob.job,
        tcp: {
          ports: '1-65535', mode: 'connect', service_detection: false, engine: 'naabu_nmap',
          profile_id: BUILTIN_NAABU_PROFILE_ID, profile_revision: 1, profile_update_available: true, profile_latest_revision: 2,
          naabu: { scan_type: 'connect', rate: 1000, workers: 25, retries: 3, timeout_ms: 1000, warm_up_seconds: 2, verify: true, address_batch_size: 16 },
        },
      },
    }
    vi.mocked(getJob).mockResolvedValue(saved as never)
    vi.mocked(listScannerProfiles).mockResolvedValue({ profiles: [currentProfile] } as never)
    vi.mocked(updateJob).mockResolvedValue({ ...saved, revision: 5 } as never)
    renderWithProviders(<Routes><Route path="/jobs/:id/edit" element={<JobEditor />} /></Routes>, { route: ['/jobs/job-1/edit'] })

    fireEvent.click(await screen.findByRole('button', { name: 'Apply latest profile' }))
    expect(screen.getByLabelText(/^Rate/)).toHaveValue(2500)
    expect(screen.queryByRole('button', { name: 'Apply latest profile' })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Save changes' }))
    await waitFor(() => expect(updateJob).toHaveBeenCalled())
    expect(vi.mocked(updateJob).mock.calls[0][2].tcp).toMatchObject({ profile_id: BUILTIN_NAABU_PROFILE_ID, profile_revision: 2, naabu: { rate: 2500 } })
  })

  it('defaults a new job to the deployment timezone from the session', async () => {
    setDisplayTimeZone('Asia/Kathmandu')
    try {
      renderWithProviders(<JobEditor />, { route: ['/jobs/new'] })
      await waitFor(() => expect(screen.getByRole('heading', { name: 'Create a monitoring job' })).toBeInTheDocument())
      expect(screen.getByLabelText(/^Timezone/)).toHaveValue('Asia/Kathmandu')
      await waitFor(() => expect(scheduleSuggestion).toHaveBeenCalledWith('0 */6 * * *', 'Asia/Kathmandu'))
    } finally {
      setDisplayTimeZone(undefined)
    }
  })

  it("defaults a new job to the browser's timezone without a deployment timezone", async () => {
    renderWithProviders(<JobEditor />, { route: ['/jobs/new'] })
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Create a monitoring job' })).toBeInTheDocument())
    expect(screen.getByLabelText(/^Timezone/)).toHaveValue(Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC')
  })

  it('validates target/protocol requirements before sending a request', async () => {
    renderWithProviders(<JobEditor />, { route: ['/jobs/new'] })
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Create a monitoring job' })).toBeInTheDocument())
    fireEvent.change(screen.getByLabelText('Job name'), { target: { value: 'Invalid job' } })
    fireEvent.change(screen.getByLabelText('Target 1'), { target: { value: '198.51.100.10' } })
    fireEvent.click(screen.getByLabelText(/TCP scan/))
    fireEvent.click(screen.getByRole('button', { name: 'Create job' }))
    await waitFor(() => expect(screen.getAllByText('Enable TCP, UDP, or both scan types.').length).toBeGreaterThan(0))
    expect(createJob).not.toHaveBeenCalled()

    fireEvent.click(screen.getByLabelText(/TCP scan/))
    fireEvent.click(screen.getByRole('button', { name: 'Add target' }))
    fireEvent.change(screen.getByLabelText('Target 2'), { target: { value: '198.51.100.10' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create job' }))
    await waitFor(() => expect(screen.getAllByText(/listed more than once/).length).toBeGreaterThan(0))
    expect(createJob).not.toHaveBeenCalled()
  })

  it('shows the schedule stagger suggestion and applies the recommended time', async () => {
    vi.mocked(scheduleSuggestion).mockResolvedValue({ suggested: true, suggested_schedule: '30 */6 * * *', offset_minutes: 30, gap_minutes: 0, nearest: { id: 'job-2', name: 'Existing job', schedule: '0 */6 * * *', timezone: 'UTC', next_run: '2026-09-13T12:00:00Z' } })
    renderWithProviders(<JobEditor />, { route: ['/jobs/new'] })
    await act(async () => {
      await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('Stagger scheduled scans'), { timeout: 2000 })
    })
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /Use later time/ }))
      await Promise.resolve()
    })
    expect(screen.getByLabelText(/^Five-field cron/)).toHaveValue('30 */6 * * *')
  })

  it('focuses the cron editor when Custom cron is selected', async () => {
    renderWithProviders(<JobEditor />, { route: ['/jobs/new'] })
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Create a monitoring job' })).toBeInTheDocument())

    fireEvent.change(screen.getByLabelText('Preset'), { target: { value: 'custom' } })

    expect(screen.getByLabelText(/^Five-field cron/)).toHaveFocus()
  })

  it('applies a standard schedule preset to the cron field', async () => {
    renderWithProviders(<JobEditor />, { route: ['/jobs/new'] })
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Create a monitoring job' })).toBeInTheDocument())

    fireEvent.change(screen.getByLabelText('Preset'), { target: { value: '0 * * * *' } })

    expect(screen.getByLabelText(/^Five-field cron/)).toHaveValue('0 * * * *')
  })

  it('does not turn a cleared Naabu numeric field into zero', async () => {
    const fields = ['rate', 'workers', 'retries', 'timeout_ms', 'warm_up_seconds', 'address_batch_size']
    vi.mocked(listScannerProfiles).mockResolvedValue({ profiles: [{
      ...profile,
      id: BUILTIN_NAABU_PROFILE_ID,
      definition: { ...profile.definition, operator_adjustable: fields, operator_bounds: Object.fromEntries(fields.map(field => [field, { min: 0, max: 100000 }])) },
    }] } as never)
    renderWithProviders(<JobEditor />, { route: ['/jobs/new'] })
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Create a monitoring job' })).toBeInTheDocument())
    await waitFor(() => expect(screen.getByLabelText(/^Rate/)).toBeEnabled())
    const optionalFields = [/^Rate/, /^Workers/, /^Retries/, /^Probe timeout \(ms\)/, /^Warm-up \(seconds\)/, /^Address batch size/]
    for (const label of optionalFields) {
      const input = screen.getByLabelText(label) as HTMLInputElement
      expect(input).toBeEnabled()
      fireEvent.change(input, { target: { value: '' } })
      expect(input).toHaveValue(null)
    }
    fireEvent.change(screen.getByLabelText('Job name'), { target: { value: 'Unset rate' } })
    fireEvent.change(screen.getByLabelText('Target 1'), { target: { value: '198.51.100.10' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create job' }))

    await waitFor(() => expect(createJob).toHaveBeenCalled())
    expect(vi.mocked(createJob).mock.calls[0][0].tcp?.naabu).toMatchObject({
      rate: undefined, workers: undefined, retries: undefined, timeout_ms: undefined,
      warm_up_seconds: undefined, address_batch_size: undefined,
    })
  })

  it('allows cancel navigation when the editor has no unsaved changes', async () => {
    renderWithProviders(<Routes><Route path="/jobs/new" element={<JobEditor />} /><Route path="/jobs" element={<p>Jobs list</p>} /></Routes>, { route: ['/jobs/new'] })
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Create a monitoring job' })).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))

    await waitFor(() => expect(screen.getByText('Jobs list')).toBeInTheDocument())
  })

  it('keeps the editor in place while a save is in progress', async () => {
    let finishCreate!: (result: never) => void
    vi.mocked(createJob).mockImplementation(() => new Promise(resolve => { finishCreate = resolve }) as never)
    renderWithProviders(<Routes><Route path="/jobs/new" element={<JobEditor />} /><Route path="/jobs" element={<p>Jobs list</p>} /></Routes>, { route: ['/jobs/new'] })
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Create a monitoring job' })).toBeInTheDocument())
    fireEvent.change(screen.getByLabelText('Job name'), { target: { value: 'Saving job' } })
    fireEvent.change(screen.getByLabelText('Target 1'), { target: { value: '198.51.100.10' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create job' }))
    await waitFor(() => expect(createJob).toHaveBeenCalled())

    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(screen.getByRole('heading', { name: 'Create a monitoring job' })).toBeInTheDocument()
    expect(screen.queryByRole('dialog', { name: 'Discard unsaved changes?' })).not.toBeInTheDocument()

    await act(async () => finishCreate({ id: 'job-created' } as never))
    await waitFor(() => expect(screen.getByText('Jobs list')).toBeInTheDocument())
  })

  it('asks before discarding a changed draft through app navigation', async () => {
    renderWithProviders(<><nav><Link to="/jobs">Jobs</Link></nav><Routes><Route path="/jobs/new" element={<JobEditor />} /><Route path="/jobs" element={<p>Jobs list</p>} /></Routes></>, { route: ['/jobs/new'] })
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Create a monitoring job' })).toBeInTheDocument())
    fireEvent.change(screen.getByLabelText('Job name'), { target: { value: 'Unsaved draft' } })

    fireEvent.click(screen.getByRole('link', { name: 'Jobs' }))
    const discardDialog = screen.getByRole('dialog', { name: 'Discard unsaved changes?' })
    expect(discardDialog).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Create a monitoring job' })).toBeInTheDocument()

    fireEvent.click(within(discardDialog).getByRole('button', { name: 'Cancel' }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Create a monitoring job' })).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(screen.getByRole('dialog', { name: 'Discard unsaved changes?' })).toBeInTheDocument()
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Cancel' }))

    fireEvent.click(screen.getByRole('link', { name: 'Jobs' }))
    fireEvent.click(screen.getByRole('button', { name: 'Discard changes' }))
    await waitFor(() => expect(screen.getByText('Jobs list')).toBeInTheDocument())
  })

  it('guards browser Back, keeps the draft on cancel, and completes Back on discard', async () => {
    window.history.replaceState({ usr: null, key: 'jobs', idx: 0 }, '', '/jobs')
    window.history.pushState({ usr: null, key: 'job-new', idx: 1 }, '', '/jobs/new')
    const client = createTestClient()
    render(<QueryClientProvider client={client}><BrowserRouter><Routes>
      <Route path="/jobs/new" element={<JobEditor />} />
      <Route path="/jobs" element={<p>Jobs list</p>} />
    </Routes></BrowserRouter></QueryClientProvider>)
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Create a monitoring job' })).toBeInTheDocument())
    fireEvent.change(screen.getByLabelText('Job name'), { target: { value: 'Keep this draft' } })

    window.history.back()
    let discardDialog = await screen.findByRole('dialog', { name: 'Discard unsaved changes?' })
    expect(window.location.pathname).toBe('/jobs/new')
    fireEvent.click(within(discardDialog).getByRole('button', { name: 'Cancel' }))
    expect(screen.getByLabelText('Job name')).toHaveValue('Keep this draft')

    window.history.back()
    discardDialog = await screen.findByRole('dialog', { name: 'Discard unsaved changes?' })
    fireEvent.click(within(discardDialog).getByRole('button', { name: 'Discard changes' }))
    await waitFor(() => expect(screen.getByText('Jobs list')).toBeInTheDocument())
    expect(window.location.pathname).toBe('/jobs')
  })

  it('keeps the native unload prompt active for a changed draft', async () => {
    renderWithProviders(<JobEditor />, { route: ['/jobs/new'] })
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Create a monitoring job' })).toBeInTheDocument())
    fireEvent.change(screen.getByLabelText('Job name'), { target: { value: 'Unsaved draft' } })

    const unload = new Event('beforeunload', { cancelable: true })
    window.dispatchEvent(unload)

    expect(unload.defaultPrevented).toBe(true)
  })

  it('shows the stagger time in the neighbouring job timezone it names', async () => {
    setDisplayTimeZone('Europe/Amsterdam')
    try {
      // 07:00 UTC is 03:00 in New York and 09:00 in Amsterdam (both on summer time).
      vi.mocked(scheduleSuggestion).mockResolvedValue({ suggested: true, suggested_schedule: '30 9 * * *', offset_minutes: 30, gap_minutes: 0, nearest: { id: 'job-2', name: 'New York edge', schedule: '0 3 * * *', timezone: 'America/New_York', next_run: '2026-09-19T07:00:00Z' } })
      renderWithProviders(<JobEditor />, { route: ['/jobs/new'] })
      await act(async () => {
        await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('Stagger scheduled scans'), { timeout: 2000 })
      })
      const notice = screen.getByRole('status')
      const newYork = new Date('2026-09-19T07:00:00Z').toLocaleString(undefined, { weekday: 'short', hour: '2-digit', minute: '2-digit', timeZone: 'America/New_York' })
      expect(newYork).toContain('03:00')
      expect(notice).toHaveTextContent(`New York edge is next at ${newYork} (America/New_York; at the same time)`)
      expect(notice).not.toHaveTextContent('09:00')
    } finally {
      setDisplayTimeZone(undefined)
    }
  })

  it('labels the stagger time with the console timezone when the neighbouring zone is unsupported', async () => {
    setDisplayTimeZone('Europe/Amsterdam')
    try {
      vi.mocked(scheduleSuggestion).mockResolvedValue({ suggested: true, suggested_schedule: '30 9 * * *', offset_minutes: 30, gap_minutes: 15, nearest: { id: 'job-2', name: 'Unknown zone job', schedule: '0 3 * * *', timezone: 'Mars/Olympus', next_run: '2026-09-19T07:00:00Z' } })
      renderWithProviders(<JobEditor />, { route: ['/jobs/new'] })
      await act(async () => {
        await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('Stagger scheduled scans'), { timeout: 2000 })
      })
      const amsterdam = new Date('2026-09-19T07:00:00Z').toLocaleString(undefined, { weekday: 'short', hour: '2-digit', minute: '2-digit', timeZone: 'Europe/Amsterdam' })
      expect(amsterdam).toContain('09:00')
      expect(screen.getByRole('status')).toHaveTextContent(`Unknown zone job is next at ${amsterdam} (Europe/Amsterdam; 15 minutes apart)`)
    } finally {
      setDisplayTimeZone(undefined)
    }
  })

  it('does not let an operator request high-cost approval on a new job', async () => {
    vi.mocked(getSession).mockResolvedValue(operator)
    renderWithProviders(<JobEditor />, { route: ['/jobs/new'] })
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Create a monitoring job' })).toBeInTheDocument())
    expect(await screen.findByText(/Only an administrator can approve high-cost scans\./)).toBeInTheDocument()
    const highCost = screen.getByRole('checkbox', { name: /Allow high-cost scans/ })
    expect(highCost).not.toBeChecked()
    expect(highCost).toBeDisabled()
  })

  it('lets an administrator approve high-cost scans on a new job', async () => {
    renderWithProviders(<JobEditor />, { route: ['/jobs/new'] })
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Create a monitoring job' })).toBeInTheDocument())
    const highCost = screen.getByRole('checkbox', { name: /Allow high-cost scans/ })
    await waitFor(() => expect(highCost).toBeEnabled())
    expect(screen.queryByText(/Only an administrator can approve high-cost scans\./)).not.toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Job name'), { target: { value: 'Broad edge' } })
    fireEvent.change(screen.getByLabelText('Target 1'), { target: { value: '198.51.100.10' } })
    fireEvent.click(highCost)
    fireEvent.click(screen.getByRole('button', { name: 'Create job' }))
    await waitFor(() => expect(createJob).toHaveBeenCalled())
    expect(vi.mocked(createJob).mock.calls[0][0]).toMatchObject({ allow_high_cost: true })
  })

  it('lets an operator keep or clear an existing high-cost approval', async () => {
    vi.mocked(getSession).mockResolvedValue(operator)
    vi.mocked(getJob).mockResolvedValue(approvedJob as never)
    renderWithProviders(<Routes><Route path="/jobs/:id/edit" element={<JobEditor />} /></Routes>, { route: ['/jobs/job-1/edit'] })
    await waitFor(() => expect(screen.getByDisplayValue('Broad edge')).toBeInTheDocument())
    expect(await screen.findByText(/Only an administrator can approve high-cost scans\./)).toBeInTheDocument()
    expect(screen.getByText(/Changing the targets, ports or scanner clears this approval, and an administrator must approve the new scope again\./)).toBeInTheDocument()
    const highCost = screen.getByRole('checkbox', { name: /Allow high-cost scans/ })
    expect(highCost).toBeChecked()
    expect(highCost).toBeEnabled()
    fireEvent.click(highCost)
    expect(highCost).not.toBeChecked()
    // Re-checking restores the saved approval, which the server accepts.
    expect(highCost).toBeEnabled()
    fireEvent.click(highCost)
    expect(highCost).toBeChecked()
    fireEvent.click(highCost)
    fireEvent.click(screen.getByRole('button', { name: 'Save changes' }))
    await waitFor(() => expect(updateJob).toHaveBeenCalled())
    expect(vi.mocked(updateJob).mock.calls[0][2]).toMatchObject({ allow_high_cost: false })
  })

  it('requires explicit rebaseline confirmation for a security-scope edit', async () => {
    const existing = { id: 'job-1', revision: 4, enabled: true, archived: false, security_hash: 'old', job: { name: 'Existing', schedule: '0 */6 * * *', timezone: 'UTC', targets: ['198.51.100.10'], max_expanded_hosts: 256, tcp: { ports: '22', mode: 'connect', service_detection: false, engine: 'nmap' }, timing: 'balanced', timeout: '1h', resume_window: '8d', baseline_samples: 1, change_confirmations: 1 }, baseline: { status: 'complete', samples: 1, attempts: 1 } }
    vi.mocked(getJob).mockResolvedValue(existing as never)
    vi.mocked(updateJob).mockRejectedValue(new APIError('rebaseline confirmation required', 'rebaseline_confirmation_required', { changes: ['TCP port scope'] }))
    renderWithProviders(<Routes><Route path="/jobs/:id/edit" element={<JobEditor />} /></Routes>, { route: ['/jobs/job-1/edit'] })
    await waitFor(() => expect(screen.getByDisplayValue('Existing')).toBeInTheDocument())
    fireEvent.change(screen.getByLabelText(/^Ports/), { target: { value: '443' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save changes' }))
    await waitFor(() => expect(screen.getByRole('dialog')).toHaveTextContent('Confirm scan-scope change'))
    expect(screen.getByRole('dialog')).toHaveTextContent('TCP port scope')
    expect(screen.getByRole('list')).toHaveTextContent('TCP port scope')
    fireEvent.click(screen.getByRole('dialog').querySelector('button[type="button"]')!)
    expect(screen.getByText('Scope change canceled.')).toBeInTheDocument()
  })

  it('saves a scope change only after the administrator confirms the rebaseline', async () => {
    const existing = { id: 'job-1', revision: 4, enabled: true, archived: false, security_hash: 'old', job: { name: 'Existing', schedule: '0 */6 * * *', timezone: 'UTC', targets: ['198.51.100.10'], max_expanded_hosts: 256, tcp: { ports: '22', mode: 'connect', service_detection: false, engine: 'nmap' }, timing: 'balanced', timeout: '1h', resume_window: '8d', baseline_samples: 1, change_confirmations: 1 }, baseline: { status: 'complete', samples: 1, attempts: 1 } }
    vi.mocked(getJob).mockResolvedValue(existing as never)
    vi.mocked(updateJob)
      .mockRejectedValueOnce(new APIError('rebaseline confirmation required', 'rebaseline_confirmation_required', { changes: ['TCP port scope'] }))
      .mockResolvedValueOnce({ ...existing, revision: 5 } as never)
    renderWithProviders(<Routes><Route path="/jobs/:id/edit" element={<JobEditor />} /></Routes>, { route: ['/jobs/job-1/edit'] })
    await waitFor(() => expect(screen.getByDisplayValue('Existing')).toBeInTheDocument())
    fireEvent.change(screen.getByLabelText(/^Ports/), { target: { value: '443' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save changes' }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Reset baseline and save' }))
    await waitFor(() => expect(updateJob).toHaveBeenCalledTimes(2))
    expect(vi.mocked(updateJob).mock.calls[1][2]).toMatchObject({ tcp: { ports: '443' } })
    expect(vi.mocked(updateJob).mock.calls[1][3]).toBe(true)
  })

  it('restores server notification routing when reloading a newer revision', async () => {
    const saved = {
      id: 'job-1', revision: 4, enabled: true, archived: false, security_hash: 'old',
      job: { name: 'Existing', schedule: '0 */6 * * *', timezone: 'UTC', targets: ['198.51.100.10'], max_expanded_hosts: 256, tcp: { ports: '22', mode: 'connect', service_detection: false, engine: 'nmap' }, timing: 'balanced', timeout: '1h', resume_window: '8d', baseline_samples: 1, change_confirmations: 1, notification_destinations: ['notify-1'] },
      baseline: { status: 'complete', samples: 1, attempts: 1 },
    }
    const remote = { ...saved, revision: 5, job: { ...saved.job, notification_destinations: ['notify-2'] } }
    vi.mocked(listNotificationDestinations).mockResolvedValue({
      ...destinationResponse,
      destinations: [
        ...destinationResponse.destinations,
        { id: 'notify-2', name: 'Backup alerts', provider: 'generic', source: 'web', enabled: true, locked: false, revision: 1 },
      ],
    } as never)
    vi.mocked(getJob).mockResolvedValue(saved as never)
    const { client } = renderWithProviders(<Routes><Route path="/jobs/:id/edit" element={<JobEditor />} /></Routes>, { route: ['/jobs/job-1/edit'] })

    await waitFor(() => expect(screen.getByDisplayValue('Existing')).toBeInTheDocument())
    const original = screen.getByRole('checkbox', { name: /Mattermost/ }) as HTMLInputElement
    const replacement = screen.getByRole('checkbox', { name: /Backup alerts/ }) as HTMLInputElement
    expect(original).toBeChecked()
    expect(replacement).not.toBeChecked()
    fireEvent.click(original)
    expect(original).not.toBeChecked()

    vi.mocked(getJob).mockResolvedValue(remote as never)
    await client.invalidateQueries({ queryKey: ['job', 'job-1'] })
    await waitFor(() => expect(screen.getByRole('button', { name: 'Reload saved version' })).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: 'Reload saved version' }))

    await waitFor(() => expect(replacement).toBeChecked())
    expect(original).not.toBeChecked()
    fireEvent.click(screen.getByRole('button', { name: 'Save changes' }))
    await waitFor(() => expect(updateJob).toHaveBeenCalled())
    expect(vi.mocked(updateJob).mock.calls.at(-1)?.[2]).toMatchObject({ notification_destinations: ['notify-2'] })
  })

  it('blocks saving a dirty draft after a newer job revision arrives', async () => {
    vi.mocked(getJob).mockResolvedValue(approvedJob as never)
    const { client } = renderWithProviders(<Routes><Route path="/jobs/:id/edit" element={<JobEditor />} /></Routes>, { route: ['/jobs/job-1/edit'] })
    await waitFor(() => expect(screen.getByDisplayValue('Broad edge')).toBeInTheDocument())
    fireEvent.change(screen.getByLabelText('Job name'), { target: { value: 'Draft name' } })
    vi.mocked(getJob).mockResolvedValue({ ...approvedJob, revision: 5 } as never)
    await client.invalidateQueries({ queryKey: ['job', 'job-1'] })
    await waitFor(() => expect(screen.getByRole('button', { name: 'Reload saved version' })).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: 'Save changes' }))
    await waitFor(() => expect(screen.getAllByRole('alert').some(alert => alert.textContent?.includes('Reload the saved version before continuing.'))).toBe(true))
    expect(updateJob).not.toHaveBeenCalled()
  })

  describe('with a saved destination that no longer exists', () => {
    const rotated = {
      id: 'job-1', revision: 4, enabled: true, archived: false, security_hash: 'old',
      job: { name: 'Existing', schedule: '0 */6 * * *', timezone: 'UTC', targets: ['198.51.100.10'], max_expanded_hosts: 256, tcp: { ports: '22', mode: 'connect', service_detection: false, engine: 'nmap' }, timing: 'balanced', timeout: '1h', resume_window: '8d', baseline_samples: 1, change_confirmations: 1, notification_destinations: ['file:old-uuid'] },
      baseline: { status: 'complete', samples: 1, attempts: 1 },
      missing_notification_destinations: ['file:old-uuid'],
    }
    beforeEach(() => {
      vi.mocked(listNotificationDestinations).mockResolvedValue({
        destinations: [{ id: 'file:new-uuid', name: 'Deployment destination', provider: 'generic', source: 'deployment', enabled: true, locked: false, read_only: true }],
        status: { deployment: 1, managed: 0, active: 1, locked: 0, key_state: 'not_required' },
      } as never)
      vi.mocked(getJob).mockResolvedValue(rotated as never)
    })

    it('saves only destinations that still exist', async () => {
      renderWithProviders(<Routes><Route path="/jobs/:id/edit" element={<JobEditor />} /></Routes>, { route: ['/jobs/job-1/edit'] })
      await waitFor(() => expect(screen.getByDisplayValue('Existing')).toBeInTheDocument())
      const replacement = await screen.findByRole('checkbox', { name: /Deployment destination/ }) as HTMLInputElement
      expect(replacement).not.toBeChecked()
      fireEvent.click(replacement)
      expect(replacement).toBeChecked()
      fireEvent.click(screen.getByRole('button', { name: 'Save changes' }))
      await waitFor(() => expect(updateJob).toHaveBeenCalled())
      expect(vi.mocked(updateJob).mock.calls.at(-1)?.[2].notification_destinations).toEqual(['file:new-uuid'])
    })

    it('shows the missing destination and lets an operator remove it', async () => {
      renderWithProviders(<Routes><Route path="/jobs/:id/edit" element={<JobEditor />} /></Routes>, { route: ['/jobs/job-1/edit'] })
      await waitFor(() => expect(screen.getByDisplayValue('Existing')).toBeInTheDocument())
      const notice = await screen.findByRole('status', { name: 'Missing notification destination' })
      expect(notice).toHaveTextContent('file:old-uuid')
      expect(notice).toHaveTextContent('deployment URL')
      fireEvent.click(screen.getByRole('button', { name: 'Remove missing destination file:old-uuid' }))
      expect(screen.queryByRole('status', { name: 'Missing notification destination' })).not.toBeInTheDocument()
      fireEvent.click(screen.getByRole('button', { name: 'Save changes' }))
      await waitFor(() => expect(updateJob).toHaveBeenCalled())
      expect(vi.mocked(updateJob).mock.calls.at(-1)?.[2].notification_destinations).toEqual([])
    })
  })

  it('covers the TCP/UDP scanner controls and capability warning', async () => {
    renderWithProviders(<JobEditor />, { route: ['/jobs/new'] })
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Create a monitoring job' })).toBeInTheDocument())

    const engine = screen.getByLabelText(/^TCP engine/) as HTMLSelectElement
    fireEvent.change(engine, { target: { value: 'nmap' } })
    expect(screen.getByLabelText(/^Ports/)).not.toBeDisabled()
    fireEvent.change(screen.getByLabelText('Connection mode'), { target: { value: 'syn' } })
    fireEvent.change(engine, { target: { value: 'naabu_nmap' } })
    expect(screen.getByLabelText(/^Ports/)).toHaveValue('1-65535')
    fireEvent.change(screen.getByLabelText('Discovery type'), { target: { value: 'syn' } })
    expect(screen.getByRole('alert')).toHaveTextContent('SYN discovery is unavailable')
    fireEvent.change(screen.getByLabelText('Discovery type'), { target: { value: 'connect' } })
    expect(screen.queryByText('SYN discovery is unavailable')).not.toBeInTheDocument()
    fireEvent.change(screen.getByLabelText(/^Rate/), { target: { value: '2500' } })
    fireEvent.change(screen.getByLabelText(/^Workers/), { target: { value: '40' } })
    fireEvent.click(screen.getByRole('checkbox', { name: /Verify discoveries/ }))

    fireEvent.click(screen.getByLabelText(/UDP scan/))
    expect(screen.getByLabelText(/^UDP scan/)).toBeChecked()
    expect(screen.getByDisplayValue('53')).toBeInTheDocument()
    fireEvent.click(screen.getByLabelText(/^UDP scan/))
    expect(screen.getByLabelText(/^UDP scan/)).not.toBeChecked()
  })

  it('renders form validation errors without sending a mutation', async () => {
    renderWithProviders(<JobEditor />, { route: ['/jobs/new'] })
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Create a monitoring job' })).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: 'Create job' }))
    await waitFor(() => expect(screen.getAllByText('A name is required.').length).toBeGreaterThan(0))
    expect(createJob).not.toHaveBeenCalled()
    fireEvent.change(screen.getByPlaceholderText('Production edge'), { target: { value: 'Valid name' } })
    fireEvent.change(screen.getByRole('spinbutton', { name: /Maximum expanded hosts/ }), { target: { value: '0' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create job' }))
    await waitFor(() => expect(screen.getByText('Use at least one host.')).toBeInTheDocument())
    expect(createJob).not.toHaveBeenCalled()
  })
})
