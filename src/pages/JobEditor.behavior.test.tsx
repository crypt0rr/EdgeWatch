/** @vitest-environment jsdom */

import { fireEvent, screen, waitFor } from '@testing-library/react'
import { act } from 'react'
import { Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { APIError, createJob, getJob, listNotificationDestinations, listScannerProfiles, scannerCapabilities, scheduleSuggestion, updateJob } from '../api'
import { renderWithProviders } from '../test/test-utils'
import { setDisplayTimeZone } from '../format'
import { JobEditor } from './JobEditor'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return { ...actual, createJob: vi.fn(), getJob: vi.fn(), listNotificationDestinations: vi.fn(), listScannerProfiles: vi.fn(), scannerCapabilities: vi.fn(), scheduleSuggestion: vi.fn(), updateJob: vi.fn() }
})

const destinationResponse = {
  destinations: [{ id: 'notify-1', name: 'Mattermost', provider: 'mattermost', source: 'web', enabled: true, locked: false, revision: 1 }],
  status: { deployment: 0, managed: 1, active: 1, locked: 0, key_state: 'ready' },
}
const capabilities = { engines: ['nmap', 'naabu_nmap'], nmap: { available: true, path: '/usr/bin/nmap', version: '7.99' }, naabu: { available: true, path: '/usr/local/bin/naabu', version: '2.6.1', syn_supported: false } }
const profile = { id: 'profile-1', name: 'Naabu default', description: '', built_in: true, archived: false, revision: 1, definition: { engine: 'naabu_nmap', naabu: { scan_type: 'connect', rate: 1000, workers: 25, retries: 3, timeout_ms: 1000, warm_up_seconds: 2, verify: true, address_batch_size: 16 }, nmap_args: [], naabu_args: [], enrichment_args: [] } }

describe('job editor workflow coverage', () => {
  beforeEach(() => {
    vi.mocked(listNotificationDestinations).mockResolvedValue(destinationResponse as never)
    vi.mocked(listScannerProfiles).mockResolvedValue({ profiles: [profile] } as never)
    vi.mocked(scannerCapabilities).mockResolvedValue(capabilities as never)
    vi.mocked(createJob).mockResolvedValue({} as never)
    vi.mocked(updateJob).mockResolvedValue({} as never)
    vi.mocked(scheduleSuggestion).mockResolvedValue({ suggested: false, gap_minutes: 60 })
  })
  afterEach(() => vi.clearAllMocks())

  it('creates a Naabu job with startup disabled and explicit empty notification routing', async () => {
    renderWithProviders(<JobEditor />, { route: ['/jobs/new'] })
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Create a monitoring job' })).toBeInTheDocument())
    fireEvent.change(screen.getByLabelText('Job name'), { target: { value: 'Public edge' } })
    fireEvent.change(screen.getByLabelText('Target 1'), { target: { value: '198.51.100.10' } })
    expect(screen.getByLabelText(/Run on startup/)).not.toBeChecked()
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
    fireEvent.click(screen.getByRole('dialog').querySelector('button[type="button"]')!)
    expect(screen.getByText('Scope change cancelled.')).toBeInTheDocument()
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
    fireEvent.change(screen.getByLabelText('Rate'), { target: { value: '2500' } })
    fireEvent.change(screen.getByLabelText('Workers'), { target: { value: '40' } })
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
