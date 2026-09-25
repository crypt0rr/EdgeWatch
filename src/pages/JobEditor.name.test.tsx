/** @vitest-environment jsdom */

import { fireEvent, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createJob, listNotificationDestinations, listScannerProfiles, scannerCapabilities, scheduleSuggestion } from '../api'
import { renderWithProviders } from '../test/test-utils'
import { JobEditor } from './JobEditor'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return { ...actual, createJob: vi.fn(), getJob: vi.fn(), listNotificationDestinations: vi.fn(), listScannerProfiles: vi.fn(), scannerCapabilities: vi.fn(), scheduleSuggestion: vi.fn(), updateJob: vi.fn() }
})

const capabilities = { engines: ['nmap', 'naabu_nmap'], nmap: { available: true, path: '/usr/bin/nmap', version: '7.99' }, naabu: { available: true, path: '/usr/local/bin/naabu', version: '2.6.1', syn_supported: false } }
const profile = { id: 'profile-1', name: 'Naabu default', description: '', built_in: true, archived: false, revision: 1, definition: { engine: 'naabu_nmap', naabu: { scan_type: 'connect', rate: 1000, workers: 25, retries: 3, timeout_ms: 1000, warm_up_seconds: 2, verify: true, address_batch_size: 16 }, nmap_args: [], naabu_args: [], enrichment_args: [] } }

describe('job editor name rule', () => {
  beforeEach(() => {
    vi.mocked(listNotificationDestinations).mockResolvedValue({ destinations: [], status: { deployment: 0, managed: 0, active: 0, locked: 0, key_state: 'ready' } } as never)
    vi.mocked(listScannerProfiles).mockResolvedValue({ profiles: [profile] } as never)
    vi.mocked(scannerCapabilities).mockResolvedValue(capabilities as never)
    vi.mocked(createJob).mockResolvedValue({} as never)
    vi.mocked(scheduleSuggestion).mockResolvedValue({ suggested: false, gap_minutes: 60 })
  })
  afterEach(() => vi.clearAllMocks())

  function submitName(name: string) {
    fireEvent.change(screen.getByPlaceholderText('Production edge'), { target: { value: name } })
    fireEvent.click(screen.getByRole('button', { name: 'Create job' }))
  }

  it('mirrors the server limit of 200 characters and rejects control characters', async () => {
    renderWithProviders(<JobEditor />, { route: ['/jobs/new'] })
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Create a monitoring job' })).toBeInTheDocument())
    fireEvent.change(screen.getByLabelText('Target 1'), { target: { value: '198.51.100.10' } })

    submitName('a'.repeat(201))
    await waitFor(() => expect(screen.getAllByText('Use at most 200 characters.').length).toBeGreaterThan(0))
    submitName('edge\tjob')
    await waitFor(() => expect(screen.getAllByText('Remove control characters such as tabs or line breaks.').length).toBeGreaterThan(0))
    expect(createJob).not.toHaveBeenCalled()

    // The limit counts characters, not UTF-16 code units: 200 emoji fit.
    submitName('🙂'.repeat(200))
    await waitFor(() => expect(createJob).toHaveBeenCalled())
    expect(vi.mocked(createJob).mock.calls[0][0]).toMatchObject({ name: '🙂'.repeat(200) })
  })
})
