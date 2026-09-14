/** @vitest-environment jsdom */

import { fireEvent, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { APIError, archiveScannerProfile, createScannerProfile, getSession, listScannerProfiles, restoreScannerProfile, updateScannerProfile, validateScannerProfile } from '../api'
import type { ScannerProfile } from '../api'
import { renderWithProviders } from '../test/test-utils'
import { ScannerProfiles } from './ScannerProfiles'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return { ...actual, archiveScannerProfile: vi.fn(), createScannerProfile: vi.fn(), getSession: vi.fn(), listScannerProfiles: vi.fn(), restoreScannerProfile: vi.fn(), updateScannerProfile: vi.fn(), validateScannerProfile: vi.fn() }
})

const profile = {
  id: 'profile-1', name: 'Managed connect', description: 'safe defaults', built_in: false, archived: false, revision: 3,
  definition: { engine: 'naabu_nmap', naabu: { scan_type: 'connect', rate: 1000, workers: 25, retries: 3, timeout_ms: 1000, warm_up_seconds: 2, verify: true, address_batch_size: 16 }, nmap_args: ['-n', '{address(es)}', '-p', '{ports}', '{structured_output}'], naabu_args: ['-host', '{address(es)}', '-p', '{ports}', '{structured_output}'], enrichment_args: ['-n', '{address(es)}', '-p', '{ports}', '{structured_output}'], operator_adjustable: ['rate'], operator_bounds: { rate: { min: 1, max: 100000 } } },
} satisfies ScannerProfile
const administrator = { role: 'administrator' as const, user_id: 'admin', username: 'admin', permissions: ['scanner_profiles.manage'], csrf_token: '', totp_enabled: false, password_requirements: { minimum_length: 12 } }

describe('scanner profiles', () => {
  beforeEach(() => {
    vi.mocked(getSession).mockResolvedValue(administrator)
    vi.mocked(listScannerProfiles).mockResolvedValue({ profiles: [profile] })
    vi.mocked(validateScannerProfile).mockResolvedValue({ valid: true, preview: [{ executable: '/usr/bin/nmap', args: ['-n', '198.51.100.10'] }] })
    vi.mocked(createScannerProfile).mockResolvedValue(profile)
    vi.mocked(updateScannerProfile).mockResolvedValue(profile)
    vi.mocked(archiveScannerProfile).mockResolvedValue(undefined)
    vi.mocked(restoreScannerProfile).mockResolvedValue(undefined)
  })
  afterEach(() => vi.clearAllMocks())

  it('keeps profile management controls out of the viewer surface', async () => {
    vi.mocked(getSession).mockResolvedValue({ ...administrator, role: 'viewer', permissions: [] })
    renderWithProviders(<ScannerProfiles />)
    await waitFor(() => expect(screen.getByText('Managed connect')).toBeInTheDocument())
    expect(screen.queryByRole('button', { name: 'New profile' })).not.toBeInTheDocument()
    expect(screen.getByText('Only administrators can create, validate, or revise scanner profiles.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Validate & preview' })).not.toBeInTheDocument()
  })

  it('validates and creates a profile with bounded Naabu settings and safe arguments', async () => {
    renderWithProviders(<ScannerProfiles />)
    await waitFor(() => expect(screen.getByText('Managed connect')).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: 'New profile' }))
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Full scan' } })
    fireEvent.change(screen.getByLabelText('Engine'), { target: { value: 'naabu_nmap' } })
    fireEvent.change(screen.getByLabelText('Nmap argument array'), { target: { value: '-n\n{address(es)}\n-p\n{ports}\n{structured_output}' } })
    fireEvent.change(screen.getByLabelText('Naabu argument array'), { target: { value: '-host\n{address(es)}\n-p\n{ports}\n{structured_output}' } })
    fireEvent.change(screen.getByLabelText('Enrichment argument array'), { target: { value: '-n\n{address(es)}\n-p\n{ports}\n{structured_output}' } })
    fireEvent.change(screen.getByLabelText('Password confirmation'), { target: { value: 'administrator-password' } })
    fireEvent.click(screen.getByRole('button', { name: 'Validate & preview' }))
    await waitFor(() => expect(validateScannerProfile).toHaveBeenCalled())
    expect(screen.getByRole('region', { name: 'Effective command preview' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Create profile' }))
    await waitFor(() => expect(createScannerProfile).toHaveBeenCalledWith(expect.objectContaining({ name: 'Full scan', engine: 'naabu_nmap', password: 'administrator-password' })))
    expect(screen.getByText('Scanner profile saved. Jobs keep their pinned revision until explicitly upgraded.')).toBeInTheDocument()
  })

  it('requires administrator confirmation for archive and surfaces conflicts', async () => {
    vi.mocked(archiveScannerProfile).mockRejectedValue(new APIError('profile changed', 'conflict'))
    renderWithProviders(<ScannerProfiles />)
    await waitFor(() => expect(screen.getByText('Managed connect')).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: 'Archive Managed connect' }))
    const dialog = screen.getByRole('dialog')
    fireEvent.change(dialog.querySelector('input[type="password"]')!, { target: { value: 'administrator-password' } })
    fireEvent.click(screen.getByRole('button', { name: 'Archive profile' }))
    await waitFor(() => expect(archiveScannerProfile).toHaveBeenCalledWith('profile-1', 3, 'administrator-password'))
    expect(screen.getAllByRole('alert').some(element => element.textContent?.includes('profile changed'))).toBe(true)
  })

  it('edits a profile, toggles operator bounds, and restores an archived profile', async () => {
    const archived = { ...profile, id: 'profile-2', name: 'Archived profile', archived: true, revision: 5 }
    vi.mocked(listScannerProfiles).mockResolvedValue({ profiles: [profile, archived], invalid_profiles: [{ id: 'invalid-1', name: 'Broken profile', error: 'invalid template' }] } as never)
    renderWithProviders(<ScannerProfiles />)
    await waitFor(() => expect(screen.getByText('Managed connect')).toBeInTheDocument())
    expect(screen.getAllByRole('status').some(element => element.textContent?.includes('need attention'))).toBe(true)
    fireEvent.click(screen.getByRole('button', { name: 'Edit Managed connect' }))
    fireEvent.change(screen.getByLabelText('Engine'), { target: { value: 'nmap' } })
    fireEvent.change(screen.getByLabelText('Description'), { target: { value: 'updated' } })
    const rateCheckbox = screen.getByRole('checkbox', { name: /rate/ })
    fireEvent.click(rateCheckbox)
    fireEvent.click(rateCheckbox)
    fireEvent.change(screen.getByLabelText('Password confirmation'), { target: { value: 'administrator-password' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save revision' }))
    await waitFor(() => expect(updateScannerProfile).toHaveBeenCalledWith('profile-1', expect.objectContaining({ engine: 'nmap', description: 'updated', password: 'administrator-password' }), 3))
    fireEvent.click(screen.getByRole('button', { name: 'Restore Archived profile' }))
    const dialog = screen.getByRole('dialog')
    fireEvent.change(dialog.querySelector('input[type="password"]')!, { target: { value: 'administrator-password' } })
    fireEvent.click(screen.getByRole('button', { name: 'Restore profile' }))
    await waitFor(() => expect(restoreScannerProfile).toHaveBeenCalledWith('profile-2', 5, 'administrator-password'))
    expect(screen.getByText(/Scanner profile restored/)).toBeInTheDocument()
  })

  it('surfaces validation and save failures while retaining the editor', async () => {
    vi.mocked(validateScannerProfile).mockRejectedValue(new Error('unsafe template'))
    vi.mocked(createScannerProfile).mockRejectedValue(new APIError('profile rejected', 'validation'))
    renderWithProviders(<ScannerProfiles />)
    await waitFor(() => expect(screen.getByText('Managed connect')).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: 'New profile' }))
    fireEvent.click(screen.getByRole('button', { name: 'Validate & preview' }))
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('unsafe template'))
    fireEvent.change(screen.getByLabelText('Password confirmation'), { target: { value: 'administrator-password' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create profile' }))
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('profile rejected'))
    expect(screen.getByRole('heading', { name: 'Create profile' })).toBeInTheDocument()
  })
})
