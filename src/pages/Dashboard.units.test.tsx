/** @vitest-environment jsdom */

import { screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { activeScans, adminStatus, getSession, listIncidents, listJobs, listScans } from '../api'
import type { DeploymentTelemetry } from '../generated/api-types'
import { renderWithProviders } from '../test/test-utils'
import { Dashboard } from './Dashboard'
import { developmentBuildUpdates } from '../test/status-fixtures'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return { ...actual, activeScans: vi.fn(), adminStatus: vi.fn(), getSession: vi.fn(), listIncidents: vi.fn(), listJobs: vi.fn(), listScans: vi.fn() }
})

const pagination = { limit: 20, offset: 0, total: 0, has_more: false, next_offset: null }
const telemetry: DeploymentTelemetry = { collected_at: '2026-09-12T08:00:00Z', jobs: 1, scans: 2, host_observations: 3, effective_hosts: 4, events: 5, scan_cycles: 6, outbox_pending: 7, outbox_retrying: 0, outbox_failed: 0 }

describe('dashboard footprint with business units', () => {
  beforeEach(() => {
    vi.mocked(getSession).mockResolvedValue({ user_id: 'acct-riley', username: 'riley', role: 'administrator', permissions: ['overview.read', 'jobs.read', 'jobs.write', 'scans.read', 'incidents.read', 'users.manage'], csrf_token: '', totp_enabled: true, password_requirements: { minimum_length: 12 }, scope: 'unit', unit: { id: 'unit-retail', name: 'Retail', slug: 'retail' }, multi_unit: true })
    vi.mocked(listJobs).mockResolvedValue({ jobs: [] })
    vi.mocked(listScans).mockResolvedValue({ scans: [], pagination })
    vi.mocked(activeScans).mockResolvedValue({ scans: [] })
    vi.mocked(listIncidents).mockResolvedValue({ incidents: [], pagination })
  })
  afterEach(() => vi.clearAllMocks())

  it('leaves out the database size for a unit that does not report it, instead of showing 0 B', async () => {
    vi.mocked(adminStatus).mockResolvedValue({ version: 'v0.19.0', updates: developmentBuildUpdates, telemetry })
    renderWithProviders(<Dashboard />)
    const footprint = (await screen.findByRole('heading', { name: 'Deployment footprint' })).closest('.panel') as HTMLElement
    expect(within(footprint).getByText('Effective hosts')).toBeInTheDocument()
    expect(within(footprint).getAllByRole('term').map(term => term.textContent)).toEqual(['Effective hosts', 'Host observations', 'Retained scans', 'Events', 'Pending delivery'])
    expect(within(footprint).getAllByRole('definition').map(value => value.textContent)).toEqual(['4', '3', '2', '5', '7'])
    expect(within(footprint).queryByText('Database')).not.toBeInTheDocument()
    expect(within(footprint).queryByText('0 B')).not.toBeInTheDocument()
  })

  it('shows the scan slots that the status reports for the unit, and leaves them out when it reports none', async () => {
    vi.mocked(adminStatus).mockResolvedValue({ version: 'v0.19.0', updates: developmentBuildUpdates, retention: '720h0m0s', max_concurrent_scans: 1 })
    const capped = renderWithProviders(<Dashboard />)
    expect(await screen.findByText(/Retention 30 days · 1 scan at a time\./)).toBeInTheDocument()
    capped.unmount()

    vi.mocked(adminStatus).mockResolvedValue({ version: 'v0.19.0', updates: developmentBuildUpdates, retention: '720h0m0s' })
    renderWithProviders(<Dashboard />)
    expect(await screen.findByText(/Retention 30 days\./)).toBeInTheDocument()
    expect(screen.queryByText(/at a time/)).not.toBeInTheDocument()
  })

  it('shows the database size when the unit reports it', async () => {
    vi.mocked(adminStatus).mockResolvedValue({ version: 'v0.19.0', updates: developmentBuildUpdates, telemetry: { ...telemetry, database_bytes: 0 } })
    renderWithProviders(<Dashboard />)
    const footprint = (await screen.findByRole('heading', { name: 'Deployment footprint' })).closest('.panel') as HTMLElement
    await waitFor(() => expect(within(footprint).getByText('Database')).toBeInTheDocument())
    expect(within(footprint).getByText('0 B')).toBeInTheDocument()
  })
})
