/** @vitest-environment jsdom */

import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { activate, activeScans, adminStatus, APIError, getSession, listIncidents, listJobs, listScans, listUnits, logout, platformStatus, recordActivity, setupStatus } from './api'
import type { SessionUser } from './api'
import { App, createQueryClient } from './main'
import { deploymentLimits, platformSession } from './test/platform-fixtures'

vi.mock('./api', async () => {
  const actual = await vi.importActual<typeof import('./api')>('./api')
  return { ...actual, activate: vi.fn(), activeScans: vi.fn(), adminStatus: vi.fn(), getSession: vi.fn(), listIncidents: vi.fn(), listJobs: vi.fn(), listScans: vi.fn(), listUnits: vi.fn(), logout: vi.fn(), platformStatus: vi.fn(), recordActivity: vi.fn(), setCSRF: vi.fn(), setupStatus: vi.fn() }
})

class EventSourceStub {
  onopen: (() => void) | null = null
  onerror: (() => void) | null = null
  onmessage: ((event: MessageEvent) => void) | null = null
  close() {}
}

const administratorPermissions = ['account.self', 'audit.read', 'baselines.read', 'hosts.read', 'incidents.read', 'jobs.read', 'jobs.write', 'overview.read', 'scans.read', 'stream.read', 'users.manage']
const riley: SessionUser = { user_id: 'acct-riley', username: 'riley', display_name: 'Riley Novak', role: 'administrator', permissions: administratorPermissions, csrf_token: 'csrf', totp_enabled: true, password_requirements: { minimum_length: 12 }, scope: 'unit', unit: { id: 'unit-retail', name: 'Retail', slug: 'retail' }, multi_unit: true }
// A busy machine renders a whole console slowly; wait longer for it than
// the default second.
const loaded = { timeout: 5000 }
const unauthenticated = () => new APIError('authentication required', 'unauthorized', undefined, 401)

/**
 * Opens the console as the browser bootstrap does, with the production router
 * and query defaults, at the given address.
 */
function openConsole(address: string) {
  window.history.replaceState(null, '', address)
  const client = createQueryClient()
  const view = render(<QueryClientProvider client={client}><App /></QueryClientProvider>)
  return { client, view }
}

describe('a one-time account link opened in a browser that holds a session', { timeout: 20_000 }, () => {
  let session: SessionUser | null
  beforeEach(() => {
    session = null
    vi.mocked(getSession).mockImplementation(async () => { if (!session) throw unauthenticated(); return session })
    vi.mocked(logout).mockImplementation(async () => { session = null; return undefined })
    vi.mocked(activate).mockResolvedValue(undefined)
    vi.mocked(setupStatus).mockResolvedValue({ configured: true, password_requirements: { minimum_length: 12 } })
    vi.mocked(adminStatus).mockResolvedValue({ version: 'v0.20.7' })
    vi.mocked(listIncidents).mockResolvedValue({ incidents: [], pagination: { limit: 1, offset: 0, total: 0, has_more: false, next_offset: null } })
    vi.mocked(listJobs).mockResolvedValue({ jobs: [] })
    vi.mocked(listScans).mockResolvedValue({ scans: [], pagination: { limit: 20, offset: 0, total: 0, has_more: false, next_offset: null } })
    vi.mocked(activeScans).mockResolvedValue({ scans: [] })
    vi.mocked(listUnits).mockResolvedValue({ limits: deploymentLimits, units: [] })
    vi.mocked(platformStatus).mockRejectedValue(new Error('not needed'))
    vi.mocked(recordActivity).mockResolvedValue(undefined)
    vi.stubGlobal('EventSource', EventSourceStub)
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    vi.clearAllMocks()
    window.history.replaceState(null, '', '/')
  })

  const accounts: [string, SessionUser, string][] = [
    ['a unit administrator', riley, 'Riley Novak (riley)'],
    ['a platform administrator', platformSession(), 'Morgan Reyes (morgan)'],
    ['an administrator who must enrol TOTP', { ...riley, totp_enabled: false, totp_enrollment_required: true, permissions: ['account.self'] }, 'Riley Novak (riley)'],
  ]
  for (const [label, account, named] of accounts) {
    it(`keeps the link for ${label} and opens it after signing out`, async () => {
      session = account
      const { client, view } = openConsole('/activate#token=ONE-TIME-TOKEN')

      // The console names the signed-in account and keeps the link, unused.
      expect(await screen.findByRole('heading', { name: 'You are already signed in' }, loaded)).toBeInTheDocument()
      expect(screen.getByText(named)).toBeInTheDocument()
      expect(`${window.location.pathname}${window.location.hash}`).toBe('/activate#token=ONE-TIME-TOKEN')
      expect(screen.queryByRole('complementary', { name: 'Primary navigation', hidden: true })).not.toBeInTheDocument()
      expect(screen.queryByRole('heading', { name: 'Choose your password' })).not.toBeInTheDocument()
      expect(activate).not.toHaveBeenCalled()

      fireEvent.click(screen.getByRole('button', { name: 'Sign out and continue' }))
      expect(await screen.findByRole('heading', { name: 'Choose your password' }, loaded)).toBeInTheDocument()
      expect(logout).toHaveBeenCalledOnce()
      expect(screen.getByLabelText('Activation token')).toHaveValue('ONE-TIME-TOKEN')
      // The activation page removes the token from the address bar.
      await waitFor(() => expect(window.location.hash).toBe(''))
      expect(window.location.pathname).toBe('/activate')

      fireEvent.change(screen.getByLabelText(/^Password/), { target: { value: 'correct horse battery staple' } })
      fireEvent.change(screen.getByLabelText('Confirm password'), { target: { value: 'correct horse battery staple' } })
      fireEvent.submit(screen.getByLabelText('Activation token').closest('form')!)
      expect(await screen.findByText('Account activated. Sign in with your new password.', undefined, loaded)).toBeInTheDocument()
      expect(activate).toHaveBeenCalledWith('ONE-TIME-TOKEN', 'correct horse battery staple')
      view.unmount()
      client.clear()
    })
  }

  it('returns to the console without using the link when asked', async () => {
    session = riley
    const { client, view } = openConsole('/activate?source=invite#token=ONE-TIME-TOKEN')
    expect(await screen.findByRole('heading', { name: 'You are already signed in' }, loaded)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Return to the console' }))
    expect(await screen.findByRole('heading', { name: 'Jobs at a glance' }, loaded)).toBeInTheDocument()
    expect(`${window.location.pathname}${window.location.search}${window.location.hash}`).toBe('/')
    expect(logout).not.toHaveBeenCalled()
    expect(activate).not.toHaveBeenCalled()
    view.unmount()
    client.clear()
  })

  it('treats a legacy query-string link the same way', async () => {
    session = riley
    const { client, view } = openConsole('/activate?token=OLD-TOKEN')
    expect(await screen.findByRole('heading', { name: 'You are already signed in' }, loaded)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Sign out and continue' }))
    expect(await screen.findByLabelText('Activation token', undefined, loaded)).toHaveValue('OLD-TOKEN')
    await waitFor(() => expect(window.location.search).toBe(''))
    view.unmount()
    client.clear()
  })

  it('sends a signed-in console at /activate without a link to its home page', async () => {
    session = riley
    const { client, view } = openConsole('/activate')
    expect(await screen.findByRole('heading', { name: 'Jobs at a glance' }, loaded)).toBeInTheDocument()
    expect(window.location.pathname).toBe('/')
    expect(screen.queryByRole('heading', { name: 'You are already signed in' })).not.toBeInTheDocument()
    view.unmount()
    client.clear()
  })

  it('opens the link at once in a signed-out browser', async () => {
    const { client, view } = openConsole('/activate#token=ONE-TIME-TOKEN')
    expect(await screen.findByRole('heading', { name: 'Choose your password' }, loaded)).toBeInTheDocument()
    expect(screen.getByLabelText('Activation token')).toHaveValue('ONE-TIME-TOKEN')
    await waitFor(() => expect(window.location.hash).toBe(''))
    expect(screen.queryByRole('heading', { name: 'You are already signed in' })).not.toBeInTheDocument()
    view.unmount()
    client.clear()
  })
})
