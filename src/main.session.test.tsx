/** @vitest-environment jsdom */

import { fireEvent, screen, waitFor } from '@testing-library/react'
import { focusManager, type QueryClient } from '@tanstack/react-query'
import { act } from 'react'
import { useLocation } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { activeScans, adminStatus, api, APIError, getSession, listIncidents, listJobs, listScans, recordActivity, setCSRF, setupStatus } from './api'
import type { SessionUser } from './api'
import { AppContent, createQueryClient } from './main'
import type { Job } from './types'
import { renderWithProviders } from './test/test-utils'

vi.mock('./api', async () => {
  const actual = await vi.importActual<typeof import('./api')>('./api')
  return { ...actual, activeScans: vi.fn(), adminStatus: vi.fn(), getSession: vi.fn(), listIncidents: vi.fn(), listJobs: vi.fn(), listScans: vi.fn(), recordActivity: vi.fn(), setCSRF: vi.fn(), setupStatus: vi.fn() }
})

class EventSourceStub {
  onopen: (() => void) | null = null
  onerror: (() => void) | null = null
  onmessage: ((event: MessageEvent) => void) | null = null
  close() {}
}

function CurrentPath() {
  return <output data-testid="current-path">{useLocation().pathname}</output>
}

const administratorPermissions = ['account.self', 'audit.read', 'baselines.read', 'hosts.read', 'incidents.read', 'jobs.read', 'jobs.write', 'overview.read', 'scans.read', 'stream.read', 'users.manage']
const configured = { configured: true, password_requirements: { minimum_length: 12 } }
// A busy machine renders a whole console slowly; wait longer for it than
// the default second.
const loaded = { timeout: 5000 }
const noIncidents = { incidents: [], pagination: { limit: 1, offset: 0, total: 0, has_more: false, next_offset: null } }

const riley: SessionUser = { user_id: 'acct-riley', username: 'riley', display_name: 'Riley Novak', role: 'administrator', permissions: administratorPermissions, csrf_token: 'csrf-riley', totp_enabled: true, password_requirements: { minimum_length: 12 }, scope: 'unit', unit: { id: 'unit-retail', name: 'Retail', slug: 'retail' }, multi_unit: true }
const bo: SessionUser = { ...riley, user_id: 'acct-bo', username: 'bo', display_name: 'Bo Lindqvist', csrf_token: 'csrf-bo', unit: { id: 'unit-logistics', name: 'Logistics', slug: 'logistics' } }
const retailJob = { id: 'job-retail', revision: 1, enabled: true, archived: false, job: { name: 'Retail POS network', targets: ['198.51.100.20'], tcp: { ports: '443' }, schedule: '0 * * * *' }, baseline: { status: 'complete', samples: 1 } } as unknown as Job

function cachedKeys(client: QueryClient) {
  return client.getQueryCache().getAll().map(query => JSON.stringify(query.queryKey))
}

/**
 * Reads the session, and the setup status when asked, again as the console
 * does when its tab regains focus after they went stale.
 */
async function readAgainOnFocus(client: QueryClient, keys: string[][] = [['session']]) {
  await act(async () => {
    for (const queryKey of keys) await client.invalidateQueries({ queryKey, exact: true, refetchType: 'none' })
    focusManager.setFocused(false)
    focusManager.setFocused(true)
    await new Promise(resolve => setTimeout(resolve, 20))
  })
}

describe('the console session', { timeout: 20_000 }, () => {
  beforeEach(() => {
    vi.mocked(setupStatus).mockResolvedValue(configured)
    vi.mocked(adminStatus).mockResolvedValue({ version: 'v0.20.7' })
    vi.mocked(listIncidents).mockResolvedValue(noIncidents)
    vi.mocked(listJobs).mockResolvedValue({ jobs: [retailJob] })
    vi.mocked(listScans).mockResolvedValue({ scans: [], pagination: { limit: 20, offset: 0, total: 0, has_more: false, next_offset: null } })
    vi.mocked(activeScans).mockResolvedValue({ scans: [] })
    vi.mocked(recordActivity).mockResolvedValue(undefined)
    vi.stubGlobal('EventSource', EventSourceStub)
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    vi.clearAllMocks()
    focusManager.setFocused(undefined)
  })

  describe('when a session read finds another account', () => {
    it('forgets the previous account’s cached data and state before the new account’s console renders', async () => {
      vi.mocked(getSession).mockResolvedValue(riley)
      const client = createQueryClient()
      const view = renderWithProviders(<><AppContent /><CurrentPath /></>, { route: ['/jobs'], client })

      // Riley, a Retail administrator, opens Jobs, which caches Retail's
      // jobs, and then Security.
      expect(await screen.findByRole('heading', { name: 'Retail POS network' }, loaded)).toBeInTheDocument()
      fireEvent.click(screen.getByRole('link', { name: 'Security' }))
      expect(await screen.findByRole('heading', { name: 'Security', level: 1 }, loaded)).toBeInTheDocument()
      client.getMutationCache().build(client, { mutationKey: ['retail-draft'] })
      expect(cachedKeys(client)).toContain('["jobs",true]')

      // In another tab of the same browser Riley signs out and Bo, a
      // Logistics administrator, signs in. This tab's next session read
      // succeeds as Bo, whose jobs are still loading when Bo opens Jobs.
      let leaked = false
      const watcher = new MutationObserver(() => { if (document.body.textContent?.includes('Retail POS network')) leaked = true })
      watcher.observe(document.body, { childList: true, subtree: true, characterData: true })
      vi.mocked(getSession).mockResolvedValue(bo)
      vi.mocked(listJobs).mockReset().mockImplementation(() => new Promise(() => {}))
      await readAgainOnFocus(client)

      expect(await screen.findByTitle('Business unit: Logistics', undefined, loaded)).toBeInTheDocument()
      expect(screen.getAllByText('Bo Lindqvist').length).toBeGreaterThan(0)
      expect(cachedKeys(client)).not.toContain('["jobs",true]')
      expect(client.getMutationCache().getAll()).toHaveLength(0)
      // The console keeps the page that was open, and the new session's
      // CSRF token.
      expect(screen.getByTestId('current-path')).toHaveTextContent('/security')
      expect(screen.getByLabelText(/^Display name/)).toHaveValue('Bo Lindqvist')
      expect(setCSRF).toHaveBeenLastCalledWith('csrf-bo')

      fireEvent.click(screen.getByRole('link', { name: 'Jobs' }))
      expect(await screen.findByRole('heading', { name: 'Jobs', level: 1 }, loaded)).toBeInTheDocument()
      await waitFor(() => expect(listJobs).toHaveBeenCalledWith(true))
      watcher.disconnect()
      expect(leaked).toBe(false)
      view.unmount()
      client.clear()
    })

    it('keeps the cache and the open page of a session read that finds the same account', async () => {
      vi.mocked(getSession).mockResolvedValue(riley)
      const client = createQueryClient()
      const view = renderWithProviders(<><AppContent /><CurrentPath /></>, { route: ['/jobs'], client })
      expect(await screen.findByRole('heading', { name: 'Retail POS network' }, loaded)).toBeInTheDocument()
      fireEvent.click(screen.getByRole('link', { name: 'Security' }))
      const field = await screen.findByLabelText(/^Display name/, undefined, loaded)
      fireEvent.change(field, { target: { value: 'unsaved draft' } })

      // A re-read, after a refused request for example, finds Riley again,
      // now with another permission.
      vi.mocked(getSession).mockResolvedValue({ ...riley, csrf_token: 'csrf-riley-2', permissions: [...administratorPermissions, 'notifications.manage'] })
      await readAgainOnFocus(client)
      expect(await screen.findByRole('link', { name: 'Notifications' }, loaded)).toBeInTheDocument()
      expect(cachedKeys(client)).toContain('["jobs",true]')
      expect(screen.getByLabelText(/^Display name/)).toHaveValue('unsaved draft')
      expect(setCSRF).toHaveBeenLastCalledWith('csrf-riley-2')
      view.unmount()
      client.clear()
    })
  })

  describe('when a read fails without ending the session', () => {
    // Each failure returns the reads that fail, which the tab reads again.
    const failures: [string, () => string[][]][] = [
      ['the session read fails with a network error', () => { vi.mocked(getSession).mockRejectedValue(new TypeError('Failed to fetch')); return [['session']] }],
      ['the session read fails with a 502', () => { vi.mocked(getSession).mockRejectedValue(new APIError('Request failed', undefined, undefined, 502)); return [['session']] }],
      ['the session and setup status reads both fail while EdgeWatch restarts', () => { vi.mocked(getSession).mockRejectedValue(new TypeError('Failed to fetch')); vi.mocked(setupStatus).mockRejectedValue(new TypeError('Failed to fetch')); return [['session'], ['setup-status']] }],
    ]
    for (const [label, fail] of failures) {
      it(`keeps the console, its page, and unsaved input when ${label}, and reconnects`, async () => {
        vi.mocked(getSession).mockResolvedValue(riley)
        const client = createQueryClient()
        const view = renderWithProviders(<><AppContent /><CurrentPath /></>, { route: ['/security'], client })
        fireEvent.change(await screen.findByLabelText(/^Display name/, undefined, loaded), { target: { value: 'unsaved draft' } })

        const failedReads = vi.mocked(getSession).mock.calls.length
        await readAgainOnFocus(client, fail())
        await waitFor(() => expect(getSession).toHaveBeenCalledTimes(failedReads + 1), loaded)
        await act(async () => { await new Promise(resolve => setTimeout(resolve, 20)) })
        expect(screen.queryByRole('heading', { name: /Sign in to EdgeWatch/ })).not.toBeInTheDocument()
        expect(screen.queryByText(/Unable to contact EdgeWatch/)).not.toBeInTheDocument()
        expect(screen.getByTestId('current-path')).toHaveTextContent('/security')
        expect(screen.getByLabelText(/^Display name/)).toHaveValue('unsaved draft')
        expect(await screen.findByText('Cannot reach EdgeWatch. Reconnecting…', undefined, loaded)).toHaveAttribute('role', 'status')

        // EdgeWatch answers again: the console reads the session again by
        // itself and stays signed in.
        const reads = vi.mocked(getSession).mock.calls.length
        vi.mocked(getSession).mockResolvedValue(riley)
        vi.mocked(setupStatus).mockResolvedValue(configured)
        await waitFor(() => expect(screen.queryByText('Cannot reach EdgeWatch. Reconnecting…')).not.toBeInTheDocument(), { timeout: 6000 })
        expect(vi.mocked(getSession).mock.calls.length).toBeGreaterThan(reads)
        expect(screen.getByTestId('current-path')).toHaveTextContent('/security')
        expect(screen.getByLabelText(/^Display name/)).toHaveValue('unsaved draft')
        view.unmount()
        client.clear()
      })
    }

    it('recovers a valid session after the first startup session request fails', async () => {
      vi.mocked(getSession)
        .mockRejectedValueOnce(new TypeError('Failed to fetch'))
        .mockResolvedValue(riley)
      const client = createQueryClient()
      const view = renderWithProviders(<><AppContent /><CurrentPath /></>, { route: ['/jobs'], client })

      // The configured setup-status response lets the application reach its
      // login route, but the session cookie is still valid. A session retry
      // must take the browser back to the originally requested page.
      expect(await screen.findByRole('heading', { name: /Sign in to EdgeWatch/ }, loaded)).toBeInTheDocument()
      expect(await screen.findByRole('heading', { name: 'Retail POS network' }, { timeout: 8000 })).toBeInTheDocument()
      expect(getSession).toHaveBeenCalledTimes(2)
      expect(screen.getByTestId('current-path')).toHaveTextContent('/jobs')

      view.unmount()
      client.clear()
    })

    it('still signs out when the session read finds the session ended', async () => {
      vi.mocked(getSession).mockResolvedValue(riley)
      const client = createQueryClient()
      const view = renderWithProviders(<><AppContent /><CurrentPath /></>, { route: ['/security'], client })
      expect(await screen.findByLabelText(/^Display name/, undefined, loaded)).toBeInTheDocument()
      vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ error: { code: 'unauthorized', message: 'authentication required' } }), { status: 401, headers: { 'Content-Type': 'application/json' } })))
      vi.mocked(getSession).mockImplementation(() => api<SessionUser>('/auth/session'))
      await readAgainOnFocus(client)
      expect(await screen.findByRole('heading', { name: /Sign in to EdgeWatch/ }, loaded)).toBeInTheDocument()
      expect(screen.getByTestId('current-path')).toHaveTextContent('/login')
      expect(screen.queryByText('Cannot reach EdgeWatch. Reconnecting…')).not.toBeInTheDocument()
      view.unmount()
      client.clear()
    })
  })
})
