/** @vitest-environment jsdom */

import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { act } from 'react'
import { QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { activeScans, adminStatus, api, APIError, getSession, listIncidents, listJobs, listScans, login, recordActivity, setupStatus } from './api'
import type { SessionUser } from './api'
import { App, createQueryClient } from './main'
import { signInReturnPath } from './pages/Auth'
import { defaultUnitScope } from './test/test-utils'

vi.mock('./api', async () => {
  const actual = await vi.importActual<typeof import('./api')>('./api')
  return { ...actual, activeScans: vi.fn(), adminStatus: vi.fn(), getSession: vi.fn(), listIncidents: vi.fn(), listJobs: vi.fn(), listScans: vi.fn(), login: vi.fn(), recordActivity: vi.fn(), setCSRF: vi.fn(), setupStatus: vi.fn() }
})

class EventSourceStub {
  onopen: (() => void) | null = null
  onerror: (() => void) | null = null
  onmessage: ((event: MessageEvent) => void) | null = null
  close() {}
}

const administratorPermissions = ['account.self', 'audit.read', 'baselines.read', 'hosts.read', 'incidents.read', 'jobs.read', 'jobs.write', 'overview.read', 'scans.read', 'stream.read', 'users.manage']
const viewerPermissions = ['account.self', 'baselines.read', 'jobs.read']

function account(overrides: Partial<SessionUser> = {}): SessionUser {
  return { user_id: 'acct-admin', username: 'admin', display_name: 'Administrator', role: 'administrator', permissions: administratorPermissions, csrf_token: 'csrf', totp_enabled: true, password_requirements: { minimum_length: 12 }, ...defaultUnitScope, ...overrides }
}

const unauthenticated = () => new APIError('authentication required', 'unauthorized', undefined, 401)
const noIncidents = { incidents: [], pagination: { limit: 1, offset: 0, total: 0, has_more: false, next_offset: null } }

/**
 * Renders the console as the browser bootstrap does, with the production
 * router and query defaults, at the given address.
 */
function openConsole(address: string) {
  window.history.replaceState(null, '', address)
  const client = createQueryClient()
  const view = render(<QueryClientProvider client={client}><App /></QueryClientProvider>)
  return { client, view }
}

function currentAddress() {
  return `${window.location.pathname}${window.location.search}`
}

async function signIn(username: string) {
  expect(await screen.findByRole('heading', { name: /Sign in to EdgeWatch/ })).toBeInTheDocument()
  fireEvent.change(screen.getByLabelText('Username'), { target: { value: username } })
  fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'correct horse battery staple' } })
  fireEvent.submit(screen.getByRole('button', { name: 'Sign in' }).closest('form')!)
  // The sign-in page finishes by re-reading the setup status, and only then
  // makes its own navigation.
  await waitFor(() => expect(setupStatus).toHaveBeenCalledTimes(2))
  await act(async () => { await new Promise(resolve => setTimeout(resolve, 20)) })
}

describe('returning to the requested page after signing in', () => {
  let session: SessionUser | null
  beforeEach(() => {
    session = null
    vi.mocked(setupStatus).mockResolvedValue({ configured: true, password_requirements: { minimum_length: 12 } })
    vi.mocked(getSession).mockImplementation(async () => { if (!session) throw unauthenticated(); return session })
    vi.mocked(login).mockImplementation(async (_password, _otp, _recovery, username = 'admin') => {
      session = username === 'taylor' ? account({ user_id: 'acct-taylor', username: 'taylor', display_name: 'Taylor Brandt', role: 'viewer', permissions: viewerPermissions }) : account()
      return { username: session.username, display_name: session.display_name, role: session.role, permissions: session.permissions, csrf_token: 'csrf', totp_required: false }
    })
    vi.mocked(adminStatus).mockResolvedValue({ version: 'v0.19.0' })
    vi.mocked(listIncidents).mockResolvedValue(noIncidents)
    vi.mocked(listJobs).mockResolvedValue({ jobs: [] })
    vi.mocked(listScans).mockResolvedValue({ scans: [], pagination: { limit: 20, offset: 0, total: 0, has_more: false, next_offset: null } })
    vi.mocked(activeScans).mockResolvedValue({ scans: [] })
    vi.mocked(recordActivity).mockResolvedValue(undefined)
    vi.stubGlobal('EventSource', EventSourceStub)
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    vi.clearAllMocks()
    window.history.replaceState(null, '', '/')
  })

  it('opens a deep link that was opened while signed out, with its search string, once signed in', async () => {
    const { client, view } = openConsole('/jobs?view=archived')
    expect(await screen.findByRole('heading', { name: /Sign in to EdgeWatch/ })).toBeInTheDocument()
    expect(currentAddress()).toBe('/login')
    const entries = window.history.length

    await signIn('admin')
    expect(currentAddress()).toBe('/jobs?view=archived')
    expect(await screen.findByRole('heading', { name: 'Jobs', level: 1 })).toBeInTheDocument()
    // The page replaces the sign-in page in the history, so going back does
    // not return to a sign-in page that would only send the console on.
    expect(window.history.length).toBe(entries)
    view.unmount()
    client.clear()
  })

  it('returns to the page that was open when the session ended, once signed in again', async () => {
    session = account()
    const { client, view } = openConsole('/incidents?offset=0')
    expect(await screen.findByRole('heading', { name: 'Incidents', level: 1 })).toBeInTheDocument()

    // The session ends on the server: the next request of the console is
    // refused with 401, and the console shows the sign-in page.
    session = null
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ error: { code: 'unauthorized', message: 'authentication required' } }), { status: 401, headers: { 'Content-Type': 'application/json' } })))
    vi.mocked(listIncidents).mockImplementation(() => api('/incidents?limit=1&offset=0'))
    await act(async () => { await client.refetchQueries({ queryKey: ['incidents', 'navigation'] }) })
    expect(await screen.findByRole('heading', { name: /Sign in to EdgeWatch/ })).toBeInTheDocument()
    expect(currentAddress()).toBe('/login')

    vi.mocked(listIncidents).mockResolvedValue(noIncidents)
    await signIn('admin')
    expect(currentAddress()).toBe('/incidents?offset=0')
    expect(await screen.findByRole('heading', { name: 'Incidents', level: 1 })).toBeInTheDocument()
    view.unmount()
    client.clear()
  })

  it('applies the permission redirects to a recorded page that the new session may not open', async () => {
    const { client, view } = openConsole('/users')
    await signIn('taylor')
    // A viewer may not open Users, and is sent on to the jobs, where it stays.
    expect(await screen.findByRole('heading', { name: 'Jobs', level: 1 })).toBeInTheDocument()
    expect(currentAddress()).toBe('/jobs')
    await act(async () => { await new Promise(resolve => setTimeout(resolve, 20)) })
    expect(currentAddress()).toBe('/jobs')
    view.unmount()
    client.clear()
  })

  it('opens the home page when the sign-in page has no page to return to', async () => {
    const { client, view } = openConsole('/login')
    await signIn('admin')
    expect(await screen.findByRole('heading', { name: 'Jobs at a glance' })).toBeInTheDocument()
    expect(currentAddress()).toBe('/')
    view.unmount()
    client.clear()
  })

  it('removes grouping whitespace from authenticator codes before sign-in', async () => {
    const { client, view } = openConsole('/login')
    await screen.findByRole('heading', { name: /Sign in to EdgeWatch/ })
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'correct horse battery staple' } })
    fireEvent.change(screen.getByLabelText('Authenticator code'), { target: { value: '123 456' } })
    fireEvent.submit(screen.getByRole('button', { name: 'Sign in' }).closest('form')!)

    await waitFor(() => expect(login).toHaveBeenCalledWith('correct horse battery staple', '123456', undefined, 'admin'))
    view.unmount()
    client.clear()
  })

  it('removes grouping whitespace and normalizes case for recovery-code sign-in', async () => {
    const { client, view } = openConsole('/login')
    await screen.findByRole('heading', { name: /Sign in to EdgeWatch/ })
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'correct horse battery staple' } })
    fireEvent.click(screen.getByRole('button', { name: 'Use a recovery code' }))
    fireEvent.change(screen.getByLabelText('Recovery code'), { target: { value: 'abcd efgh ijkl' } })
    fireEvent.submit(screen.getByRole('button', { name: 'Sign in' }).closest('form')!)

    await waitFor(() => expect(login).toHaveBeenCalledWith('correct horse battery staple', '', 'ABCDEFGHIJKL', 'admin'))
    view.unmount()
    client.clear()
  })
})

describe('the page that the sign-in page returns to', () => {
  it('is the recorded path with its search string, and only a path within the console', () => {
    expect(signInReturnPath({ from: { pathname: '/jobs/job-1', search: '?view=scans' } })).toBe('/jobs/job-1?view=scans')
    expect(signInReturnPath({ from: { pathname: '/jobs' } })).toBe('/jobs')
    for (const state of [null, undefined, 'from', {}, { message: 'Account activated.' }, { from: null }, { from: {} }, { from: { pathname: 42 } }, { from: { pathname: 'jobs' } }, { from: { pathname: '//example.com/jobs' } }]) {
      expect(signInReturnPath(state)).toBeNull()
    }
  })
})
