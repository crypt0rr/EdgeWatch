/** @vitest-environment jsdom */

import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { useLocation } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { adminStatus, api, getSession, listIncidents, logout, platformStatus, recordActivity } from '../api'
import { renderWithProviders } from '../test/test-utils'
import { TotpEnrollmentShell } from './TotpEnrollment'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return { ...actual, adminStatus: vi.fn(), api: vi.fn(), getSession: vi.fn(), listIncidents: vi.fn(), logout: vi.fn(), platformStatus: vi.fn(), recordActivity: vi.fn(), setCSRF: vi.fn() }
})

function Location() {
  return <output data-testid="location">{useLocation().pathname}</output>
}

const enrolling = { user_id: 'acct-riley', username: 'riley', display_name: 'Riley Novak', role: 'administrator' as const, permissions: ['account.self'], csrf_token: 'csrf', totp_enabled: false, totp_enrollment_required: true, password_requirements: { minimum_length: 12 }, scope: 'unit' as const, unit: { id: 'unit-retail', name: 'Retail', slug: 'retail' }, multi_unit: true }

describe('forced TOTP enrolment', () => {
  beforeEach(() => {
    vi.mocked(getSession).mockResolvedValue(enrolling)
    vi.mocked(recordActivity).mockResolvedValue(undefined)
    vi.mocked(logout).mockResolvedValue(undefined)
    vi.mocked(api).mockImplementation(async (path: string) => {
      if (path === '/auth/totp/setup') return { secret: 'JBSWY3DPEHPK3PXP', otpauth: 'otpauth://totp/EdgeWatch:riley' } as never
      if (path === '/auth/totp/enable') return { recovery_codes: ['AAAA-1111', 'BBBB-2222'] } as never
      return {} as never
    })
  })
  afterEach(() => vi.clearAllMocks())

  it('shows only the enrolment, a password change, and sign-out on every path', async () => {
    const onLogout = vi.fn()
    renderWithProviders(<><TotpEnrollmentShell displayName="Riley Novak" onLogout={onLogout} /><Location /></>, { route: ['/jobs/job-1'] })
    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent('/security'))
    expect(screen.getByRole('heading', { name: 'Set up an authenticator' })).toBeInTheDocument()
    expect(screen.getByText('Set up TOTP to continue.')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Password' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Authenticator app' })).toBeInTheDocument()
    expect(await screen.findByText('Required before you can use the console.')).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Profile' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Log out all sessions/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('navigation')).not.toBeInTheDocument()
    for (const request of [adminStatus, listIncidents, platformStatus]) expect(request).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: /Sign out/ }))
    expect(onLogout).toHaveBeenCalledOnce()
  })

  it('enrols with the account password, shows the recovery codes, and signs out to sign in again', async () => {
    renderWithProviders(<><TotpEnrollmentShell displayName="Riley Novak" onLogout={vi.fn()} /><Location /></>, { route: ['/security'] })
    const password = await screen.findByLabelText(/^Account password/)
    const authenticator = password.closest('form') as HTMLFormElement
    fireEvent.change(password, { target: { value: 'account password' } })
    fireEvent.submit(authenticator)
    await waitFor(() => expect(api).toHaveBeenCalledWith('/auth/totp/setup', { method: 'POST', body: JSON.stringify({ password: 'account password' }) }))
    expect(await screen.findByText('JBSWY3DPEHPK3PXP')).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Verification code'), { target: { value: '123456' } })
    vi.mocked(getSession).mockResolvedValue({ ...enrolling, totp_enabled: true, totp_enrollment_required: undefined })
    fireEvent.click(screen.getByRole('button', { name: 'Enable TOTP' }))
    const recovery = await screen.findByRole('heading', { name: 'Save your recovery codes' })
    expect(within(recovery.closest('.panel') as HTMLElement).getByText('AAAA-1111')).toBeInTheDocument()
    await waitFor(() => expect(screen.getByText('Enabled')).toBeInTheDocument())
    expect(screen.queryByRole('button', { name: 'Disable TOTP' })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('checkbox', { name: /I saved these recovery codes/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Continue to sign in' }))
    await waitFor(() => expect(logout).toHaveBeenCalledOnce())
    // The signed-out console then shows sign-in; this shell alone keeps no
    // other route to go to.
    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent('/security'))
  })
})
