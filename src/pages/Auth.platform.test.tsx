/** @vitest-environment jsdom */

import { fireEvent, screen, waitFor } from '@testing-library/react'
import { act } from 'react'
import { Route, Routes, useLocation } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { APIError, login, platformSetup, setup, setupStatus } from '../api'
import { renderWithProviders } from '../test/test-utils'
import { Login, Setup } from './Auth'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return { ...actual, login: vi.fn(), platformSetup: vi.fn(), setCSRF: vi.fn(), setup: vi.fn(), setupStatus: vi.fn() }
})

function Location() {
  const location = useLocation()
  return <output data-testid="location">{location.pathname}</output>
}

function LoginNotice() {
  const location = useLocation()
  return <p data-testid="notice">{(location.state as { message?: string } | null)?.message}</p>
}

function renderSetup() {
  return renderWithProviders(<><Routes><Route path="/setup" element={<Setup />} /><Route path="/login" element={<LoginNotice />} /></Routes><Location /></>, { route: ['/setup'] })
}

describe('platform setup', () => {
  beforeEach(() => {
    vi.mocked(setupStatus).mockResolvedValue({ configured: true, setup_available: false, password_requirements: { minimum_length: 14 }, platform_setup_available: true })
    vi.mocked(platformSetup).mockResolvedValue({ configured: true, username: 'morgan' })
  })
  afterEach(() => vi.clearAllMocks())

  it('redeems the host’s platform setup token and creates the platform administrator', async () => {
    renderSetup()
    expect(await screen.findByRole('heading', { name: 'Create the platform administrator' })).toBeInTheDocument()
    expect(screen.getByText('edgewatch admin platform-setup-token')).toBeInTheDocument()
    const submit = () => fireEvent.submit(screen.getByLabelText('Platform setup token').closest('form')!)
    fireEvent.change(screen.getByLabelText('Platform setup token'), { target: { value: ' platform-token ' } })
    submit()
    expect(await screen.findByRole('alert')).toHaveTextContent('Choose a username for the platform administrator.')
    fireEvent.change(screen.getByLabelText(/^Username/), { target: { value: 'root/admin' } })
    submit()
    expect(await screen.findByRole('alert')).toHaveTextContent(/cannot contain control characters/)
    fireEvent.change(screen.getByLabelText(/^Username/), { target: { value: ' morgan ' } })
    fireEvent.change(screen.getByLabelText(/^Password/), { target: { value: 'thirteen char' } })
    submit()
    expect(await screen.findByRole('alert')).toHaveTextContent('Use at least 14 characters for the password.')
    fireEvent.change(screen.getByLabelText(/^Password/), { target: { value: 'correct horse battery staple' } })
    fireEvent.change(screen.getByLabelText('Confirm password'), { target: { value: 'different password' } })
    submit()
    expect(await screen.findByRole('alert')).toHaveTextContent('Passwords do not match.')
    expect(platformSetup).not.toHaveBeenCalled()

    vi.mocked(platformSetup).mockRejectedValueOnce(new APIError('platform administrator setup could not be completed', 'setup_failed'))
    fireEvent.change(screen.getByLabelText('Confirm password'), { target: { value: 'correct horse battery staple' } })
    submit()
    expect(await screen.findByRole('alert')).toHaveTextContent('platform administrator setup could not be completed')
    submit()
    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent('/login'))
    expect(platformSetup).toHaveBeenLastCalledWith('platform-token', 'morgan', 'correct horse battery staple')
    expect(setup).not.toHaveBeenCalled()
    expect(screen.getByTestId('notice')).toHaveTextContent('Platform administrator created. Sign in with the new account.')
  })

  it('stays the first-run setup without a platform setup token', async () => {
    vi.mocked(setupStatus).mockResolvedValue({ configured: false, setup_available: true, password_requirements: { minimum_length: 12 } })
    renderSetup()
    expect(await screen.findByRole('heading', { name: 'Create your administrator' })).toBeInTheDocument()
    await waitFor(() => expect(setupStatus).toHaveBeenCalled())
    expect(screen.queryByRole('heading', { name: 'Create the platform administrator' })).not.toBeInTheDocument()
  })

  it('explains that a set-up deployment has no platform setup token instead of offering the first-run setup', async () => {
    vi.mocked(setupStatus).mockResolvedValue({ configured: true, setup_available: false, password_requirements: { minimum_length: 12 }, platform_setup_available: false })
    renderSetup()
    expect(await screen.findByRole('heading', { name: 'EdgeWatch is already set up' })).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Create your administrator' })).not.toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Create the platform administrator' })).not.toBeInTheDocument()
    expect(screen.queryByLabelText('Setup token')).not.toBeInTheDocument()
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument()
    // It says how to get a platform setup token, and leads to sign-in.
    expect(screen.getByText('edgewatch admin platform-setup-token')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Go to sign in' })).toHaveAttribute('href', '/login')
    expect(setup).not.toHaveBeenCalled()
  })

  it('keeps the platform setup and what was typed when its token lapses while the page is open', async () => {
    const { client } = renderSetup()
    expect(await screen.findByRole('heading', { name: 'Create the platform administrator' })).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Platform setup token'), { target: { value: 'platform-token' } })
    fireEvent.change(screen.getByLabelText(/^Username/), { target: { value: 'morgan' } })
    fireEvent.change(screen.getByLabelText(/^Password/), { target: { value: 'correct horse battery staple' } })
    fireEvent.change(screen.getByLabelText('Confirm password'), { target: { value: 'correct horse battery staple' } })
    vi.mocked(platformSetup).mockRejectedValueOnce(new APIError('previous setup request failed', 'setup_failed'))
    fireEvent.submit(screen.getByLabelText('Platform setup token').closest('form')!)
    expect(await screen.findByRole('alert')).toHaveTextContent('previous setup request failed')

    const passwordVisibility = screen.getByRole('button', { name: 'Show password' })
    const confirmationVisibility = screen.getByRole('button', { name: 'Show confirmation password' })
    expect(passwordVisibility).toHaveAttribute('aria-controls', 'platform-password')
    expect(confirmationVisibility).toHaveAttribute('aria-controls', 'platform-password-confirm')
    fireEvent.click(passwordVisibility)
    fireEvent.click(confirmationVisibility)
    expect(screen.getByLabelText(/^Password/)).toHaveAttribute('type', 'text')
    expect(screen.getByLabelText('Confirm password')).toHaveAttribute('type', 'text')
    expect(screen.queryByText(/has expired or was already used/)).not.toBeInTheDocument()

    // The token expires, or another operator uses it, and the status is read
    // again.
    vi.mocked(setupStatus).mockResolvedValue({ configured: true, setup_available: false, password_requirements: { minimum_length: 14 }, platform_setup_available: false })
    await act(async () => { await client.refetchQueries({ queryKey: ['setup-status'] }); await new Promise(resolve => setTimeout(resolve, 20)) })
    expect(screen.queryByRole('heading', { name: 'Create your administrator' })).not.toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'EdgeWatch is already set up' })).not.toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Create the platform administrator' })).toBeInTheDocument()
    expect(screen.getByLabelText('Platform setup token')).toHaveValue('platform-token')
    expect(screen.getByLabelText(/^Username/)).toHaveValue('morgan')
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(await screen.findByText(/The platform setup token has expired or was already used/)).toBeInTheDocument()

    // A new token printed on the host makes the status available again.
    vi.mocked(setupStatus).mockResolvedValue({ configured: true, setup_available: false, password_requirements: { minimum_length: 14 }, platform_setup_available: true })
    await act(async () => { await client.refetchQueries({ queryKey: ['setup-status'] }) })
    await waitFor(() => expect(screen.queryByText(/has expired or was already used/)).not.toBeInTheDocument())
    expect(screen.getByLabelText(/^Username/)).toHaveValue('morgan')
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('offers no setup form while the setup status cannot be read', async () => {
    vi.mocked(setupStatus).mockRejectedValue(new Error('offline'))
    renderSetup()
    expect(await screen.findByRole('heading', { name: 'EdgeWatch is unavailable' })).toBeInTheDocument()
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Go to sign in' })).toHaveAttribute('href', '/login')
  })

  it('points the sign-in page to the platform setup while its token is valid', async () => {
    const view = renderWithProviders(<Login />, { route: ['/login'] })
    expect(await screen.findByText(/A platform setup token from the EdgeWatch host is waiting to be used/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Create the platform administrator' })).toHaveAttribute('href', '/setup')
    view.unmount()
    vi.mocked(setupStatus).mockResolvedValue({ configured: true, password_requirements: { minimum_length: 12 } })
    renderWithProviders(<Login />, { route: ['/login'] })
    await waitFor(() => expect(setupStatus).toHaveBeenCalledTimes(2))
    expect(screen.queryByRole('link', { name: 'Create the platform administrator' })).not.toBeInTheDocument()
  })

  it('opens the enrolment after signing in when TOTP must be set up first', async () => {
    vi.mocked(login).mockResolvedValue({ username: 'riley', role: 'administrator', permissions: ['account.self'], csrf_token: 'csrf', totp_required: false, totp_enrollment_required: true })
    renderWithProviders(<><Routes><Route path="/login" element={<Login />} /><Route path="*" element={null} /></Routes><Location /></>, { route: ['/login'] })
    fireEvent.change(await screen.findByLabelText('Username'), { target: { value: 'riley' } })
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'account password' } })
    fireEvent.submit(screen.getByLabelText('Password').closest('form')!)
    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent('/security'))
  })
})
