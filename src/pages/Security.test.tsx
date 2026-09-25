/** @vitest-environment jsdom */

import { fireEvent, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { api, APIError, getSession, logout, logoutAllSessions, setCSRF, updateDisplayName } from '../api'
import { Security } from './Security'
import { renderWithProviders } from '../test/test-utils'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return { ...actual, api: vi.fn(), getSession: vi.fn(), logout: vi.fn(), logoutAllSessions: vi.fn(), setCSRF: vi.fn(), updateDisplayName: vi.fn() }
})

const administrator = { role: 'administrator' as const, user_id: 'user-1', username: 'admin', display_name: 'Admin', permissions: [], csrf_token: 'csrf', totp_enabled: false, password_requirements: { minimum_length: 12 } }

describe('security settings', () => {
  beforeEach(() => {
    vi.mocked(getSession).mockResolvedValue(administrator)
    vi.mocked(updateDisplayName).mockResolvedValue({ display_name: 'Updated Admin' })
    vi.mocked(api).mockResolvedValue({} as never)
    vi.mocked(logout).mockResolvedValue(undefined)
    vi.mocked(logoutAllSessions).mockResolvedValue(undefined)
  })
  afterEach(() => vi.clearAllMocks())

  function renderPage() {
    return renderWithProviders(<Routes><Route path="*" element={<><Security /><p data-testid="route"><span /></p></>} /></Routes>, { route: ['/security'] })
  }

  it('saves a display name and refreshes session/status queries', async () => {
    const { client } = renderPage()
    await waitFor(() => expect(screen.getByDisplayValue('Admin')).toBeInTheDocument())
    const displayName = screen.getByRole('textbox', { name: /^Display name/ })
    fireEvent.change(displayName, { target: { value: 'Updated Admin' } })
    fireEvent.submit(displayName.closest('form')!)
    await waitFor(() => expect(updateDisplayName).toHaveBeenCalledWith('Updated Admin'))
    expect(screen.getByText('Display name updated.')).toBeInTheDocument()
    expect(client.getQueryData(['session'])).toMatchObject({ display_name: 'Admin' })
  })

  it('changes the password and routes to login on success', async () => {
    const { container } = renderPage()
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Security' })).toBeInTheDocument())
    const currentPassword = screen.getByLabelText('Current password')
    const newPassword = screen.getByLabelText(/New password/)
    fireEvent.change(currentPassword, { target: { value: 'old-password' } })
    fireEvent.change(newPassword, { target: { value: 'new-password-123' } })
    fireEvent.submit(currentPassword.closest('form')!)
    await waitFor(() => expect(api).toHaveBeenCalledWith('/auth/password', expect.objectContaining({ method: 'PUT', body: JSON.stringify({ current_password: 'old-password', new_password: 'new-password-123' }) })))
    expect(setCSRF).toHaveBeenCalledWith('')
    expect(container.textContent).toContain('Security')
  })

  it('covers TOTP enrollment, recovery acknowledgement, and logout', async () => {
    vi.mocked(api).mockImplementation(async (path: string) => path === '/auth/totp/setup' ? { secret: 'BASE32SECRET', otpauth: 'otpauth://totp/EdgeWatch' } as never : { recovery_codes: ['one', 'two'] } as never)
    renderPage()
    await waitFor(() => expect(screen.getByRole('button', { name: 'Set up authenticator' })).toBeInTheDocument())
    fireEvent.change(screen.getByLabelText('Current password'), { target: { value: 'correct-password' } })
    fireEvent.click(screen.getByRole('button', { name: 'Set up authenticator' }))
    await waitFor(() => expect(screen.getByText('BASE32SECRET')).toBeInTheDocument())
    fireEvent.change(screen.getByLabelText('Verification code'), { target: { value: '123456' } })
    fireEvent.click(screen.getByRole('button', { name: 'Enable TOTP' }))
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Save your recovery codes' })).toBeInTheDocument())
    fireEvent.click(screen.getByRole('checkbox', { name: /I saved these recovery codes/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Continue to sign in' }))
    await waitFor(() => expect(logout).toHaveBeenCalledOnce())
  })

  it('keeps the enrolment open after a mistyped code and restarts it once the setup expired', async () => {
    let enableAttempts = 0
    vi.mocked(api).mockImplementation(async (path: string) => {
      if (path === '/auth/totp/setup') return { secret: 'BASE32SECRET', otpauth: 'otpauth://totp/EdgeWatch' } as never
      enableAttempts += 1
      if (enableAttempts === 1) throw new APIError('the verification code is incorrect; 4 attempts remain', 'totp_failed', { remaining_attempts: 4 })
      throw new APIError('TOTP setup expired; start setup again', 'totp_setup_expired')
    })
    renderPage()
    await waitFor(() => expect(screen.getByRole('button', { name: 'Set up authenticator' })).toBeInTheDocument())
    fireEvent.change(screen.getByLabelText('Current password'), { target: { value: 'correct-password' } })
    fireEvent.click(screen.getByRole('button', { name: 'Set up authenticator' }))
    await waitFor(() => expect(screen.getByText('BASE32SECRET')).toBeInTheDocument())

    fireEvent.change(screen.getByLabelText('Verification code'), { target: { value: '000000' } })
    fireEvent.click(screen.getByRole('button', { name: 'Enable TOTP' }))
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('4 attempts remain'))
    expect(screen.getByText('BASE32SECRET')).toBeInTheDocument()
    expect(screen.getByLabelText('Verification code')).toHaveValue('')
    expect(screen.queryByRole('button', { name: 'Set up authenticator' })).not.toBeInTheDocument()

    fireEvent.change(screen.getByLabelText('Verification code'), { target: { value: '111111' } })
    fireEvent.click(screen.getByRole('button', { name: 'Enable TOTP' }))
    await waitFor(() => expect(screen.getByRole('button', { name: 'Set up authenticator' })).toBeInTheDocument())
    expect(screen.queryByText('BASE32SECRET')).not.toBeInTheDocument()
    expect(screen.getByRole('alert')).toHaveTextContent('Start setup again')
  })

  it('restores the replacement action when a replacement enrolment expired', async () => {
    vi.mocked(getSession).mockResolvedValue({ ...administrator, totp_enabled: true })
    vi.mocked(api).mockImplementation(async (path: string) => {
      if (path === '/auth/totp/setup') return { secret: 'REPLACEMENTSECRET', otpauth: 'otpauth://totp/EdgeWatch' } as never
      throw new APIError('TOTP setup expired; start setup again', 'totp_setup_expired')
    })
    renderPage()
    await waitFor(() => expect(screen.getByRole('button', { name: 'Replace authenticator' })).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: 'Replace authenticator' }))
    const dialog = screen.getByRole('dialog')
    fireEvent.change(screen.getByLabelText('Account password'), { target: { value: 'correct-password' } })
    fireEvent.change(screen.getByLabelText('Current authenticator code or recovery code'), { target: { value: '123456' } })
    fireEvent.click(dialog.querySelector('button[type="submit"]')!)
    await waitFor(() => expect(screen.getByText('REPLACEMENTSECRET')).toBeInTheDocument())

    fireEvent.change(screen.getByLabelText('Verification code'), { target: { value: '654321' } })
    fireEvent.click(screen.getByRole('button', { name: 'Replace authenticator' }))
    await waitFor(() => expect(screen.queryByText('REPLACEMENTSECRET')).not.toBeInTheDocument())
    expect(screen.getByRole('button', { name: 'Replace authenticator' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Disable TOTP' })).toBeInTheDocument()
  })

  it('requires confirmation for session revocation and handles server errors', async () => {
    vi.mocked(logoutAllSessions).mockRejectedValue(new Error('sessions unavailable'))
    renderPage()
    await waitFor(() => expect(screen.getByRole('button', { name: /Log out all sessions/ })).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: /Log out all sessions/ }))
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('dialog').querySelector('button[type="submit"]')!)
    await waitFor(() => expect(screen.getAllByRole('alert').some(element => element.textContent?.includes('sessions unavailable'))).toBe(true))
  })

  it('disables an enabled authenticator after password confirmation', async () => {
    vi.mocked(getSession).mockResolvedValue({ ...administrator, totp_enabled: true })
    renderPage()
    await waitFor(() => expect(screen.getByRole('button', { name: 'Disable TOTP' })).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: 'Disable TOTP' }))
    const dialog = screen.getByRole('dialog')
    fireEvent.change(dialog.querySelector('input[type="password"]')!, { target: { value: 'correct-password' } })
    fireEvent.change(screen.getByLabelText('Current authenticator code or recovery code'), { target: { value: '123456' } })
    fireEvent.click(dialog.querySelector('button[type="submit"]')!)
    await waitFor(() => expect(api).toHaveBeenCalledWith('/auth/totp', expect.objectContaining({ method: 'DELETE' })))
    expect(logout).not.toHaveBeenCalled()
  })

  it('allows an enabled authenticator to be replaced after step-up confirmation', async () => {
    vi.mocked(getSession).mockResolvedValue({ ...administrator, totp_enabled: true })
    vi.mocked(api).mockImplementation(async (path: string) => path === '/auth/totp/setup' ? { secret: 'REPLACEMENTSECRET', otpauth: 'otpauth://totp/EdgeWatch' } as never : { recovery_codes: ['replacement-one'] } as never)
    renderPage()
    await waitFor(() => expect(screen.getByRole('button', { name: 'Replace authenticator' })).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: 'Replace authenticator' }))
    const dialog = screen.getByRole('dialog')
    fireEvent.change(screen.getByLabelText('Account password'), { target: { value: 'correct-password' } })
    fireEvent.change(screen.getByLabelText('Current authenticator code or recovery code'), { target: { value: '123456' } })
    fireEvent.click(dialog.querySelector('button[type="submit"]')!)
    await waitFor(() => expect(screen.getByText('REPLACEMENTSECRET')).toBeInTheDocument())
    expect(api).toHaveBeenCalledWith('/auth/totp/setup', expect.objectContaining({ body: JSON.stringify({ password: 'correct-password', code: '123456', recovery_code: '' }) }))

    fireEvent.change(screen.getByLabelText('Verification code'), { target: { value: '654321' } })
    fireEvent.click(screen.getByRole('button', { name: 'Replace authenticator' }))
    await waitFor(() => expect(screen.getByText('replacement-one')).toBeInTheDocument())
    expect(api).toHaveBeenCalledWith('/auth/totp/enable', expect.objectContaining({ body: JSON.stringify({ code: '654321' }) }))
    expect(screen.getByRole('button', { name: 'Disable TOTP' })).toBeInTheDocument()
  })

  it('regenerates recovery codes after the current factor and surfaces failures', async () => {
    vi.mocked(getSession).mockResolvedValue({ ...administrator, totp_enabled: true })
    vi.mocked(api).mockRejectedValueOnce(new Error('registry unavailable'))
    renderPage()
    await waitFor(() => expect(screen.getByRole('button', { name: 'Regenerate recovery codes' })).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: 'Regenerate recovery codes' }))
    const dialog = screen.getByRole('dialog')
    fireEvent.change(screen.getByLabelText('Account password'), { target: { value: 'correct-password' } })
    fireEvent.change(screen.getByLabelText('Current authenticator code or recovery code'), { target: { value: '654321' } })
    fireEvent.click(dialog.querySelector('button[type="submit"]')!)
    await waitFor(() => expect(screen.getAllByRole('alert').some(element => element.textContent?.includes('registry unavailable'))).toBe(true))

    vi.mocked(api).mockResolvedValue({ recovery_codes: ['new-one', 'new-two'] } as never)
    fireEvent.click(dialog.querySelector('button[type="submit"]')!)
    await waitFor(() => expect(screen.getByText('new-one')).toBeInTheDocument())
    expect(screen.getByText('Recovery codes regenerated. Save the new codes before leaving this page.')).toBeInTheDocument()
    expect(api).toHaveBeenLastCalledWith('/auth/totp/recovery-codes', expect.objectContaining({ body: JSON.stringify({ password: 'correct-password', code: '654321', recovery_code: '' }) }))
  })
})
