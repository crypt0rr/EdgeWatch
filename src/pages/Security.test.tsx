/** @vitest-environment jsdom */

import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { Route, Routes, useLocation } from 'react-router-dom'
import { api, APIError, getSession, logout, logoutAllSessions, setCSRF, updateDisplayName } from '../api'
import { Security } from './Security'
import { renderWithProviders, defaultUnitScope } from '../test/test-utils'

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api')
  return { ...actual, api: vi.fn(), getSession: vi.fn(), logout: vi.fn(), logoutAllSessions: vi.fn(), setCSRF: vi.fn(), updateDisplayName: vi.fn() }
})

const administrator = { role: 'administrator' as const, user_id: 'user-1', username: 'admin', display_name: 'Admin', permissions: [], csrf_token: 'csrf', totp_enabled: false, password_requirements: { minimum_length: 12 }, ...defaultUnitScope }
const originalClipboard = Object.getOwnPropertyDescriptor(navigator, 'clipboard')

describe('security settings', () => {
  beforeEach(() => {
    vi.mocked(getSession).mockResolvedValue(administrator)
    vi.mocked(updateDisplayName).mockResolvedValue({ display_name: 'Updated Admin' })
    vi.mocked(api).mockResolvedValue({} as never)
    vi.mocked(logout).mockResolvedValue(undefined)
    vi.mocked(logoutAllSessions).mockResolvedValue(undefined)
  })
  afterEach(() => {
    vi.clearAllMocks()
    if (originalClipboard) Object.defineProperty(navigator, 'clipboard', originalClipboard)
    else Reflect.deleteProperty(navigator, 'clipboard')
  })

function renderPage() {
    return renderWithProviders(<Routes><Route path="/security" element={<Security />} /><Route path="/login" element={<LoginNotice />} /></Routes>, { route: ['/security'] })
  }

  function LoginNotice() {
    const location = useLocation()
    const message = (location.state as { message?: string } | null)?.message
    return <main><h1>Sign in</h1>{message && <p role="status">{message}</p>}</main>
  }

  async function startAuthenticatorSetup(password = 'correct-password') {
    fireEvent.click(screen.getByRole('button', { name: 'Set up authenticator' }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText('Account password'), { target: { value: password } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Start setup' }))
    await waitFor(() => expect(screen.getByLabelText('Authenticator secret')).toBeInTheDocument())
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

  it('changes the password, signs out, and explains the next login', async () => {
    renderPage()
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Security' })).toBeInTheDocument())
    const currentPassword = screen.getByLabelText('Current password')
    const newPassword = screen.getByLabelText('New password')
    const confirmation = screen.getByLabelText('Confirm new password')
    fireEvent.change(currentPassword, { target: { value: 'old-password' } })
    fireEvent.change(newPassword, { target: { value: 'new-password-123' } })
    fireEvent.change(confirmation, { target: { value: 'new-password-123' } })
    let finishRequest: (() => void) | undefined
    vi.mocked(api).mockImplementationOnce(() => new Promise<void>(resolve => { finishRequest = resolve }) as never)
    fireEvent.click(screen.getByRole('button', { name: 'Update password' }))
    await waitFor(() => expect(api).toHaveBeenCalledWith('/auth/password', expect.objectContaining({ method: 'PUT', body: JSON.stringify({ current_password: 'old-password', new_password: 'new-password-123' }) })))
    expect(screen.getByRole('button', { name: 'Updating…' })).toBeDisabled()
    await act(async () => finishRequest?.())
    await waitFor(() => expect(api).toHaveBeenCalledWith('/auth/password', expect.objectContaining({ method: 'PUT', body: JSON.stringify({ current_password: 'old-password', new_password: 'new-password-123' }) })))
    expect(setCSRF).toHaveBeenCalledWith('')
    expect(await screen.findByRole('status')).toHaveTextContent('Your password was changed. Sign in with the new password.')
    expect(screen.getByRole('heading', { name: 'Sign in' })).toBeInTheDocument()
  })

  it('rejects mismatched new-password confirmation without contacting the server', async () => {
    renderPage()
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Security' })).toBeInTheDocument())
    fireEvent.change(screen.getByLabelText('Current password'), { target: { value: 'old-password' } })
    fireEvent.change(screen.getByLabelText('New password'), { target: { value: 'new-password-123' } })
    fireEvent.change(screen.getByLabelText('Confirm new password'), { target: { value: 'different-password-123' } })
    fireEvent.click(screen.getByRole('button', { name: 'Update password' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('The new passwords do not match.')
    expect(screen.getByLabelText('Confirm new password')).toHaveAttribute('aria-invalid', 'true')
    expect(screen.getByLabelText('Confirm new password')).toHaveAccessibleDescription('The new passwords do not match.')
    expect(api).not.toHaveBeenCalled()
  })

  it('marks the current-password field when the server rejects it', async () => {
    vi.mocked(api).mockRejectedValueOnce(new APIError('password incorrect', 'invalid_password'))
    renderPage()
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Security' })).toBeInTheDocument())
    fireEvent.change(screen.getByLabelText('Current password'), { target: { value: 'incorrect-password' } })
    fireEvent.change(screen.getByLabelText('New password'), { target: { value: 'new-password-123' } })
    fireEvent.change(screen.getByLabelText('Confirm new password'), { target: { value: 'new-password-123' } })
    fireEvent.click(screen.getByRole('button', { name: 'Update password' }))
    await waitFor(() => expect(screen.getByLabelText('Current password')).toHaveAttribute('aria-invalid', 'true'))
    expect(screen.getByLabelText('Current password')).toHaveAccessibleDescription('Current password is incorrect.')
    expect(screen.getByRole('alert')).toHaveTextContent('password incorrect')
  })

  it('lets keyboard users reveal and hide each password field', async () => {
    renderPage()
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Security' })).toBeInTheDocument())
    const newPassword = screen.getByLabelText('New password')
    expect(newPassword).toHaveAttribute('type', 'password')
    fireEvent.click(screen.getByRole('button', { name: 'Show new password' }))
    expect(newPassword).toHaveAttribute('type', 'text')
    fireEvent.click(screen.getByRole('button', { name: 'Hide new password' }))
    expect(newPassword).toHaveAttribute('type', 'password')
    const confirmation = screen.getByLabelText('Confirm new password')
    fireEvent.click(screen.getByRole('button', { name: 'Show confirmation password' }))
    expect(confirmation).toHaveAttribute('type', 'text')
  })

  it('covers TOTP enrollment, recovery acknowledgement, and logout', async () => {
    vi.mocked(api).mockImplementation(async (path: string) => path === '/auth/totp/setup' ? { secret: 'BASE32SECRET', otpauth: 'otpauth://totp/EdgeWatch' } as never : { recovery_codes: ['one', 'two'] } as never)
    renderPage()
    await waitFor(() => expect(screen.getByRole('button', { name: 'Set up authenticator' })).toBeInTheDocument())
    fireEvent.change(screen.getByLabelText('Current password'), { target: { value: 'password-from-another-form' } })
    await startAuthenticatorSetup()
    expect(api).toHaveBeenCalledWith('/auth/totp/setup', expect.objectContaining({ body: JSON.stringify({ password: 'correct-password' }) }))
    expect(screen.getByLabelText('Current password')).toHaveValue('')
    expect(screen.getByLabelText('Authenticator secret')).toHaveTextContent('BASE 32SE CRET')
    expect(screen.getByRole('link', { name: 'Open authenticator app' })).toHaveAttribute('href', 'otpauth://totp/EdgeWatch')
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Verification code'), { target: { value: '123 456' } })
    fireEvent.click(screen.getByRole('button', { name: 'Enable TOTP' }))
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Save your recovery codes' })).toBeInTheDocument())
    expect(api).toHaveBeenCalledWith('/auth/totp/enable', expect.objectContaining({ body: JSON.stringify({ code: '123456' }) }))
    const acknowledgement = screen.getByRole('checkbox', { name: /I saved these recovery codes/ })
    expect(acknowledgement.closest('label')).toHaveClass('checkbox-label', 'recovery-ack')
    expect(acknowledgement.closest('label')?.querySelector('span')).toHaveTextContent('I saved these recovery codes in a secure place.')
    fireEvent.click(acknowledgement)
    expect(screen.getByRole('button', { name: 'Continue to sign in' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Continue to sign in' }))
    await waitFor(() => expect(logout).toHaveBeenCalledOnce())
  })

  it('copies recovery codes and announces success or failure', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } })
    vi.mocked(api).mockImplementation(async (path: string) => path === '/auth/totp/setup' ? { secret: 'BASE32SECRET', otpauth: 'otpauth://totp/EdgeWatch' } as never : { recovery_codes: ['one', 'two'] } as never)
    renderPage()
    await waitFor(() => expect(screen.getByRole('button', { name: 'Set up authenticator' })).toBeInTheDocument())
    await startAuthenticatorSetup()
    fireEvent.change(screen.getByLabelText('Verification code'), { target: { value: '123456' } })
    fireEvent.click(screen.getByRole('button', { name: 'Enable TOTP' }))
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Save your recovery codes' })).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: 'Copy codes' }))
    await waitFor(() => expect(screen.getByText('Recovery codes copied.')).toBeInTheDocument())
    expect(writeText).toHaveBeenCalledWith('one\ntwo')
    writeText.mockRejectedValueOnce(new Error('clipboard denied'))
    fireEvent.click(screen.getByRole('button', { name: 'Copy codes' }))
    await waitFor(() => expect(screen.getByText('The recovery codes could not be copied. Select the codes and copy them manually.')).toBeInTheDocument())
  })

  it('shows authenticator setup errors inside the password confirmation dialog', async () => {
    vi.mocked(api).mockRejectedValueOnce(new Error('Password confirmation failed'))
    renderPage()
    await waitFor(() => expect(screen.getByRole('button', { name: 'Set up authenticator' })).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: 'Set up authenticator' }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText('Account password'), { target: { value: 'incorrect-password' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Start setup' }))
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('Password confirmation failed')
    expect(screen.queryByLabelText('Authenticator secret')).not.toBeInTheDocument()
  })

  it('copies the ungrouped authenticator secret and announces the result', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } })
    vi.mocked(api).mockImplementation(async (path: string) => path === '/auth/totp/setup' ? { secret: 'BASE32SECRET', otpauth: 'otpauth://totp/EdgeWatch' } as never : {} as never)
    renderPage()
    await waitFor(() => expect(screen.getByRole('button', { name: 'Set up authenticator' })).toBeInTheDocument())
    await startAuthenticatorSetup()
    fireEvent.click(screen.getByRole('button', { name: 'Copy secret' }))
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('Authenticator secret copied.'))
    expect(writeText).toHaveBeenCalledWith('BASE32SECRET')
    writeText.mockRejectedValueOnce(new Error('clipboard denied'))
    fireEvent.click(screen.getByRole('button', { name: 'Copy secret' }))
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('The secret could not be copied. Select and copy it manually.'))
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
    await startAuthenticatorSetup()

    fireEvent.change(screen.getByLabelText('Verification code'), { target: { value: '000000' } })
    fireEvent.click(screen.getByRole('button', { name: 'Enable TOTP' }))
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('4 attempts remain'))
    expect(screen.getByLabelText('Authenticator secret')).toHaveTextContent('BASE 32SE CRET')
    expect(screen.getByLabelText('Verification code')).toHaveValue('')
    expect(screen.queryByRole('button', { name: 'Set up authenticator' })).not.toBeInTheDocument()

    fireEvent.change(screen.getByLabelText('Verification code'), { target: { value: '111111' } })
    fireEvent.click(screen.getByRole('button', { name: 'Enable TOTP' }))
    await waitFor(() => expect(screen.getByRole('button', { name: 'Set up authenticator' })).toBeInTheDocument())
    expect(screen.queryByLabelText('Authenticator secret')).not.toBeInTheDocument()
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
    fireEvent.change(screen.getByLabelText('Current authenticator code or recovery code'), { target: { value: '123 456' } })
    fireEvent.click(dialog.querySelector('button[type="submit"]')!)
    await waitFor(() => expect(screen.getByLabelText('Authenticator secret').textContent?.replaceAll(' ', '')).toBe('REPLACEMENTSECRET'))

    fireEvent.change(screen.getByLabelText('Verification code'), { target: { value: '654321' } })
    fireEvent.click(screen.getByRole('button', { name: 'Replace authenticator' }))
    await waitFor(() => expect(screen.queryByLabelText('Authenticator secret')).not.toBeInTheDocument())
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

  it('confirms session revocation and explains that the administrator must sign in again', async () => {
    renderPage()
    await waitFor(() => expect(screen.getByRole('button', { name: /Log out all sessions/ })).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: /Log out all sessions/ }))
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Log out all sessions' }))
    await waitFor(() => expect(logoutAllSessions).toHaveBeenCalledOnce())
    expect(setCSRF).toHaveBeenCalledWith('')
    expect(await screen.findByRole('status')).toHaveTextContent('All sessions were signed out. Sign in again.')
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
    fireEvent.change(screen.getByLabelText('Current authenticator code or recovery code'), { target: { value: '123 456' } })
    fireEvent.click(dialog.querySelector('button[type="submit"]')!)
    await waitFor(() => expect(screen.getByLabelText('Authenticator secret').textContent?.replaceAll(' ', '')).toBe('REPLACEMENTSECRET'))
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
    const acknowledge = screen.getByRole('checkbox', { name: /I saved these recovery codes/ })
    expect(screen.getByRole('button', { name: 'Done' })).toBeDisabled()
    fireEvent.click(acknowledge)
    fireEvent.click(screen.getByRole('button', { name: 'Done' }))
    await waitFor(() => expect(screen.queryByRole('heading', { name: 'Save your recovery codes' })).not.toBeInTheDocument())
    expect(screen.getByRole('status')).toHaveTextContent('Recovery codes saved. Your session remains active.')
    expect(logout).not.toHaveBeenCalled()
  })

  it.each([
    ['Regenerate recovery codes', '/auth/totp/recovery-codes', 'POST', 'Regenerate codes'],
    ['Replace authenticator', '/auth/totp/setup', 'POST', 'Start replacement'],
    ['Disable TOTP', '/auth/totp', 'DELETE', 'Disable TOTP'],
  ] as const)('%s removes recovery-code grouping before sending the factor', async (openLabel, path, method, confirmLabel) => {
    vi.mocked(getSession).mockResolvedValue({ ...administrator, totp_enabled: true })
    vi.mocked(api).mockImplementation(async requestPath => {
      if (requestPath === '/auth/totp/setup') return { secret: 'REPLACEMENTSECRET', otpauth: 'otpauth://totp/EdgeWatch' } as never
      if (requestPath === '/auth/totp/recovery-codes') return { recovery_codes: ['new-recovery-code'] } as never
      return {} as never
    })
    renderPage()
    await waitFor(() => expect(screen.getByRole('button', { name: openLabel })).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: openLabel }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText('Account password'), { target: { value: 'correct-password' } })
    fireEvent.change(within(dialog).getByLabelText('Current authenticator code or recovery code'), { target: { value: 'ABCD EFGH IJKL MNOP QRST UVWX YZ' } })
    fireEvent.click(within(dialog).getByRole('button', { name: confirmLabel }))

    await waitFor(() => expect(api).toHaveBeenCalledWith(path, expect.objectContaining({
      method,
      body: JSON.stringify({ password: 'correct-password', code: '', recovery_code: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' }),
    })))
  })
})
