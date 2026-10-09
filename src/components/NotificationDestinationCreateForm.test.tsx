/** @vitest-environment jsdom */

import { fireEvent, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { APIError, type NotificationDestination } from '../api'
import { renderWithProviders } from '../test/test-utils'
import { NotificationDestinationCreateForm } from './NotificationDestinationCreateForm'

const savedDestination: NotificationDestination = {
  id: 'destination-created',
  name: 'Operations',
  provider: 'smtp',
  source: 'web',
  enabled: true,
  locked: false,
  read_only: false,
  revision: 1,
}

function fillForm() {
  fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'Operations' } })
  fireEvent.change(screen.getByLabelText('SMTP server'), { target: { value: 'smtp.example.test' } })
  fireEvent.change(screen.getByLabelText('From address'), { target: { value: 'edge@example.test' } })
  fireEvent.change(screen.getByLabelText(/^Recipients/), { target: { value: 'ops@example.test' } })
  fireEvent.change(screen.getByLabelText('SMTP username'), { target: { value: 'smtp-user' } })
  fireEvent.change(screen.getByLabelText('SMTP password'), { target: { value: 'smtp-secret-value' } })
  fireEvent.change(screen.getByLabelText(/^Password confirmation/), { target: { value: 'account-password-value' } })
}

function submitForm() {
  const form = document.querySelector('.notification-destination-create-form')
  if (!form) throw new Error('Destination form not found')
  fireEvent.submit(form)
}

afterEach(() => vi.clearAllMocks())

describe('NotificationDestinationCreateForm', () => {
  it('saves once, clears provider credentials, and uses explicit test delivery wording', async () => {
    const create = vi.fn(async () => savedDestination)
    const onCreated = vi.fn()
    const onTest = vi.fn(async () => ({ sent: 1 }))
    const { client } = renderWithProviders(<NotificationDestinationCreateForm create={create} onCreated={onCreated} onTest={onTest} />)
    fillForm()

    fireEvent.click(screen.getByRole('button', { name: /Add destination/ }))
    await screen.findByText(/Notification destination added/)
    expect(create).toHaveBeenCalledTimes(1)
    expect(onCreated).toHaveBeenCalledWith(savedDestination)
    expect(screen.getByLabelText(/^Name/)).toHaveValue('')
    expect(screen.getByLabelText('SMTP server')).toHaveValue('')
    expect(screen.getByLabelText('SMTP password')).toHaveValue('')
    expect(screen.getByLabelText(/^Password confirmation/)).toHaveValue('')
    expect(JSON.stringify(client.getQueryCache().getAll())).not.toContain('smtp-secret-value')
    expect(JSON.stringify(client.getQueryCache().getAll())).not.toContain('account-password-value')

    fireEvent.click(screen.getByRole('button', { name: 'Test destination' }))
    await screen.findByText(/Test send completed for Operations\. Check that the message arrived\./)
    expect(onTest).toHaveBeenCalledWith(savedDestination)
  })

  it('keeps edits after a failed save and redacts echoed credentials from the error', async () => {
    const create = vi.fn(async () => {
      throw new APIError('Save failed', 'invalid', { message: 'smtp-secret-value account-password-value' }, 400)
    })
    renderWithProviders(<NotificationDestinationCreateForm create={create} />)
    fillForm()
    submitForm()

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('[redacted] [redacted]')
    expect(alert).not.toHaveTextContent('smtp-secret-value')
    expect(alert).not.toHaveTextContent('account-password-value')
    expect(screen.getByLabelText(/^Name/)).toHaveValue('Operations')
    expect(screen.getByLabelText('SMTP password')).toHaveValue('smtp-secret-value')
    expect(screen.getByLabelText(/^Password confirmation/)).toHaveValue('account-password-value')
  })

  it('does not retry create when post-save list refresh fails', async () => {
    const create = vi.fn(async () => savedDestination)
    const onCreated = vi.fn().mockRejectedValueOnce(new Error('temporary list failure')).mockResolvedValue(undefined)
    renderWithProviders(<NotificationDestinationCreateForm create={create} onCreated={onCreated} />)
    fillForm()
    submitForm()

    expect(await screen.findByRole('alert')).toHaveTextContent('The destination was created, but the destination list could not be refreshed or selected. It remains in Notifications.')
    expect(screen.getByRole('button', { name: 'Retry list refresh' })).toBeInTheDocument()
    expect(screen.getByText(/Notification destination added/)).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Retry list refresh' }))
    await waitFor(() => expect(onCreated).toHaveBeenCalledTimes(2))
    expect(create).toHaveBeenCalledTimes(1)
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('blocks duplicate submissions synchronously and keeps its secrets out of shared state', async () => {
    let resolveCreate!: (value: NotificationDestination) => void
    const create = vi.fn(() => new Promise<NotificationDestination>(resolve => { resolveCreate = resolve }))
    const { client, unmount } = renderWithProviders(<NotificationDestinationCreateForm create={create} />)
    fillForm()
    submitForm()
    submitForm()

    expect(create).toHaveBeenCalledTimes(1)
    const cacheSnapshot = JSON.stringify(client.getQueryCache().getAll())
    expect(cacheSnapshot).not.toContain('smtp-secret-value')
    expect(cacheSnapshot).not.toContain('account-password-value')
    unmount()

    resolveCreate(savedDestination)
    renderWithProviders(<NotificationDestinationCreateForm create={vi.fn(async () => savedDestination)} />)
    expect(screen.getByLabelText(/^Name/)).toHaveValue('')
    expect(screen.getByLabelText('SMTP password')).toHaveValue('')
    expect(screen.getByLabelText(/^Password confirmation/)).toHaveValue('')
  })
})
