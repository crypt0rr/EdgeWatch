/** @vitest-environment jsdom */

import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { OneTimeLink } from './OneTimeLink'

const originalClipboard = Object.getOwnPropertyDescriptor(navigator, 'clipboard')

function setClipboard(value?: Clipboard) {
  if (value) Object.defineProperty(navigator, 'clipboard', { configurable: true, value })
  else Reflect.deleteProperty(navigator, 'clipboard')
}

describe('one-time activation links', () => {
  afterEach(() => {
    if (originalClipboard) Object.defineProperty(navigator, 'clipboard', originalClipboard)
    else Reflect.deleteProperty(navigator, 'clipboard')
  })

  it('displays the full link, confirms a successful copy, and dismisses', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    const onDismiss = vi.fn()
    setClipboard({ writeText } as unknown as Clipboard)
    render(<OneTimeLink title="Activation link for Morgan" path="/activate#token=secret" note="Expires soon." onDismiss={onDismiss} />)

    expect(screen.getByLabelText('Activation link for Morgan')).toHaveTextContent(`${window.location.origin}/activate#token=secret`)
    fireEvent.click(screen.getByRole('button', { name: 'Copy link' }))
    await waitFor(() => expect(screen.getByRole('button', { name: 'Copied' })).toBeInTheDocument())
    expect(writeText).toHaveBeenCalledWith(`${window.location.origin}/activate#token=secret`)
    fireEvent.click(screen.getByRole('button', { name: 'Done' }))
    expect(onDismiss).toHaveBeenCalledOnce()
  })

  it('explains when clipboard access is unavailable', () => {
    setClipboard()
    render(<OneTimeLink title="Activation link" path="/activate#token=secret" note="Expires soon." onDismiss={() => {}} />)
    fireEvent.click(screen.getByRole('button', { name: 'Copy link' }))
    expect(screen.getByRole('status')).toHaveTextContent('Clipboard access is unavailable')
  })

  it('reports a rejected clipboard write instead of claiming it copied', async () => {
    setClipboard({ writeText: vi.fn().mockRejectedValue(new Error('denied')) } as unknown as Clipboard)
    render(<OneTimeLink title="Activation link" path="/activate#token=secret" note="Expires soon." onDismiss={() => {}} />)
    fireEvent.click(screen.getByRole('button', { name: 'Copy link' }))
    expect(await screen.findByRole('status')).toHaveTextContent('The link could not be copied')
    expect(screen.getByRole('button', { name: 'Copy link' })).toBeInTheDocument()
  })
})
