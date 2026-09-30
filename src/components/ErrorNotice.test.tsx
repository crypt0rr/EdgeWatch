/** @vitest-environment jsdom */

import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { ErrorNotice } from './ErrorNotice'

describe('ErrorNotice', () => {
  it('announces a safe message and retries the failed read', () => {
    const onRetry = vi.fn()
    render(<ErrorNotice message="Could not load hosts." onRetry={onRetry} />)

    expect(screen.getByRole('alert')).toHaveTextContent('Could not load hosts.')
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(onRetry).toHaveBeenCalledOnce()
  })

  it('can show a reload action for startup failures', () => {
    render(<ErrorNotice message="Unable to contact EdgeWatch." retryLabel="Reload" onRetry={vi.fn()} />)
    expect(screen.getByRole('button', { name: 'Reload' })).toBeInTheDocument()
  })
})
