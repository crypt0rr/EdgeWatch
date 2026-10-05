/** @vitest-environment jsdom */

import { cleanup, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { PageErrorBoundary } from './PageErrorBoundary'
import { renderWithProviders } from '../test/test-utils'

function CrashingPage(): never {
  throw new Error('invalid host detail')
}

describe('PageErrorBoundary', () => {
  afterEach(() => {
    cleanup()
    vi.restoreAllMocks()
  })

  it('shows a recoverable error with a safe route back to the application', () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})

    renderWithProviders(<PageErrorBoundary homePath="/" homeLabel="Overview"><CrashingPage /></PageErrorBoundary>)

    expect(screen.getByRole('alert')).toHaveTextContent('This page could not be displayed.')
    expect(screen.getByRole('button', { name: 'Reload page' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Go to Overview' })).toHaveAttribute('href', '/')
  })
})
