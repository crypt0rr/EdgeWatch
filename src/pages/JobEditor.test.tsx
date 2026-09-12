/** @vitest-environment jsdom */

import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { getJob, listNotificationDestinations, listScannerProfiles, scannerCapabilities } from '../api'
import { JobEditor } from './JobEditor'

vi.mock('../api', () => ({
  BUILTIN_NAABU_PROFILE_ID: 'builtin-naabu',
  getJob: vi.fn(),
  listNotificationDestinations: vi.fn(),
  listScannerProfiles: vi.fn(),
  scannerCapabilities: vi.fn(),
  scheduleSuggestion: vi.fn(),
  createJob: vi.fn(),
  updateJob: vi.fn(),
}))

;(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true

describe('job editor', () => {
  let root: Root
  let container: HTMLDivElement
  let queryClient: QueryClient

  beforeEach(() => {
    container = document.createElement('div')
    document.body.appendChild(container)
    root = createRoot(container)
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    vi.mocked(listNotificationDestinations).mockResolvedValue({
      destinations: [],
      status: { deployment: 0, managed: 0, active: 0, locked: 0, key_state: 'ready' },
    })
    vi.mocked(listScannerProfiles).mockResolvedValue({ profiles: [] })
    vi.mocked(scannerCapabilities).mockResolvedValue({
      engines: ['nmap', 'naabu_nmap'],
      nmap: { available: true, path: '/usr/bin/nmap', version: '7.99' },
      naabu: { available: true, path: '/usr/local/bin/naabu', version: '2.6.1', syn_supported: false },
    })
  })

  afterEach(() => {
    act(() => root.unmount())
    queryClient.clear()
    container.remove()
    vi.clearAllMocks()
  })

  it('shows an actionable error instead of a blank edit form when loading fails', async () => {
    vi.mocked(getJob).mockRejectedValue(new Error('database offline'))

    await act(async () => {
      root.render(
        <QueryClientProvider client={queryClient}>
          <MemoryRouter initialEntries={['/jobs/job-1/edit']}>
            <Routes>
              <Route path="/jobs/:id/edit" element={<JobEditor />} />
            </Routes>
          </MemoryRouter>
        </QueryClientProvider>,
      )
    })

    await vi.waitFor(() => expect(container.querySelector('[role="alert"]')).toBeTruthy(), { timeout: 1000 })
    expect(container.querySelector('[role="alert"]')?.textContent).toContain('Job details are unavailable.')
    expect(container.querySelector('[role="alert"]')?.textContent).toContain('database offline')
    expect(container.textContent).toContain('Try again')
    expect(container.querySelector('a[href="/jobs/job-1"]')).toBeTruthy()
    expect(container.querySelector('input[placeholder="Production edge"]')).toBeNull()
  })
})
