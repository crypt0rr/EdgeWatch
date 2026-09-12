/** @vitest-environment jsdom */

import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { APIError, getPublicDashboard, getPublicDashboardConfig, listHosts, savePublicDashboardConfig } from '../api'
import type { PublicDashboard, PublicDashboardConfig } from '../api'
import type { GlobalHostsResponse } from '../types'
import { PublicDashboard as PublicDashboardView, PublicDashboardAdmin } from './PublicDashboard'

vi.mock('../api', () => ({
  APIError: class APIError extends Error {
    code?: string
    constructor(message: string, code?: string) {
      super(message)
      this.name = 'APIError'
      this.code = code
    }
  },
  getPublicDashboard: vi.fn(),
  getPublicDashboardConfig: vi.fn(),
  listHosts: vi.fn(),
  savePublicDashboardConfig: vi.fn(),
}))

;(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true

const dashboard: PublicDashboard = {
  title: 'Edge status',
  introduction: 'Monitored services',
  updated_at: '2026-09-12T08:00:00Z',
  hosts: [
    {
      job: 'production',
      address: '198.51.100.10',
      address_family: 'IPv4',
      public: true,
      private: false,
      last_successful_scan: '2026-09-12T07:00:00Z',
      open_ports: [{ protocol: 'tcp', port: 443, service: 'https' }],
      open_filtered_ports: [{ protocol: 'udp', port: 53 }],
      rdap: { status: 'success', network_name: 'Example network', country: 'ZZ' },
    },
    { job: 'internal', address: '192.0.2.20', address_family: 'IPv4', public: false, private: true, open_ports: [], open_filtered_ports: [] },
  ],
}

const publicConfig: PublicDashboardConfig = {
  enabled: false,
  title: 'EdgeWatch public status',
  introduction: '',
  updated_at: '2026-09-12T08:00:00Z',
  hosts: [],
}

const pickerResponse: GlobalHostsResponse = {
  hosts: [
    { address: '198.51.100.10', job_id: 'job-1', job: 'production', scan_id: 'scan-1', scanned_at: '2026-09-12T07:00:00Z', data_quality: 'detailed', open_ports: 1, open_filtered_ports: 0, has_open_ports: true, archived: false },
    { address: '198.51.100.11', job_id: 'job-2', job: 'retired', scan_id: 'scan-2', scanned_at: '2026-09-11T07:00:00Z', data_quality: 'detailed', open_ports: 0, open_filtered_ports: 0, has_open_ports: false, archived: true },
    { address: '198.51.100.12', job_id: '', job: 'legacy', scan_id: 'scan-3', scanned_at: '2026-09-10T07:00:00Z', data_quality: 'legacy', open_ports: 0, open_filtered_ports: 0, has_open_ports: false },
  ],
  pagination: { limit: 100, offset: 0, total: 3, has_more: false, next_offset: null },
}

describe('public dashboard pages', () => {
  let root: Root
  let container: HTMLDivElement
  let queryClient: QueryClient

  beforeEach(() => {
    container = document.createElement('div')
    document.body.appendChild(container)
    root = createRoot(container)
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    vi.mocked(getPublicDashboard).mockResolvedValue(dashboard)
    vi.mocked(getPublicDashboardConfig).mockResolvedValue(publicConfig)
    vi.mocked(listHosts).mockResolvedValue(pickerResponse)
    vi.mocked(savePublicDashboardConfig).mockResolvedValue({ ...publicConfig, enabled: true })
  })

  afterEach(() => {
    act(() => root.unmount())
    queryClient.clear()
    container.remove()
    vi.clearAllMocks()
  })

  async function renderPage(element: React.ReactNode) {
    await act(async () => {
      root.render(<QueryClientProvider client={queryClient}>{element}</QueryClientProvider>)
    })
    // TanStack Query schedules its observer notification after the fetch
    // promise resolves; wait outside the initial render act for that update.
    await vi.waitFor(() => expect(container.textContent).not.toContain('Loading public'), { timeout: 1000 })
  }

  it('renders public host summaries, services, registration data, and private badges', async () => {
    await renderPage(<PublicDashboardView />)
    expect(container.querySelector('h1')?.textContent).toBe('Edge status')
    expect(container.textContent).toContain('Monitored services')
    expect(container.textContent).toContain('198.51.100.10')
    expect(container.textContent).toContain('443/tcp')
    expect(container.textContent).toContain('https')
    expect(container.textContent).toContain('Example network')
    expect(container.textContent).toContain('Private IP')
    expect(container.textContent).toContain('No confirmed open ports')
  })

  it('shows a safe message for rate-limited public status requests', async () => {
    vi.mocked(getPublicDashboard).mockRejectedValue(new APIError('try later', 'rate_limited'))
    await renderPage(<PublicDashboardView />)
    expect(container.querySelector('h1')?.textContent).toBe('Public status unavailable')
    expect(container.textContent).toContain('temporarily rate limited')
    expect(container.querySelector('a[href="/login"]')).toBeTruthy()
  })

  it('separates archived and legacy hosts and saves checkbox changes', async () => {
    await renderPage(<PublicDashboardAdmin />)
    expect(container.textContent).toContain('Active jobs')
    expect(container.textContent).toContain('Archived jobs')
    expect(container.textContent).toContain('recreate this host in a web-managed job')
    const checkboxes = Array.from(container.querySelectorAll('input[id^="public-host-"]')) as HTMLInputElement[]
    expect(checkboxes).toHaveLength(3)
    expect(checkboxes[0].disabled).toBe(false)
    expect(checkboxes[1].disabled).toBe(true)
    expect(checkboxes[2].disabled).toBe(true)

    act(() => checkboxes[0].click())
    const enabled = checkboxes[0]
    expect(enabled.checked).toBe(true)
    const saveButton = Array.from(container.querySelectorAll('button')).find(button => button.textContent?.includes('Save public view')) as HTMLButtonElement
    await act(async () => {
      saveButton.click()
      await Promise.resolve()
      await Promise.resolve()
    })
    expect(savePublicDashboardConfig).toHaveBeenCalledWith(expect.objectContaining({
      hosts: [{ job_id: 'job-1', address: '198.51.100.10' }],
    }))
    expect(container.textContent).toContain('Public view saved.')
  })
})
