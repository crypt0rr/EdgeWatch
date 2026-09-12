/** @vitest-environment jsdom */

import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { baselineHosts } from '../api'
import type { BaselineHostsResponse } from '../types'
import { BaselineHosts } from './BaselineHosts'

vi.mock('../api', () => ({ baselineHosts: vi.fn() }))

;(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true

const detailed: BaselineHostsResponse = {
  job_id: 'job-1',
  job: 'production',
  data_quality: 'detailed',
  hosts: [
    { address: '198.51.100.10', address_family: 'IPv4', source_targets: ['router.example'], protocols: [{ protocol: 'tcp', scanned_ports: '443', scanned_port_count: 1, service_detection: true, open_ports: 1, open_filtered_ports: 0 }], open_ports: 1, open_filtered_ports: 0, has_open_ports: true },
  ],
  pagination: { limit: 1, offset: 0, total: 2, has_more: true, next_offset: 1 },
}

describe('baseline host explorer', () => {
  let root: Root
  let container: HTMLDivElement
  let queryClient: QueryClient

  beforeEach(() => {
    container = document.createElement('div')
    document.body.appendChild(container)
    root = createRoot(container)
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    vi.mocked(baselineHosts).mockResolvedValue(detailed)
  })

  afterEach(() => {
    act(() => root.unmount())
    queryClient.clear()
    container.remove()
    vi.clearAllMocks()
  })

  async function renderPage() {
    await act(async () => {
      root.render(<QueryClientProvider client={queryClient}><MemoryRouter initialEntries={['/jobs/job-1/baseline']}><Routes><Route path="/jobs/:id/baseline" element={<BaselineHosts />} /></Routes></MemoryRouter></QueryClientProvider>)
    })
    await vi.waitFor(() => expect(container.textContent).toContain('Baseline hosts'), { timeout: 1000 })
  }

  it('renders detailed baseline hosts and resets filters to the first page', async () => {
    await renderPage()
    expect(container.textContent).toContain('Explore baseline')
    expect(container.textContent).toContain('router.example')
    expect(container.textContent).toContain('TCP')
    expect(container.querySelector('a[href="/jobs/job-1/baseline/hosts/198.51.100.10"]')).toBeTruthy()

    const search = container.querySelector('input[placeholder*="Search IP"]') as HTMLInputElement
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set
    vi.mocked(baselineHosts).mockClear()
    await act(async () => {
      setter?.call(search, 'r')
      search.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertText' }))
      setter?.call(search, 'ro')
      search.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertText' }))
      setter?.call(search, 'router')
      search.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertText' }))
      await new Promise(resolve => setTimeout(resolve, 300))
    })
    expect(baselineHosts).toHaveBeenCalledTimes(1)
    expect(baselineHosts).toHaveBeenCalledWith('job-1', expect.objectContaining({ q: 'router', offset: 0 }))
    const protocol = container.querySelectorAll('select')[0] as HTMLSelectElement
    await act(async () => {
      protocol.value = 'tcp'
      protocol.dispatchEvent(new Event('change', { bubbles: true }))
      await vi.waitFor(() => expect(baselineHosts).toHaveBeenCalledWith('job-1', expect.objectContaining({ protocol: 'tcp', offset: 0 })), { timeout: 1000 })
    })
  })

  it('explains when a job has no active baseline', async () => {
    vi.mocked(baselineHosts).mockResolvedValue({ ...detailed, data_quality: 'none', hosts: [], pagination: { limit: 50, offset: 0, total: 0, has_more: false, next_offset: null } })
    await act(async () => {
      root.render(<QueryClientProvider client={queryClient}><MemoryRouter initialEntries={['/jobs/job-1/baseline']}><Routes><Route path="/jobs/:id/baseline" element={<BaselineHosts />} /></Routes></MemoryRouter></QueryClientProvider>)
    })
    await vi.waitFor(() => expect(container.textContent).toContain('No active baseline'), { timeout: 1000 })
    expect(container.textContent).toContain('Complete the configured baseline samples')
    expect(container.querySelector('input[placeholder*="Search IP"]')).toBeNull()
  })
})
