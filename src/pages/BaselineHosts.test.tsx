/** @vitest-environment jsdom */

import { act } from 'react'
import { fireEvent } from '@testing-library/react'
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

  it('offers a retry when baseline hosts cannot be loaded', async () => {
    vi.mocked(baselineHosts).mockRejectedValueOnce(new Error('baseline unavailable'))
    await act(async () => {
      root.render(<QueryClientProvider client={queryClient}><MemoryRouter initialEntries={['/jobs/job-1/baseline']}><Routes><Route path="/jobs/:id/baseline" element={<BaselineHosts />} /></Routes></MemoryRouter></QueryClientProvider>)
    })
    await vi.waitFor(() => expect(container.querySelector('[role="alert"]')).toBeTruthy(), { timeout: 1000 })
    expect(container.textContent).toContain('Could not load baseline hosts')
    const retry = Array.from(container.querySelectorAll('button')).find(button => button.textContent === 'Retry') as HTMLButtonElement
    expect(retry).toBeTruthy()
    vi.mocked(baselineHosts).mockResolvedValueOnce(detailed)
    await act(async () => retry.click())
    await vi.waitFor(() => expect(container.textContent).toContain('router.example'), { timeout: 1000 })
  })

  it('resets pagination for every filter and renders legacy/private host states', async () => {
    const hosts = [
      { address: '10.0.0.1', source_targets: [], protocols: [{ protocol: 'tcp', open_ports: 0, open_filtered_ports: 0 }], open_ports: 0, open_filtered_ports: 0, has_open_ports: false },
      { address: '2001:db8::1', address_family: 'IPv6', source_targets: ['dns.example'], protocols: [{ protocol: 'udp', open_ports: 1, open_filtered_ports: 2 }], open_ports: 1, open_filtered_ports: 2, has_open_ports: true, legacy: true },
    ] as never
    vi.mocked(baselineHosts).mockImplementation(async (_job, filters) => ({
      ...detailed,
      data_quality: 'legacy',
      hosts,
      pagination: { limit: 1, offset: filters?.offset ?? 0, total: 2, has_more: (filters?.offset ?? 0) === 0, next_offset: (filters?.offset ?? 0) === 0 ? 1 : null },
    }))
    await renderPage()
    expect(container.textContent).toContain('Older scan details')
    expect(container.textContent).toContain('Private')
    expect(container.textContent).toContain('Legacy detail')
    expect(container.textContent).toContain('2 open|filtered')

    const next = container.querySelector('nav[aria-label="Pagination"] button:last-child') as HTMLButtonElement
    expect(next).toBeTruthy()
    await act(async () => next.click())
    await vi.waitFor(() => expect(baselineHosts).toHaveBeenLastCalledWith('job-1', expect.objectContaining({ offset: 1 })), { timeout: 1000 })

    const selects = container.querySelectorAll('select')
    await act(async () => {
      fireEvent.change(selects[1], { target: { value: 'true' } })
      await vi.waitFor(() => expect(baselineHosts).toHaveBeenLastCalledWith('job-1', expect.objectContaining({ has_open_ports: true, offset: 0 })), { timeout: 1000 })
      fireEvent.change(selects[1], { target: { value: 'false' } })
      await vi.waitFor(() => expect(baselineHosts).toHaveBeenLastCalledWith('job-1', expect.objectContaining({ has_open_ports: false, offset: 0 })), { timeout: 1000 })
    })
  })
})
