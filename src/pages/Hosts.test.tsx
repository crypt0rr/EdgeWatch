/** @vitest-environment jsdom */

import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { listHosts } from '../api'
import type { GlobalHostsResponse } from '../types'
import { Hosts } from './Hosts'

vi.mock('../api', () => ({ listHosts: vi.fn() }))

;(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true

const response: GlobalHostsResponse = {
  hosts: [
    { address: '198.51.100.10', address_family: 'IPv4', source_targets: ['router.example'], protocols: [{ protocol: 'tcp', scanned_ports: '22,443', scanned_port_count: 2, service_detection: false, open_ports: 1, open_filtered_ports: 0 }], open_ports: 1, open_filtered_ports: 0, has_open_ports: true, job_id: 'job-1', job: 'production', scan_id: 'scan-1', scanned_at: '2026-09-12T07:00:00Z', data_quality: 'detailed' },
    { address: 'fd00::1', address_family: 'IPv6', dns_names: ['internal.example'], protocols: [{ protocol: 'udp', scanned_ports: '53', scanned_port_count: 1, service_detection: true, open_ports: 0, open_filtered_ports: 1 }], open_ports: 0, open_filtered_ports: 1, has_open_ports: true, job_id: 'job-2', job: 'retired', scan_id: 'scan-2', scanned_at: '2026-09-11T07:00:00Z', data_quality: 'legacy', archived: true, legacy: true },
  ],
  pagination: { limit: 1, offset: 0, total: 2, has_more: true, next_offset: 1 },
}

describe('global hosts explorer', () => {
  let root: Root
  let container: HTMLDivElement
  let queryClient: QueryClient

  beforeEach(() => {
    container = document.createElement('div')
    document.body.appendChild(container)
    root = createRoot(container)
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    vi.mocked(listHosts).mockResolvedValue(response)
  })

  afterEach(() => {
    act(() => root.unmount())
    queryClient.clear()
    container.remove()
    vi.clearAllMocks()
  })

  async function renderPage() {
    await act(async () => {
      root.render(<QueryClientProvider client={queryClient}><MemoryRouter><Hosts /></MemoryRouter></QueryClientProvider>)
    })
    await vi.waitFor(() => expect(container.textContent).toContain('Scanned hosts'), { timeout: 1000 })
  }

  function setInputValue(input: HTMLInputElement, value: string) {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set
    setter?.call(input, value)
    input.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertText' }))
  }

  it('renders active and archived hosts with searchable filter controls', async () => {
    await renderPage()
    expect(container.textContent).toContain('Active jobs')
    expect(container.textContent).toContain('Archived jobs')
    expect(container.textContent).toContain('198.51.100.10')
    expect(container.textContent).toContain('IPv6')
    expect(container.textContent).toContain('Legacy detail')
    expect(container.querySelector('a[href="/scans/scan-1/hosts/198.51.100.10"]')).toBeTruthy()
    expect(container.querySelector('a[href="/scans/scan-2/hosts/fd00%3A%3A1"]')).toBeTruthy()

    const search = container.querySelector('input[placeholder*="Search IP"]') as HTMLInputElement
    vi.mocked(listHosts).mockClear()
    await act(async () => {
      setInputValue(search, 'r')
      setInputValue(search, 'ro')
      setInputValue(search, 'router')
      await new Promise(resolve => setTimeout(resolve, 300))
    })
    expect(listHosts).toHaveBeenCalledTimes(1)
    expect(listHosts).toHaveBeenCalledWith(expect.objectContaining({ q: 'router', offset: 0 }))
    const selects = Array.from(container.querySelectorAll('select')) as HTMLSelectElement[]
    await act(async () => {
      selects[0].value = 'udp'
      selects[0].dispatchEvent(new Event('change', { bubbles: true }))
      selects[1].value = 'true'
      selects[1].dispatchEvent(new Event('change', { bubbles: true }))
      await vi.waitFor(() => expect(listHosts).toHaveBeenCalledWith(expect.objectContaining({ q: 'router', protocol: 'udp', has_open_ports: true, offset: 0 })), { timeout: 1000 })
    })

    await vi.waitFor(() => expect(Array.from(container.querySelectorAll('button')).find(button => button.textContent === 'Next')).toBeTruthy(), { timeout: 1000 })
    const next = Array.from(container.querySelectorAll('button')).find(button => button.textContent === 'Next') as HTMLButtonElement
    await act(async () => {
      next.click()
      await vi.waitFor(() => expect(listHosts).toHaveBeenCalledWith(expect.objectContaining({ offset: 1 })), { timeout: 1000 })
    })
  })

  it('shows an actionable error when the host index cannot be queried', async () => {
    vi.mocked(listHosts).mockRejectedValue(new Error('offline'))
    await act(async () => {
      root.render(<QueryClientProvider client={queryClient}><MemoryRouter><Hosts /></MemoryRouter></QueryClientProvider>)
    })
    await vi.waitFor(() => expect(container.querySelector('[role="alert"]')).toBeTruthy(), { timeout: 1000 })
    expect(container.querySelector('[role="alert"]')?.textContent).toContain('Could not load scanned hosts.')
  })

  it('keeps newer search results when an aborted request resolves late', async () => {
    const requests: Array<{ filters: NonNullable<Parameters<typeof listHosts>[0]>; resolve: (value: GlobalHostsResponse) => void }> = []
    vi.mocked(listHosts).mockImplementation((filters = {}) => new Promise(resolve => {
      requests.push({ filters, resolve })
    }))

    await act(async () => {
      root.render(<QueryClientProvider client={queryClient}><MemoryRouter><Hosts /></MemoryRouter></QueryClientProvider>)
    })
    await vi.waitFor(() => expect(requests).toHaveLength(1), { timeout: 1000 })
    await act(async () => {
      requests[0].resolve(response)
      await Promise.resolve()
    })
    await vi.waitFor(() => expect(container.textContent).toContain('198.51.100.10'), { timeout: 1000 })

    const search = container.querySelector('input[placeholder*="Search IP"]') as HTMLInputElement
    await act(async () => {
      setInputValue(search, 'old')
      await new Promise(resolve => setTimeout(resolve, 300))
    })
    await vi.waitFor(() => expect(requests).toHaveLength(2), { timeout: 1000 })
    await act(async () => {
      setInputValue(search, 'new')
      await new Promise(resolve => setTimeout(resolve, 300))
    })
    await vi.waitFor(() => expect(requests).toHaveLength(3), { timeout: 1000 })

    const oldResponse = { ...response, hosts: [{ ...response.hosts[0], address: '198.51.100.20' }] }
    const newResponse = { ...response, hosts: [{ ...response.hosts[0], address: '198.51.100.30' }] }
    await act(async () => {
      requests[2].resolve(newResponse)
      await Promise.resolve()
    })
    await vi.waitFor(() => expect(container.textContent).toContain('198.51.100.30'), { timeout: 1000 })
    await act(async () => {
      requests[1]!.resolve(oldResponse)
      await Promise.resolve()
    })
    expect(requests[1]!.filters.signal?.aborted).toBe(true)
    expect(container.textContent).toContain('198.51.100.30')
    expect(container.textContent).not.toContain('198.51.100.20')
  })
})
