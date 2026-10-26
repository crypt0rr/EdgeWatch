/** @vitest-environment jsdom */

import { act } from 'react'
import { fireEvent } from '@testing-library/react'
import { createRoot, type Root } from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes, useLocation, useNavigate } from 'react-router-dom'
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

function NavigationProbe() {
  const location = useLocation()
  const navigate = useNavigate()
  const returnTo = (location.state as { returnTo?: unknown } | null)?.returnTo
  return <><output data-testid="current-location">{location.pathname}{location.search}</output><output data-testid="return-to">{typeof returnTo === 'string' ? returnTo : ''}</output><button type="button" onClick={() => navigate(-1)}>Browser Back</button><button type="button" onClick={() => navigate(1)}>Browser Forward</button></>
}

function setInputValue(input: HTMLInputElement, value: string) {
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set
  setter?.call(input, value)
  input.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertText' }))
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

  async function renderPage(initialEntry = '/jobs/job-1/baseline') {
    await act(async () => {
      root.render(<QueryClientProvider client={queryClient}><MemoryRouter initialEntries={[initialEntry]}><Routes><Route path="/jobs/:id/baseline" element={<BaselineHosts />} /></Routes></MemoryRouter></QueryClientProvider>)
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
    })
    // Commit the input update before waiting so its debounce timer runs inside a separate act.
    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 300))
    })
    await vi.waitFor(() => expect(baselineHosts).toHaveBeenCalledWith('job-1', expect.objectContaining({ q: 'router', offset: 0 })), { timeout: 1000 })
    expect(baselineHosts).toHaveBeenCalledTimes(1)
    expect(baselineHosts).toHaveBeenCalledWith('job-1', expect.objectContaining({ q: 'router', offset: 0 }))
    const protocol = container.querySelectorAll('select')[0] as HTMLSelectElement
    fireEvent.change(protocol, { target: { value: 'tcp' } })
    await vi.waitFor(() => expect(baselineHosts).toHaveBeenCalledWith('job-1', expect.objectContaining({ protocol: 'tcp', offset: 0 })), { timeout: 1000 })
  })

  it('offers the first page when a restored offset is past the baseline end', async () => {
    const stalePage: BaselineHostsResponse = {
      ...detailed,
      hosts: [],
      pagination: { limit: 50, offset: 500, total: 30, has_more: false, next_offset: null },
    }
    vi.mocked(baselineHosts).mockImplementation(async (_job, filters) => filters?.offset === 500 ? stalePage : detailed)
    await renderPage('/jobs/job-1/baseline?offset=500')

    expect(baselineHosts).toHaveBeenCalledWith('job-1', expect.objectContaining({ offset: 500 }))
    expect(container).toHaveTextContent('No hosts on this page.')
    expect(container).not.toHaveTextContent('No hosts are in this baseline.')
    const goToFirstPage = Array.from(container.querySelectorAll('button')).find(button => button.textContent === 'Go to first page') as HTMLButtonElement
    expect(goToFirstPage).toBeTruthy()
    await act(async () => fireEvent.click(goToFirstPage))
    await vi.waitFor(() => expect(baselineHosts).toHaveBeenLastCalledWith('job-1', expect.objectContaining({ offset: 0 })), { timeout: 1000 })
    await vi.waitFor(() => expect(container.textContent).toContain('router.example'), { timeout: 1000 })
  })

  it('keeps search, filters, and page in the URL when returning from a baseline host', async () => {
    const returnTo = '/jobs/job-1/baseline?q=router&protocol=tcp&has_open_ports=true&offset=50'
    vi.mocked(baselineHosts).mockResolvedValue({
      ...detailed,
      pagination: { limit: 50, offset: 50, total: 100, has_more: false, next_offset: null },
    })
    await act(async () => {
      root.render(<QueryClientProvider client={queryClient}><MemoryRouter initialEntries={[returnTo]}>
        <Routes>
          <Route path="/jobs/:id/baseline" element={<BaselineHosts />} />
          <Route path="/jobs/:id/baseline/hosts/:address" element={<p>Baseline host detail</p>} />
        </Routes>
        <NavigationProbe />
      </MemoryRouter></QueryClientProvider>)
    })
    await vi.waitFor(() => expect(container.textContent).toContain('Baseline hosts'), { timeout: 1000 })
    expect(baselineHosts).toHaveBeenCalledWith('job-1', expect.objectContaining({ q: 'router', protocol: 'tcp', has_open_ports: true, offset: 50 }))
    expect((container.querySelector('input[placeholder*="Search IP"]') as HTMLInputElement).value).toBe('router')
    expect((container.querySelectorAll('select')[0] as HTMLSelectElement).value).toBe('tcp')
    expect((container.querySelectorAll('select')[1] as HTMLSelectElement).value).toBe('true')
    expect(container.textContent).toContain('51–100 of 100')

    const hostLink = container.querySelector('a[href="/jobs/job-1/baseline/hosts/198.51.100.10"]') as HTMLAnchorElement
    fireEvent.click(hostLink)
    await vi.waitFor(() => expect(container.querySelector('[data-testid="current-location"]')?.textContent).toBe('/jobs/job-1/baseline/hosts/198.51.100.10'), { timeout: 1000 })
    expect(container.querySelector('[data-testid="return-to"]')?.textContent).toBe(returnTo)

    fireEvent.click(Array.from(container.querySelectorAll('button')).find(button => button.textContent === 'Browser Back')!)
    await vi.waitFor(() => expect(container.querySelector('[data-testid="current-location"]')?.textContent).toBe(returnTo), { timeout: 1000 })
    expect((container.querySelector('input[placeholder*="Search IP"]') as HTMLInputElement).value).toBe('router')
    expect((container.querySelectorAll('select')[0] as HTMLSelectElement).value).toBe('tcp')
    expect((container.querySelectorAll('select')[1] as HTMLSelectElement).value).toBe('true')
    expect(container.textContent).toContain('51–100 of 100')
  })

  it('syncs search from browser Back and Forward URL changes', async () => {
    await act(async () => {
      root.render(<QueryClientProvider client={queryClient}><MemoryRouter initialEntries={['/jobs/job-1/baseline?q=router', '/jobs/job-1/baseline?q=database']}>
        <Routes><Route path="/jobs/:id/baseline" element={<BaselineHosts />} /></Routes>
        <NavigationProbe />
      </MemoryRouter></QueryClientProvider>)
    })
    const search = container.querySelector('input[placeholder*="Search IP"]') as HTMLInputElement
    await vi.waitFor(() => expect(search.value).toBe('database'))

    fireEvent.click(Array.from(container.querySelectorAll('button')).find(button => button.textContent === 'Browser Back')!)
    await vi.waitFor(() => expect(search.value).toBe('router'))
    fireEvent.click(Array.from(container.querySelectorAll('button')).find(button => button.textContent === 'Browser Forward')!)
    await vi.waitFor(() => expect(search.value).toBe('database'))
  })

  it('replaces search edits without adding a browser history entry per character', async () => {
    const previous = '/jobs/job-1/baseline?q=previous&protocol=udp&has_open_ports=false&offset=50'
    await act(async () => {
      root.render(<QueryClientProvider client={queryClient}><MemoryRouter initialEntries={[previous, '/jobs/job-1/baseline?protocol=tcp&has_open_ports=true&offset=50']}>
        <Routes><Route path="/jobs/:id/baseline" element={<BaselineHosts />} /></Routes>
        <NavigationProbe />
      </MemoryRouter></QueryClientProvider>)
    })
    const search = container.querySelector('input[placeholder*="Search IP"]') as HTMLInputElement
    await vi.waitFor(() => expect(search.value).toBe(''))

    for (const character of 'router') act(() => setInputValue(search, `${search.value}${character}`))
    await vi.waitFor(() => {
      const location = new URL(container.querySelector('[data-testid="current-location"]')?.textContent ?? '', 'http://localhost')
      expect(location.pathname).toBe('/jobs/job-1/baseline')
      expect(location.searchParams.get('q')).toBe('router')
      expect(location.searchParams.get('protocol')).toBe('tcp')
      expect(location.searchParams.get('has_open_ports')).toBe('true')
      expect(location.searchParams.has('offset')).toBe(false)
    })
    expect((container.querySelectorAll('select')[0] as HTMLSelectElement).value).toBe('tcp')
    expect((container.querySelectorAll('select')[1] as HTMLSelectElement).value).toBe('true')

    fireEvent.click(Array.from(container.querySelectorAll('button')).find(button => button.textContent === 'Browser Back')!)
    await vi.waitFor(() => expect(container.querySelector('[data-testid="current-location"]')?.textContent).toBe(previous))
    expect(search.value).toBe('previous')
    expect((container.querySelectorAll('select')[0] as HTMLSelectElement).value).toBe('udp')
    expect((container.querySelectorAll('select')[1] as HTMLSelectElement).value).toBe('false')
    fireEvent.click(Array.from(container.querySelectorAll('button')).find(button => button.textContent === 'Browser Forward')!)
    await vi.waitFor(() => expect(new URL(container.querySelector('[data-testid="current-location"]')?.textContent ?? '', 'http://localhost').searchParams.get('q')).toBe('router'))
    expect(search.value).toBe('router')
  })

  it('keeps short searches local and explains the minimum before querying', async () => {
    await renderPage()
    const search = container.querySelector('input[placeholder*="Search IP"]') as HTMLInputElement
    vi.mocked(baselineHosts).mockClear()
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set

    await act(async () => {
      setter?.call(search, '4')
      search.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertText' }))
    })
    expect(container.querySelector('[role="status"]')?.textContent).toContain('at least 3 characters')
    await act(async () => new Promise(resolve => setTimeout(resolve, 300)))
    expect(baselineHosts).not.toHaveBeenCalled()

    await act(async () => {
      setter?.call(search, '443')
      search.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertText' }))
    })
    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 300))
    })
    await vi.waitFor(() => expect(baselineHosts).toHaveBeenCalledWith('job-1', expect.objectContaining({ q: '443' })), { timeout: 1000 })
    expect(baselineHosts).toHaveBeenCalledTimes(1)
    expect(baselineHosts).toHaveBeenCalledWith('job-1', expect.objectContaining({ q: '443' }))
  })

  it('names an empty baseline search and offers clear and filter reset actions', async () => {
    vi.mocked(baselineHosts).mockImplementation(async (_job, filters) => filters?.q || filters?.protocol
      ? { ...detailed, hosts: [], pagination: { limit: 1, offset: 0, total: 0, has_more: false, next_offset: null } }
      : detailed)
    await renderPage()

    const search = container.querySelector('input[placeholder*="Search IP"]') as HTMLInputElement
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set
    await act(async () => {
      setter?.call(search, 'no-such-host.example.com')
      search.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertText' }))
    })
    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 300))
    })
    await vi.waitFor(() => expect(container.querySelector('[role="status"]')?.textContent).toContain('No hosts match “no-such-host.example.com”.'), { timeout: 1000 })
    expect(Array.from(container.querySelectorAll('button')).some(button => button.textContent === 'Clear search')).toBe(true)

    await act(async () => fireEvent.click(Array.from(container.querySelectorAll('button')).find(button => button.textContent === 'Clear search')!))
    expect(search.value).toBe('')
    // The search value is debounced; keep its timer-driven state update inside act.
    await act(async () => new Promise(resolve => setTimeout(resolve, 300)))
    await vi.waitFor(() => expect(container.textContent).toContain('router.example'), { timeout: 1000 })

    const protocol = container.querySelectorAll('select')[0] as HTMLSelectElement
    await act(async () => fireEvent.change(protocol, { target: { value: 'tcp' } }))
    await act(async () => new Promise(resolve => setTimeout(resolve, 300)))
    await vi.waitFor(() => expect(container.querySelector('[role="status"]')?.textContent).toContain('No hosts match TCP.'), { timeout: 1000 })
    const resetFilters = Array.from(container.querySelectorAll('button')).find(button => button.textContent === 'Reset filters')
    expect(resetFilters).toBeTruthy()
    await act(async () => fireEvent.click(resetFilters!))
    expect(protocol.value).toBe('')
    await act(async () => new Promise(resolve => setTimeout(resolve, 300)))
    await vi.waitFor(() => expect(container.textContent).toContain('router.example'), { timeout: 1000 })
  })

  it('explains when a job has no active baseline', async () => {
    vi.mocked(baselineHosts).mockResolvedValue({ ...detailed, data_quality: 'none', hosts: [], pagination: { limit: 50, offset: 0, total: 0, has_more: false, next_offset: null } })
    await act(async () => {
      root.render(<QueryClientProvider client={queryClient}><MemoryRouter initialEntries={['/jobs/job-1/baseline']}><Routes><Route path="/jobs/:id/baseline" element={<BaselineHosts />} /></Routes></MemoryRouter></QueryClientProvider>)
    })
    await vi.waitFor(() => expect(container.textContent).toContain('No active baseline'), { timeout: 1000 })
    // The empty state sits under the page's level-one heading (#1680).
    expect(container.querySelector('h2')?.textContent).toBe('No active baseline')
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
      { address: '10.0.0.1', visibility: 'non_public', source_targets: [], protocols: [{ protocol: 'tcp', open_ports: 0, open_filtered_ports: 0 }], open_ports: 0, open_filtered_ports: 0, has_open_ports: false },
      { address: '2001:db8::1', address_family: 'IPv6', visibility: 'non_public', source_targets: ['dns.example'], protocols: [{ protocol: 'udp', open_ports: 1, open_filtered_ports: 2 }], open_ports: 1, open_filtered_ports: 2, has_open_ports: true, legacy: true },
    ] as never
    vi.mocked(baselineHosts).mockImplementation(async (_job, filters) => ({
      ...detailed,
      data_quality: 'legacy',
      hosts,
      pagination: { limit: 1, offset: filters?.offset ?? 0, total: 2, has_more: (filters?.offset ?? 0) === 0, next_offset: (filters?.offset ?? 0) === 0 ? 1 : null },
    }))
    await renderPage()
    expect(container.textContent).toContain('Older scan details')
    expect(container.textContent).toContain('Non-public')
    expect(container.textContent).toContain('Legacy detail')
    expect(container.textContent).toContain('2 open|filtered')

    const next = container.querySelector('nav[aria-label="Pagination"] button:last-child') as HTMLButtonElement
    expect(next).toBeTruthy()
    await act(async () => next.click())
    await vi.waitFor(() => expect(baselineHosts).toHaveBeenLastCalledWith('job-1', expect.objectContaining({ offset: 1 })), { timeout: 1000 })

    const selects = container.querySelectorAll('select')
    fireEvent.change(selects[1], { target: { value: 'true' } })
    await vi.waitFor(() => expect(baselineHosts).toHaveBeenLastCalledWith('job-1', expect.objectContaining({ has_open_ports: true, offset: 0 })), { timeout: 1000 })
    fireEvent.change(selects[1], { target: { value: 'false' } })
    await vi.waitFor(() => expect(baselineHosts).toHaveBeenLastCalledWith('job-1', expect.objectContaining({ has_open_ports: false, offset: 0 })), { timeout: 1000 })
  })
})
