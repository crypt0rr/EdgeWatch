/** @vitest-environment jsdom */

import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { getScan, historicalScanHosts } from '../api'
import type { Scan, ScanSummary } from '../types'
import { ScanDetail } from './ScanDetail'

vi.mock('../api', () => ({
  getScan: vi.fn(),
  historicalScanHosts: vi.fn(),
}))

;(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true

const scan = {
  id: 'legacy-scan',
  job: 'legacy job',
  started_at: '2026-09-12T07:00:00Z',
  finished_at: '2026-09-12T07:01:00Z',
  status: 'success',
  config_hash: 'hash',
  scanner_engine: 'naabu_nmap',
  nmap_version: '7.99',
} as Scan

const summary = scan as unknown as ScanSummary

describe('historical scan detail', () => {
  let root: Root
  let container: HTMLDivElement
  let queryClient: QueryClient

  beforeEach(() => {
    container = document.createElement('div')
    document.body.appendChild(container)
    root = createRoot(container)
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    vi.mocked(getScan).mockResolvedValue(scan)
    vi.mocked(historicalScanHosts).mockResolvedValue({
      job: scan.job,
      scan: summary,
      data_quality: 'detailed',
      hosts: [
        { address: '198.51.100.10', protocols: [{ protocol: 'tcp', scanned_ports: '443', scanned_port_count: 1, service_detection: true, open_ports: 1, open_filtered_ports: 0 }], open_ports: 1, open_filtered_ports: 0, has_open_ports: true },
      ],
      pagination: { limit: 1, offset: 0, total: 2, has_more: true, next_offset: 1 },
    })
  })

  afterEach(() => {
    act(() => root.unmount())
    queryClient.clear()
    container.remove()
    vi.clearAllMocks()
  })

  async function renderPage() {
    await act(async () => {
      root.render(<QueryClientProvider client={queryClient}><MemoryRouter initialEntries={['/scans/legacy-scan']}><Routes><Route path="/scans/:scanId" element={<ScanDetail />} /></Routes></MemoryRouter></QueryClientProvider>)
    })
    await vi.waitFor(() => expect(container.textContent).not.toContain('Loading scan'), { timeout: 1000 })
  }

  it('renders scanner metadata and links effective hosts to detailed evidence', async () => {
    await renderPage()
    expect(container.querySelector('h1')?.textContent).toBe('legacy job')
    expect(container.textContent).toContain('Naabu → Nmap')
    expect(container.textContent).toContain('7.99')
    expect(container.textContent).toContain('198.51.100.10')
    expect(container.textContent).toContain('1 positive ports')
    expect(container.querySelector('a[href="/scans/legacy-scan/hosts/198.51.100.10"]')).toBeTruthy()

    const next = Array.from(container.querySelectorAll('button')).find(button => button.textContent === 'Next') as HTMLButtonElement
    await act(async () => {
      next.click()
      await Promise.resolve()
      await Promise.resolve()
    })
    expect(historicalScanHosts).toHaveBeenCalledWith('legacy-scan', { offset: 1 })
  })

  it('shows a not-found state when the historical scan cannot be loaded', async () => {
    vi.mocked(getScan).mockRejectedValue(new Error('missing'))
    await renderPage()
    expect(container.querySelector('[role="alert"]')?.textContent).toContain('could not be found')
    expect(container.querySelector('h1')).toBeNull()
  })
})
