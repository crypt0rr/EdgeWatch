/** @vitest-environment jsdom */

import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { baselineHost, baselineHostRDAP, historicalScanHost, historicalScanHostRDAP, scanHost, scanHostRDAP } from '../api'
import type { HostDetailResponse, HostObservation, RdapResult, ScanSummary } from '../types'
import { HostDetail } from './HostDetail'

vi.mock('../api', () => ({
  baselineHost: vi.fn(),
  baselineHostRDAP: vi.fn(),
  historicalScanHost: vi.fn(),
  historicalScanHostRDAP: vi.fn(),
  scanHost: vi.fn(),
  scanHostRDAP: vi.fn(),
}))

;(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true

const sourceScan = {
  id: 'scan-1',
  job_id: 'job-1',
  job: 'production',
  started_at: '2026-09-12T07:00:00Z',
  finished_at: '2026-09-12T07:01:00Z',
  status: 'success',
  config_hash: 'hash',
  job_revision: 4,
  nmap_version: '7.99',
  scanner_engine: 'naabu_nmap',
  scanner_profile_id: 'profile-1',
  scanner_profile_revision: 2,
  naabu_version: '2.6.1',
  discovery_ports: 3,
  confirmed_ports: 2,
  discovery_duration_ms: 500,
  enrichment_duration_ms: 1500,
} as ScanSummary

const host: HostObservation = {
  address: '198.51.100.10',
  address_family: 'IPv4',
  status: 'up',
  status_reason: 'syn-ack',
  reason_ttl: 64,
  latency_ms: 2.5,
  source_targets: ['router.example'],
  dns_names: ['router.example'],
  hostnames: [{ name: 'edge-router', type: 'PTR' }],
  link_addresses: [{ address: '00:11:22:33:44:55', type: 'mac', vendor: 'Example Vendor' }],
  protocols: [
    {
      protocol: 'tcp',
      scan_type: 'connect',
      scanned_ports: '1-65535',
      scanned_port_count: 65535,
      service_detection: true,
      discovery_engine: 'naabu',
      ports: [
        { port: 443, state: 'open', reason: 'syn-ack', reason_ttl: 64, service: { name: 'https', product: 'nginx', version: '1.25', extra_info: 'TLS', method: 'probed', confidence: 10, tunnel: 'ssl', os_type: 'Linux', device_type: 'server', cpes: ['cpe:/a:nginx:nginx:1.25'] } },
        { port: 80, state: 'open|filtered', reason: 'no-response' },
      ],
      discovered_ports: [{ port: 80, state: 'open', verification: 'discovered', reason: 'syn-ack' }],
      unconfirmed_ports: [{ port: 8080, state: 'open', verification: 'unconfirmed', reason: 'reset' }],
      state_summaries: [{ state: 'closed', count: 65533, reasons: [{ reason: 'reset', count: 65533 }] }],
      nse_profile: 'banner',
    },
    { protocol: 'udp', scan_type: 'udp', scanned_ports: '53', scanned_port_count: 1, service_detection: false, ports: [], state_summaries: [{ state: 'filtered', count: 1 }] },
  ],
}

const detail: HostDetailResponse = { job_id: 'job-1', job: 'production', data_quality: 'detailed', host, source_scan: sourceScan }
const rdap: RdapResult = { status: 'success', address: host.address, network_name: 'Example Network', handle: 'NET-1', prefix: '198.51.100.0/24', country: 'ZZ', allocation_type: 'ASSIGNED', registry: 'example.registry', organizations: ['Example Org'], statuses: ['active'], events: [{ action: 'registration', date: '2020-01-01T00:00:00Z' }], source_url: 'https://registry.example/record', fetched_at: '2026-09-12T08:00:00Z' }

describe('host detail', () => {
  let root: Root
  let container: HTMLDivElement
  let queryClient: QueryClient

  beforeEach(() => {
    container = document.createElement('div')
    document.body.appendChild(container)
    root = createRoot(container)
    queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    vi.mocked(baselineHost).mockResolvedValue(detail)
    vi.mocked(baselineHostRDAP).mockResolvedValue({ rdap })
    vi.mocked(historicalScanHost).mockResolvedValue({ ...detail, scan: sourceScan, expected: host })
    vi.mocked(historicalScanHostRDAP).mockResolvedValue({ rdap: { ...rdap, status: 'private' } })
    vi.mocked(scanHost).mockResolvedValue(detail)
    vi.mocked(scanHostRDAP).mockResolvedValue({ rdap })
  })

  afterEach(() => {
    act(() => root.unmount())
    queryClient.clear()
    container.remove()
    vi.clearAllMocks()
  })

  async function renderRoute(path: string, pattern: string) {
    await act(async () => {
      root.render(<QueryClientProvider client={queryClient}><MemoryRouter initialEntries={[path]}><Routes><Route path={pattern} element={<HostDetail />} /></Routes></MemoryRouter></QueryClientProvider>)
    })
    await vi.waitFor(() => expect(container.textContent).not.toContain('Loading host evidence'), { timeout: 1000 })
  }

  it('renders identity, RDAP, scanner provenance, service evidence, and sortable ports', async () => {
    await renderRoute('/jobs/job-1/baseline/hosts/198.51.100.10', '/jobs/:id/baseline/hosts/:address')
    expect(container.textContent).toContain('198.51.100.10')
    expect(container.textContent).toContain('syn-ack · TTL 64')
    expect(container.textContent).toContain('router.example')
    expect(container.textContent).toContain('Example Vendor')
    expect(container.textContent).toContain('Example Network')
    expect(container.textContent).toContain('NET-1')
    expect(container.textContent).toContain('Naabu discovery → Nmap confirmation')
    expect(container.textContent).toContain('nginx · 1.25')
    expect(container.textContent).toContain('confidence 10')
    expect(container.textContent).toContain('cpe:/a:nginx:nginx:1.25')
    expect(container.textContent).toContain('Naabu discoveries')
    expect(container.textContent).toContain('Nmap disagreements')
    expect(container.textContent).toContain('Closed, filtered, and other non-open ports')
    expect(container.querySelector('a[href="https://registry.example/record"]')).toBeTruthy()

    const stateSort = container.querySelector('button[aria-label="Sort by state"]') as HTMLButtonElement
    act(() => stateSort.click())
    expect(stateSort.textContent).toContain('↑')
    act(() => stateSort.click())
    expect(stateSort.textContent).toContain('↓')
    const serviceSort = container.querySelector('button[aria-label="Sort by service"]') as HTMLButtonElement
    act(() => serviceSort.click())
    expect(serviceSort.textContent).toContain('↑')
  })

  it('shows baseline expectations and special-use RDAP state for historical hosts', async () => {
    await renderRoute('/scans/scan-1/hosts/198.51.100.10', '/scans/:scanId/hosts/:address')
    expect(historicalScanHost).toHaveBeenCalledWith('scan-1', '198.51.100.10')
    expect(container.textContent).toContain('Baseline expectation')
    expect(container.textContent).toContain('Private or special-use addresses are not sent to an external registry.')
    expect(container.querySelector('a[href="/hosts"]')).toBeTruthy()
  })

  it('renders a not-found state when host evidence is unavailable', async () => {
    vi.mocked(baselineHost).mockRejectedValue(new Error('missing'))
    await renderRoute('/jobs/job-1/baseline/hosts/198.51.100.10', '/jobs/:id/baseline/hosts/:address')
    expect(container.querySelector('.error-card')?.textContent).toContain('could not be found')
  })
})
