import type { PerimeterBlocks, PerimeterMonitorRef, PerimeterOverview, PerimeterRange, PerimeterRangeDetail, PerimeterSuggestion } from '../generated/api-types'

// Perimeter report fixtures shaped like the API's responses: every list is an
// array, and address counts are plain numbers.

export function perimeterMonitor(overrides: Partial<PerimeterMonitorRef> = {}): PerimeterMonitorRef {
  return {
    job_id: 'job-edge',
    name: 'Edge TCP',
    state: 'covering',
    reasons: [],
    stale: false,
    stale_reason: '',
    stalled_cycle: false,
    last_attempt_status: 'success',
    last_success_at: '2026-10-19T08:00:00Z',
    host_discovery: false,
    protocols: ['full_tcp', 'any_tcp'],
    dns_targets: 0,
    ...overrides,
  }
}

export function perimeterRange(overrides: Partial<PerimeterRange> = {}): PerimeterRange {
  return {
    id: 'range-1',
    kind: 'prefix',
    value: '203.0.113.0/24',
    label: 'DC1 edge',
    family: 4,
    created_at: '2026-10-18T09:30:00Z',
    created_by: 'alice',
    addresses: 256,
    excluded: 0,
    coverage: { full_tcp: 128, any_tcp: 256, udp: 0 },
    ipv6_monitored: { full_tcp: 0, any_tcp: 0, udp: 0 },
    monitor_ids: ['job-edge'],
    ...overrides,
  }
}

export function perimeterOverview(overrides: Partial<PerimeterOverview> = {}): PerimeterOverview {
  return {
    ranges: [perimeterRange()],
    monitors: [perimeterMonitor()],
    outside: [],
    outside_truncated: false,
    totals: {
      declared_ipv4: 256,
      excluded_ipv4: 0,
      covered_full_tcp: 128,
      covered_any_tcp: 256,
      covered_udp: 0,
      ranges: 1,
      ipv6_ranges: 0,
      cannot_scan_monitors: 0,
      unproven_monitors: 0,
      outside_targets: 0,
    },
    limits: { max_job_hosts: 65536, max_probe_count: 20_000_000, max_naabu_probe_count: 20_000_000, max_ranges: 1024, max_entries_per_request: 256 },
    generated_at: '2026-10-20T10:00:00Z',
    ...overrides,
  }
}

export function emptyPerimeterOverview(): PerimeterOverview {
  return perimeterOverview({
    ranges: [],
    monitors: [],
    totals: { declared_ipv4: 0, excluded_ipv4: 0, covered_full_tcp: 0, covered_any_tcp: 0, covered_udp: 0, ranges: 0, ipv6_ranges: 0, cannot_scan_monitors: 0, unproven_monitors: 0, outside_targets: 0 },
  })
}

export const fullTCPProtocol = { protocol: 'tcp', engine: 'naabu_nmap', ports: '1-65535', mode: 'connect', service_detection: false, profile_id: '00000000-0000-0000-0000-000000000014' }
export const selectedTCPProtocol = { protocol: 'tcp', engine: 'nmap', ports: '22,443', mode: 'connect', service_detection: false }
export const udpProtocol = { protocol: 'udp', engine: 'nmap', ports: '53,123,161,500,1194,4500', service_detection: true }

export function perimeterSuggestion(overrides: Partial<PerimeterSuggestion> = {}): PerimeterSuggestion {
  return { mode: 'full_tcp', targets: ['203.0.113.0/25'], addresses: 128, estimated_probes: 8_388_480, protocol: fullTCPProtocol, ...overrides }
}

export function blocks(cidrs: string[], total = cidrs.length): PerimeterBlocks {
  return { cidrs, truncated: total > cidrs.length, total }
}

export function perimeterRangeDetail(overrides: Partial<PerimeterRangeDetail> = {}): PerimeterRangeDetail {
  return {
    range: perimeterRange(),
    monitors: [perimeterMonitor()],
    uncovered: { full_tcp: blocks(['203.0.113.128/25']), any_tcp: blocks([]), udp: blocks(['203.0.113.0/24']) },
    addresses_per_monitor: { full_tcp: 305, selected_tcp: 4096, udp: 1024 },
    monitors_needed: { full_tcp: 1, selected_tcp: 0, udp: 1 },
    suggestions: [
      perimeterSuggestion({ targets: ['203.0.113.128/25'], minimum_duration_seconds: 8_389 }),
      perimeterSuggestion({ mode: 'udp', targets: ['203.0.113.0/24'], addresses: 256, estimated_probes: 3072, protocol: udpProtocol }),
    ],
    suggestions_truncated: { full_tcp: false, selected_tcp: false, udp: false },
    budget_too_low: { full_tcp: false, selected_tcp: false, udp: false },
    ...overrides,
  }
}
