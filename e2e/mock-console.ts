import type { Page } from '@playwright/test'
import type { AdminStatus, HostObservation, IncidentInboxItem, IncidentInboxPage, IncidentInboxSummary, PerimeterBlocks, PerimeterDeclareResult, PerimeterLineError, PerimeterMonitorRef, PerimeterOutsideTarget, PerimeterOverview, PerimeterProtocol, PerimeterRange, PerimeterRangeDetail, PerimeterSuggestion, PlatformStatus, Scan, ScanSlotDemand, ScanSummary } from '../src/generated/api-types'
import type { ActivityEvent, Job, JobForm } from '../src/types'

export type UnitConsoleRole = 'administrator' | 'operator' | 'viewer'
/** platform_admin is the business units' platform administrator. */
export type ConsoleRole = UnitConsoleRole | 'platform_admin'

export const rolePermissions: Record<ConsoleRole, string[]> = {
  administrator: [
    'overview.read', 'jobs.read', 'jobs.write', 'jobs.run', 'jobs.delete',
    'hosts.read', 'scans.read', 'baselines.read', 'baselines.manage',
    'incidents.read', 'incidents.manage', 'notification_options.read',
    'notifications.manage', 'users.manage', 'public_dashboard.manage',
    'stream.read', 'scanner_profiles.read', 'scanner_profiles.manage',
    'perimeter.read', 'perimeter.manage', 'audit.read', 'account.self',
  ],
  operator: [
    'overview.read', 'jobs.read', 'jobs.write', 'jobs.run',
    'hosts.read', 'scans.read', 'baselines.read', 'baselines.manage',
    'incidents.read', 'incidents.manage', 'notification_options.read',
    'stream.read', 'scanner_profiles.read', 'perimeter.read', 'account.self',
  ],
  viewer: ['jobs.read', 'baselines.read', 'account.self'],
  platform_admin: [
    'account.self', 'platform_audit.read', 'platform_notifications.manage',
    'platform_status.read', 'unit_accounts.manage', 'units.manage',
  ],
}

export type ConsoleMockControls = {
  failNext: (operation: string) => void
  setPreviewResponse: (response: unknown) => void
  deferNextPreview: () => { started: Promise<void>; resolve: (response: unknown) => void }
  /** Rewrites every perimeter overview the mock serves from now on, such as to truncate its outside list. */
  transformPerimeterOverview: (transform: (overview: PerimeterOverview) => PerimeterOverview) => void
  calls: Record<string, number>
  payloads: Record<string, unknown[]>
}

const job: Job = {
  id: 'job-1',
  revision: 1,
  enabled: true,
  archived: false,
  security_hash: 'fixture-security-hash',
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
  job: {
    name: 'fixture-job',
    schedule: '0 * * * *',
    timezone: 'UTC',
    targets: ['192.0.2.10'],
    max_expanded_hosts: 256,
    tcp: { ports: '22,443', mode: 'connect', service_detection: false, engine: 'nmap' },
    timing: 'balanced',
    timeout: '1h',
    resume_window: '8d',
    baseline_samples: 1,
    change_confirmations: 1,
    run_on_start: false,
    assume_alive: true,
    allow_high_cost: false,
  },
  baseline: { status: 'complete', samples: 1, attempts: 1, host_count: 1, scan_id: 'scan-1' },
}

const scan: Scan = {
  id: 'scan-1',
  job_id: 'job-1',
  job: 'fixture-job',
  job_revision: 1,
  started_at: '2026-01-01T00:00:00Z',
  finished_at: '2026-01-01T00:00:01Z',
  status: 'success',
  config_hash: 'fixture-security-hash',
  snapshot: { units: [], scopes: [] },
}

const scanSummary: ScanSummary = {
  id: scan.id,
  job: scan.job,
  started_at: scan.started_at,
  finished_at: scan.finished_at,
  status: scan.status,
  nmap_version: '7.99',
  scanner_engine: 'nmap',
  config_hash: scan.config_hash,
}

const activityEvent: ActivityEvent = {
  type: 'changes-detected',
  job_id: 'job-1',
  job: 'fixture-job',
  scan_id: 'scan-1',
  message: 'Fixture activity event confirms a baseline change.',
  created_at: '2026-01-01T00:00:00Z',
  changes: [],
}

const scanSlotDemand: ScanSlotDemand = {
  enabled_jobs: 1,
  history_jobs: 1,
  lower_bound_jobs: 0,
  unestimated_jobs: 0,
  cadence_unattainable_jobs: 0,
  slots: 2,
  estimated_slot_seconds_per_day: 3_600,
  capacity_slot_seconds_per_day: 7_200,
  utilization_percent: 50,
  over_capacity: false,
}

const host: HostObservation = {
  address: '192.0.2.10',
  address_family: 'IPv4',
  source_targets: ['router.example.com'],
  dns_names: ['router.example.com'],
  status: 'up',
  status_reason: 'arp-response',
  protocols: [{
    protocol: 'tcp',
    scanned_ports: '22,443',
    scanned_port_count: 2,
    service_detection: false,
    ports: [{ port: 443, state: 'open', reason: 'syn-ack' }],
    state_summaries: [{ state: 'open', count: 1 }, { state: 'closed', count: 1 }],
  }],
}

const destination = {
  id: 'dest-1',
  name: 'Operations',
  provider: 'generic',
  source: 'web',
  enabled: true,
  locked: false,
  read_only: false,
  revision: 1,
}

const profile = {
  id: 'profile-1',
  name: 'Nmap standard',
  built_in: true,
  archived: false,
  revision: 1,
  definition: {
    engine: 'nmap',
    naabu: { scan_type: 'connect', rate: 1000, workers: 25, retries: 3, timeout_ms: 1000, warm_up_seconds: 2, verify: true, address_batch_size: 16 },
    nmap_args: [],
    naabu_args: [],
    enrichment_args: [],
  },
}

function pagination(total: number, limit = 50) {
  return { limit, offset: 0, total, has_more: false, next_offset: null }
}

const deploymentLimits = { max_concurrent_scans: 4, max_probe_count: 5_000_000, max_naabu_probe_count: 20_000_000, max_probe_count_limit: 100_000_000 }

function platformUnit(overrides: Record<string, unknown>) {
  return { status: 'active', is_default: false, revision: 1, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z', state_changed_at: '2026-01-01T00:00:00Z', accounts: 0, administrators: 0, jobs: 0, stored_scans: 0, slots: { in_use: 0, queued: 0 }, ...overrides }
}

function platformAccount(overrides: Record<string, unknown>) {
  return { enabled: true, pending: false, totp_enabled: false, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z', revision: 1, ...overrides }
}

// The default unit's perimeter, shaped like the generated PerimeterOverview
// and PerimeterRangeDetail types. The four ranges show an owned IPv4 range
// with suggestions, an authorized range that needs more monitors than the
// page lists, an IPv6 range, and a range that the deployment excludes
// entirely. The monitors show every list of the page: covering, paused, over
// budget and expansion, stale with host discovery, stalled with a failed
// attempt, and a stale monitor that touches no range and so is listed only
// for its target outside the perimeter.

/** The report time of every perimeter fixture. */
const perimeterGeneratedAt = '2026-10-20T10:00:00Z'

type PerimeterBucket = 'full_tcp' | 'any_tcp' | 'udp'
type PerimeterMode = 'full_tcp' | 'selected_tcp' | 'udp'

function perimeterMonitor(overrides: Partial<PerimeterMonitorRef> & Pick<PerimeterMonitorRef, 'job_id' | 'name'>): PerimeterMonitorRef {
  return { state: 'covering', reasons: [], stale: false, stale_reason: '', stalled_cycle: false, last_attempt_status: 'success', last_success_at: '2026-10-20T06:00:00Z', host_discovery: false, protocols: ['any_tcp'], dns_targets: 0, ...overrides }
}

// Only a covering monitor carries stale and stalled_cycle; the report lists
// monitors in the byte order of their names, as the job list does.
const perimeterMonitors: PerimeterMonitorRef[] = [
  perimeterMonitor({ job_id: 'job-dns', name: 'Edge DNS UDP', state: 'paused', reasons: ['paused'], protocols: ['udp'], last_success_at: '2026-09-01T06:00:00Z' }),
  perimeterMonitor({ job_id: 'job-edge', name: 'Edge full TCP', protocols: ['full_tcp', 'any_tcp'] }),
  perimeterMonitor({ job_id: 'job-edge-web', name: 'Edge web ports', stale: true, stale_reason: 'overdue', last_success_at: '2026-10-01T06:00:00Z', host_discovery: true, dns_targets: 1 }),
  perimeterMonitor({ job_id: 'job-partner', name: 'Partner TCP', stalled_cycle: true, last_attempt_status: 'failed', last_success_at: null }),
  perimeterMonitor({ job_id: 'job-wide', name: 'Partner sweep', state: 'over_budget', reasons: ['over_budget', 'over_expansion'], protocols: ['full_tcp', 'any_tcp'], last_attempt_status: '', last_success_at: null }),
  perimeterMonitor({ job_id: 'job-1', name: 'fixture-job', stale: true, stale_reason: 'overdue', last_success_at: '2026-01-01T00:00:01Z' }),
]

/**
 * The monitored targets outside the declared ranges, in the order of their
 * monitors. This is a static fixture: it is served whenever any range is
 * declared and does not follow the declarations or removals a test makes.
 */
const perimeterOutside: PerimeterOutsideTarget[] = [
  { job_id: 'job-wide', job_name: 'Partner sweep', state: 'over_budget', target: '198.18.0.0/15', partial: true, outside_addresses: 65_536 },
  { job_id: 'job-1', job_name: 'fixture-job', state: 'covering', target: '192.0.2.10', partial: false, outside_addresses: 1 },
]

function perimeterRange(overrides: Partial<PerimeterRange> & Pick<PerimeterRange, 'id' | 'value'>): PerimeterRange {
  return { kind: 'prefix', label: '', family: 4, created_at: '2026-10-18T09:30:00Z', created_by: 'admin', addresses: 0, excluded: 0, coverage: { full_tcp: 0, any_tcp: 0, udp: 0 }, ipv6_monitored: { full_tcp: 0, any_tcp: 0, udp: 0 }, monitor_ids: [], ...overrides }
}

const perimeterFixtureRanges = (): PerimeterRange[] => [
  perimeterRange({ id: 'range-1', value: '203.0.113.0/24', label: 'DC1 edge', addresses: 256, coverage: { full_tcp: 128, any_tcp: 256, udp: 0 }, monitor_ids: ['job-dns', 'job-edge', 'job-edge-web'] }),
  perimeterRange({ id: 'range-2', kind: 'authorized', value: '198.18.0.0/16', label: 'Partner cloud', addresses: 65_536, coverage: { full_tcp: 0, any_tcp: 128, udp: 0 }, monitor_ids: ['job-partner', 'job-wide'] }),
  perimeterRange({ id: 'range-3', value: '2001:db8:100::/48', label: 'IPv6 edge', family: 6, ipv6_monitored: { full_tcp: 0, any_tcp: 256, udp: 0 }, monitor_ids: ['job-edge-web'] }),
  perimeterRange({ id: 'range-4', value: '192.0.2.128/30', label: 'Lab', addresses: 4, excluded: 4 }),
]

// The uncovered blocks of each fixture range per bucket. A range declared
// in a test has no monitor, so every address of it is uncovered.
const perimeterGaps: Record<string, () => Record<PerimeterBucket, string[]>> = {
  'range-1': () => ({ full_tcp: ['203.0.113.128/25'], any_tcp: [], udp: ['203.0.113.0/24'] }),
  'range-2': () => ({ full_tcp: ['198.18.0.0/16'], any_tcp: perimeterRemainder('198.18.0.0/16', '198.18.0.0/25'), udp: ['198.18.0.0/16'] }),
  'range-3': () => ({ full_tcp: ['2001:db8:100::/48'], any_tcp: perimeterRemainder('2001:db8:100::/48', '2001:db8:100::/120'), udp: ['2001:db8:100::/48'] }),
  'range-4': () => ({ full_tcp: [], any_tcp: [], udp: [] }),
}

// The suggestion presets as the report returns them, with the addresses per
// monitor at the default probe budgets and the probes each address costs, as
// config.EstimateJobWork counts them: Naabu probes all 65,535 TCP ports, and
// Nmap probes each port twice with service detection, so the UDP preset's 6
// ports cost 12.
const perimeterPresets: Record<PerimeterMode, { bucket: PerimeterBucket; perMonitor: number; probesPerAddress: number; protocol: PerimeterProtocol }> = {
  full_tcp: { bucket: 'full_tcp', perMonitor: 305, probesPerAddress: 65_535, protocol: { protocol: 'tcp', engine: 'naabu_nmap', ports: '1-65535', mode: 'connect', service_detection: false, profile_id: '00000000-0000-0000-0000-000000000014' } },
  selected_tcp: { bucket: 'any_tcp', perMonitor: 4_096, probesPerAddress: 2, protocol: { protocol: 'tcp', engine: 'nmap', ports: '22,443', mode: 'connect', service_detection: false } },
  udp: { bucket: 'udp', perMonitor: 1_024, probesPerAddress: 12, protocol: { protocol: 'udp', engine: 'nmap', ports: '53,123,161,500,1194,4500', service_detection: true } },
}
const perimeterModes = Object.keys(perimeterPresets) as PerimeterMode[]

type PerimeterBlock = { family: 4 | 6; start: bigint; bits: number }

const familyWidth = (family: 4 | 6) => family === 4 ? 32 : 128
const blockSize = (block: PerimeterBlock) => 1n << BigInt(familyWidth(block.family) - block.bits)

/** Parses an IP address or CIDR prefix with its host bits masked, as the server canonicalizes it, or returns null. */
function parsePerimeterValue(value: string): PerimeterBlock | null {
  const [address, length, ...rest] = value.split('/')
  if (rest.length || !address) return null
  const family = address.includes(':') ? 6 : 4
  const width = familyWidth(family)
  const bits = length === undefined ? width : /^\d{1,3}$/.test(length) ? Number(length) : Number.NaN
  if (!Number.isInteger(bits) || bits > width) return null
  let start = 0n
  if (family === 4) {
    const octets = address.split('.')
    if (octets.length !== 4 || !octets.every(octet => /^\d{1,3}$/.test(octet) && Number(octet) <= 255)) return null
    for (const octet of octets) start = (start << 8n) | BigInt(octet)
  } else {
    const halves = address.split('::')
    if (halves.length > 2) return null
    const groups = (part: string) => part === '' ? [] : part.split(':')
    const head = groups(halves[0])
    const tail = halves.length === 2 ? groups(halves[1]) : []
    const missing = 8 - head.length - tail.length
    if (halves.length === 2 ? missing < 1 : missing !== 0) return null
    const all = [...head, ...Array<string>(halves.length === 2 ? missing : 0).fill('0'), ...tail]
    if (!all.every(group => /^[0-9a-f]{1,4}$/i.test(group))) return null
    for (const group of all) start = (start << 16n) | BigInt(`0x${group}`)
  }
  const block = { family, start, bits } as PerimeterBlock
  return { ...block, start: start - (start % blockSize(block)) }
}

/** Formats a block as the server does: dotted IPv4, or IPv6 with its longest run of zero groups compressed. */
function formatPerimeterBlock(block: PerimeterBlock): string {
  if (block.family === 4) return `${[24n, 16n, 8n, 0n].map(shift => String((block.start >> shift) & 255n)).join('.')}/${block.bits}`
  const groups = Array.from({ length: 8 }, (_, index) => Number((block.start >> BigInt(112 - index * 16)) & 0xffffn))
  let longest = { at: -1, length: 1 }
  for (let index = 0; index < groups.length;) {
    let end = index
    while (end < groups.length && groups[end] === 0) end++
    if (end - index > longest.length) longest = { at: index, length: end - index }
    index = Math.max(end, index + 1)
  }
  const hex = groups.map(group => group.toString(16))
  const text = longest.at < 0 ? hex.join(':') : `${hex.slice(0, longest.at).join(':')}::${hex.slice(longest.at + longest.length).join(':')}`
  return `${text}/${block.bits}`
}

/** The fewest aligned blocks of range that remain when covered, a block at its start, is taken out, in address order. */
function perimeterRemainder(range: string, covered: string): string[] {
  const whole = parsePerimeterValue(range)!
  const first = parsePerimeterValue(covered)!
  const blocks: string[] = []
  for (let bits = first.bits; bits > whole.bits; bits--) blocks.push(formatPerimeterBlock({ family: whole.family, start: whole.start + (1n << BigInt(familyWidth(whole.family) - bits)), bits }))
  return blocks
}

/**
 * Packs uncovered blocks into monitors as addrspace.Pack does. P is the
 * largest power of two that fits a monitor. First, every block of at least P
 * addresses, in address order, is split into blocks of P with a monitor each.
 * Then every smaller block, in address order, joins the first monitor, in the
 * order the monitors opened, with room for it, or opens a new monitor at the
 * end. Each monitor lists its blocks in address order.
 */
function packPerimeterBlocks(cidrs: string[], perMonitor: number): string[][] {
  const capacity = BigInt(perMonitor)
  let unit = 1n
  while (unit * 2n <= capacity) unit *= 2n
  const monitors: { blocks: PerimeterBlock[]; room: bigint }[] = []
  const blocks = cidrs.map(cidr => parsePerimeterValue(cidr)!).sort(byStart)
  const small: PerimeterBlock[] = []
  for (const block of blocks) {
    const size = blockSize(block)
    if (size < unit) {
      small.push(block)
      continue
    }
    const bits = familyWidth(block.family) - (unit.toString(2).length - 1)
    for (let start = block.start; start < block.start + size; start += unit) monitors.push({ blocks: [{ family: block.family, start, bits }], room: capacity - unit })
  }
  for (const block of small) {
    const size = blockSize(block)
    const open = monitors.find(monitor => monitor.room >= size)
    if (open) {
      open.blocks.push(block)
      open.room -= size
    } else {
      monitors.push({ blocks: [block], room: capacity - size })
    }
  }
  return monitors.map(monitor => [...monitor.blocks].sort(byStart).map(formatPerimeterBlock))
}

function byStart(left: PerimeterBlock, right: PerimeterBlock): number {
  return left.start < right.start ? -1 : left.start > right.start ? 1 : 0
}

function perimeterBlocks(cidrs: string[]): PerimeterBlocks {
  return { cidrs: cidrs.slice(0, 256), truncated: cidrs.length > 256, total: cidrs.length }
}

/** The detail of a declared range: its monitors, its uncovered blocks, and at most 64 suggestions per mode for IPv4. */
function perimeterRangeDetail(range: PerimeterRange): PerimeterRangeDetail {
  const gaps = perimeterGaps[range.id]?.() ?? { full_tcp: [range.value], any_tcp: [range.value], udp: [range.value] }
  const ids = new Set(range.monitor_ids ?? [])
  const suggestions: PerimeterSuggestion[] = []
  const needed = { full_tcp: 0, selected_tcp: 0, udp: 0 }
  const truncated = { full_tcp: false, selected_tcp: false, udp: false }
  for (const mode of perimeterModes) {
    if (range.family !== 4) continue
    const preset = perimeterPresets[mode]
    const sets = packPerimeterBlocks(gaps[preset.bucket], preset.perMonitor)
    needed[mode] = sets.length
    truncated[mode] = sets.length > 64
    for (const targets of sets.slice(0, 64)) {
      const addresses = targets.reduce((sum, target) => sum + Number(blockSize(parsePerimeterValue(target)!)), 0)
      suggestions.push({ mode, targets, addresses, already_covered_addresses: 0, estimated_probes: addresses * preset.probesPerAddress, protocol: { ...preset.protocol } })
    }
  }
  return {
    range,
    monitors: perimeterMonitors.filter(monitor => ids.has(monitor.job_id)),
    uncovered: { full_tcp: perimeterBlocks(gaps.full_tcp), any_tcp: perimeterBlocks(gaps.any_tcp), udp: perimeterBlocks(gaps.udp) },
    addresses_per_monitor: { full_tcp: perimeterPresets.full_tcp.perMonitor, selected_tcp: perimeterPresets.selected_tcp.perMonitor, udp: perimeterPresets.udp.perMonitor },
    monitors_needed: needed,
    suggestions,
    suggestions_truncated: truncated,
    coalesced_monitors_needed: { full_tcp: 0, selected_tcp: 0, udp: 0 },
    coalesced_suggestions: [],
    coalesced_suggestions_truncated: { full_tcp: false, selected_tcp: false, udp: false },
    budget_too_low: { full_tcp: false, selected_tcp: false, udp: false },
  }
}

const unprovenAttempts = new Set(['failed', 'timed_out', 'incomplete'])

/** Orders declared ranges as the store does: IPv4 before IPv6, then by address and prefix length. */
function comparePerimeterRanges(left: PerimeterRange, right: PerimeterRange): number {
  const a = parsePerimeterValue(left.value)!
  const b = parsePerimeterValue(right.value)!
  return a.family - b.family || byStart(a, b) || a.bits - b.bits || left.kind.localeCompare(right.kind) || left.id.localeCompare(right.id)
}

/** The overview of the declared ranges, with totals counted over the fixture ranges, which do not overlap. */
function perimeterOverview(declaredRanges: PerimeterRange[]): PerimeterOverview {
  const ranges = [...declaredRanges].sort(comparePerimeterRanges)
  const declared = ranges.length > 0
  const touching = new Set(ranges.flatMap(range => range.monitor_ids ?? []))
  const outside = declared ? perimeterOutside : []
  const listed = declared ? perimeterMonitors.filter(monitor => touching.has(monitor.job_id) || outside.some(target => target.job_id === monitor.job_id)) : []
  const ipv4 = ranges.filter(range => range.family === 4)
  const sum = (count: (range: PerimeterRange) => number) => ipv4.reduce((total, range) => total + count(range), 0)
  const touchingMonitors = listed.filter(monitor => touching.has(monitor.job_id))
  return {
    ranges,
    monitors: listed,
    outside,
    outside_truncated: false,
    totals: {
      declared_ipv4: sum(range => range.addresses),
      excluded_ipv4: sum(range => range.excluded),
      covered_full_tcp: sum(range => range.coverage.full_tcp),
      covered_any_tcp: sum(range => range.coverage.any_tcp),
      covered_udp: sum(range => range.coverage.udp),
      ranges: ranges.length,
      ipv6_ranges: ranges.length - ipv4.length,
      cannot_scan_monitors: touchingMonitors.filter(monitor => monitor.state !== 'covering').length,
      unproven_monitors: touchingMonitors.filter(monitor => monitor.state === 'covering' && (monitor.stale || monitor.stalled_cycle || unprovenAttempts.has(monitor.last_attempt_status))).length,
      outside_targets: outside.length,
    },
    limits: { max_job_hosts: 65_536, max_probe_count: deploymentLimits.max_probe_count, max_naabu_probe_count: deploymentLimits.max_naabu_probe_count, max_ranges: 1_024, max_entries_per_request: 256 },
    generated_at: perimeterGeneratedAt,
  }
}

/**
 * The address spaces that no declared range may overlap, in the order the
 * store checks them, before the prefix length rules.
 */
const perimeterSpecialRanges = [
  ['0.0.0.0/32', 'unspecified address space is not allowed'],
  ['127.0.0.0/8', 'loopback address space is not allowed'],
  ['224.0.0.0/4', 'multicast address space is not allowed'],
  ['169.254.0.0/16', 'link-local address space is not allowed'],
  ['::/128', 'unspecified address space is not allowed'],
  ['::1/128', 'loopback address space is not allowed'],
  ['ff00::/8', 'multicast address space is not allowed'],
  ['fe80::/10', 'link-local address space is not allowed'],
].map(([value, reason]) => ({ block: parsePerimeterValue(value)!, reason }))
const perimeterMappedBlock = parsePerimeterValue('::ffff:0:0/96')!

function perimeterBlocksOverlap(left: PerimeterBlock, right: PerimeterBlock): boolean {
  return left.family === right.family && left.start < right.start + blockSize(right) && right.start < left.start + blockSize(left)
}

/** Why the store refuses a declared value, in its order, or '' for an allowed one. */
function perimeterValueReason(value: string, block: PerimeterBlock | null): string {
  const [address] = value.split('/', 1)
  const zone = address.indexOf('%')
  if (zone > 0 && zone < address.length - 1 && address.includes(':') && parsePerimeterValue(address.slice(0, zone))) return 'zones are not allowed'
  if (!block) return 'not an IP address or CIDR prefix'
  const special = perimeterSpecialRanges.find(range => perimeterBlocksOverlap(block, range.block))
  if (special) return special.reason
  if (block.family === 4 && block.bits < 8) return 'IPv4 prefixes must be /8 or longer'
  if (block.family === 6 && block.bits < 16) return 'IPv6 prefixes must be /16 or longer'
  if (perimeterBlocksOverlap(block, perimeterMappedBlock)) return 'write the IPv4 form'
  return ''
}

/** Why the store refuses a label, or ''. */
function perimeterLabelReason(label: string): string {
  if (Array.from(label).length > 200) return 'label must be at most 200 characters'
  if (/\p{Cc}/u.test(label)) return 'label must not contain control characters'
  return ''
}

/**
 * Declares entries as the server does, all or nothing: every refused entry
 * is listed with its index and reason, a value already declared under the
 * other kind is refused, and a repeat under the same kind is skipped. Values
 * and labels are refused for the store's reasons, in its order.
 */
function declarePerimeter(ranges: PerimeterRange[], entries: Array<{ kind?: unknown; value?: unknown; label?: unknown }>, nextID: () => string): { refused: PerimeterLineError[]; result: PerimeterDeclareResult; created: PerimeterRange[] } {
  const refused: PerimeterLineError[] = []
  const created: PerimeterRange[] = []
  const declared = new Map(ranges.map(range => [range.value, range.kind]))
  let skipped = 0
  entries.forEach((entry, index) => {
    const value = typeof entry.value === 'string' ? entry.value.trim() : ''
    const refuse = (reason: string) => refused.push({ index, value: value.slice(0, 64), reason })
    if (entry.kind === 'asn') { refuse('ASN declarations are not supported; declare the prefixes the ASN announces'); return }
    if (entry.kind !== 'prefix' && entry.kind !== 'authorized') { refuse('kind must be prefix or authorized'); return }
    const block = parsePerimeterValue(value)
    const reason = perimeterValueReason(value, block)
    if (reason || !block) { refuse(reason); return }
    const canonical = formatPerimeterBlock(block)
    const kind = declared.get(canonical)
    // As in the store, the first entry with a value sets its kind even when
    // its label is refused.
    if (!kind) declared.set(canonical, entry.kind)
    const label = typeof entry.label === 'string' ? entry.label.trim() : ''
    const labelReason = perimeterLabelReason(label)
    if (labelReason) { refuse(labelReason); return }
    if (kind && kind !== entry.kind) { refuse(kind === 'prefix' ? 'already declared as owned' : 'already declared as authorized'); return }
    if (kind) { skipped++; return }
    created.push(perimeterRange({ id: nextID(), kind: entry.kind, value: canonical, label, family: block.family, created_at: perimeterGeneratedAt, addresses: block.family === 4 ? Number(blockSize(block)) : 0 }))
  })
  return { refused, result: { created: refused.length ? 0 : created.length, skipped: refused.length ? 0 : skipped }, created: refused.length ? [] : created }
}

/**
 * Install a deterministic API surface for browser acceptance tests. The
 * fixture intentionally models the same role/permission contract as the Go
 * authorization table and exposes mutation failures on demand so every
 * high-risk console flow has a browser-level error path. A unit role's
 * session belongs to the default unit of a single-unit installation. With
 * platformTOTP false, the platform administrator has no TOTP and the
 * deployment starts
 * with the default unit only; once a second unit exists, its session must
 * enrol TOTP and holds only account.self, and the platform routes are
 * refused, as the server's permission gate does. With emptyPerimeter, the
 * unit starts without declared ranges.
 */
export async function mockConsole(page: Page, role: ConsoleRole = 'administrator', { platformTOTP = true, emptyPerimeter = false, accessibilityFixtures = false, routeAuditFixtures = false }: { platformTOTP?: boolean; emptyPerimeter?: boolean; accessibilityFixtures?: boolean; routeAuditFixtures?: boolean } = {}): Promise<ConsoleMockControls> {
  const activityScans = accessibilityFixtures
    ? [{ ...scan, id: 'scan-failed', status: 'failed', error: 'Target timed out after 10 seconds.' }]
    : [scan]
  let incidents: IncidentInboxItem[] = [{
    job_id: 'job-1',
    job: 'fixture-job',
    occurrence_token: 'fixture-occurrence-1',
    opening_time_known: true, opening_scan_available: true,
    view_status: 'needs_review',
    incident: {
      change: { key: 'port|192.0.2.10|tcp|443', kind: 'port', target: '192.0.2.10', protocol: 'tcp', port: 443, severity: 'critical' },
      scan_id: 'scan-1',
      opened_at: '2026-01-01T00:00:00Z',
      last_seen_at: '2026-01-01T00:00:00Z',
      recovery_count: 0,
    },
    review: { status: 'needs_review', reviewer_label: null, reviewed_at: null, note: '', follow_up_at: null, revision: 0 },
    observation_uncertainty: { status: 'unknown', reason: 'no_newer_observation' },
  }]
  let publicDashboard: any = {
    enabled: false,
    title: 'Fixture public status',
    introduction: '',
    updated_at: '2026-01-01T00:00:00Z',
    hosts: [],
  }
  let updateRouting = { configured: true, destinations: ['dest-1'] }
  let incidentRemindersEnabled = true
  let incidentReminderCadence = 'every_scan'
  // The platform console's state, used when the role is platform_admin.
  const units: any[] = [
    platformUnit({ id: 'unit-default', name: 'Default', slug: 'default', is_default: true, accounts: 3, administrators: 1, jobs: 1, stored_scans: 12 }),
    platformUnit({ id: 'unit-retail', name: 'Retail', slug: 'retail', accounts: 3, administrators: 1, jobs: 2, stored_scans: 1480, slots: { in_use: 1, queued: 0 } }),
  ].slice(0, platformTOTP ? 2 : 1)
  if (accessibilityFixtures) units.push(platformUnit({ id: 'unit-disabled', name: 'Retail', slug: 'retail-lifecycle', status: 'disabled' }))
  const multipleUnits = () => units.filter(unit => unit.status !== 'deleted').length > 1
  const mustEnrol = () => role === 'platform_admin' && !platformTOTP && multipleUnits()
  const unitAccounts: Record<string, any[]> = {
    'unit-default': [platformAccount({ id: 'acct-admin', username: 'admin', display_name: 'Administrator', role: 'administrator', totp_enabled: true })],
    'unit-retail': [
      platformAccount({ id: 'acct-riley', username: 'riley', display_name: 'Riley Novak', role: 'administrator' }),
      platformAccount({ id: 'acct-casey', username: 'casey', display_name: 'Casey Lindqvist', role: 'operator' }),
      platformAccount({ id: 'acct-taylor', username: 'taylor', display_name: 'Taylor Brandt', role: 'viewer' }),
    ],
  }
  const platformAdmins: any[] = [platformAccount({ id: 'user-platform_admin', username: 'platform', display_name: 'platform_admin', role: 'platform_admin', totp_enabled: true })]
  let createdUnitUser: Record<string, unknown> | null = null
  let createdJob: Job | null = null
  let createdDestination: any = null
  let previewResponse: unknown = null
  let perimeterRanges = emptyPerimeter ? [] : perimeterFixtureRanges()
  let perimeterTransform = (overview: PerimeterOverview) => overview
  let declaredRanges = 0
  const previewGates: Array<{ started: () => void; response: Promise<unknown> }> = []
  let platformRouting = { configured: false, destinations: [] as string[] }
  const failures = new Set<string>()
  const calls: Record<string, number> = {}
  const payloads: Record<string, unknown[]> = {}
  const controls: ConsoleMockControls = {
    failNext: (operation) => failures.add(operation),
    setPreviewResponse: (response) => { previewResponse = response },
    deferNextPreview: () => {
      let markStarted!: () => void
      let release!: (response: unknown) => void
      const started = new Promise<void>(resolve => { markStarted = resolve })
      const response = new Promise<unknown>(resolve => { release = resolve })
      previewGates.push({ started: markStarted, response })
      return { started, resolve: release }
    },
    transformPerimeterOverview: (transform) => { perimeterTransform = transform },
    calls,
    payloads,
  }

  const record = (operation: string, value?: unknown) => {
    calls[operation] = (calls[operation] ?? 0) + 1
    if (value !== undefined) payloads[operation] = [...(payloads[operation] ?? []), value]
  }
  const jsonError = (operation: string) => ({ error: { code: 'validation_failed', message: `fixture ${operation} failed`, details: {} } })

  await page.route('**/api/v1/**', async route => {
    const request = route.request()
    const url = new URL(request.url())
    const path = url.pathname.replace('/api/v1', '')
    const method = request.method()
    const json = <T,>(body: T, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })
    const body = () => {
      try { return JSON.parse(request.postData() ?? '{}') as unknown } catch { return {} }
    }
    const mutate = async (operation: string, response: unknown, status = 200) => {
      const value = body()
      record(operation, value)
      if (failures.delete(operation)) {
        await json(jsonError(operation), 422)
        return
      }
      await json(response, status)
    }

    if (path === '/stream') { await route.abort(); return }
    if (path === '/setup/status') { await json({ configured: true, setup_available: false, password_requirements: { minimum_length: 12 }, platform_setup_available: false }); return }
    if (path === '/auth/session') {
      // A platform administrator's session names the platform console, and
      // a unit role's names the default unit.
      const scope = role === 'platform_admin' ? { scope: 'platform', unit: null, multi_unit: multipleUnits() } : { scope: 'unit', unit: { id: 'unit-default', name: 'Default', slug: 'default' }, multi_unit: false }
      const permissions = mustEnrol() ? ['account.self'] : rolePermissions[role]
      const enrolment = mustEnrol() ? { totp_enrollment_required: true } : {}
      // Only a unit administrator may approve high-cost scans.
      const highCost = role === 'administrator' && !mustEnrol() ? { high_cost_override: true } : {}
      await json({ user_id: `user-${role}`, username: role === 'administrator' ? 'admin' : role === 'platform_admin' ? 'platform' : role, display_name: role, role, permissions, csrf_token: 'fixture-csrf', totp_enabled: role === 'platform_admin' && platformTOTP, password_requirements: { minimum_length: 12 }, ...scope, ...enrolment, ...highCost })
      return
    }
    if (mustEnrol() && path.startsWith('/platform/')) {
      // A session that must enrol TOTP holds only its own account.
      record('platform-refused', `${method} ${path}`)
      await json({ error: { code: 'forbidden', message: 'your account is not allowed to perform this action', details: { permission: 'route' } } }, 403)
      return
    }
    if (role === 'platform_admin' && !path.startsWith('/platform/') && !path.startsWith('/auth/')) {
      // A platform administrator holds no permission on a unit's data.
      record('unit-data', `${method} ${path}`)
      await json({ error: { code: 'forbidden', message: 'your account is not allowed to perform this action', details: { permission: 'route' } } }, 403)
      return
    }
    if (role === 'platform_admin' && path.startsWith('/platform/')) {
      const parts = path.split('/').filter(Boolean).slice(1)
      const unit = parts[0] === 'units' && parts[1] ? units.find(item => item.id === parts[1]) : undefined
      if (parts[0] === 'units' && parts[1] && !unit) { await json({ error: { code: 'not_found', message: 'business unit not found' } }, 404); return }
      if (parts.length === 1 && parts[0] === 'units' && method === 'GET') { await json({ units, limits: deploymentLimits }); return }
      if (parts.length === 1 && parts[0] === 'units' && method === 'POST') {
        const value = body() as { name?: string; slug?: string }
        record('unit-create', value)
        if (failures.delete('unit-create')) { await json(jsonError('unit-create'), 422); return }
        const created = platformUnit({ id: `unit-${units.length + 1}`, name: value.name, slug: value.slug || String(value.name ?? '').toLowerCase().replace(/[^a-z0-9]+/g, '-') })
        units.push(created)
        unitAccounts[String((created as Record<string, unknown>).id)] = []
        await json(created, 201); return
      }
      if (unit && parts.length === 2 && method === 'GET') { await json(unit); return }
      if (unit && parts.length === 2 && method === 'PATCH') {
        const value = body() as { name?: string; slug?: string }
        record('unit-rename', value)
        Object.assign(unit, { ...value, revision: unit.revision + 1 })
        await json(unit); return
      }
      if (unit && parts.length === 2 && method === 'DELETE') {
        record('unit-delete', body())
        Object.assign(unit, { status: 'deleting', purge: { phase: 'jobs', rows: 12 }, revision: unit.revision + 1 })
        await json(unit); return
      }
      if (parts.length === 3 && (parts[2] === 'disable' || parts[2] === 'enable') && method === 'POST') {
        record(`unit-${parts[2]}`, body())
        Object.assign(unit, { status: parts[2] === 'disable' ? 'disabled' : 'active', revision: unit.revision + 1 })
        await json(unit); return
      }
      if (parts.length === 3 && parts[2] === 'capacity') {
        if (method === 'PATCH') record('unit-capacity', body())
        // A unit without a high-cost grant, as every new unit starts.
        await json({ unit_id: unit.id, revision: unit.revision, capacity: { max_concurrent_scans: 2, max_probe_count: null, max_naabu_probe_count: null, high_cost_ceiling: 0 }, limits: deploymentLimits, slots: { ...unit.slots, limit: 2 } }); return
      }
      if (parts.length === 3 && parts[2] === 'accounts' && method === 'GET') { await json({ accounts: unitAccounts[unit.id] ?? [] }); return }
      if (parts.length === 3 && parts[2] === 'accounts' && method === 'POST') {
        const value = body() as { username?: string; display_name?: string; role?: string }
        record('unit-admin-invite', value)
        if (failures.delete('unit-admin-invite')) { await json(jsonError('unit-admin-invite'), 422); return }
        const invited = platformAccount({ id: `acct-${value.username}`, username: value.username, display_name: value.display_name || value.username, role: 'administrator', enabled: false, pending: true })
        unitAccounts[unit.id] = [...(unitAccounts[unit.id] ?? []), invited]
        await json({ user: invited, activation_token: 'FIXTURE-INVITE', activation_path: '/activate#token=FIXTURE-INVITE' }, 201); return
      }
      if (parts.length === 5 && parts[2] === 'accounts' && parts[4] === 'password-reset' && method === 'POST') {
        const account = (unitAccounts[unit.id] ?? []).find(item => item.id === parts[3])
        record('unit-admin-reset', { account: parts[3], ...(body() as object) })
        await json({ activation_token: 'FIXTURE-RESET', activation_path: '/activate#token=FIXTURE-RESET', expires_at: '2026-01-01T00:30:00Z', totp_enrolled: !!account?.totp_enabled }); return
      }
      if (parts.length === 5 && parts[2] === 'accounts' && parts[4] === 'sessions' && method === 'DELETE') { record('unit-account-sessions', { account: parts[3] }); await route.fulfill({ status: 204 }); return }
      if (parts.length === 1 && parts[0] === 'admins' && method === 'GET') { await json({ admins: platformAdmins }); return }
      if (parts.length === 1 && parts[0] === 'admins' && method === 'POST') {
        const value = body() as { username?: string; display_name?: string }
        record('platform-admin-invite', value)
        const invited = platformAccount({ id: `user-${value.username}`, username: value.username, display_name: value.display_name || value.username, role: 'platform_admin', enabled: false, pending: true })
        platformAdmins.push(invited)
        await json({ user: invited, activation_token: 'FIXTURE-ADMIN', activation_path: '/activate#token=FIXTURE-ADMIN' }, 201); return
      }
      if (parts.length === 3 && parts[0] === 'admins' && parts[2] === 'activation' && method === 'DELETE') {
        record('platform-admin-revoke', { account: parts[1], ...(body() as object) })
        // Only a pending platform administrator's invitation is revoked.
        if (!platformAdmins.find(item => item.id === parts[1])?.pending) { await json({ error: { code: 'not_permitted', message: 'only a pending platform administrator\'s invitation can be revoked' } }, 403); return }
        await route.fulfill({ status: 204 }); return
      }
      if (parts.length === 3 && parts[0] === 'admins' && parts[2] === 'activation' && method === 'POST') {
        record('platform-admin-renew', { account: parts[1], ...(body() as object) })
        // Only a pending platform administrator's invitation is renewed.
        const pending = platformAdmins.find(item => item.id === parts[1])
        if (!pending?.pending) { await json({ error: { code: 'not_permitted', message: 'only a pending platform administrator\'s invitation can be renewed' } }, 403); return }
        await json({ user: pending, activation_token: 'FIXTURE-RENEWED', activation_path: '/activate#token=FIXTURE-RENEWED', expires_at: '2026-01-01T00:30:00Z' }); return
      }
      if (parts.length === 2 && parts[0] === 'admins' && method === 'DELETE') {
        record('platform-admin-remove', { account: parts[1], ...(body() as object) })
        // Only a pending platform administrator is removed, which frees its username.
        const index = platformAdmins.findIndex(item => item.id === parts[1])
        if (index < 0 || !platformAdmins[index].pending) { await json({ error: { code: 'not_permitted', message: 'only a pending platform administrator, which has not redeemed its invitation, can be removed' } }, 403); return }
        platformAdmins.splice(index, 1)
        await route.fulfill({ status: 204 }); return
      }
      if (parts.length === 1 && parts[0] === 'audit' && method === 'GET') {
        await json({ entries: [{ id: 2, created_at: '2026-01-01T00:00:02Z', action: 'tenant.created', category: 'platform', actor: { kind: 'platform', username: 'platform' }, detail: 'business unit Retail created', unit: { id: 'unit-retail', name: 'Retail', slug: 'retail' } }], next_before: null }); return
      }
      if (parts.length === 1 && parts[0] === 'notifications' && method === 'GET') { await json({ destinations: [{ ...destination, id: 'platform-1', name: 'Platform pager' }], status: { deployment: 0, managed: 1, active: 1, locked: 0, key_state: 'ready' }, update_routing: platformRouting }); return }
      if (parts.length === 2 && parts[0] === 'notifications' && parts[1] === 'update-routing' && method === 'PATCH') {
        const value = body() as { destination_id: string; enabled: boolean; password: string }
        record('platform-update-routing', value)
        const selected = new Set(platformRouting.configured ? platformRouting.destinations : [])
        if (value.enabled) selected.add(value.destination_id)
        else selected.delete(value.destination_id)
        platformRouting = { configured: true, destinations: [...selected].sort() }
        await json(platformRouting); return
      }
      if (parts.length === 1 && parts[0] === 'status' && method === 'GET') {
        await json<PlatformStatus>({ version: 'v0.18.65', units: { total: units.length, active: units.filter(item => item.status === 'active').length, disabled: units.filter(item => item.status === 'disabled').length, deleting: units.filter(item => item.status === 'deleting').length }, accounts: 6, jobs: 3, stored_scans: 1492, platform_admins: { total: platformAdmins.length, enabled: 1 }, capacity: { limits: deploymentLimits, slots: { capacity: 4, in_use: 1, queued: 0 } }, updates: { enabled: true, status: 'up_to_date', current_version: 'v0.18.65', available: false, stale: false } }); return
      }
      await json({ error: { code: 'not_found', message: `${method} ${path}` } }, 404); return
    }
    if (path === '/status') {
      await json<AdminStatus>({ configured: true, username: role, display_name: role, role, version: 'v0.18.65', notification_destinations: 1, notifications: { deployment: 0, managed: 1, active: 1, locked: 0, key_state: 'ready' }, retention: '90d', max_concurrent_scans: 1, updates: { enabled: true, status: 'up_to_date', current_version: 'v0.18.65', available: false, stale: false } })
      return
    }
    if (path === '/audit' && method === 'GET') {
      await json({ entries: [{ id: 1, created_at: '2026-01-01T00:00:01Z', action: 'user.login', category: 'account', actor: { kind: 'user', user_id: 'user-administrator', username: 'admin' }, detail: 'signed in', source_ip: '127.0.0.1' }], next_before: null }); return
    }
    if (path === '/incidents' && method === 'GET') {
      const limit = Math.min(200, Math.max(1, Number(url.searchParams.get('limit')) || 20))
      const offset = Math.max(0, Number(url.searchParams.get('offset')) || 0)
      const matching = incidents
      const hasMore = offset + limit < matching.length
      await json<IncidentInboxPage>({ incidents: matching.slice(offset, offset + limit), truncated: false, active_count: incidents.length, server_now: new Date().toISOString(), next_follow_up_at: null, pagination: { limit, offset, total: matching.length, has_more: hasMore, next_offset: hasMore ? offset + limit : null } }); return
    }
    if (path === '/incidents/summary' && method === 'GET') { await json<IncidentInboxSummary>({ active_count: incidents.length }); return }
    if (routeAuditFixtures && path === '/events' && method === 'GET') { await json({ events: [activityEvent], pagination: pagination(1, 20) }); return }
    if (path === '/hosts' && method === 'GET') {
      const hosts = [{ ...host, job_id: 'job-1', job: 'fixture-job', scan_id: 'scan-1', scanned_at: scan.finished_at, open_ports: 1, open_filtered_ports: 0, has_open_ports: true, data_quality: 'detailed' }]
      await json({ hosts, pagination: pagination(hosts.length) }); return
    }
    if (path === '/jobs' && method === 'GET') { await json({ jobs: createdJob ? [job, createdJob] : [job] }); return }
    if (routeAuditFixtures && path === '/jobs/slot-demand' && method === 'GET') { await json<ScanSlotDemand>(scanSlotDemand); return }
    if (path === '/jobs/schedule-suggestion' && method === 'GET') { await json({ suggested: false, draft_next_run: '2026-01-01T06:00:00Z', gap_minutes: 45 }); return }
    if (/^\/jobs\/[^/]+\/change-windows$/.test(path) && method === 'GET') { await json({ windows: [] }); return }
    if (path === '/jobs/job-1' && method === 'GET') { await json<Job>(job); return }
    // Like the API, a known job with no successful scan or no saved cycle
    // answers 200 with null rather than 404.
    if (/^\/jobs\/job-(1|created)\/scans\/latest-successful$/.test(path) && method === 'GET') { await json<{ scan: Scan | null }>({ scan: path.startsWith('/jobs/job-1/') ? scan : null }); return }
    if (/^\/jobs\/job-(1|created)\/scan-cycle$/.test(path) && method === 'GET') { await json({ cycle: null }); return }
    if (path === '/jobs/job-created' && method === 'GET') { createdJob ? await json(createdJob) : await json({ error: { code: 'not_found', message: 'job not found' } }, 404); return }
    if (path === '/jobs/job-created/scans' && method === 'GET') { await json({ scans: [], pagination: pagination(0, 20) }); return }
    if (path === '/jobs/job-1/scans' && method === 'GET') { await json({ scans: [scan], pagination: pagination(1, 20) }); return }
    if (path === '/jobs/job-1/scans/scan-1' && method === 'GET') { await json({ scan, changes: [], changes_pagination: pagination(0), current_security_hash: job.security_hash }); return }
    if (path === '/jobs/job-1/scans/scan-1/results' && method === 'GET') { await json({ results: [], pagination: pagination(0) }); return }
    if (path === '/jobs/job-1/scans/scan-1/changes' && method === 'GET') { await json({ changes: [], pagination: pagination(0) }); return }
    if (path === '/jobs/job-1/scans/scan-1/hosts/192.0.2.10/rdap' && method === 'GET') { await json({ rdap: { status: 'private', address: host.address } }); return }
    if (path === '/jobs/job-1/scans/scan-1/hosts/192.0.2.10' && method === 'GET') { await json({ job_id: 'job-1', job: job.job.name, scan, data_quality: 'detailed', host, expected: host }); return }
    if (path === '/jobs/job-1/baseline' && method === 'GET') { await json({ job_id: 'job-1', job: job.job.name, revision: 1, security_hash: job.security_hash, baseline: job.baseline, snapshot: { units: [], scopes: [] }, pagination: pagination(0) }); return }
    if (path === '/jobs/job-1/baseline/hosts' && method === 'GET') { await json({ job_id: 'job-1', job: job.job.name, source_scan: scan, data_quality: 'detailed', hosts: [host], pagination: pagination(1) }); return }
    if (path.startsWith('/jobs/job-1/baseline/hosts/') && method === 'GET') { await json({ job_id: 'job-1', job: job.job.name, source_scan: scan, data_quality: 'detailed', host, expected: host }); return }
    if (path === '/scans' && method === 'GET') { await json({ scans: activityScans, pagination: pagination(activityScans.length, 20) }); return }
    if (path === '/scans/scan-1/summary' && method === 'GET') { await json({ scan: scanSummary }); return }
    if (path === '/scans/scan-1' && method === 'GET') { await json({ scan }); return }
    if (path === '/scans/scan-1/hosts/192.0.2.10/rdap' && method === 'GET') { await json({ rdap: { status: 'private', address: host.address } }); return }
    if (path === '/scans/scan-1/hosts/192.0.2.10' && method === 'GET') { await json({ job_id: 'job-1', job: job.job.name, scan, data_quality: 'detailed', host }); return }
    if (path === '/scans/scan-1/hosts' && method === 'GET') { await json({ job_id: 'job-1', job: job.job.name, scan, data_quality: 'detailed', hosts: [host], pagination: pagination(1) }); return }
    if (path === '/scans/active' && method === 'GET') { await json({ scans: [] }); return }
    if (path === '/notifications/destinations' && method === 'GET') { await json({ destinations: createdDestination ? [destination, createdDestination] : [destination], status: { deployment: 0, managed: createdDestination ? 2 : 1, active: createdDestination ? 2 : 1, locked: 0, key_state: 'ready' }, update_routing: updateRouting, incident_reminders_enabled: incidentRemindersEnabled, incident_reminder_cadence: incidentReminderCadence }); return }
    if (path === '/users' && method === 'GET') {
      const users = [{ id: 'user-2', username: 'operator', display_name: 'Operator', role: 'operator', enabled: true, pending: false, totp_enabled: false, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z', revision: 1 }]
      await json({ users: createdUnitUser ? [...users, createdUnitUser] : users }); return
    }
    if (path === '/public-dashboard' && method === 'GET') { await json(publicDashboard); return }
    if (path === '/public-dashboard' && method === 'PUT') {
      const value = body() as Record<string, unknown>
      record('public-dashboard', value)
      if (failures.delete('public-dashboard')) { await json(jsonError('public-dashboard'), 422); return }
      publicDashboard = { ...publicDashboard, ...value, updated_at: '2026-01-01T00:00:01Z' }
      await json(publicDashboard); return
    }
    if (path === '/scanner/capabilities' && method === 'GET') { await json({ engines: ['nmap', 'naabu_nmap'], nmap: { path: '/usr/bin/nmap', version: '7.99', available: true }, naabu: { path: '/usr/local/bin/naabu', version: '2.6.1', available: true, syn_supported: false } }); return }
    if (path === '/scanner-profiles' && method === 'GET') { await json({ profiles: [profile] }); return }
    if (path === '/scanner-profiles/profile-1' && method === 'GET') { await json(profile); return }
    if (path === '/perimeter' && method === 'GET') { await json<PerimeterOverview>(perimeterTransform(perimeterOverview(perimeterRanges))); return }
    if (path === '/perimeter/seeds' && method === 'POST') {
      const value = body() as { entries?: unknown }
      record('perimeter-declare', value)
      // The audit record cannot be written, so nothing is stored.
      if (failures.delete('perimeter-declare')) { await json({ error: { code: 'audit_unavailable', message: 'the action was not committed because the security audit could not be recorded' } }, 503); return }
      const entries = Array.isArray(value.entries) ? value.entries as Array<Record<string, unknown>> : []
      if (entries.length < 1 || entries.length > 256) { await json({ error: { code: 'validation_failed', message: 'Declare between 1 and 256 entries.', details: { limit: 256 } } }, 400); return }
      const declaration = declarePerimeter(perimeterRanges, entries, () => `range-new-${++declaredRanges}`)
      if (declaration.refused.length) { await json({ error: { code: 'validation_failed', message: 'Some entries were refused; nothing was saved.', details: { entries: declaration.refused } } }, 400); return }
      perimeterRanges = [...perimeterRanges, ...declaration.created]
      await json(declaration.result); return
    }
    const perimeterSeed = /^\/perimeter\/seeds\/([^/]+)$/.exec(path)
    if (perimeterSeed) {
      const id = decodeURIComponent(perimeterSeed[1])
      const range = perimeterRanges.find(item => item.id === id)
      if (method === 'DELETE') {
        record('perimeter-remove', id)
        if (failures.delete('perimeter-remove')) { await json({ error: { code: 'audit_unavailable', message: 'the action was not committed because the security audit could not be recorded' } }, 503); return }
        if (range) perimeterRanges = perimeterRanges.filter(item => item !== range)
      }
      // An unknown range and another unit's answer alike, without the ID.
      if (!range) { await json({ error: { code: 'not_found', message: 'perimeter range not found' } }, 404); return }
      if (method === 'DELETE') { await route.fulfill({ status: 204 }); return }
      if (method === 'GET') { await json<PerimeterRangeDetail>(perimeterRangeDetail(range)); return }
    }

    if (path === '/jobs/preview' && method === 'POST') {
      const value = body() as Record<string, any>
      const estimate = { hosts: value.targets?.length ?? 1, tcp_ports: value.tcp?.ports === '1-65535' ? 65_535 : value.tcp ? 2 : 0, udp_ports: value.udp ? 1 : 0, probes: value.tcp?.ports === '1-65535' ? 65_535 : 2, nmap_invocations: value.tcp?.engine === 'naabu_nmap' ? 1 : Number(!!value.tcp) + Number(!!value.udp), naabu_invocations: value.tcp?.engine === 'naabu_nmap' ? 1 : 0, unknown_dns: value.targets?.some((target: string) => !/^\d/.test(target)) ? 1 : 0 }
      const override = previewResponse as Record<string, unknown> | null
      let response: unknown = override
        ? { ...override, job: override.job ?? value }
        : { job: value, scan_estimate: estimate, scan_budget: { exceeded: false, limit: 5_000_000 }, warnings: [{ code: 'elapsed_time_unknown', message: 'Elapsed time depends on scanner behavior and target responses.' }] }
      const gate = previewGates.shift()
      if (gate) {
        gate.started()
        response = await gate.response
      }
      try {
        await mutate('job-preview', response)
      } catch {
        // A guided form may abort an old preview when the draft changes.
      }
      return
    }
    if (path === '/jobs' && method === 'POST') {
      const value = body() as JobForm
      record('job-create', value)
      if (failures.delete('job-create')) { await json(jsonError('job-create'), 422); return }
      createdJob = { ...job, id: 'job-created', revision: 1, job: value, baseline: { status: 'learning', samples: 0, attempts: 0 }, scan_budget: { exceeded: false }, scan_cycle: null }
      await json<Job>(createdJob, 201)
      return
    }
    if (path === '/jobs/job-created/run' && method === 'POST') {
      record('job-run', body())
      if (failures.delete('job-run')) { await json(jsonError('job-run'), 422); return }
      await json({ status: 'accepted', job_id: 'job-created' }, 202)
      return
    }
    if (path === '/jobs/job-1' && method === 'PUT') { await mutate('job-update', job); return }
    if (path === '/jobs/job-1/incidents/accept' && method === 'POST') {
      record('incident-accept', body())
      if (failures.delete('incident-accept')) { await json(jsonError('incident-accept'), 422); return }
      incidents = []
      await route.fulfill({ status: 204 }); return
    }
    if (path === '/jobs/job-1/incidents/suppress' && method === 'POST') {
      record('incident-suppress', body())
      if (failures.delete('incident-suppress')) { await json(jsonError('incident-suppress'), 422); return }
      await route.fulfill({ status: 204 }); return
    }
    if (path === '/notifications/update-routing' && method === 'PATCH') {
      const value = body() as { destination_id: string; enabled: boolean; password: string }
      record('update-routing', value)
      if (failures.delete('update-routing')) { await json(jsonError('update-routing'), 422); return }
      const selected = new Set(updateRouting.configured ? updateRouting.destinations : ['dest-1'])
      if (value.enabled) selected.add(value.destination_id)
      else selected.delete(value.destination_id)
      updateRouting = { configured: true, destinations: [...selected].sort() }
      await json(updateRouting); return
    }
    if (path === '/notifications/incident-reminders' && method === 'PUT') {
      const value = body() as { enabled?: boolean; cadence?: string; password?: string }
      record('incident-reminders', value)
      if (failures.delete('incident-reminders')) { await json(jsonError('incident-reminders'), 422); return }
      incidentRemindersEnabled = value.enabled ?? incidentRemindersEnabled
      incidentReminderCadence = value.cadence ?? incidentReminderCadence
      await json({ enabled: incidentRemindersEnabled, cadence: incidentReminderCadence }); return
    }
    if (path === '/notifications/destinations' && method === 'POST') {
      const value = body() as { name?: string }
      record('notification-create', value)
      if (failures.delete('notification-create')) { await json(jsonError('notification-create'), 422); return }
      createdDestination = { ...destination, id: 'dest-created', name: value.name ?? 'Test destination', provider: 'generic', source: 'web' }
      await json(createdDestination, 201)
      return
    }
    if (path === '/notifications/destinations/dest-1' && method === 'PUT') { await mutate('notification-update', destination); return }
    if (path === '/notifications/destinations/dest-1' && method === 'DELETE') { await mutate('notification-delete', undefined, 204); return }
    if (path.startsWith('/notifications/destinations/') && path.endsWith('/test') && method === 'POST') { await mutate('notification-test', { sent: 1 }); return }
    if (path === '/scanner-profiles/validate' && method === 'POST') { await mutate('profile-validate', { valid: true, preview: [{ executable: '/usr/bin/nmap', args: ['-n', '-Pn', '-p', '22'] }] }); return }
    if (path === '/scanner-profiles' && method === 'POST') { await mutate('profile-create', profile, 201); return }
    if (path === '/scanner-profiles/profile-1' && method === 'PUT') { await mutate('profile-update', profile); return }
    if (path === '/users' && method === 'POST') {
      const value = body()
      record('user-create', value)
      if (failures.delete('user-create')) { await json(jsonError('user-create'), 422); return }
      createdUnitUser = { id: 'user-created', username: 'new-user', display_name: 'New User', role: 'viewer', enabled: false, pending: true, totp_enabled: false, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z', revision: 1 }
      await json({ user: createdUnitUser, activation_token: 'FIXTURE-TOKEN', activation_path: '/activate#token=FIXTURE-TOKEN' }, 201); return
    }
    if (path === '/users/user-2' && method === 'PATCH') { await mutate('user-update', { ...job, id: 'user-2' }); return }
    if (path === '/auth/display-name' && method === 'PUT') { await mutate('display-name', { display_name: 'Renamed admin' }); return }
    if (path === '/auth/password' && method === 'PUT') { await mutate('password', undefined, 204); return }
    if (path === '/auth/totp/setup' && method === 'POST') { await mutate('totp-setup', { secret: 'FIXTURE', otpauth: 'otpauth://fixture' }); return }
    if (path === '/auth/totp/enable' && method === 'POST') { await mutate('totp-enable', { recovery_codes: ['FIXTURE-CODE'] }); return }
    if (path === '/auth/totp' && method === 'DELETE') { await mutate('totp-disable', undefined, 204); return }
    if (path === '/auth/sessions' && method === 'DELETE') { await mutate('sessions-revoke', undefined, 204); return }
    if (path === '/auth/logout' && method === 'POST') { await route.fulfill({ status: 204 }); return }
    await json({ error: { code: 'not_found', message: `${method} ${path}` } }, 404)
  })

  return controls
}
