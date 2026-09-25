// Business-units prototype: in-memory fixture data for the dev-only mock API.
// Nothing here is imported by src/ or shipped in the production bundle.
// Names are fictional and every address is in a documentation range
// (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).

export type UnitRole = 'administrator' | 'operator' | 'viewer'
export type Role = UnitRole | 'platform_admin'
export type UnitStatus = 'active' | 'disabled' | 'deleting' | 'deleted'

export type Account = {
  id: string; username: string; display_name: string; role: Role; unit_id: string | null
  enabled: boolean; pending: boolean; totp_enabled: boolean; created_at: string; updated_at: string
  last_login_at?: string; revision: number
}

export type PublicConfig = { enabled: boolean; title: string; introduction: string; updated_at: string; hosts: { job_id: string; address: string; created_at: string }[] }

export type UnitState = {
  id: string; name: string; slug: string; status: UnitStatus; is_default: boolean; revision: number
  created_at: string; updated_at: string; disabled_at?: string; delete_started_at?: number
  slot_cap: number; max_probe_count: number; max_naabu_probe_count: number
  deployment_destinations: string[]; notifications_revision: number; public: PublicConfig
}

export type Port = { port: number; state: string; reason?: string; verification?: string; service?: { name?: string; product?: string; version?: string; method?: string; confidence?: number } }
export type HostProtocol = { protocol: string; scan_type?: string; scanned_ports: string; scanned_port_count: number; service_detection: boolean; ports: Port[]; state_summaries: { state: string; count: number }[] }
export type Host = { address: string; address_family: string; source_targets: string[]; dns_names: string[]; status: string; status_reason: string; latency_ms: number; protocols: HostProtocol[] }

export type Scan = {
  id: string; job_id: string; job: string; job_revision: number; started_at: string; finished_at: string; status: string; error?: string
  config_hash: string; scanner_engine: string; nmap_version: string; scanner_profile_id?: string; scanner_profile_revision?: number
  hosts: Host[]; changes: Change[]
}

export type Change = { key: string; kind: string; target: string; protocol?: string; port?: number; old?: string; new?: string; severity: string }
export type Incident = { job_id: string; job: string; incident: { change: Change; scan_id: string; opened_at: string; last_seen_at: string } }

export type JobRecord = { unit_id: string; job: any; scans: Scan[]; baselineHosts: Host[]; incidents: Incident[] }
export type Destination = { id: string; unit_id: string; name: string; provider: string; source: 'web'; enabled: boolean; locked: false; read_only: false; revision: number; created_at: string; updated_at: string; last_success_at?: string }
export type DeploymentDestination = { id: string; name: string; provider: string; enabled: boolean }
export type Profile = { unit_id: string | null; profile: any }
export type AuditActor = { kind: 'unit' | 'platform' | 'host'; username?: string; display_name?: string }
export type AuditRow = { id: number; at: string; action: string; category: 'platform' | 'account' | 'data'; actor: AuditActor; unit_id: string | null; target?: string; detail: string }
export type Run = { id: string; unit_id: string; job_id: string; queued_at: number; started_at?: number; duration_ms: number }

export type State = {
  startedAt: number
  units: UnitState[]
  accounts: Account[]
  jobs: JobRecord[]
  destinations: Destination[]
  deploymentDestinations: DeploymentDestination[]
  profiles: Profile[]
  audit: AuditRow[]
  runs: Run[]
  revokedSessions: Set<string>
  activationTokens: Map<string, string>
  sequence: number
}

export const DEFAULT_UNIT_ID = '00000000-0000-0000-0000-000000000100'
export const BUILTIN_NMAP_PROFILE_ID = '00000000-0000-0000-0000-000000000013'
export const BUILTIN_NAABU_PROFILE_ID = '00000000-0000-0000-0000-000000000014'
export const VERSION = 'v0.18.145'

export const DEPLOYMENT_LIMITS = { max_concurrent_scans: 4, max_probe_count: 5_000_000, max_naabu_probe_count: 20_000_000, max_probe_count_limit: 100_000_000 }

export const UNIT_PERMISSIONS: Record<UnitRole, string[]> = {
  administrator: [
    'overview.read', 'jobs.read', 'jobs.write', 'jobs.run', 'jobs.delete',
    'hosts.read', 'scans.read', 'baselines.read', 'baselines.manage',
    'incidents.read', 'incidents.manage', 'notification_options.read',
    'notifications.manage', 'users.manage', 'public_dashboard.manage',
    'stream.read', 'scanner_profiles.read', 'scanner_profiles.manage',
    'account.self', 'audit.read',
  ],
  operator: [
    'overview.read', 'jobs.read', 'jobs.write', 'jobs.run',
    'hosts.read', 'scans.read', 'baselines.read', 'baselines.manage',
    'incidents.read', 'incidents.manage', 'notification_options.read',
    'stream.read', 'scanner_profiles.read', 'account.self',
  ],
  viewer: ['jobs.read', 'baselines.read', 'account.self'],
}

export const PLATFORM_PERMISSIONS = ['units.manage', 'unit_accounts.manage', 'platform_audit.read', 'platform_notifications.manage', 'platform_status.read', 'account.self']

export const ERASE_CATEGORIES = [
  { key: 'jobs', label: 'Jobs and schedules', detail: 'Every job, its targets, and its schedule.' },
  { key: 'history', label: 'Scan history and host evidence', detail: 'All scans, host observations, and raw scanner evidence.' },
  { key: 'baselines', label: 'Baselines and incidents', detail: 'Expected surfaces, open and closed incidents, and accepted changes.' },
  { key: 'notifications', label: 'Notification destinations and queued alerts', detail: 'The unit’s own destinations and undelivered alerts. Deployment destinations stay in config.yaml.' },
  { key: 'profiles', label: 'Custom scanner profiles', detail: 'Built-in profiles are shared and are not affected.' },
  { key: 'public', label: 'Public status page', detail: 'The page and its published hosts. The slug becomes available again.' },
  { key: 'accounts', label: 'Accounts, sessions, and invitations', detail: 'Every account in the unit, including its administrators.' },
  { key: 'audit', label: 'The unit’s audit log', detail: 'Platform actions on the unit stay in the platform audit.' },
]

/**
 * Persona keys are account IDs, plus two states without a session. The
 * persona switcher in prototype/persona-switcher.ts lists the same keys.
 */
export const PERSONAS = [
  { key: 'acct-morgan', label: 'Main admin', hint: 'Platform console: units, their accounts, capacity, and audit. No job data.' },
  { key: 'acct-riley', label: 'Unit A admin (Retail)', hint: 'Retail’s console plus the Audit page. riley has no TOTP.' },
  { key: 'acct-casey', label: 'Unit A operator (Retail)', hint: 'Today’s operator navigation, scoped to Retail.' },
  { key: 'acct-taylor', label: 'Unit A viewer (Retail)', hint: 'Today’s read-only viewer navigation, scoped to Retail.' },
  { key: 'acct-quinn', label: 'Unit B admin (Manufacturing, disabled)', hint: 'Manufacturing is disabled: its sessions ended. Sign in as quinn to see the refusal.' },
  { key: 'fresh-upgrade', label: 'Fresh upgrade (no main admin yet)', hint: 'Platform setup variant. Any setup token works in the prototype.' },
  { key: 'signed-out', label: 'Signed out', hint: 'Any password works. Users: morgan, sam, riley, jordan, casey, taylor, quinn, alex, dana, lee.' },
]
export const DEFAULT_PERSONA = 'acct-morgan'

const HOUR = 3_600_000
const DAY = 24 * HOUR

function countPorts(expression: string) {
  return expression.split(',').reduce((total, part) => {
    const [start, end] = part.split('-').map(Number)
    return total + (end ? end - start + 1 : 1)
  }, 0)
}

type PortSpec = [number, string, string?, string?]

function protocol(name: 'tcp' | 'udp', scope: string, open: PortSpec[], state = 'open'): HostProtocol {
  const count = countPorts(scope)
  return {
    protocol: name,
    scan_type: name === 'tcp' ? 'connect' : 'udp',
    scanned_ports: scope,
    scanned_port_count: count,
    service_detection: true,
    ports: open.map(([port, service, product, version]) => ({ port, state, reason: name === 'tcp' ? 'syn-ack' : 'udp-response', verification: 'confirmed', service: { name: service, product, version, method: 'probed', confidence: 10 } })),
    state_summaries: [{ state, count: open.length }, { state: name === 'tcp' ? 'closed' : 'open|filtered', count: Math.max(0, count - open.length) }],
  }
}

function host(address: string, target: string, protocols: HostProtocol[], dns: string[] = []): Host {
  return { address, address_family: 'IPv4', source_targets: [target], dns_names: dns, status: 'up', status_reason: 'syn-ack', latency_ms: 8 + (address.length % 7), protocols }
}

type JobSpec = {
  id: string; unit_id: string; name: string; targets: string[]; tcp?: string; udp?: string; schedule: string
  hosts: Host[]; incidents?: { address: string; protocol: 'tcp' | 'udp'; port: number; service: string; kind?: 'port' | 'service'; old?: string; new?: string; severity?: string; hoursAgo: number }[]
  learning?: boolean; archived?: boolean; enabled?: boolean; profile_id?: string; destinations?: string[]; createdDaysAgo: number
}

function iso(state: { startedAt: number }, msAgo: number) {
  return new Date(state.startedAt - msAgo).toISOString()
}

function withIncidentPorts(hosts: Host[], incidents: NonNullable<JobSpec['incidents']>) {
  return hosts.map(item => {
    const extra = incidents.filter(incident => incident.address === item.address && (incident.kind ?? 'port') === 'port')
    if (!extra.length) return item
    return {
      ...item,
      protocols: item.protocols.map(proto => {
        const ports = extra.filter(incident => incident.protocol === proto.protocol).map(incident => ({ port: incident.port, state: 'open', reason: 'syn-ack', verification: 'confirmed', service: { name: incident.service, method: 'probed', confidence: 10 } }))
        return ports.length ? { ...proto, ports: [...proto.ports, ...ports], state_summaries: [{ state: 'open', count: proto.ports.length + ports.length }, { state: 'closed', count: Math.max(0, proto.scanned_port_count - proto.ports.length - ports.length) }] } : proto
      }),
    }
  })
}

export function buildJob(state: { startedAt: number }, spec: JobSpec): JobRecord {
  const incidents = spec.incidents ?? []
  const created = iso(state, spec.createdDaysAgo * DAY)
  const profileID = spec.profile_id ?? BUILTIN_NMAP_PROFILE_ID
  const job = {
    id: spec.id,
    revision: 3,
    enabled: spec.enabled ?? !spec.archived,
    archived: !!spec.archived,
    security_hash: `sha256:${spec.id}`,
    created_at: created,
    updated_at: iso(state, 2 * DAY),
    job: {
      name: spec.name, schedule: spec.schedule, timezone: 'Europe/Amsterdam', targets: spec.targets, max_expanded_hosts: 256,
      tcp: spec.tcp ? { ports: spec.tcp, mode: 'connect', service_detection: true, engine: 'nmap', profile_id: profileID, profile_revision: 1 } : undefined,
      udp: spec.udp ? { ports: spec.udp, mode: 'udp', service_detection: true, engine: 'nmap', profile_id: BUILTIN_NMAP_PROFILE_ID, profile_revision: 1 } : undefined,
      timing: 'balanced', timeout: '1h', resume_window: '8d', baseline_samples: 2, change_confirmations: 2,
      run_on_start: false, assume_alive: true, allow_high_cost: false, notification_destinations: spec.destinations ?? [],
    },
    baseline: spec.learning
      ? { status: 'learning', samples: 1, attempts: 1, host_count: spec.hosts.length }
      : { status: 'complete', samples: 2, attempts: 2, host_count: spec.hosts.length, scan_id: `scan-${spec.id}-2`, incidents: incidents.length, modified: false },
    scan_estimate: { hosts: spec.hosts.length || spec.targets.length, tcp_ports: spec.tcp ? countPorts(spec.tcp) : 0, udp_ports: spec.udp ? countPorts(spec.udp) : 0, probes: (spec.hosts.length || 1) * ((spec.tcp ? countPorts(spec.tcp) : 0) + (spec.udp ? countPorts(spec.udp) : 0)), nmap_invocations: spec.udp && spec.tcp ? 2 : 1, estimated_seconds: 180, unknown_dns: spec.targets.filter(target => /[a-z]/i.test(target)).length },
  }
  const latestHosts = withIncidentPorts(spec.hosts, incidents)
  const scans: Scan[] = []
  const count = spec.learning ? 2 : 6
  for (let index = 1; index <= count; index += 1) {
    const age = (count - index) * 6 * HOUR + (spec.archived ? 30 * DAY : HOUR)
    const latest = index === count
    const failed = !spec.learning && index === 3
    const changes: Change[] = latest ? incidents.map(incident => changeFor(incident)) : []
    scans.push({
      id: `scan-${spec.id}-${index}`, job_id: spec.id, job: spec.name, job_revision: 3,
      started_at: iso(state, age + 4 * 60_000), finished_at: iso(state, age), status: failed ? 'failed' : 'success',
      error: failed ? 'nmap exited with status 1: host timeout budget exceeded' : undefined,
      config_hash: job.security_hash, scanner_engine: 'nmap', nmap_version: '7.95', scanner_profile_id: profileID, scanner_profile_revision: 1,
      hosts: failed ? [] : latest ? latestHosts : spec.hosts, changes,
    })
  }
  const latestScan = scans[scans.length - 1]
  return {
    unit_id: spec.unit_id,
    job,
    scans,
    baselineHosts: spec.hosts,
    incidents: incidents.map(incident => ({ job_id: spec.id, job: spec.name, incident: { change: changeFor(incident), scan_id: latestScan.id, opened_at: iso(state, incident.hoursAgo * HOUR), last_seen_at: latestScan.finished_at } })),
  }
}

function changeFor(incident: NonNullable<JobSpec['incidents']>[number]): Change {
  const kind = incident.kind ?? 'port'
  return {
    key: `${kind}|${incident.address}|${incident.protocol}|${incident.port}`,
    kind, target: incident.address, protocol: incident.protocol, port: incident.port,
    old: incident.old ?? 'closed', new: incident.new ?? `open (${incident.service})`, severity: incident.severity ?? 'critical',
  }
}

function account(state: { startedAt: number }, id: string, username: string, display_name: string, role: Role, unit_id: string | null, options: Partial<Account> & { daysAgo?: number; lastLoginHours?: number } = {}): Account {
  const { daysAgo = 90, lastLoginHours, ...rest } = options
  return {
    id, username, display_name, role, unit_id, enabled: true, pending: false, totp_enabled: false,
    created_at: iso(state, daysAgo * DAY), updated_at: iso(state, Math.min(daysAgo, 10) * DAY),
    last_login_at: lastLoginHours === undefined ? undefined : iso(state, lastLoginHours * HOUR), revision: 1, ...rest,
  }
}

function publicConfig(state: { startedAt: number }, enabled: boolean, title: string, introduction: string, hosts: [string, string][]): PublicConfig {
  return { enabled, title, introduction, updated_at: iso(state, 3 * DAY), hosts: hosts.map(([job_id, address]) => ({ job_id, address, created_at: iso(state, 3 * DAY) })) }
}

function profile(id: string, name: string, description: string, definition: Record<string, unknown>, options: { builtIn?: boolean; createdBy?: string; daysAgo?: number; state: { startedAt: number } }) {
  return {
    id, name, description, built_in: !!options.builtIn, archived: false, revision: 1,
    created_by: options.createdBy, created_at: iso(options.state, (options.daysAgo ?? 200) * DAY), updated_at: iso(options.state, (options.daysAgo ?? 200) * DAY),
    definition: {
      engine: 'nmap',
      naabu: { scan_type: 'connect', rate: 1000, workers: 25, retries: 3, timeout_ms: 1000, warm_up_seconds: 2, verify: true, address_batch_size: 16 },
      nmap_args: [], naabu_args: [], enrichment_args: [], operator_adjustable: [], operator_bounds: {},
      ...definition,
    },
  }
}

export function createState(): State {
  const state = { startedAt: Date.now() } as State
  const RETAIL = 'unit-retail'
  const MANUFACTURING = 'unit-manufacturing'
  state.sequence = 1000
  // Disabling Manufacturing ended its sessions; its members must sign in
  // again once a main administrator enables the unit.
  state.revokedSessions = new Set(['acct-quinn', 'acct-avery'])
  state.activationTokens = new Map()
  state.deploymentDestinations = [
    { id: 'deploy-ops-slack', name: 'Ops Slack', provider: 'slack', enabled: true },
    { id: 'deploy-security-mail', name: 'Security mail', provider: 'smtp', enabled: true },
  ]
  state.units = [
    {
      id: DEFAULT_UNIT_ID, name: 'Default', slug: 'default', status: 'active', is_default: true, revision: 4,
      created_at: iso(state, 400 * DAY), updated_at: iso(state, 20 * DAY), slot_cap: 2, max_probe_count: 5_000_000, max_naabu_probe_count: 20_000_000,
      deployment_destinations: ['deploy-ops-slack', 'deploy-security-mail'], notifications_revision: 2,
      public: publicConfig(state, true, 'Corporate edge status', 'Open services on our corporate internet edge, updated after each scan.', [['job-perimeter', '192.0.2.1'], ['job-branch-vpn', '198.51.100.20']]),
    },
    {
      id: RETAIL, name: 'Retail', slug: 'retail', status: 'active', is_default: false, revision: 3,
      created_at: iso(state, 30 * DAY), updated_at: iso(state, 5 * DAY), slot_cap: 1, max_probe_count: 2_000_000, max_naabu_probe_count: 10_000_000,
      deployment_destinations: ['deploy-ops-slack'], notifications_revision: 1,
      public: publicConfig(state, true, 'Retail storefront status', 'Public services behind our online store.', [['job-storefront', '203.0.113.10'], ['job-payments', '198.51.100.20']]),
    },
    {
      id: MANUFACTURING, name: 'Manufacturing', slug: 'manufacturing', status: 'disabled', is_default: false, revision: 5,
      created_at: iso(state, 29 * DAY), updated_at: iso(state, 2 * DAY), disabled_at: iso(state, 2 * DAY), slot_cap: 1, max_probe_count: 1_000_000, max_naabu_probe_count: 5_000_000,
      deployment_destinations: ['deploy-security-mail'], notifications_revision: 1,
      public: publicConfig(state, true, 'Plant connectivity', '', [['job-plant', '198.51.100.60']]),
    },
  ]
  state.accounts = [
    account(state, 'acct-morgan', 'morgan', 'Morgan Reyes', 'platform_admin', null, { daysAgo: 31, lastLoginHours: 3 }),
    account(state, 'acct-sam', 'sam', 'Sam Okafor', 'platform_admin', null, { daysAgo: 25, lastLoginHours: 50, totp_enabled: true }),
    account(state, '00000000-0000-0000-0000-000000000001', 'alex', 'Alex Moreau', 'administrator', DEFAULT_UNIT_ID, { daysAgo: 400, lastLoginHours: 5, totp_enabled: true }),
    account(state, 'acct-dana', 'dana', 'Dana Whitfield', 'operator', DEFAULT_UNIT_ID, { daysAgo: 300, lastLoginHours: 20 }),
    account(state, 'acct-lee', 'lee', 'Lee Park', 'viewer', DEFAULT_UNIT_ID, { daysAgo: 120, lastLoginHours: 72 }),
    account(state, 'acct-riley', 'riley', 'Riley Novak', 'administrator', RETAIL, { daysAgo: 30, lastLoginHours: 1 }),
    account(state, 'acct-jordan', 'jordan', 'Jordan Ellis', 'administrator', RETAIL, { daysAgo: 28, lastLoginHours: 30, totp_enabled: true }),
    account(state, 'acct-casey', 'casey', 'Casey Lindqvist', 'operator', RETAIL, { daysAgo: 27, lastLoginHours: 4 }),
    account(state, 'acct-taylor', 'taylor', 'Taylor Brandt', 'viewer', RETAIL, { daysAgo: 20, lastLoginHours: 26 }),
    account(state, 'acct-pat', 'pat', 'Pat Osei', 'viewer', RETAIL, { daysAgo: 1, pending: true, enabled: false }),
    account(state, 'acct-quinn', 'quinn', 'Quinn Harlow', 'administrator', MANUFACTURING, { daysAgo: 29, lastLoginHours: 60 }),
    account(state, 'acct-avery', 'avery', 'Avery Santos', 'operator', MANUFACTURING, { daysAgo: 25, lastLoginHours: 70 }),
  ]
  state.destinations = [
    { id: 'dest-noc-teams', unit_id: DEFAULT_UNIT_ID, name: 'NOC Teams', provider: 'teams', source: 'web', enabled: true, locked: false, read_only: false, revision: 2, created_at: iso(state, 200 * DAY), updated_at: iso(state, 40 * DAY), last_success_at: iso(state, 6 * HOUR) },
    { id: 'dest-retail-oncall', unit_id: RETAIL, name: 'Retail on-call', provider: 'pushover', source: 'web', enabled: true, locked: false, read_only: false, revision: 1, created_at: iso(state, 25 * DAY), updated_at: iso(state, 25 * DAY), last_success_at: iso(state, 3 * HOUR) },
    { id: 'dest-store-ops', unit_id: RETAIL, name: 'Store ops email', provider: 'smtp', source: 'web', enabled: true, locked: false, read_only: false, revision: 1, created_at: iso(state, 24 * DAY), updated_at: iso(state, 24 * DAY) },
    { id: 'dest-plant-teams', unit_id: MANUFACTURING, name: 'Plant ops Teams', provider: 'teams', source: 'web', enabled: true, locked: false, read_only: false, revision: 1, created_at: iso(state, 28 * DAY), updated_at: iso(state, 28 * DAY) },
  ]
  state.profiles = [
    { unit_id: null, profile: profile(BUILTIN_NMAP_PROFILE_ID, 'Nmap standard', 'Nmap connect scan with service detection.', {}, { builtIn: true, state }) },
    { unit_id: null, profile: profile(BUILTIN_NAABU_PROFILE_ID, 'Naabu full TCP → Nmap', 'Fast Naabu discovery confirmed by Nmap.', { engine: 'naabu_nmap' }, { builtIn: true, state }) },
    { unit_id: DEFAULT_UNIT_ID, profile: profile('profile-default-lowrate', 'Branch low rate', 'Gentle timing for branch links.', { nmap_args: ['--max-rate', '50'] }, { createdBy: 'alex', daysAgo: 90, state }) },
    { unit_id: RETAIL, profile: profile('profile-retail-pci', 'Retail PCI sweep', 'Full TCP discovery for cardholder-data systems.', { engine: 'naabu_nmap', naabu: { scan_type: 'connect', rate: 500, workers: 10, retries: 2, timeout_ms: 1500, warm_up_seconds: 2, verify: true, address_batch_size: 8 } }, { createdBy: 'riley', daysAgo: 20, state }) },
    { unit_id: MANUFACTURING, profile: profile('profile-plant-ot', 'OT safe', 'Low-rate probes that are safe for PLCs.', { nmap_args: ['--max-rate', '10', '--scan-delay', '100ms'] }, { createdBy: 'quinn', daysAgo: 22, state }) },
  ]
  state.jobs = [
    buildJob(state, {
      id: 'job-perimeter', unit_id: DEFAULT_UNIT_ID, name: 'Perimeter TCP', targets: ['192.0.2.0/28'], tcp: '22,80,443,3389,8443', schedule: '0 */6 * * *', createdDaysAgo: 380, destinations: ['dest-noc-teams', 'deploy-security-mail'],
      hosts: [
        host('192.0.2.1', '192.0.2.0/28', [protocol('tcp', '22,80,443,3389,8443', [[80, 'http', 'nginx', '1.26.2'], [443, 'https', 'nginx', '1.26.2']])], ['www.example.com']),
        host('192.0.2.5', '192.0.2.0/28', [protocol('tcp', '22,80,443,3389,8443', [[22, 'ssh', 'OpenSSH', '9.6']])], ['bastion.example.com']),
        host('192.0.2.9', '192.0.2.0/28', [protocol('tcp', '22,80,443,3389,8443', [[443, 'https'], [8443, 'https-alt']])]),
      ],
      incidents: [{ address: '192.0.2.9', protocol: 'tcp', port: 3389, service: 'ms-wbt-server', hoursAgo: 5 }],
    }),
    buildJob(state, {
      id: 'job-branch-vpn', unit_id: DEFAULT_UNIT_ID, name: 'Branch VPN', targets: ['198.51.100.20', 'vpn.example.net'], tcp: '443,1194', udp: '500,4500', schedule: '30 2 * * *', createdDaysAgo: 250, destinations: ['deploy-ops-slack'],
      hosts: [host('198.51.100.20', '198.51.100.20', [protocol('tcp', '443,1194', [[443, 'https', 'nginx', '1.24.0']]), protocol('udp', '500,4500', [[500, 'isakmp'], [4500, 'nat-t-ike']], 'open|filtered')], ['vpn.example.net'])],
      incidents: [{ address: '198.51.100.20', protocol: 'tcp', port: 443, service: 'https', kind: 'service', old: 'https nginx 1.24.0', new: 'https nginx 1.27.1', severity: 'warning', hoursAgo: 20 }],
    }),
    buildJob(state, {
      id: 'job-dns', unit_id: DEFAULT_UNIT_ID, name: 'DNS resolvers', targets: ['192.0.2.53', '192.0.2.54'], udp: '53,123', schedule: '0 4 * * 1', createdDaysAgo: 6, learning: true, profile_id: 'profile-default-lowrate',
      hosts: [host('192.0.2.53', '192.0.2.53', [protocol('udp', '53,123', [[53, 'domain', 'Unbound']])]), host('192.0.2.54', '192.0.2.54', [protocol('udp', '53,123', [[53, 'domain', 'Unbound'], [123, 'ntp']])])],
    }),
    buildJob(state, {
      id: 'job-storefront', unit_id: RETAIL, name: 'Storefront edge', targets: ['203.0.113.10', '203.0.113.11', '203.0.113.12'], tcp: '80,443,8080', schedule: '15 * * * *', createdDaysAgo: 26, destinations: ['dest-retail-oncall', 'deploy-ops-slack'],
      hosts: [
        host('203.0.113.10', '203.0.113.10', [protocol('tcp', '80,443,8080', [[80, 'http', 'Varnish'], [443, 'https', 'Varnish']])], ['shop.example.org']),
        host('203.0.113.11', '203.0.113.11', [protocol('tcp', '80,443,8080', [[443, 'https', 'nginx', '1.27.1']])], ['api.shop.example.org']),
        host('203.0.113.12', '203.0.113.12', [protocol('tcp', '80,443,8080', [[443, 'https', 'nginx', '1.27.1']])], ['cdn-origin.example.org']),
      ],
      incidents: [{ address: '203.0.113.12', protocol: 'tcp', port: 8080, service: 'http-proxy', hoursAgo: 2 }],
    }),
    buildJob(state, {
      id: 'job-payments', unit_id: RETAIL, name: 'Payment gateway', targets: ['198.51.100.20', '203.0.113.40'], tcp: '22,443,8443', schedule: '45 */2 * * *', createdDaysAgo: 22, profile_id: 'profile-retail-pci', destinations: ['dest-store-ops'],
      hosts: [
        host('198.51.100.20', '198.51.100.20', [protocol('tcp', '22,443,8443', [[8443, 'https-alt', 'Jetty', '12.0']])], ['pay-gw.example.org']),
        host('203.0.113.40', '203.0.113.40', [protocol('tcp', '22,443,8443', [[443, 'https', 'HAProxy']])], ['checkout.example.org']),
      ],
      incidents: [{ address: '198.51.100.20', protocol: 'tcp', port: 22, service: 'ssh', hoursAgo: 9 }],
    }),
    buildJob(state, {
      id: 'job-kiosk', unit_id: RETAIL, name: 'Old kiosk network', targets: ['203.0.113.64/29'], tcp: '23,80', schedule: '0 1 * * *', createdDaysAgo: 29, archived: true,
      hosts: [host('203.0.113.66', '203.0.113.64/29', [protocol('tcp', '23,80', [[23, 'telnet']])])],
    }),
    buildJob(state, {
      id: 'job-plant', unit_id: MANUFACTURING, name: 'Plant OT gateway', targets: ['198.51.100.60'], tcp: '102,443,502', schedule: '0 */4 * * *', createdDaysAgo: 27, profile_id: 'profile-plant-ot', destinations: ['dest-plant-teams'], enabled: false,
      hosts: [host('198.51.100.60', '198.51.100.60', [protocol('tcp', '102,443,502', [[443, 'https'], [502, 'modbus']])], ['ot-gw.example.net'])],
      incidents: [{ address: '198.51.100.60', protocol: 'tcp', port: 102, service: 'iso-tsap', hoursAgo: 70 }],
    }),
    buildJob(state, {
      id: 'job-lines', unit_id: MANUFACTURING, name: 'Line controllers', targets: ['192.0.2.130', '192.0.2.131'], tcp: '22,80,502', schedule: '30 3 * * *', createdDaysAgo: 12, learning: true, enabled: false,
      hosts: [host('192.0.2.130', '192.0.2.130', [protocol('tcp', '22,80,502', [[80, 'http', 'lighttpd']])]), host('192.0.2.131', '192.0.2.131', [protocol('tcp', '22,80,502', [[22, 'ssh', 'Dropbear']])])],
    }),
  ]
  // Long-running and queued scans so capacity shows real per-unit use.
  state.runs = [
    { id: 'run-perimeter', unit_id: DEFAULT_UNIT_ID, job_id: 'job-perimeter', queued_at: state.startedAt - 14 * 60_000, started_at: state.startedAt - 12 * 60_000, duration_ms: 3 * HOUR },
    { id: 'run-branch-vpn', unit_id: DEFAULT_UNIT_ID, job_id: 'job-branch-vpn', queued_at: state.startedAt - 5 * 60_000, started_at: state.startedAt - 4 * 60_000, duration_ms: 2 * HOUR },
    { id: 'run-dns', unit_id: DEFAULT_UNIT_ID, job_id: 'job-dns', queued_at: state.startedAt - 2 * 60_000, duration_ms: 60_000 },
    { id: 'run-storefront', unit_id: RETAIL, job_id: 'job-storefront', queued_at: state.startedAt - 26 * 60_000, started_at: state.startedAt - 25 * 60_000, duration_ms: 3 * HOUR },
  ]
  state.audit = buildAudit(state)
  return state
}

type AuditSeed = Omit<AuditRow, 'id' | 'at'> & { ms: number }

function buildAudit(state: State): AuditRow[] {
  const RETAIL = 'unit-retail'
  const MANUFACTURING = 'unit-manufacturing'
  const morgan: AuditActor = { kind: 'platform', username: 'morgan', display_name: 'Morgan Reyes' }
  const sam: AuditActor = { kind: 'platform', username: 'sam', display_name: 'Sam Okafor' }
  const hostCLI: AuditActor = { kind: 'host', username: 'host-cli' }
  const unitActor = (username: string) => {
    const found = state.accounts.find(item => item.username === username)
    return { kind: 'unit' as const, username, display_name: found?.display_name }
  }
  const seeds: AuditSeed[] = [
    { ms: 31 * DAY + 2 * HOUR, action: 'platform.setup_token_issued', category: 'platform', actor: hostCLI, unit_id: null, detail: 'Platform setup token printed by `edgewatch admin platform-setup-token`.' },
    { ms: 31 * DAY + HOUR, action: 'platform.setup_completed', category: 'platform', actor: morgan, unit_id: null, target: 'morgan', detail: 'First main administrator created from the platform setup token.' },
    { ms: 31 * DAY, action: 'unit.migrated', category: 'platform', actor: hostCLI, unit_id: DEFAULT_UNIT_ID, detail: 'Existing jobs, results, destinations, and accounts moved into the Default unit during the upgrade.' },
    { ms: 30 * DAY + 3 * HOUR, action: 'unit.created', category: 'platform', actor: morgan, unit_id: RETAIL, target: 'Retail', detail: 'Business unit Retail created with slug retail.' },
    { ms: 30 * DAY + 2 * HOUR, action: 'user.created', category: 'account', actor: morgan, unit_id: RETAIL, target: 'riley', detail: 'Administrator invitation created by a main administrator.' },
    { ms: 30 * DAY + HOUR, action: 'user.activated', category: 'account', actor: unitActor('riley'), unit_id: RETAIL, target: 'riley', detail: 'Account activated from the invitation link.' },
    { ms: 29 * DAY + 5 * HOUR, action: 'unit.created', category: 'platform', actor: morgan, unit_id: MANUFACTURING, target: 'Manufacturing', detail: 'Business unit Manufacturing created with slug manufacturing.' },
    { ms: 29 * DAY + 4 * HOUR, action: 'user.created', category: 'account', actor: morgan, unit_id: MANUFACTURING, target: 'quinn', detail: 'Administrator invitation created by a main administrator.' },
    { ms: 28 * DAY, action: 'user.created', category: 'account', actor: unitActor('riley'), unit_id: RETAIL, target: 'jordan', detail: 'Administrator invitation created.' },
    { ms: 27 * DAY, action: 'user.created', category: 'account', actor: unitActor('riley'), unit_id: RETAIL, target: 'casey', detail: 'Operator invitation created.' },
    { ms: 26 * DAY, action: 'job.created', category: 'data', actor: unitActor('riley'), unit_id: RETAIL, target: 'Storefront edge', detail: 'Job Storefront edge created (3 targets, TCP 80,443,8080).' },
    { ms: 25 * DAY + 6 * HOUR, action: 'platform.admin_invited', category: 'platform', actor: morgan, unit_id: null, target: 'sam', detail: 'Main administrator invitation created.' },
    { ms: 25 * DAY + 5 * HOUR, action: 'user.activated', category: 'account', actor: sam, unit_id: null, target: 'sam', detail: 'Main administrator account activated.' },
    { ms: 25 * DAY, action: 'notifications.created', category: 'data', actor: unitActor('riley'), unit_id: RETAIL, target: 'Retail on-call', detail: 'Notification destination Retail on-call added (pushover).' },
    { ms: 24 * DAY, action: 'unit.notifications_assigned', category: 'platform', actor: morgan, unit_id: RETAIL, target: 'Retail', detail: 'Deployment destination Ops Slack assigned.' },
    { ms: 22 * DAY, action: 'scanner_profile.created', category: 'data', actor: unitActor('riley'), unit_id: RETAIL, target: 'Retail PCI sweep', detail: 'Custom scanner profile created.' },
    { ms: 22 * DAY - HOUR, action: 'job.created', category: 'data', actor: unitActor('casey'), unit_id: RETAIL, target: 'Payment gateway', detail: 'Job Payment gateway created (2 targets, TCP 22,443,8443).' },
    { ms: 18 * DAY, action: 'user.totp_disabled', category: 'account', actor: hostCLI, unit_id: DEFAULT_UNIT_ID, target: 'dana', detail: 'TOTP disabled from the host with `edgewatch admin disable-totp`.' },
    { ms: 12 * DAY, action: 'unit.capacity_updated', category: 'platform', actor: sam, unit_id: RETAIL, target: 'Retail', detail: 'Nmap probe budget 1,000,000 → 2,000,000.' },
    { ms: 9 * DAY, action: 'job.archived', category: 'data', actor: unitActor('riley'), unit_id: RETAIL, target: 'Old kiosk network', detail: 'Job archived.' },
    { ms: 6 * DAY, action: 'user.password_reset_issued', category: 'account', actor: morgan, unit_id: RETAIL, target: 'riley', detail: 'Password reset link issued by a main administrator. riley has no TOTP: the link allows signing in as this account.' },
    { ms: 6 * DAY - 40 * 60_000, action: 'user.password_reset_redeemed', category: 'account', actor: unitActor('riley'), unit_id: RETAIL, target: 'riley', detail: 'Password reset link used; a new password was set.' },
    { ms: 5 * DAY, action: 'public_dashboard.updated', category: 'data', actor: unitActor('riley'), unit_id: RETAIL, target: 'Public status', detail: 'Public page enabled with 2 hosts.' },
    { ms: 4 * DAY, action: 'user.password_reset', category: 'account', actor: hostCLI, unit_id: MANUFACTURING, target: 'avery', detail: 'Password reset from the host with `edgewatch admin reset-password`.' },
    { ms: 3 * DAY, action: 'incident.accepted', category: 'data', actor: unitActor('casey'), unit_id: RETAIL, target: 'Storefront edge', detail: 'Change on 203.0.113.11 tcp/443 accepted into the baseline.' },
    { ms: 2 * DAY + HOUR, action: 'user.sessions_revoked', category: 'account', actor: morgan, unit_id: MANUFACTURING, target: 'quinn', detail: 'Sessions ended because the unit was disabled.' },
    { ms: 2 * DAY, action: 'unit.disabled', category: 'platform', actor: morgan, unit_id: MANUFACTURING, target: 'Manufacturing', detail: 'Unit disabled: 2 sessions ended, 0 invitations revoked, 0 scans cancelled, schedules stopped.' },
    { ms: DAY, action: 'user.created', category: 'account', actor: unitActor('riley'), unit_id: RETAIL, target: 'pat', detail: 'Viewer invitation created.' },
  ]
  // Sign-ins and routine changes over six weeks, so both audit views need
  // "Load older" to reach the platform setup rows.
  const signIns: [string, string][] = [['riley', RETAIL], ['casey', RETAIL], ['alex', DEFAULT_UNIT_ID], ['taylor', RETAIL], ['dana', DEFAULT_UNIT_ID], ['jordan', RETAIL], ['morgan', ''], ['quinn', MANUFACTURING]]
  for (let day = 0; day < 42; day += 1) {
    for (let slot = 0; slot < 3; slot += 1) {
      const [username, unit] = signIns[(day * 3 + slot) % signIns.length]
      if (unit === MANUFACTURING && day < 2) continue
      if (unit === RETAIL && day > 29) continue
      const actor = username === 'morgan' ? morgan : unitActor(username)
      seeds.push({ ms: day * DAY + (slot * 5 + 2) * HOUR + 17 * 60_000, action: 'auth.session_created', category: 'account', actor, unit_id: unit || null, target: username, detail: 'Signed in with password.' })
    }
    if (day % 4 === 1 && day < 26) seeds.push({ ms: day * DAY + 9 * HOUR, action: 'baseline.approve', category: 'data', actor: unitActor('casey'), unit_id: RETAIL, target: 'Storefront edge', detail: 'Scan approved as the new baseline.' })
    if (day % 5 === 2) seeds.push({ ms: day * DAY + 11 * HOUR, action: 'job.updated', category: 'data', actor: unitActor('dana'), unit_id: DEFAULT_UNIT_ID, target: 'Perimeter TCP', detail: 'Job schedule or targets changed.' })
  }
  seeds.sort((a, b) => b.ms - a.ms)
  return seeds.map((seed, index) => {
    const { ms, ...row } = seed
    return { ...row, id: index + 1, at: iso(state, ms) }
  })
}
