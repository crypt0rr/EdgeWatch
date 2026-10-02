import type { Page } from '@playwright/test'

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
    'audit.read', 'account.self',
  ],
  operator: [
    'overview.read', 'jobs.read', 'jobs.write', 'jobs.run',
    'hosts.read', 'scans.read', 'baselines.read', 'baselines.manage',
    'incidents.read', 'incidents.manage', 'notification_options.read',
    'stream.read', 'scanner_profiles.read', 'account.self',
  ],
  viewer: ['jobs.read', 'baselines.read', 'account.self'],
  platform_admin: [
    'account.self', 'platform_audit.read', 'platform_notifications.manage',
    'platform_status.read', 'unit_accounts.manage', 'units.manage',
  ],
}

export type ConsoleMockControls = {
  failNext: (operation: string) => void
  calls: Record<string, number>
  payloads: Record<string, unknown[]>
}

const job = {
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

const scan = {
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

const host = {
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
 * refused, as the server's permission gate does.
 */
export async function mockConsole(page: Page, role: ConsoleRole = 'administrator', { platformTOTP = true }: { platformTOTP?: boolean } = {}): Promise<ConsoleMockControls> {
  let incidents: any[] = [{
    job_id: 'job-1',
    job: 'fixture-job',
    incident: {
      change: { key: 'port|192.0.2.10|tcp|443', kind: 'port', target: '192.0.2.10', protocol: 'tcp', port: 443, severity: 'critical' },
      opened_at: '2026-01-01T00:00:00Z',
      last_seen_at: '2026-01-01T00:00:00Z',
    },
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
  // The platform console's state, used when the role is platform_admin.
  const units: any[] = [
    platformUnit({ id: 'unit-default', name: 'Default', slug: 'default', is_default: true, accounts: 3, administrators: 1, jobs: 1, stored_scans: 12 }),
    platformUnit({ id: 'unit-retail', name: 'Retail', slug: 'retail', accounts: 3, administrators: 1, jobs: 2, stored_scans: 1480, slots: { in_use: 1, queued: 0 } }),
  ].slice(0, platformTOTP ? 2 : 1)
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
  let platformRouting = { configured: false, destinations: [] as string[] }
  const failures = new Set<string>()
  const calls: Record<string, number> = {}
  const payloads: Record<string, unknown[]> = {}
  const controls: ConsoleMockControls = {
    failNext: (operation) => failures.add(operation),
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
    const json = (body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })
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
      await json({ user_id: `user-${role}`, username: role === 'administrator' ? 'admin' : role === 'platform_admin' ? 'platform' : role, display_name: role, role, permissions, csrf_token: 'fixture-csrf', totp_enabled: role === 'platform_admin' && platformTOTP, password_requirements: { minimum_length: 12 }, ...scope, ...enrolment })
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
        unitAccounts[created.id] = []
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
        await json({ version: 'v0.18.65', units: { total: units.length, active: units.filter(item => item.status === 'active').length, disabled: units.filter(item => item.status === 'disabled').length, deleting: units.filter(item => item.status === 'deleting').length }, accounts: 6, jobs: 3, stored_scans: 1492, platform_admins: { total: platformAdmins.length, enabled: 1 }, capacity: { limits: deploymentLimits, slots: { capacity: 4, in_use: 1, queued: 0 } }, updates: { enabled: true, status: 'up_to_date', current_version: 'v0.18.65' } }); return
      }
      await json({ error: { code: 'not_found', message: `${method} ${path}` } }, 404); return
    }
    if (path === '/status') {
      await json({ configured: true, username: role, display_name: role, role, version: 'v0.18.65', notification_destinations: 1, notifications: { deployment: 0, managed: 1, active: 1, locked: 0, key_state: 'ready' }, retention: '90d', max_concurrent_scans: 1, updates: { enabled: true, status: 'up_to_date', current_version: 'v0.18.65' } })
      return
    }
    if (path === '/audit' && method === 'GET') {
      await json({ entries: [{ id: 1, created_at: '2026-01-01T00:00:01Z', action: 'user.login', category: 'account', actor: { kind: 'user', user_id: 'user-administrator', username: 'admin' }, detail: 'signed in', source_ip: '127.0.0.1' }], next_before: null }); return
    }
    if (path === '/incidents' && method === 'GET') { await json({ incidents, pagination: pagination(incidents.length) }); return }
    if (path === '/hosts' && method === 'GET') {
      const hosts = [{ ...host, job_id: 'job-1', job: 'fixture-job', scan_id: 'scan-1', scanned_at: scan.finished_at, open_ports: 1, open_filtered_ports: 0, has_open_ports: true, data_quality: 'detailed' }]
      await json({ hosts, pagination: pagination(hosts.length) }); return
    }
    if (path === '/jobs' && method === 'GET') { await json({ jobs: [job] }); return }
    if (path === '/jobs/schedule-suggestion' && method === 'GET') { await json({ suggested: false, gap_minutes: 45 }); return }
    if (path === '/jobs/job-1' && method === 'GET') { await json(job); return }
    if (path === '/jobs/job-1/scans' && method === 'GET') { await json({ scans: [scan], pagination: pagination(1, 20) }); return }
    if (path === '/jobs/job-1/scans/scan-1' && method === 'GET') { await json({ scan, changes: [], changes_pagination: pagination(0), current_security_hash: job.security_hash }); return }
    if (path === '/jobs/job-1/scans/scan-1/results' && method === 'GET') { await json({ results: [], pagination: pagination(0) }); return }
    if (path === '/jobs/job-1/scans/scan-1/changes' && method === 'GET') { await json({ changes: [], pagination: pagination(0) }); return }
    if (path === '/jobs/job-1/baseline' && method === 'GET') { await json({ job_id: 'job-1', job: job.job.name, revision: 1, security_hash: job.security_hash, baseline: job.baseline, snapshot: { units: [], scopes: [] }, pagination: pagination(0) }); return }
    if (path === '/jobs/job-1/baseline/hosts' && method === 'GET') { await json({ job_id: 'job-1', job: job.job.name, source_scan: scan, data_quality: 'detailed', hosts: [host], pagination: pagination(1) }); return }
    if (path.startsWith('/jobs/job-1/baseline/hosts/') && method === 'GET') { await json({ job_id: 'job-1', job: job.job.name, source_scan: scan, data_quality: 'detailed', host, expected: host }); return }
    if (path === '/scans' && method === 'GET') { await json({ scans: [scan], pagination: pagination(1, 20) }); return }
    if (path === '/scans/scan-1' && method === 'GET') { await json({ scan }); return }
    if (path.startsWith('/scans/scan-1/hosts') && method === 'GET') { await json({ job_id: 'job-1', job: job.job.name, scan, data_quality: 'detailed', hosts: [host], pagination: pagination(1) }); return }
    if (path === '/scans/active' && method === 'GET') { await json({ scans: [] }); return }
    if (path === '/notifications/destinations' && method === 'GET') { await json({ destinations: [destination], status: { deployment: 0, managed: 1, active: 1, locked: 0, key_state: 'ready' }, update_routing: updateRouting, incident_reminders_enabled: incidentRemindersEnabled }); return }
    if (path === '/users' && method === 'GET') {
      await json({ users: [{ id: 'user-2', username: 'operator', display_name: 'Operator', role: 'operator', enabled: true, pending: false, totp_enabled: false, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z', revision: 1 }] }); return
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

    if (path === '/jobs' && method === 'POST') { await mutate('job-create', { ...job, id: 'job-created', job: body() }, 201); return }
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
      const value = body() as { enabled?: boolean; password?: string }
      record('incident-reminders', value)
      if (failures.delete('incident-reminders')) { await json(jsonError('incident-reminders'), 422); return }
      incidentRemindersEnabled = value.enabled ?? incidentRemindersEnabled
      await json({ enabled: incidentRemindersEnabled }); return
    }
    if (path === '/notifications/destinations' && method === 'POST') { await mutate('notification-create', destination, 201); return }
    if (path === '/notifications/destinations/dest-1' && method === 'PUT') { await mutate('notification-update', destination); return }
    if (path === '/notifications/destinations/dest-1' && method === 'DELETE') { await mutate('notification-delete', undefined, 204); return }
    if (path === '/notifications/destinations/dest-1/test' && method === 'POST') { await mutate('notification-test', { sent: 1 }); return }
    if (path === '/scanner-profiles/validate' && method === 'POST') { await mutate('profile-validate', { valid: true, preview: [{ executable: '/usr/bin/nmap', args: ['-n', '-Pn', '-p', '22'] }] }); return }
    if (path === '/scanner-profiles' && method === 'POST') { await mutate('profile-create', profile, 201); return }
    if (path === '/scanner-profiles/profile-1' && method === 'PUT') { await mutate('profile-update', profile); return }
    if (path === '/users' && method === 'POST') {
      await mutate('user-create', { user: { id: 'user-created', username: 'new-user', display_name: 'New User', role: 'viewer', enabled: false, pending: true, totp_enabled: false, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z', revision: 1 }, activation_token: 'FIXTURE-TOKEN', activation_path: '/activate#token=FIXTURE-TOKEN' }, 201); return
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
