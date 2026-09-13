import type { Page } from '@playwright/test'

export type ConsoleRole = 'administrator' | 'operator' | 'viewer'

export const rolePermissions: Record<ConsoleRole, string[]> = {
  administrator: [
    'overview.read', 'jobs.read', 'jobs.write', 'jobs.run', 'jobs.delete',
    'hosts.read', 'scans.read', 'baselines.read', 'baselines.manage',
    'incidents.read', 'incidents.manage', 'notification_options.read',
    'notifications.manage', 'users.manage', 'public_dashboard.manage',
    'stream.read', 'scanner_profiles.read', 'scanner_profiles.manage',
    'account.self',
  ],
  operator: [
    'overview.read', 'jobs.read', 'jobs.write', 'jobs.run',
    'hosts.read', 'scans.read', 'baselines.read', 'baselines.manage',
    'incidents.read', 'incidents.manage', 'notification_options.read',
    'stream.read', 'scanner_profiles.read', 'account.self',
  ],
  viewer: ['jobs.read', 'baselines.read', 'account.self'],
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

/**
 * Install a deterministic API surface for browser acceptance tests. The
 * fixture intentionally models the same role/permission contract as the Go
 * authorization table and exposes mutation failures on demand so every
 * high-risk console flow has a browser-level error path.
 */
export async function mockConsole(page: Page, role: ConsoleRole = 'administrator'): Promise<ConsoleMockControls> {
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
    if (path === '/setup/status') { await json({ configured: true, setup_available: false, version: 'v0.18.65', password_requirements: { minimum_length: 12 } }); return }
    if (path === '/auth/session') {
      await json({ user_id: `user-${role}`, username: role === 'administrator' ? 'admin' : role, display_name: role, role, permissions: rolePermissions[role], csrf_token: 'fixture-csrf', totp_enabled: false, password_requirements: { minimum_length: 12 } })
      return
    }
    if (path === '/status') {
      await json({ configured: true, username: role, display_name: role, role, version: 'v0.18.65', notification_destinations: 1, notifications: { deployment: 0, managed: 1, active: 1, locked: 0, key_state: 'ready' }, retention: '90d', max_concurrent_scans: 1, updates: { enabled: true, status: 'up_to_date', current_version: 'v0.18.65' } })
      return
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
    if (path === '/notifications/destinations' && method === 'GET') { await json({ destinations: [destination], status: { deployment: 0, managed: 1, active: 1, locked: 0, key_state: 'ready' }, update_routing: updateRouting }); return }
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
    if (path === '/notifications/update-routing' && method === 'PUT') {
      const value = body() as { destinations?: string[] }
      record('update-routing', value)
      if (failures.delete('update-routing')) { await json(jsonError('update-routing'), 422); return }
      updateRouting = { configured: true, destinations: value.destinations ?? [] }
      await json(updateRouting); return
    }
    if (path === '/notifications/destinations' && method === 'POST') { await mutate('notification-create', destination, 201); return }
    if (path === '/notifications/destinations/dest-1' && method === 'PUT') { await mutate('notification-update', destination); return }
    if (path === '/notifications/destinations/dest-1' && method === 'DELETE') { await mutate('notification-delete', undefined, 204); return }
    if (path === '/notifications/destinations/dest-1/test' && method === 'POST') { await mutate('notification-test', { sent: 1 }); return }
    if (path === '/scanner-profiles/validate' && method === 'POST') { await mutate('profile-validate', { valid: true, preview: [{ executable: '/usr/bin/nmap', args: ['-n', '-Pn', '-p', '22'] }] }); return }
    if (path === '/scanner-profiles' && method === 'POST') { await mutate('profile-create', profile, 201); return }
    if (path === '/scanner-profiles/profile-1' && method === 'PUT') { await mutate('profile-update', profile); return }
    if (path === '/users' && method === 'POST') {
      await mutate('user-create', { user: { id: 'user-created', username: 'new-user', display_name: 'New User', role: 'viewer', enabled: false, pending: true, totp_enabled: false, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z', revision: 1 }, activation_token: 'FIXTURE-TOKEN', activation_path: '/activate?token=FIXTURE-TOKEN' }, 201); return
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

