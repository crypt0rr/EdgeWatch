// Business-units prototype: a dev-only mock of the EdgeWatch API.
//
// `npm run dev:prototype` (vite --mode prototype) installs this plugin; every
// other mode proxies /api to a real backend as before. The plugin serves
// /api/v1/* and /api/public/v1/* from in-memory state that resets whenever the
// dev server starts, and injects the "Viewing as" persona switcher. It lives
// outside src/, so it never reaches the production bundle.

import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Plugin } from 'vite'
import { createState, DEFAULT_PERSONA, DEPLOYMENT_LIMITS, ERASE_CATEGORIES, PERSONAS, PLATFORM_PERMISSIONS, UNIT_PERMISSIONS, VERSION } from './fixtures'
import type { Account, AuditActor, AuditRow, Host, JobRecord, Run, Scan, State, UnitRole, UnitState } from './fixtures'
import { personaSwitcherTags } from './persona-switcher'

type Session = { account: Account; unit: UnitState | null }
type Ctx = { state: State; req: IncomingMessage; res: ServerResponse; url: URL; method: string; path: string; body: any; persona: string; session: Session | null; params: string[] }
type Handler = (ctx: Ctx) => unknown

/** A response with an explicit status or headers; any other handler result is a 200 JSON body. */
class Reply {
  status: number
  body?: unknown
  headers?: Record<string, string>
  constructor(status: number, body?: unknown, headers?: Record<string, string>) {
    this.status = status
    this.body = body
    this.headers = headers
  }
}
const STREAMING = Symbol('streaming')

class HTTPError extends Error {
  status: number
  code: string
  details?: Record<string, unknown>
  constructor(status: number, code: string, message: string, details?: Record<string, unknown>) {
    super(message)
    this.status = status
    this.code = code
    this.details = details
  }
}

const COOKIE = 'proto_persona'
const UNIT_ROLES: UnitRole[] = ['administrator', 'operator', 'viewer']
const SLUG = /^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$/
const MINUTE = 60_000

function reply(status: number, body?: unknown, headers?: Record<string, string>) {
  return new Reply(status, body, headers)
}
const notFound = (what = 'resource') => new HTTPError(404, 'not_found', `${what} not found`)
const forbidden = () => new HTTPError(403, 'forbidden', 'You do not have permission for this action.')

// ---------------------------------------------------------------- sessions

function cookieValue(req: IncomingMessage, name: string) {
  const header = req.headers.cookie ?? ''
  for (const part of header.split(/;\s*/)) {
    const index = part.indexOf('=')
    if (index > 0 && part.slice(0, index) === name) return decodeURIComponent(part.slice(index + 1))
  }
  return undefined
}

function personaCookie(key: string) {
  return `${COOKIE}=${encodeURIComponent(key)}; Path=/; SameSite=Lax; Max-Age=31536000`
}

function resolveSession(state: State, persona: string): Session | null {
  if (persona === 'signed-out' || persona === 'fresh-upgrade') return null
  const account = state.accounts.find(item => item.id === persona)
  if (!account || !account.enabled || account.pending || state.revokedSessions.has(account.id)) return null
  if (!account.unit_id) return { account, unit: null }
  const unit = state.units.find(item => item.id === account.unit_id)
  if (!unit || unit.status !== 'active') return null
  return { account, unit }
}

function permissionsFor(account: Account) {
  return account.role === 'platform_admin' ? PLATFORM_PERMISSIONS : UNIT_PERMISSIONS[account.role as UnitRole]
}

function requireSession(ctx: Ctx) {
  if (!ctx.session) throw new HTTPError(401, 'unauthorized', 'authentication required')
  return ctx.session
}

function requireUnit(ctx: Ctx, permission?: string) {
  const session = requireSession(ctx)
  // Platform sessions never reach unit data: the design answers 403 here.
  if (!session.unit) throw forbidden()
  if (permission && !permissionsFor(session.account).includes(permission)) throw forbidden()
  return { account: session.account, unit: session.unit }
}

function requirePlatform(ctx: Ctx, permission: string) {
  const session = requireSession(ctx)
  if (session.unit || !PLATFORM_PERMISSIONS.includes(permission)) throw forbidden()
  return session.account
}

function requirePassword(value: unknown) {
  if (typeof value !== 'string' || !value.trim()) throw new HTTPError(401, 'invalid_password', 'password confirmation failed')
}

function actorFor(account: Account): AuditActor {
  return { kind: account.unit_id ? 'unit' : 'platform', username: account.username, display_name: account.display_name }
}

function audit(state: State, row: Omit<AuditRow, 'id' | 'at'>) {
  const id = (state.audit[state.audit.length - 1]?.id ?? 0) + 1
  state.audit.push({ ...row, id, at: new Date().toISOString() })
}

function nextID(state: State, prefix: string) {
  state.sequence += 1
  return `${prefix}-${state.sequence}`
}

/** Revoke the activation and reset links whose account matches; returns how many were revoked. */
function revokeTokens(state: State, matches: (accountID: string) => boolean) {
  const revoked = Array.from(state.activationTokens.entries()).filter(([, id]) => matches(id))
  revoked.forEach(([value]) => state.activationTokens.delete(value))
  return revoked.length
}

function token(state: State, accountID: string) {
  state.sequence += 1
  const value = `PROTO-${state.sequence}-${Math.random().toString(36).slice(2, 10).toUpperCase()}`
  state.activationTokens.set(value, accountID)
  return value
}

// ---------------------------------------------------------------- live state

const streams = new Set<{ unit_id: string; res: ServerResponse }>()

function broadcast(unitID: string, event: Record<string, unknown>) {
  streams.forEach(stream => { if (stream.unit_id === unitID) stream.res.write(`data: ${JSON.stringify(event)}\n\n`) })
}

/**
 * Advance time-based state before each request: finish unit deletions and
 * start, finish, or queue scans within each unit's slot cap.
 */
function tick(state: State) {
  const now = Date.now()
  for (const unit of state.units) {
    if (unit.status === 'deleting' && unit.delete_started_at && now - unit.delete_started_at >= 8000) purgeUnit(state, unit)
  }
  for (const run of [...state.runs]) {
    if (run.started_at && now - run.started_at >= run.duration_ms) completeRun(state, run)
  }
  for (const unit of state.units) {
    const runs = state.runs.filter(run => run.unit_id === unit.id).sort((a, b) => a.queued_at - b.queued_at)
    let running = runs.filter(run => run.started_at).length
    for (const run of runs) {
      if (run.started_at || running >= unit.slot_cap || unit.status !== 'active') continue
      run.started_at = now
      running += 1
      broadcast(unit.id, { type: 'scan.started', job_id: run.job_id })
    }
  }
}

// A job created in the prototype has no history; give its literal IPv4
// targets the first port of its scope so a finished scan shows results.
function syntheticHosts(record: JobRecord): Host[] {
  const job = record.job.job
  const scope = job.tcp?.ports ?? job.udp?.ports ?? '443'
  const name = job.tcp ? 'tcp' : 'udp'
  const first = Number(String(scope).split(/[,-]/)[0]) || 443
  return (job.targets as string[]).filter(target => /^\d+\.\d+\.\d+\.\d+$/.test(target)).map(address => ({
    address, address_family: 'IPv4', source_targets: [address], dns_names: [], status: 'up', status_reason: 'syn-ack', latency_ms: 11,
    protocols: [{ protocol: name, scan_type: name === 'tcp' ? 'connect' : 'udp', scanned_ports: String(scope), scanned_port_count: String(scope).split(',').length, service_detection: true, ports: [{ port: first, state: 'open', reason: 'syn-ack', verification: 'confirmed', service: { name: first === 443 ? 'https' : 'unknown' } }], state_summaries: [{ state: 'open', count: 1 }] }],
  }))
}

function completeRun(state: State, run: Run) {
  state.runs = state.runs.filter(item => item !== run)
  const record = state.jobs.find(item => item.job.id === run.job_id)
  if (!record) return
  const last = record.scans[record.scans.length - 1]
  const hosts = last?.hosts.length ? last.hosts : record.baselineHosts.length ? record.baselineHosts : syntheticHosts(record)
  const scan: Scan = {
    id: nextID(state, `scan-${record.job.id}`), job_id: record.job.id, job: record.job.job.name, job_revision: record.job.revision,
    started_at: new Date(run.started_at ?? Date.now()).toISOString(), finished_at: new Date().toISOString(), status: 'success',
    config_hash: record.job.security_hash, scanner_engine: 'nmap', nmap_version: '7.95', scanner_profile_id: record.job.job.tcp?.profile_id, scanner_profile_revision: 1,
    hosts, changes: [],
  }
  record.scans.push(scan)
  if (record.job.baseline.status !== 'complete') {
    const samples = (record.job.baseline.samples ?? 0) + 1
    const complete = samples >= (record.job.job.baseline_samples ?? 2)
    record.job = { ...record.job, baseline: complete ? { status: 'complete', samples, attempts: samples, scan_id: scan.id, host_count: hosts.length, modified: false, incidents: 0 } : { status: 'learning', samples, attempts: samples, host_count: hosts.length } }
    if (complete) record.baselineHosts = hosts
  }
  broadcast(record.unit_id, { type: 'scan.completed', job_id: record.job.id })
}

function purgeUnit(state: State, unit: UnitState) {
  const accountIDs = new Set(state.accounts.filter(item => item.unit_id === unit.id).map(item => item.id))
  unit.status = 'deleted'
  unit.deployment_destinations = []
  unit.public = { ...unit.public, enabled: false, hosts: [] }
  state.accounts = state.accounts.filter(item => item.unit_id !== unit.id)
  state.jobs = state.jobs.filter(item => item.unit_id !== unit.id)
  state.destinations = state.destinations.filter(item => item.unit_id !== unit.id)
  state.profiles = state.profiles.filter(item => item.unit_id !== unit.id)
  state.runs = state.runs.filter(item => item.unit_id !== unit.id)
  state.audit = state.audit.filter(row => row.unit_id !== unit.id || row.actor.kind === 'platform')
  revokeTokens(state, id => accountIDs.has(id))
  audit(state, { action: 'unit.deleted', category: 'platform', actor: { kind: 'host', username: 'edgewatch' }, unit_id: unit.id, target: unit.name, detail: 'Background purge finished. Unit data was erased; the unit row remains as a tombstone.' })
}

// ---------------------------------------------------------------- views

function userSummary(account: Account) {
  const { unit_id: _unit, ...rest } = account
  return rest
}

function unitRef(unit: UnitState) {
  return { id: unit.id, name: unit.name, slug: unit.slug }
}

function capacityOf(state: State, unit: UnitState) {
  const runs = state.runs.filter(run => run.unit_id === unit.id)
  return { slot_cap: unit.slot_cap, slots_in_use: runs.filter(run => run.started_at).length, queued: runs.filter(run => !run.started_at).length, max_probe_count: unit.max_probe_count, max_naabu_probe_count: unit.max_naabu_probe_count }
}

function unitView(state: State, unit: UnitState) {
  const members = state.accounts.filter(item => item.unit_id === unit.id)
  const progress = unit.status === 'deleting' && unit.delete_started_at ? Math.min(99, Math.floor((Date.now() - unit.delete_started_at) / 80)) : unit.status === 'deleted' ? 100 : undefined
  return {
    ...unitRef(unit), status: unit.status, is_default: unit.is_default, revision: unit.revision, created_at: unit.created_at, updated_at: unit.updated_at, disabled_at: unit.disabled_at,
    accounts: members.length, administrators: members.filter(item => item.role === 'administrator' && !item.pending).length, pending_invitations: members.filter(item => item.pending).length,
    public_enabled: unit.public.enabled, capacity: capacityOf(state, unit), delete_progress: progress,
  }
}

function unitDetail(state: State, unit: UnitState) {
  return { ...unitView(state, unit), limits: DEPLOYMENT_LIMITS, erase_categories: ERASE_CATEGORIES }
}

function hostSummary(host: Host) {
  const protocols = host.protocols.map(protocol => ({
    protocol: protocol.protocol, scan_type: protocol.scan_type, scanned_ports: protocol.scanned_ports, scanned_port_count: protocol.scanned_port_count, service_detection: protocol.service_detection,
    open_ports: protocol.ports.filter(port => port.state === 'open').length, open_filtered_ports: protocol.ports.filter(port => port.state === 'open|filtered').length,
  }))
  const open = protocols.reduce((total, item) => total + item.open_ports, 0)
  const openFiltered = protocols.reduce((total, item) => total + item.open_filtered_ports, 0)
  return { address: host.address, address_family: host.address_family, source_targets: host.source_targets, dns_names: host.dns_names, protocols, open_ports: open, open_filtered_ports: openFiltered, has_open_ports: open + openFiltered > 0 }
}

function surface(hosts: Host[]) {
  const units = new Map<string, { target: string; protocol: string; addresses: string[]; ports: { port: number; state: string; service?: string; addresses: string[] }[] }>()
  for (const host of hosts) {
    for (const protocol of host.protocols) {
      const target = host.source_targets[0] ?? host.address
      const key = `${target}|${protocol.protocol}`
      const unit = units.get(key) ?? { target, protocol: protocol.protocol, addresses: [], ports: [] }
      if (!unit.addresses.includes(host.address)) unit.addresses.push(host.address)
      for (const port of protocol.ports) {
        const existing = unit.ports.find(item => item.port === port.port && item.state === port.state)
        if (existing) existing.addresses.push(host.address)
        else unit.ports.push({ port: port.port, state: port.state, service: port.service?.name, addresses: [host.address] })
      }
      units.set(key, unit)
    }
  }
  return Array.from(units.values())
}

function scopes(record: JobRecord) {
  const job = record.job.job
  return job.targets.flatMap((target: string) => [
    ...(job.tcp ? [{ target, protocol: 'tcp', ports: job.tcp.ports, service_detection: true }] : []),
    ...(job.udp ? [{ target, protocol: 'udp', ports: job.udp.ports, service_detection: true }] : []),
  ])
}

function scanSummary(scan: Scan) {
  const { hosts: _hosts, changes: _changes, ...summary } = scan
  return summary
}

function fullScan(record: JobRecord, scan: Scan) {
  return { ...scanSummary(scan), snapshot: { units: surface(scan.hosts), scopes: scopes(record), hosts: scan.hosts } }
}

function paginate<T>(items: T[], url: URL, defaultLimit = 50) {
  const limit = Math.max(1, Math.min(500, Number(url.searchParams.get('limit') ?? defaultLimit) || defaultLimit))
  const offset = Math.max(0, Number(url.searchParams.get('offset') ?? 0) || 0)
  const slice = items.slice(offset, offset + limit)
  const hasMore = offset + limit < items.length
  return { slice, pagination: { limit, offset, total: items.length, has_more: hasMore, next_offset: hasMore ? offset + limit : null } }
}

function filterHosts<T extends { address: string; dns_names?: string[]; source_targets?: string[]; protocols?: { protocol: string }[]; has_open_ports: boolean; job?: string }>(hosts: T[], url: URL) {
  const q = url.searchParams.get('q')?.toLowerCase().trim()
  const protocol = url.searchParams.get('protocol')
  const open = url.searchParams.get('has_open_ports')
  return hosts.filter(host => {
    if (q && ![host.address, host.job ?? '', ...(host.dns_names ?? []), ...(host.source_targets ?? [])].some(value => value.toLowerCase().includes(q))) return false
    if (protocol && !host.protocols?.some(item => item.protocol === protocol)) return false
    if (open === 'true' && !host.has_open_ports) return false
    if (open === 'false' && host.has_open_ports) return false
    return true
  })
}

function rdap(address: string) {
  const prefix = address.split('.').slice(0, 3).join('.') + '.0/24'
  return { rdap: { status: 'success', address, registry: 'IANA', network_name: 'Documentation address block', handle: `DOC-${prefix}`, prefix, country: 'ZZ', allocation_type: 'reserved', organizations: ['Internet Assigned Numbers Authority (documentation range)'], source_url: 'https://rdap.example.net/ip/' + prefix, fetched_at: new Date().toISOString() } }
}

function unitJobs(state: State, unit: UnitState) {
  return state.jobs.filter(record => record.unit_id === unit.id)
}

function findJob(ctx: Ctx, unit: UnitState, id: string) {
  // Another unit's job answers exactly like an unknown ID.
  const record = unitJobs(ctx.state, unit).find(item => item.job.id === id)
  if (!record) throw notFound('job')
  return record
}

function findScan(record: JobRecord, id: string) {
  const scan = record.scans.find(item => item.id === id)
  if (!scan) throw notFound('scan')
  return scan
}

function findUnitScan(ctx: Ctx, unit: UnitState, id: string) {
  for (const record of unitJobs(ctx.state, unit)) {
    const scan = record.scans.find(item => item.id === id)
    if (scan) return { record, scan }
  }
  throw notFound('scan')
}

function latestSuccess(record: JobRecord) {
  return [...record.scans].reverse().find(scan => scan.status === 'success') ?? null
}

function unitDestinations(state: State, unit: UnitState) {
  const own = state.destinations.filter(item => item.unit_id === unit.id).map(({ unit_id: _unit, ...item }) => item)
  const deployment = state.deploymentDestinations.filter(item => unit.deployment_destinations.includes(item.id)).map(item => ({ ...item, source: 'deployment', locked: false, read_only: true }))
  return [...deployment, ...own]
}

function notificationStatus(state: State, unit: UnitState) {
  const destinations = unitDestinations(state, unit)
  return { deployment: unit.deployment_destinations.length, managed: destinations.length - unit.deployment_destinations.length, active: destinations.filter(item => item.enabled).length, locked: 0, key_state: 'ready', delivery_pending: 0, delivery_retrying: 0, delivery_deferrals: 0, delivery_terminal_failures: 0 }
}

function unitProfiles(state: State, unit: UnitState, includeArchived: boolean) {
  return state.profiles.filter(item => (item.unit_id === null || item.unit_id === unit.id) && (includeArchived || !item.profile.archived)).map(item => item.profile)
}

function findProfile(state: State, unit: UnitState, id: string) {
  const found = state.profiles.find(item => item.profile.id === id && (item.unit_id === null || item.unit_id === unit.id))
  if (!found) throw notFound('scanner profile')
  return found
}

function activeScan(state: State, run: Run) {
  const record = state.jobs.find(item => item.job.id === run.job_id)
  const elapsed = Math.max(0, Date.now() - (run.started_at ?? Date.now()))
  const percent = Math.min(99, Math.floor(elapsed / run.duration_ms * 100))
  const total = record?.job.scan_estimate?.probes ?? 1000
  return {
    id: run.id, job_id: run.job_id, job: record?.job.job.name ?? 'job', job_revision: record?.job.revision, started_at: new Date(run.started_at ?? Date.now()).toISOString(),
    estimated_probes: total, total_probes: total, completed_probes: Math.floor(total * percent / 100), progress_percent: percent, phase: 'Port scan', protocol: record?.job.job.tcp ? 'tcp' : 'udp',
    elapsed_seconds: Math.floor(elapsed / 1000), process_alive: true, process_progress_percent: percent, scanner: 'nmap', scanner_profile_revision: 1,
    last_output: `Stats: ${Math.floor(elapsed / 60000)}:${String(Math.floor(elapsed / 1000) % 60).padStart(2, '0')} elapsed; Connect Scan Timing: About ${percent}.00% done`,
  }
}

function sessionBody(state: State, session: Session) {
  const { account, unit } = session
  return { user_id: account.id, username: account.username, display_name: account.display_name, role: account.role, permissions: permissionsFor(account), csrf_token: 'prototype-csrf', totp_enabled: account.totp_enabled, password_requirements: { minimum_length: 12 }, scope: unit ? 'unit' : 'platform', unit: unit ? unitRef(unit) : null, multi_unit: state.units.length > 0 }
}

function lastAdminGuard(state: State, unit: UnitState, account: Account, next: { role?: string; enabled?: boolean }) {
  const role = next.role ?? account.role
  const enabled = next.enabled ?? account.enabled
  if (account.role !== 'administrator' || (role === 'administrator' && enabled)) return
  const others = state.accounts.filter(item => item.unit_id === unit.id && item.id !== account.id && item.role === 'administrator' && item.enabled && !item.pending)
  if (!others.length) throw new HTTPError(409, 'last_administrator', `${unit.name} must keep at least one enabled administrator.`)
}

function checkUsername(state: State, username: unknown) {
  if (typeof username !== 'string' || !username.trim()) throw new HTTPError(422, 'validation_failed', 'Enter a username.')
  if (state.accounts.some(item => item.username.toLowerCase() === username.trim().toLowerCase())) throw new HTTPError(409, 'username_taken', 'That username is already in use.')
}

function createAccount(state: State, username: string, displayName: string, role: Account['role'], unitID: string | null) {
  const now = new Date().toISOString()
  const created: Account = { id: nextID(state, 'acct'), username: username.trim(), display_name: displayName.trim() || username.trim(), role, unit_id: unitID, enabled: false, pending: true, totp_enabled: false, created_at: now, updated_at: now, revision: 1 }
  state.accounts.push(created)
  const value = token(state, created.id)
  return { user: userSummary(created), activation_token: value, activation_path: `/activate#token=${value}` }
}

function roleLabel(role: string) {
  return role === 'platform_admin' ? 'main administrator' : role
}

// ---------------------------------------------------------------- audit pages

function auditPage(rows: AuditRow[], url: URL, state: State) {
  const before = Number(url.searchParams.get('before') ?? '')
  const limit = Math.max(1, Math.min(200, Number(url.searchParams.get('limit') ?? 50) || 50))
  const sorted = rows.filter(row => !Number.isFinite(before) || before <= 0 || row.id < before).sort((a, b) => b.id - a.id)
  const page = sorted.slice(0, limit)
  const units = new Map(state.units.map(unit => [unit.id, unitRef(unit)]))
  return {
    entries: page.map(({ unit_id, ...row }) => ({ ...row, unit: unit_id ? units.get(unit_id) ?? { id: unit_id, name: 'Deleted unit', slug: '' } : null })),
    next_before: sorted.length > limit ? page[page.length - 1].id : null,
  }
}

// ---------------------------------------------------------------- routes

const routes: [string, RegExp, Handler][] = []
function route(method: string, pattern: string, handler: Handler) {
  routes.push([method, new RegExp(`^${pattern}$`), handler])
}

// Setup, sessions, and the signed-in account.
route('GET', '/setup/status', ctx => {
  const home = ctx.state.units.find(unit => unit.is_default)
  // The "Fresh upgrade" persona stands for a deployment that has just been
  // upgraded to business units and has no main administrator yet.
  return { configured: true, setup_available: false, public_dashboard_enabled: !!home?.public.enabled && home.status === 'active', password_requirements: { minimum_length: 12 }, multi_unit: true, platform_setup_available: ctx.persona === 'fresh-upgrade' }
})
route('POST', '/setup', () => { throw new HTTPError(409, 'already_configured', 'EdgeWatch is already configured.') })
route('POST', '/setup/platform', ctx => {
  if (ctx.persona !== 'fresh-upgrade') throw new HTTPError(409, 'setup_unavailable', 'A main administrator already exists.')
  if (typeof ctx.body.token !== 'string' || !ctx.body.token.trim()) throw new HTTPError(401, 'invalid_token', 'The setup token is invalid or has expired.')
  checkUsername(ctx.state, ctx.body.username)
  if (typeof ctx.body.password !== 'string' || ctx.body.password.length < 12) throw new HTTPError(422, 'validation_failed', 'Use at least 12 characters for the password.')
  const now = new Date().toISOString()
  const created: Account = { id: nextID(ctx.state, 'acct'), username: ctx.body.username.trim(), display_name: ctx.body.username.trim(), role: 'platform_admin', unit_id: null, enabled: true, pending: false, totp_enabled: false, created_at: now, updated_at: now, revision: 1 }
  ctx.state.accounts.push(created)
  audit(ctx.state, { action: 'platform.setup_completed', category: 'platform', actor: actorFor(created), unit_id: null, target: created.username, detail: 'First main administrator created from the platform setup token.' })
  return reply(204, undefined, { 'Set-Cookie': personaCookie('signed-out') })
})
route('GET', '/auth/session', ctx => sessionBody(ctx.state, requireSession(ctx)))
route('POST', '/auth/login', ctx => {
  const username = typeof ctx.body.username === 'string' ? ctx.body.username.trim().toLowerCase() : ''
  const account = ctx.state.accounts.find(item => item.username.toLowerCase() === username)
  if (!account || typeof ctx.body.password !== 'string' || !ctx.body.password || account.pending || !account.enabled) throw new HTTPError(401, 'login_failed', 'invalid credentials')
  const unit = account.unit_id ? ctx.state.units.find(item => item.id === account.unit_id) : null
  if (account.unit_id && (!unit || unit.status === 'deleted' || unit.status === 'deleting')) throw new HTTPError(401, 'login_failed', 'invalid credentials')
  if (unit && unit.status === 'disabled') {
    audit(ctx.state, { action: 'auth.login_refused', category: 'account', actor: actorFor(account), unit_id: unit.id, target: account.username, detail: 'Sign-in refused because the business unit is disabled.' })
    throw new HTTPError(403, 'unit_disabled', `Sign-in refused: the business unit “${unit.name}” is disabled. Contact an EdgeWatch main administrator.`)
  }
  ctx.state.revokedSessions.delete(account.id)
  account.last_login_at = new Date().toISOString()
  audit(ctx.state, { action: 'auth.session_created', category: 'account', actor: actorFor(account), unit_id: account.unit_id, target: account.username, detail: 'Signed in with password.' })
  return reply(200, { username: account.username, display_name: account.display_name, role: account.role, permissions: permissionsFor(account), csrf_token: 'prototype-csrf', totp_required: account.totp_enabled }, { 'Set-Cookie': personaCookie(account.id) })
})
route('POST', '/auth/logout', () => reply(204, undefined, { 'Set-Cookie': personaCookie('signed-out') }))
route('POST', '/auth/activity', ctx => { requireSession(ctx) })
route('POST', '/auth/activate', ctx => {
  const accountID = ctx.state.activationTokens.get(String(ctx.body.token ?? '').trim())
  const account = ctx.state.accounts.find(item => item.id === accountID)
  if (!account) throw new HTTPError(400, 'invalid_token', 'This activation link is invalid or has expired.')
  if (typeof ctx.body.password !== 'string' || ctx.body.password.length < 12) throw new HTTPError(422, 'validation_failed', 'Use at least 12 characters.')
  const wasPending = account.pending
  account.pending = false
  account.enabled = true
  account.revision += 1
  ctx.state.activationTokens.delete(String(ctx.body.token).trim())
  audit(ctx.state, { action: wasPending ? 'user.activated' : 'user.password_reset_redeemed', category: 'account', actor: actorFor(account), unit_id: account.unit_id, target: account.username, detail: wasPending ? 'Account activated from the invitation link.' : 'Password reset link used; a new password was set.' })
})
route('PUT', '/auth/display-name', ctx => {
  const { account } = requireSession(ctx)
  account.display_name = String(ctx.body.display_name ?? '').trim() || account.username
  return { display_name: account.display_name }
})
route('PUT', '/auth/password', ctx => { requireSession(ctx); return reply(204, undefined, { 'Set-Cookie': personaCookie('signed-out') }) })
route('DELETE', '/auth/sessions', ctx => { requireSession(ctx); return reply(204, undefined, { 'Set-Cookie': personaCookie('signed-out') }) })
route('POST', '/auth/totp/setup', ctx => { requireSession(ctx); return { secret: 'JBSWY3DPEHPK3PXP', otpauth: 'otpauth://totp/EdgeWatch:prototype?secret=JBSWY3DPEHPK3PXP&issuer=EdgeWatch' } })
route('POST', '/auth/totp/enable', ctx => { requireSession(ctx).account.totp_enabled = true; return { recovery_codes: ['PROTO-1111', 'PROTO-2222', 'PROTO-3333', 'PROTO-4444', 'PROTO-5555', 'PROTO-6666', 'PROTO-7777', 'PROTO-8888', 'PROTO-9999', 'PROTO-0000'] } })
route('DELETE', '/auth/totp', ctx => { requireSession(ctx).account.totp_enabled = false })
route('POST', '/auth/totp/recovery-codes', ctx => { requireSession(ctx); return { recovery_codes: ['PROTO-AAAA', 'PROTO-BBBB', 'PROTO-CCCC', 'PROTO-DDDD', 'PROTO-EEEE', 'PROTO-FFFF', 'PROTO-GGGG', 'PROTO-HHHH', 'PROTO-IIII', 'PROTO-JJJJ'] } })

// Unit console: status and live updates.
route('GET', '/status', ctx => {
  const { account, unit } = requireUnit(ctx, 'jobs.read')
  const jobs = unitJobs(ctx.state, unit)
  const hosts = new Set(jobs.flatMap(record => latestSuccess(record)?.hosts.map(host => host.address) ?? []))
  return {
    configured: true, username: account.username, display_name: account.display_name, role: account.role, permissions: permissionsFor(account),
    version: VERSION, version_release_url: `https://github.com/crypt0rr/EdgeWatch/releases/tag/${VERSION}`,
    notification_destinations: unitDestinations(ctx.state, unit).length, notifications: notificationStatus(ctx.state, unit), retention: '2160h0m0s',
    max_concurrent_scans: unit.slot_cap, max_probe_count: unit.max_probe_count, max_naabu_probe_count: unit.max_naabu_probe_count, rdap_enabled: true,
    public_dashboard_enabled: unit.public.enabled, live_updates: { history_size: 256, dropped_events: 0 }, updates: { enabled: true, status: 'up_to_date', current_version: VERSION },
    telemetry: { collected_at: new Date().toISOString(), database_bytes: 4_800_000 + jobs.length * 1_900_000, jobs: jobs.length, scans: jobs.reduce((total, record) => total + record.scans.length, 0), host_observations: jobs.reduce((total, record) => total + record.scans.reduce((sum, scan) => sum + scan.hosts.length, 0), 0), effective_hosts: hosts.size, events: 240 + jobs.length * 37, scan_cycles: 0, outbox_pending: 0, outbox_retrying: 0, outbox_failed: 0 },
  }
})
route('GET', '/stream', ctx => {
  const { unit } = requireUnit(ctx, 'stream.read')
  ctx.res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' })
  ctx.res.write('retry: 5000\n: connected to the prototype stream\n\n')
  const entry = { unit_id: unit.id, res: ctx.res }
  streams.add(entry)
  const timer = setInterval(() => ctx.res.write(': ping\n\n'), 15_000)
  ctx.req.on('close', () => { clearInterval(timer); streams.delete(entry) })
  return STREAMING
})

// Unit console: jobs, scans, baselines, and incidents.
route('GET', '/jobs', ctx => {
  const { unit } = requireUnit(ctx, 'jobs.read')
  const archived = ctx.url.searchParams.get('include_archived') === 'true'
  return { jobs: unitJobs(ctx.state, unit).filter(record => archived || !record.job.archived).map(record => record.job) }
})
route('GET', '/jobs/schedule-suggestion', ctx => {
  const { unit } = requireUnit(ctx, 'jobs.write')
  const schedule = ctx.url.searchParams.get('schedule') ?? ''
  const clash = unitJobs(ctx.state, unit).find(record => record.job.job.schedule === schedule && !record.job.archived)
  if (!clash) return { suggested: false, gap_minutes: 45 }
  const parts = schedule.split(' ')
  const minute = (Number(parts[0]) || 0) + 20
  return { suggested: true, suggested_schedule: [String(minute % 60), ...parts.slice(1)].join(' '), offset_minutes: 20, nearest: { id: clash.job.id, name: clash.job.job.name, schedule: clash.job.job.schedule, timezone: clash.job.job.timezone, next_run: new Date(Date.now() + 40 * MINUTE).toISOString() }, gap_minutes: 0 }
})
route('POST', '/jobs', ctx => {
  const { account, unit } = requireUnit(ctx, 'jobs.write')
  const form = ctx.body
  if (!form.name?.trim()) throw new HTTPError(422, 'validation_failed', 'Enter a job name.', { name: 'Enter a job name.' })
  if (unitJobs(ctx.state, unit).some(record => record.job.job.name.toLowerCase() === form.name.trim().toLowerCase())) throw new HTTPError(409, 'conflict', 'A job with this name already exists in this unit.', { name: 'A job with this name already exists in this unit.' })
  const id = nextID(ctx.state, 'job')
  const now = new Date().toISOString()
  const job = { id, revision: 1, enabled: form.enabled ?? true, archived: false, security_hash: `sha256:${id}`, created_at: now, updated_at: now, job: { ...form, name: form.name.trim() }, baseline: { status: 'learning', samples: 0, attempts: 0 } }
  ctx.state.jobs.push({ unit_id: unit.id, job, scans: [], baselineHosts: [], incidents: [] })
  audit(ctx.state, { action: 'job.created', category: 'data', actor: actorFor(account), unit_id: unit.id, target: job.job.name, detail: `Job ${job.job.name} created.` })
  broadcast(unit.id, { type: 'job.created', job_id: id })
  return reply(201, job)
})
route('GET', '/jobs/([^/]+)', ctx => findJob(ctx, requireUnit(ctx, 'jobs.read').unit, ctx.params[0]).job)
route('PUT', '/jobs/([^/]+)', ctx => {
  const { account, unit } = requireUnit(ctx, 'jobs.write')
  const record = findJob(ctx, unit, ctx.params[0])
  if (ctx.body.revision !== record.job.revision) throw new HTTPError(409, 'conflict', 'This job changed in another session.')
  const { revision: _revision, confirm_rebaseline: _confirm, ...form } = ctx.body
  record.job = { ...record.job, revision: record.job.revision + 1, updated_at: new Date().toISOString(), job: { ...record.job.job, ...form } }
  audit(ctx.state, { action: 'job.updated', category: 'data', actor: actorFor(account), unit_id: unit.id, target: record.job.job.name, detail: 'Job configuration changed.' })
  return record.job
})
route('DELETE', '/jobs/([^/]+)', ctx => {
  const { account, unit } = requireUnit(ctx, 'jobs.delete')
  const record = findJob(ctx, unit, ctx.params[0])
  if (ctx.body.confirm_name !== record.job.job.name) throw new HTTPError(422, 'confirmation_mismatch', 'The typed name does not match the job name.')
  ctx.state.jobs = ctx.state.jobs.filter(item => item !== record)
  audit(ctx.state, { action: 'job.deleted', category: 'data', actor: actorFor(account), unit_id: unit.id, target: record.job.job.name, detail: 'Job and its history deleted.' })
})
for (const [action, change] of [['archive', { archived: true, enabled: false }], ['restore', { archived: false }], ['pause', { enabled: false }], ['resume', { enabled: true }]] as const) {
  route('POST', `/jobs/([^/]+)/${action}`, ctx => {
    const { account, unit } = requireUnit(ctx, 'jobs.write')
    const record = findJob(ctx, unit, ctx.params[0])
    record.job = { ...record.job, ...change, revision: record.job.revision + 1, updated_at: new Date().toISOString() }
    audit(ctx.state, { action: `job.${action === 'archive' ? 'archived' : action === 'restore' ? 'restored' : action === 'pause' ? 'paused' : 'resumed'}`, category: 'data', actor: actorFor(account), unit_id: unit.id, target: record.job.job.name, detail: `Job ${action}d.` })
    return record.job
  })
}
route('POST', '/jobs/([^/]+)/run', ctx => {
  const { unit } = requireUnit(ctx, 'jobs.run')
  const record = findJob(ctx, unit, ctx.params[0])
  if (record.job.archived) throw new HTTPError(409, 'job_archived', 'Restore the job before scanning it.')
  ctx.state.runs.push({ id: nextID(ctx.state, 'run'), unit_id: unit.id, job_id: record.job.id, queued_at: Date.now(), duration_ms: 40_000 })
  tick(ctx.state)
  return { status: 'queued', job_id: record.job.id }
})
route('GET', '/jobs/([^/]+)/scan-cycle', ctx => { findJob(ctx, requireUnit(ctx, 'jobs.read').unit, ctx.params[0]); return { cycle: null } })
route('DELETE', '/jobs/([^/]+)/scan-cycle/([^/]+)', ctx => { findJob(ctx, requireUnit(ctx, 'jobs.write').unit, ctx.params[0]) })
route('GET', '/jobs/([^/]+)/scans', ctx => {
  const record = findJob(ctx, requireUnit(ctx, 'scans.read').unit, ctx.params[0])
  const { slice, pagination } = paginate([...record.scans].reverse().map(scanSummary), ctx.url, 20)
  return { scans: slice, pagination }
})
route('GET', '/jobs/([^/]+)/scans/latest-successful', ctx => {
  const record = findJob(ctx, requireUnit(ctx, 'scans.read').unit, ctx.params[0])
  const scan = latestSuccess(record)
  return { scan: scan ? scanSummary(scan) : null }
})
route('GET', '/jobs/([^/]+)/scans/([^/]+)', ctx => {
  const record = findJob(ctx, requireUnit(ctx, 'scans.read').unit, ctx.params[0])
  const scan = findScan(record, ctx.params[1])
  const { slice, pagination } = paginate(scan.changes, ctx.url)
  return { scan: fullScan(record, scan), changes: slice, changes_pagination: pagination, current_security_hash: record.job.security_hash, comparison_state: scan.status === 'success' ? 'compared' : 'not_compared', baseline_scan_id: record.job.baseline.scan_id }
})
route('GET', '/jobs/([^/]+)/scans/([^/]+)/results', ctx => {
  const record = findJob(ctx, requireUnit(ctx, 'scans.read').unit, ctx.params[0])
  const { slice, pagination } = paginate(surface(findScan(record, ctx.params[1]).hosts), ctx.url)
  return { results: slice, pagination }
})
route('GET', '/jobs/([^/]+)/scans/([^/]+)/changes', ctx => {
  const record = findJob(ctx, requireUnit(ctx, 'scans.read').unit, ctx.params[0])
  const { slice, pagination } = paginate(findScan(record, ctx.params[1]).changes, ctx.url)
  return { changes: slice, pagination }
})
route('GET', '/jobs/([^/]+)/scans/([^/]+)/hosts', ctx => {
  const record = findJob(ctx, requireUnit(ctx, 'scans.read').unit, ctx.params[0])
  const scan = findScan(record, ctx.params[1])
  const { slice, pagination } = paginate(filterHosts(scan.hosts.map(hostSummary), ctx.url), ctx.url)
  return { job_id: record.job.id, job: record.job.job.name, scan: scanSummary(scan), data_quality: 'detailed', hosts: slice, pagination }
})
route('GET', '/jobs/([^/]+)/scans/([^/]+)/hosts/([^/]+)', ctx => {
  const record = findJob(ctx, requireUnit(ctx, 'scans.read').unit, ctx.params[0])
  const scan = findScan(record, ctx.params[1])
  const host = scan.hosts.find(item => item.address === ctx.params[2])
  if (!host) throw notFound('host')
  return { job_id: record.job.id, job: record.job.job.name, data_quality: 'detailed', host, expected: record.baselineHosts.find(item => item.address === host.address) ?? null, scan: scanSummary(scan) }
})
route('GET', '/jobs/([^/]+)/scans/([^/]+)/hosts/([^/]+)/rdap', ctx => { findJob(ctx, requireUnit(ctx, 'scans.read').unit, ctx.params[0]); return rdap(ctx.params[2]) })
route('GET', '/jobs/([^/]+)/baseline', ctx => {
  const record = findJob(ctx, requireUnit(ctx, 'baselines.read').unit, ctx.params[0])
  const complete = record.job.baseline.status === 'complete'
  const { slice, pagination } = paginate(complete ? surface(record.baselineHosts) : [], ctx.url)
  return { job_id: record.job.id, job: record.job.job.name, revision: record.job.revision, security_hash: record.job.security_hash, baseline: record.job.baseline, snapshot: complete ? { units: slice, scopes: scopes(record) } : null, pagination }
})
route('GET', '/jobs/([^/]+)/baseline/hosts', ctx => {
  const record = findJob(ctx, requireUnit(ctx, 'baselines.read').unit, ctx.params[0])
  const source = record.scans.find(scan => scan.id === record.job.baseline.scan_id)
  const { slice, pagination } = paginate(filterHosts(record.baselineHosts.map(hostSummary), ctx.url), ctx.url)
  return { job_id: record.job.id, job: record.job.job.name, source_scan: source ? scanSummary(source) : null, data_quality: 'detailed', hosts: slice, pagination }
})
route('GET', '/jobs/([^/]+)/baseline/hosts/([^/]+)', ctx => {
  const record = findJob(ctx, requireUnit(ctx, 'baselines.read').unit, ctx.params[0])
  const host = record.baselineHosts.find(item => item.address === ctx.params[1])
  if (!host) throw notFound('host')
  const source = record.scans.find(scan => scan.id === record.job.baseline.scan_id)
  return { job_id: record.job.id, job: record.job.job.name, data_quality: 'detailed', host, expected: host, source_scan: source ? scanSummary(source) : null }
})
route('GET', '/jobs/([^/]+)/baseline/hosts/([^/]+)/rdap', ctx => { findJob(ctx, requireUnit(ctx, 'baselines.read').unit, ctx.params[0]); return rdap(ctx.params[1]) })
route('POST', '/jobs/([^/]+)/baseline/reset', ctx => {
  const { account, unit } = requireUnit(ctx, 'baselines.manage')
  const record = findJob(ctx, unit, ctx.params[0])
  record.job = { ...record.job, baseline: { status: 'learning', samples: 0, attempts: 0 } }
  record.incidents = []
  audit(ctx.state, { action: 'baseline.reset', category: 'data', actor: actorFor(account), unit_id: unit.id, target: record.job.job.name, detail: 'Baseline reset; learning restarts.' })
})
route('POST', '/jobs/([^/]+)/baseline/approve', ctx => {
  const { account, unit } = requireUnit(ctx, 'baselines.manage')
  const record = findJob(ctx, unit, ctx.params[0])
  const scan = findScan(record, String(ctx.body.scan_id ?? ''))
  record.baselineHosts = scan.hosts
  record.incidents = []
  record.job = { ...record.job, baseline: { status: 'complete', samples: 2, attempts: 2, scan_id: scan.id, host_count: scan.hosts.length, modified: false, incidents: 0 } }
  audit(ctx.state, { action: 'baseline.approve', category: 'data', actor: actorFor(account), unit_id: unit.id, target: record.job.job.name, detail: 'Scan approved as the new baseline.' })
})
for (const action of ['accept', 'suppress'] as const) {
  route('POST', `/jobs/([^/]+)/incidents/${action}`, ctx => {
    const { account, unit } = requireUnit(ctx, 'incidents.manage')
    const record = findJob(ctx, unit, ctx.params[0])
    const incident = record.incidents.find(item => item.incident.change.key === ctx.body.key)
    if (!incident) throw new HTTPError(409, 'incident_conflict', 'This incident changed while it was open.')
    if (action === 'accept') {
      record.incidents = record.incidents.filter(item => item !== incident)
      record.job = { ...record.job, baseline: { ...record.job.baseline, incidents: record.incidents.length } }
    }
    audit(ctx.state, { action: `incident.${action === 'accept' ? 'accepted' : 'suppressed'}`, category: 'data', actor: actorFor(account), unit_id: unit.id, target: record.job.job.name, detail: `Change on ${incident.incident.change.target} ${action === 'accept' ? 'accepted into the baseline' : 'suppressed for one scan'}.` })
  })
}
route('GET', '/scans', ctx => {
  const { unit } = requireUnit(ctx, 'scans.read')
  const scans = unitJobs(ctx.state, unit).flatMap(record => record.scans).sort((a, b) => b.finished_at.localeCompare(a.finished_at)).map(scanSummary)
  const { slice, pagination } = paginate(scans, ctx.url, 20)
  return { scans: slice, pagination }
})
route('GET', '/scans/active', ctx => {
  const { unit } = requireUnit(ctx, 'jobs.write')
  return { scans: ctx.state.runs.filter(run => run.unit_id === unit.id && run.started_at).map(run => activeScan(ctx.state, run)) }
})
route('POST', '/scans/([^/]+)/cancel', ctx => {
  const { unit } = requireUnit(ctx, 'jobs.run')
  const run = ctx.state.runs.find(item => item.id === ctx.params[0] && item.unit_id === unit.id)
  if (!run) throw notFound('scan')
  ctx.state.runs = ctx.state.runs.filter(item => item !== run)
  broadcast(unit.id, { type: 'scan-canceled', job_id: run.job_id })
  return { status: 'canceled', scan_id: run.id }
})
route('GET', '/scans/([^/]+)', ctx => {
  const { record, scan } = findUnitScan(ctx, requireUnit(ctx, 'scans.read').unit, ctx.params[0])
  return { scan: fullScan(record, scan) }
})
route('GET', '/scans/([^/]+)/summary', ctx => ({ scan: scanSummary(findUnitScan(ctx, requireUnit(ctx, 'scans.read').unit, ctx.params[0]).scan) }))
route('GET', '/scans/([^/]+)/hosts', ctx => {
  const { record, scan } = findUnitScan(ctx, requireUnit(ctx, 'scans.read').unit, ctx.params[0])
  const { slice, pagination } = paginate(filterHosts(scan.hosts.map(hostSummary), ctx.url), ctx.url)
  return { job_id: record.job.id, job: record.job.job.name, scan: scanSummary(scan), data_quality: 'detailed', hosts: slice, pagination }
})
route('GET', '/scans/([^/]+)/hosts/([^/]+)', ctx => {
  const { record, scan } = findUnitScan(ctx, requireUnit(ctx, 'scans.read').unit, ctx.params[0])
  const host = scan.hosts.find(item => item.address === ctx.params[1])
  if (!host) throw notFound('host')
  return { job_id: record.job.id, job: record.job.job.name, data_quality: 'detailed', host, expected: record.baselineHosts.find(item => item.address === host.address) ?? null, scan: scanSummary(scan) }
})
route('GET', '/scans/([^/]+)/hosts/([^/]+)/rdap', ctx => { findUnitScan(ctx, requireUnit(ctx, 'scans.read').unit, ctx.params[0]); return rdap(ctx.params[1]) })
route('GET', '/hosts', ctx => {
  const { unit } = requireUnit(ctx, 'hosts.read')
  // Each unit has its own inventory: an address scanned by two units appears
  // once in each unit, with that unit's own evidence.
  const latest = new Map<string, any>()
  for (const record of unitJobs(ctx.state, unit)) {
    const scan = latestSuccess(record)
    if (!scan) continue
    for (const host of scan.hosts) {
      const current = latest.get(host.address)
      if (current && current.scanned_at >= scan.finished_at) continue
      latest.set(host.address, { ...hostSummary(host), job_id: record.job.id, job: record.job.job.name, scan_id: scan.id, scanned_at: scan.finished_at, data_quality: 'detailed', archived: record.job.archived })
    }
  }
  const hosts = filterHosts(Array.from(latest.values()).sort((a, b) => a.address.localeCompare(b.address, undefined, { numeric: true })), ctx.url)
  const { slice, pagination } = paginate(hosts, ctx.url)
  return { hosts: slice, pagination }
})
route('GET', '/incidents', ctx => {
  const { unit } = requireUnit(ctx, 'incidents.read')
  const incidents = unitJobs(ctx.state, unit).filter(record => !record.job.archived).flatMap(record => record.incidents).sort((a, b) => b.incident.last_seen_at.localeCompare(a.incident.last_seen_at))
  const { slice, pagination } = paginate(incidents, ctx.url, 20)
  return { incidents: slice, pagination }
})
route('GET', '/events', ctx => {
  requireUnit(ctx, 'jobs.read')
  const { pagination } = paginate([], ctx.url, 20)
  return { events: [], pagination }
})

// Unit console: notification destinations.
route('GET', '/notifications/destinations', ctx => {
  const { unit } = requireUnit(ctx, 'notification_options.read')
  return { destinations: unitDestinations(ctx.state, unit), status: notificationStatus(ctx.state, unit), update_routing: { configured: true, destinations: unit.deployment_destinations.slice(0, 1) } }
})
route('POST', '/notifications/destinations', ctx => {
  const { account, unit } = requireUnit(ctx, 'notifications.manage')
  requirePassword(ctx.body.password)
  const name = String(ctx.body.name ?? '').trim()
  if (!name || !String(ctx.body.url ?? '').trim()) throw new HTTPError(422, 'validation_failed', 'Name and URL are required.')
  if (unitDestinations(ctx.state, unit).some(item => item.name.toLowerCase() === name.toLowerCase())) throw new HTTPError(409, 'conflict', 'A destination with this name already exists in this unit.')
  const provider = String(ctx.body.url).split(':')[0] || 'generic'
  const now = new Date().toISOString()
  const created = { id: nextID(ctx.state, 'dest'), unit_id: unit.id, name, provider, source: 'web' as const, enabled: ctx.body.enabled !== false, locked: false as const, read_only: false as const, revision: 1, created_at: now, updated_at: now }
  ctx.state.destinations.push(created)
  audit(ctx.state, { action: 'notifications.created', category: 'data', actor: actorFor(account), unit_id: unit.id, target: name, detail: `Notification destination ${name} added (${provider}).` })
  const { unit_id: _unit, ...view } = created
  return reply(201, view)
})
function findDestination(ctx: Ctx, unit: UnitState) {
  const found = ctx.state.destinations.find(item => item.id === ctx.params[0] && item.unit_id === unit.id)
  if (!found) throw notFound('destination')
  return found
}
route('GET', '/notifications/destinations/([^/]+)', ctx => {
  const { unit } = requireUnit(ctx, 'notifications.manage')
  const { unit_id: _unit, ...view } = findDestination(ctx, unit)
  return view
})
route('PUT', '/notifications/destinations/([^/]+)', ctx => {
  const { unit } = requireUnit(ctx, 'notifications.manage')
  requirePassword(ctx.body.password)
  const found = findDestination(ctx, unit)
  if (ctx.body.revision !== found.revision) throw new HTTPError(409, 'conflict', 'This destination changed in another session.')
  found.name = String(ctx.body.name ?? found.name).trim() || found.name
  if (typeof ctx.body.enabled === 'boolean') found.enabled = ctx.body.enabled
  found.revision += 1
  found.updated_at = new Date().toISOString()
  const { unit_id: _unit, ...view } = found
  return view
})
route('DELETE', '/notifications/destinations/([^/]+)', ctx => {
  const { unit } = requireUnit(ctx, 'notifications.manage')
  requirePassword(ctx.body.password)
  const found = findDestination(ctx, unit)
  ctx.state.destinations = ctx.state.destinations.filter(item => item !== found)
})
route('POST', '/notifications/destinations/([^/]+)/test', ctx => {
  const { unit } = requireUnit(ctx, 'notifications.manage')
  if (!unit.deployment_destinations.includes(ctx.params[0])) findDestination(ctx, unit)
  return { sent: 1 }
})
route('POST', '/notifications/test', ctx => {
  const { unit } = requireUnit(ctx, 'notifications.manage')
  return { sent: unitDestinations(ctx.state, unit).filter(item => item.enabled).length }
})
route('PUT', '/notifications/update-routing', ctx => {
  requireUnit(ctx, 'notifications.manage')
  requirePassword(ctx.body.password)
  return { configured: true, destinations: Array.isArray(ctx.body.destinations) ? ctx.body.destinations : [] }
})

// Unit console: users (the unit administrator's view of its own accounts).
function findUnitAccount(ctx: Ctx, unit: UnitState, id: string) {
  const found = ctx.state.accounts.find(item => item.id === id && item.unit_id === unit.id)
  if (!found) throw notFound('user')
  return found
}
route('GET', '/users', ctx => {
  const { unit } = requireUnit(ctx, 'users.manage')
  return { users: ctx.state.accounts.filter(item => item.unit_id === unit.id).map(userSummary) }
})
route('POST', '/users', ctx => {
  const { account, unit } = requireUnit(ctx, 'users.manage')
  requirePassword(ctx.body.password)
  checkUsername(ctx.state, ctx.body.username)
  if (!UNIT_ROLES.includes(ctx.body.role)) throw new HTTPError(422, 'validation_failed', 'Choose a unit role.')
  const created = createAccount(ctx.state, ctx.body.username, String(ctx.body.display_name ?? ''), ctx.body.role, unit.id)
  audit(ctx.state, { action: 'user.created', category: 'account', actor: actorFor(account), unit_id: unit.id, target: created.user.username, detail: `${ctx.body.role} invitation created.` })
  return reply(201, created)
})
route('PATCH', '/users/([^/]+)', ctx => {
  const { account, unit } = requireUnit(ctx, 'users.manage')
  requirePassword(ctx.body.password)
  const target = findUnitAccount(ctx, unit, ctx.params[0])
  if (ctx.body.revision !== undefined && ctx.body.revision !== target.revision) throw new HTTPError(409, 'conflict', 'This account changed in another session.')
  lastAdminGuard(ctx.state, unit, target, { role: ctx.body.role, enabled: ctx.body.enabled })
  if (UNIT_ROLES.includes(ctx.body.role)) target.role = ctx.body.role
  if (typeof ctx.body.enabled === 'boolean') { target.enabled = ctx.body.enabled; if (!target.enabled) ctx.state.revokedSessions.add(target.id) }
  if (typeof ctx.body.display_name === 'string' && ctx.body.display_name.trim()) target.display_name = ctx.body.display_name.trim()
  target.revision += 1
  target.updated_at = new Date().toISOString()
  audit(ctx.state, { action: 'user.updated', category: 'account', actor: actorFor(account), unit_id: unit.id, target: target.username, detail: 'Account role or status changed.' })
  return userSummary(target)
})
route('POST', '/users/([^/]+)/activation', ctx => {
  const { account, unit } = requireUnit(ctx, 'users.manage')
  requirePassword(ctx.body.password)
  const target = findUnitAccount(ctx, unit, ctx.params[0])
  const value = token(ctx.state, target.id)
  audit(ctx.state, { action: target.pending ? 'user.activation_issued' : 'user.password_reset_issued', category: 'account', actor: actorFor(account), unit_id: unit.id, target: target.username, detail: target.pending ? 'Invitation link renewed.' : 'Password reset link issued by a unit administrator.' })
  return { activation_token: value, activation_path: `/activate#token=${value}`, expires_at: new Date(Date.now() + 30 * MINUTE).toISOString() }
})
route('DELETE', '/users/([^/]+)/activation', ctx => {
  const { unit } = requireUnit(ctx, 'users.manage')
  const target = findUnitAccount(ctx, unit, ctx.params[0])
  revokeTokens(ctx.state, id => id === target.id)
})
route('DELETE', '/users/([^/]+)/sessions', ctx => {
  const { unit } = requireUnit(ctx, 'users.manage')
  ctx.state.revokedSessions.add(findUnitAccount(ctx, unit, ctx.params[0]).id)
})

// Unit console: public status configuration.
route('GET', '/public-dashboard', ctx => requireUnit(ctx, 'public_dashboard.manage').unit.public)
route('PUT', '/public-dashboard', ctx => {
  const { account, unit } = requireUnit(ctx, 'public_dashboard.manage')
  if (ctx.body.updated_at !== unit.public.updated_at) throw new HTTPError(409, 'conflict', 'The public view changed in another session.')
  const jobs = unitJobs(ctx.state, unit)
  const hosts = Array.isArray(ctx.body.hosts) ? ctx.body.hosts : []
  // Host selections are validated against this unit's jobs only.
  if (hosts.some((item: any) => !jobs.some(record => record.job.id === item.job_id))) throw new HTTPError(422, 'validation_failed', 'A selected host does not belong to this unit.')
  const now = new Date().toISOString()
  unit.public = { enabled: !!ctx.body.enabled, title: String(ctx.body.title ?? ''), introduction: String(ctx.body.introduction ?? ''), updated_at: now, hosts: hosts.map((item: any) => ({ job_id: item.job_id, address: item.address, created_at: now })) }
  audit(ctx.state, { action: 'public_dashboard.updated', category: 'data', actor: actorFor(account), unit_id: unit.id, target: 'Public status', detail: `Public page ${unit.public.enabled ? 'enabled' : 'disabled'} with ${hosts.length} host${hosts.length === 1 ? '' : 's'}.` })
  return unit.public
})

// Unit console: scanner profiles (built-ins are shared by every unit).
route('GET', '/scanner/capabilities', ctx => { requireUnit(ctx); return { engines: ['nmap', 'naabu_nmap'], nmap: { path: '/usr/bin/nmap', version: '7.95', available: true }, naabu: { path: '/usr/local/bin/naabu', version: '2.6.1', available: true, syn_supported: false } } })
route('GET', '/scanner-profiles', ctx => {
  const { unit } = requireUnit(ctx, 'scanner_profiles.read')
  return { profiles: unitProfiles(ctx.state, unit, ctx.url.searchParams.get('include_archived') === 'true') }
})
route('POST', '/scanner-profiles/validate', ctx => {
  requireUnit(ctx, 'scanner_profiles.read')
  return { valid: true, preview: [{ executable: '/usr/bin/nmap', args: ['-n', '-Pn', '-sT', ...(Array.isArray(ctx.body.nmap_args) ? ctx.body.nmap_args : []), '-p', '<ports>', '<targets>'] }] }
})
route('POST', '/scanner-profiles', ctx => {
  const { account, unit } = requireUnit(ctx, 'scanner_profiles.manage')
  const name = String(ctx.body.name ?? '').trim()
  if (!name) throw new HTTPError(422, 'validation_failed', 'Enter a profile name.')
  if (unitProfiles(ctx.state, unit, true).some(item => item.name.toLowerCase() === name.toLowerCase())) throw new HTTPError(409, 'conflict', 'A profile with this name already exists in this unit.')
  const now = new Date().toISOString()
  const { name: _name, description, password: _password, revision: _revision, ...definition } = ctx.body
  const created = { id: nextID(ctx.state, 'profile'), name, description, built_in: false, archived: false, revision: 1, created_by: account.username, created_at: now, updated_at: now, definition }
  ctx.state.profiles.push({ unit_id: unit.id, profile: created })
  audit(ctx.state, { action: 'scanner_profile.created', category: 'data', actor: actorFor(account), unit_id: unit.id, target: name, detail: 'Custom scanner profile created.' })
  return reply(201, created)
})
route('GET', '/scanner-profiles/([^/]+)', ctx => findProfile(ctx.state, requireUnit(ctx, 'scanner_profiles.read').unit, ctx.params[0]).profile)
route('PUT', '/scanner-profiles/([^/]+)', ctx => {
  const { unit } = requireUnit(ctx, 'scanner_profiles.manage')
  const found = findProfile(ctx.state, unit, ctx.params[0])
  if (found.unit_id === null) throw new HTTPError(409, 'read_only', 'Built-in profiles cannot be changed.')
  const { name, description, password: _password, revision: _revision, ...definition } = ctx.body
  found.profile = { ...found.profile, name: name ?? found.profile.name, description, definition: { ...found.profile.definition, ...definition }, revision: found.profile.revision + 1, updated_at: new Date().toISOString() }
  return found.profile
})
route('DELETE', '/scanner-profiles/([^/]+)', ctx => {
  const { unit } = requireUnit(ctx, 'scanner_profiles.manage')
  requirePassword(ctx.body.password)
  const found = findProfile(ctx.state, unit, ctx.params[0])
  if (found.unit_id === null) throw new HTTPError(409, 'read_only', 'Built-in profiles cannot be archived.')
  found.profile = { ...found.profile, archived: true, revision: found.profile.revision + 1 }
})
route('POST', '/scanner-profiles/([^/]+)/restore', ctx => {
  const { unit } = requireUnit(ctx, 'scanner_profiles.manage')
  requirePassword(ctx.body.password)
  const found = findProfile(ctx.state, unit, ctx.params[0])
  found.profile = { ...found.profile, archived: false, revision: found.profile.revision + 1 }
})

// Unit console: the unit administrator's read-only audit.
route('GET', '/audit', ctx => {
  const { unit } = requireUnit(ctx, 'audit.read')
  return auditPage(ctx.state.audit.filter(row => row.unit_id === unit.id), ctx.url, ctx.state)
})

// Platform console.
function findPlatformUnit(ctx: Ctx, id = ctx.params[0]) {
  const unit = ctx.state.units.find(item => item.id === id)
  if (!unit) throw notFound('unit')
  return unit
}
function liveUnits(state: State) {
  return state.units.filter(unit => unit.status !== 'deleted')
}
function checkUnitIdentity(state: State, unit: UnitState | null, name: unknown, slug: unknown) {
  if (typeof name !== 'string' || !name.trim() || name.trim().length > 80) throw new HTTPError(422, 'validation_failed', 'Enter a unit name of at most 80 characters.')
  if (typeof slug !== 'string' || !SLUG.test(slug)) throw new HTTPError(422, 'validation_failed', 'Use 1 to 40 lowercase letters, digits, or hyphens for the slug.')
  const others = liveUnits(state).filter(item => item !== unit)
  if (others.some(item => item.name.toLowerCase() === name.trim().toLowerCase())) throw new HTTPError(409, 'name_taken', 'Another unit already uses this name.')
  if (others.some(item => item.slug === slug)) throw new HTTPError(409, 'slug_taken', 'Another unit already uses this slug.')
}

route('GET', '/platform/units', ctx => {
  requirePlatform(ctx, 'units.manage')
  return { units: ctx.state.units.map(unit => unitView(ctx.state, unit)), limits: DEPLOYMENT_LIMITS }
})
route('POST', '/platform/units', ctx => {
  const account = requirePlatform(ctx, 'units.manage')
  checkUnitIdentity(ctx.state, null, ctx.body.name, ctx.body.slug)
  const now = new Date().toISOString()
  const unit: UnitState = {
    id: nextID(ctx.state, 'unit'), name: ctx.body.name.trim(), slug: ctx.body.slug, status: 'active', is_default: false, revision: 1, created_at: now, updated_at: now,
    slot_cap: 1, max_probe_count: 1_000_000, max_naabu_probe_count: 5_000_000, deployment_destinations: [], notifications_revision: 1,
    public: { enabled: false, title: `${ctx.body.name.trim()} status`, introduction: '', updated_at: now, hosts: [] },
  }
  ctx.state.units.push(unit)
  audit(ctx.state, { action: 'unit.created', category: 'platform', actor: actorFor(account), unit_id: unit.id, target: unit.name, detail: `Business unit ${unit.name} created with slug ${unit.slug}.` })
  return reply(201, unitView(ctx.state, unit))
})
route('GET', '/platform/units/([^/]+)', ctx => { requirePlatform(ctx, 'units.manage'); return unitDetail(ctx.state, findPlatformUnit(ctx)) })
route('PATCH', '/platform/units/([^/]+)', ctx => {
  const account = requirePlatform(ctx, 'units.manage')
  const unit = findPlatformUnit(ctx)
  if (unit.status === 'deleting' || unit.status === 'deleted') throw new HTTPError(409, 'unit_deleted', 'This unit is being deleted.')
  if (ctx.body.revision !== unit.revision) throw new HTTPError(409, 'conflict', 'This unit changed in another session.')
  const name = ctx.body.name ?? unit.name
  const slug = ctx.body.slug ?? unit.slug
  checkUnitIdentity(ctx.state, unit, name, slug)
  const actor = actorFor(account)
  if (name.trim() !== unit.name) audit(ctx.state, { action: 'unit.renamed', category: 'platform', actor, unit_id: unit.id, target: name.trim(), detail: `Renamed from ${unit.name} to ${name.trim()}.` })
  if (slug !== unit.slug) audit(ctx.state, { action: 'unit.slug_changed', category: 'platform', actor, unit_id: unit.id, target: name.trim(), detail: `Public link moved from /public/${unit.slug} to /public/${slug}.` })
  unit.name = name.trim()
  unit.slug = slug
  const capacity = ctx.body.capacity
  if (capacity) {
    const within = (value: unknown, maximum: number) => Number.isInteger(value) && (value as number) >= 1 && (value as number) <= maximum
    if (!within(capacity.slot_cap, DEPLOYMENT_LIMITS.max_concurrent_scans) || !within(capacity.max_probe_count, DEPLOYMENT_LIMITS.max_probe_count) || !within(capacity.max_naabu_probe_count, DEPLOYMENT_LIMITS.max_naabu_probe_count)) {
      throw new HTTPError(422, 'validation_failed', 'Capacity must stay within the deployment limits.')
    }
    audit(ctx.state, { action: 'unit.capacity_updated', category: 'platform', actor, unit_id: unit.id, target: unit.name, detail: `Slot cap ${unit.slot_cap} → ${capacity.slot_cap}; Nmap budget ${unit.max_probe_count.toLocaleString('en')} → ${capacity.max_probe_count.toLocaleString('en')}; Naabu budget ${unit.max_naabu_probe_count.toLocaleString('en')} → ${capacity.max_naabu_probe_count.toLocaleString('en')}.` })
    unit.slot_cap = capacity.slot_cap
    unit.max_probe_count = capacity.max_probe_count
    unit.max_naabu_probe_count = capacity.max_naabu_probe_count
  }
  unit.revision += 1
  unit.updated_at = new Date().toISOString()
  tick(ctx.state)
  return unitDetail(ctx.state, unit)
})
route('POST', '/platform/units/([^/]+)/disable', ctx => {
  const account = requirePlatform(ctx, 'units.manage')
  requirePassword(ctx.body.password)
  const unit = findPlatformUnit(ctx)
  if (unit.status !== 'active') throw new HTTPError(409, 'conflict', 'Only an active unit can be disabled.')
  const members = ctx.state.accounts.filter(item => item.unit_id === unit.id)
  const sessions = members.filter(item => item.enabled && !item.pending).length
  const invitations = revokeTokens(ctx.state, id => members.some(item => item.id === id))
  const cancelled = ctx.state.runs.filter(run => run.unit_id === unit.id).length
  ctx.state.runs = ctx.state.runs.filter(run => run.unit_id !== unit.id)
  members.forEach(item => ctx.state.revokedSessions.add(item.id))
  Array.from(streams).forEach(stream => { if (stream.unit_id === unit.id) { stream.res.end(); streams.delete(stream) } })
  unit.status = 'disabled'
  unit.disabled_at = new Date().toISOString()
  unit.revision += 1
  audit(ctx.state, { action: 'unit.disabled', category: 'platform', actor: actorFor(account), unit_id: unit.id, target: unit.name, detail: `Unit disabled: ${sessions} sessions ended, ${invitations} invitations revoked, ${cancelled} scans cancelled, schedules stopped.` })
  return unitDetail(ctx.state, unit)
})
route('POST', '/platform/units/([^/]+)/enable', ctx => {
  const account = requirePlatform(ctx, 'units.manage')
  requirePassword(ctx.body.password)
  const unit = findPlatformUnit(ctx)
  if (unit.status !== 'disabled') throw new HTTPError(409, 'conflict', 'Only a disabled unit can be enabled.')
  unit.status = 'active'
  unit.disabled_at = undefined
  unit.revision += 1
  audit(ctx.state, { action: 'unit.enabled', category: 'platform', actor: actorFor(account), unit_id: unit.id, target: unit.name, detail: 'Unit enabled; members can sign in and schedules resume.' })
  return unitDetail(ctx.state, unit)
})
route('DELETE', '/platform/units/([^/]+)', ctx => {
  const account = requirePlatform(ctx, 'units.manage')
  requirePassword(ctx.body.password)
  const unit = findPlatformUnit(ctx)
  if (unit.is_default) throw new HTTPError(409, 'default_unit', 'The default unit cannot be deleted.')
  if (unit.status !== 'disabled') throw new HTTPError(409, 'unit_not_disabled', 'Disable the unit before deleting it.')
  if (ctx.body.confirm_name !== unit.name) throw new HTTPError(422, 'confirmation_mismatch', 'The typed name does not match the unit name.')
  unit.status = 'deleting'
  unit.delete_started_at = Date.now()
  audit(ctx.state, { action: 'unit.delete_started', category: 'platform', actor: actorFor(account), unit_id: unit.id, target: unit.name, detail: 'Deletion confirmed with the typed unit name and password; background purge started.' })
  return reply(202, unitDetail(ctx.state, unit))
})
route('GET', '/platform/units/([^/]+)/accounts', ctx => {
  requirePlatform(ctx, 'unit_accounts.manage')
  const unit = findPlatformUnit(ctx)
  return { accounts: ctx.state.accounts.filter(item => item.unit_id === unit.id).map(userSummary) }
})
route('POST', '/platform/units/([^/]+)/accounts', ctx => {
  const account = requirePlatform(ctx, 'unit_accounts.manage')
  requirePassword(ctx.body.password)
  const unit = findPlatformUnit(ctx)
  if (unit.status !== 'active') throw new HTTPError(409, 'unit_disabled', 'Enable the unit before inviting accounts.')
  checkUsername(ctx.state, ctx.body.username)
  if (!UNIT_ROLES.includes(ctx.body.role)) throw new HTTPError(422, 'validation_failed', 'Choose administrator, operator, or viewer.')
  const created = createAccount(ctx.state, ctx.body.username, String(ctx.body.display_name ?? ''), ctx.body.role, unit.id)
  audit(ctx.state, { action: 'user.created', category: 'account', actor: actorFor(account), unit_id: unit.id, target: created.user.username, detail: `${ctx.body.role[0].toUpperCase()}${ctx.body.role.slice(1)} invitation created by a main administrator.` })
  return reply(201, created)
})
route('PATCH', '/platform/units/([^/]+)/accounts/([^/]+)', ctx => {
  const account = requirePlatform(ctx, 'unit_accounts.manage')
  requirePassword(ctx.body.password)
  const unit = findPlatformUnit(ctx)
  const target = findUnitAccount(ctx, unit, ctx.params[1])
  if (ctx.body.revision !== target.revision) throw new HTTPError(409, 'conflict', 'This account changed in another session.')
  if (ctx.body.role !== undefined && !UNIT_ROLES.includes(ctx.body.role)) throw new HTTPError(422, 'validation_failed', 'Choose administrator, operator, or viewer.')
  lastAdminGuard(ctx.state, unit, target, { role: ctx.body.role, enabled: ctx.body.enabled })
  const changes: string[] = []
  if (ctx.body.role !== undefined && ctx.body.role !== target.role) { changes.push(`role ${target.role} → ${ctx.body.role}`); target.role = ctx.body.role }
  if (typeof ctx.body.enabled === 'boolean' && ctx.body.enabled !== target.enabled) {
    changes.push(ctx.body.enabled ? 'enabled' : 'disabled and signed out')
    target.enabled = ctx.body.enabled
    if (!target.enabled) ctx.state.revokedSessions.add(target.id)
  }
  target.revision += 1
  target.updated_at = new Date().toISOString()
  audit(ctx.state, { action: 'user.updated', category: 'account', actor: actorFor(account), unit_id: unit.id, target: target.username, detail: `Changed by a main administrator: ${changes.join(', ') || 'no change'}.` })
  return userSummary(target)
})
route('POST', '/platform/units/([^/]+)/accounts/([^/]+)/password-reset', ctx => {
  const account = requirePlatform(ctx, 'unit_accounts.manage')
  requirePassword(ctx.body.password)
  const unit = findPlatformUnit(ctx)
  const target = findUnitAccount(ctx, unit, ctx.params[1])
  // The reset rule depends on the target account, not on the route.
  if (target.role !== 'administrator') throw new HTTPError(403, 'reset_not_allowed', `Main administrators can reset only unit administrators. Ask ${unit.name}’s administrators to reset operators and viewers.`)
  if (target.pending) throw new HTTPError(409, 'conflict', 'This account has not been activated yet.')
  const value = token(ctx.state, target.id)
  audit(ctx.state, { action: 'user.password_reset_issued', category: 'account', actor: actorFor(account), unit_id: unit.id, target: target.username, detail: target.totp_enabled ? 'Password reset link issued by a main administrator. The account keeps its TOTP.' : `Password reset link issued by a main administrator. ${target.username} has no TOTP: the link allows signing in as this account.` })
  return { activation_token: value, activation_path: `/activate#token=${value}`, expires_at: new Date(Date.now() + 30 * MINUTE).toISOString(), target_totp_enabled: target.totp_enabled }
})
route('DELETE', '/platform/units/([^/]+)/accounts/([^/]+)/sessions', ctx => {
  const account = requirePlatform(ctx, 'unit_accounts.manage')
  requirePassword(ctx.body.password)
  const unit = findPlatformUnit(ctx)
  const target = findUnitAccount(ctx, unit, ctx.params[1])
  ctx.state.revokedSessions.add(target.id)
  audit(ctx.state, { action: 'user.sessions_revoked', category: 'account', actor: actorFor(account), unit_id: unit.id, target: target.username, detail: 'All sessions ended by a main administrator.' })
})
route('GET', '/platform/units/([^/]+)/notifications', ctx => {
  requirePlatform(ctx, 'platform_notifications.manage')
  const unit = findPlatformUnit(ctx)
  return { revision: unit.notifications_revision, destinations: ctx.state.deploymentDestinations.map(item => ({ ...item, assigned: unit.deployment_destinations.includes(item.id) })) }
})
route('PUT', '/platform/units/([^/]+)/notifications', ctx => {
  const account = requirePlatform(ctx, 'platform_notifications.manage')
  const unit = findPlatformUnit(ctx)
  if (ctx.body.revision !== unit.notifications_revision) throw new HTTPError(409, 'conflict', 'The assignment changed in another session.')
  const ids: string[] = Array.isArray(ctx.body.destinations) ? ctx.body.destinations : []
  if (ids.some(id => !ctx.state.deploymentDestinations.some(item => item.id === id))) throw new HTTPError(422, 'validation_failed', 'Unknown deployment destination.')
  unit.deployment_destinations = ids
  unit.notifications_revision += 1
  const names = ctx.state.deploymentDestinations.filter(item => ids.includes(item.id)).map(item => item.name)
  audit(ctx.state, { action: 'unit.notifications_assigned', category: 'platform', actor: actorFor(account), unit_id: unit.id, target: unit.name, detail: names.length ? `Deployment destinations assigned: ${names.join(', ')}.` : 'All deployment destinations unassigned.' })
  return { revision: unit.notifications_revision, destinations: ctx.state.deploymentDestinations.map(item => ({ ...item, assigned: ids.includes(item.id) })) }
})
route('GET', '/platform/notifications', ctx => {
  requirePlatform(ctx, 'platform_notifications.manage')
  return { destinations: ctx.state.deploymentDestinations.map(item => ({ ...item, units: liveUnits(ctx.state).filter(unit => unit.deployment_destinations.includes(item.id)).map(unitRef) })) }
})
route('GET', '/platform/admins', ctx => {
  requirePlatform(ctx, 'units.manage')
  return { admins: ctx.state.accounts.filter(item => item.role === 'platform_admin').map(userSummary) }
})
route('POST', '/platform/admins', ctx => {
  const account = requirePlatform(ctx, 'units.manage')
  requirePassword(ctx.body.password)
  checkUsername(ctx.state, ctx.body.username)
  const created = createAccount(ctx.state, ctx.body.username, String(ctx.body.display_name ?? ''), 'platform_admin', null)
  audit(ctx.state, { action: 'platform.admin_invited', category: 'platform', actor: actorFor(account), unit_id: null, target: created.user.username, detail: `${roleLabel('platform_admin')} invitation created.` })
  return reply(201, created)
})
route('GET', '/platform/capacity', ctx => {
  requirePlatform(ctx, 'platform_status.read')
  const units = liveUnits(ctx.state).map(unit => ({ ...unitRef(unit), status: unit.status, is_default: unit.is_default, capacity: capacityOf(ctx.state, unit) }))
  return {
    version: VERSION, limits: DEPLOYMENT_LIMITS, units,
    totals: { slots_in_use: units.reduce((total, unit) => total + unit.capacity.slots_in_use, 0), queued: units.reduce((total, unit) => total + unit.capacity.queued, 0), slot_caps: units.reduce((total, unit) => total + unit.capacity.slot_cap, 0) },
  }
})
route('GET', '/platform/audit', ctx => {
  requirePlatform(ctx, 'platform_audit.read')
  const unit = ctx.url.searchParams.get('unit')
  const action = ctx.url.searchParams.get('action')
  const since = ctx.url.searchParams.get('since')
  const from = since ? Date.parse(`${since}T00:00:00`) : NaN
  // The platform view holds platform and account rows only, never unit data.
  const rows = ctx.state.audit.filter(row => row.category !== 'data')
    .filter(row => !unit || (unit === 'platform' ? row.unit_id === null : row.unit_id === unit))
    .filter(row => !action || row.action.startsWith(action))
    .filter(row => Number.isNaN(from) || Date.parse(row.at) >= from)
  return auditPage(rows, ctx.url, ctx.state)
})

// ---------------------------------------------------------------- public pages

function publicDashboard(state: State, slug: string | null): Reply {
  const unit = slug === null ? state.units.find(item => item.is_default) : state.units.find(item => item.slug === slug && item.status !== 'deleted')
  if (!unit) return reply(404, { error: { code: 'not_found', message: 'No public status page exists at this address.' } })
  if (unit.status !== 'active' || !unit.public.enabled) return reply(404, { error: { code: 'public_disabled', message: 'This status page is not enabled.' } })
  const jobs = unitJobs(state, unit)
  const hosts = unit.public.hosts.flatMap(selection => {
    const record = jobs.find(item => item.job.id === selection.job_id && !item.job.archived)
    const scan = record && latestSuccess(record)
    const host = scan?.hosts.find(item => item.address === selection.address)
    if (!record || !scan || !host) return []
    const ports = (state: string) => host.protocols.flatMap(protocol => protocol.ports.filter(port => port.state === state).map(port => ({ protocol: protocol.protocol, port: port.port, service: port.service?.name })))
    return [{ job: record.job.job.name, address: host.address, address_family: host.address_family, public: true, private: false, last_successful_scan: scan.finished_at, open_ports: ports('open'), open_filtered_ports: ports('open|filtered'), rdap: { status: 'success', network_name: 'Documentation address block' } }]
  })
  return reply(200, { title: unit.public.title, introduction: unit.public.introduction, updated_at: unit.public.updated_at, hosts })
}

// ---------------------------------------------------------------- plugin

function readBody(req: IncomingMessage): Promise<any> {
  return new Promise(resolve => {
    const chunks: Buffer[] = []
    req.on('data', chunk => chunks.push(Buffer.from(chunk)))
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8')
      if (!raw) return resolve({})
      try { resolve(JSON.parse(raw)) } catch { resolve({}) }
    })
    req.on('error', () => resolve({}))
  })
}

function send(res: ServerResponse, value: Reply) {
  for (const [name, header] of Object.entries(value.headers ?? {})) res.setHeader(name, header)
  res.setHeader('Cache-Control', 'no-store')
  res.statusCode = value.status
  if (value.status === 204 || value.body === undefined) { res.end(); return }
  res.setHeader('Content-Type', 'application/json')
  res.end(JSON.stringify(value.body))
}

async function handle(state: State, req: IncomingMessage, res: ServerResponse) {
  const url = new URL(req.url ?? '/', 'http://prototype.invalid')
  const method = req.method ?? 'GET'
  tick(state)
  if (url.pathname.startsWith('/api/public/v1/dashboard')) {
    const slug = url.pathname === '/api/public/v1/dashboard' || url.pathname === '/api/public/v1/dashboard/' ? null : decodeURIComponent(url.pathname.slice('/api/public/v1/dashboard/'.length).replace(/\/$/, ''))
    send(res, publicDashboard(state, slug))
    return
  }
  if (!url.pathname.startsWith('/api/v1/')) {
    send(res, reply(404, { error: { code: 'not_found', message: 'not found' } }))
    return
  }
  const path = url.pathname.slice('/api/v1'.length)
  const persona = cookieValue(req, COOKIE) ?? DEFAULT_PERSONA
  const body = method === 'GET' || method === 'HEAD' ? {} : await readBody(req)
  const ctx: Ctx = { state, req, res, url, method, path, body, persona, session: resolveSession(state, persona), params: [] }
  for (const [routeMethod, pattern, handler] of routes) {
    if (routeMethod !== method) continue
    const match = pattern.exec(path)
    if (!match) continue
    ctx.params = match.slice(1).map(value => decodeURIComponent(value))
    try {
      const result = await handler(ctx)
      if (result === STREAMING) return
      if (result instanceof Reply) send(res, result)
      else if (result === undefined) send(res, reply(204))
      else send(res, reply(200, result))
    } catch (error) {
      if (error instanceof HTTPError) send(res, reply(error.status, { error: { code: error.code, message: error.message, details: error.details } }))
      else send(res, reply(500, { error: { code: 'internal', message: error instanceof Error ? error.message : 'prototype mock failure' } }))
    }
    return
  }
  send(res, reply(404, { error: { code: 'not_found', message: `${method} ${path} is not part of the prototype mock` } }))
}

/**
 * The Vite plugin used by `vite --mode prototype`. `apply: 'serve'` keeps it
 * out of every build, so even `vite build --mode prototype` emits no mock or
 * persona switcher.
 */
export function prototypeMockAPI(): Plugin {
  let state = createState()
  return {
    name: 'edgewatch-business-units-prototype',
    apply: 'serve',
    configureServer(server) {
      state = createState()
      server.middlewares.use((req, res, next) => {
        const pathname = (req.url ?? '').split('?')[0]
        if (pathname === '/__prototype/reset' && req.method === 'POST') {
          state = createState()
          streams.forEach(stream => stream.res.end())
          streams.clear()
          send(res, reply(204))
          return
        }
        if (!pathname.startsWith('/api/')) { next(); return }
        handle(state, req, res).catch(error => send(res, reply(500, { error: { code: 'internal', message: String(error) } })))
      })
    },
    transformIndexHtml() {
      return personaSwitcherTags(PERSONAS, DEFAULT_PERSONA)
    },
  }
}
