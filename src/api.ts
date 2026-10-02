import type { ActiveScan, BaselineHostsResponse, Change, GlobalHostsResponse, HostDetailResponse, Incident, Job, JobForm, Pagination, RdapResult, Scan, ScanSummary, Unit, NaabuOptions } from './types'
import { setDisplayTimeZone } from './format'

export type NotificationDestination = {
  id: string
  name: string
  provider: string
  source: 'deployment' | 'web' | string
  enabled: boolean
  locked: boolean
  read_only: boolean
  revision?: number
  created_at?: string
  updated_at?: string
  error_code?: string
  pending?: number
  retrying?: number
  deferrals?: number
  terminal_failures?: number
  last_success_at?: string
  last_failure_at?: string
  last_terminal_at?: string
  last_error_code?: string
  last_error_fingerprint?: string
}
export type NotificationStatus = {
  deployment: number
  managed: number
  active: number
  locked: number
  key_state: string
  /** Set while config.yaml still lists imported notification URLs, or when their import failed. */
  config_import?: 'imported' | 'failed' | string
  delivery_pending?: number
  delivery_retrying?: number
  delivery_deferrals?: number
  delivery_terminal_failures?: number
}
export type NotificationUpdateRouting = {
  configured: boolean
  destinations: string[]
}
export type NotificationDestinationsResponse = {
  destinations: NotificationDestination[]
  status: NotificationStatus
  update_routing?: NotificationUpdateRouting
  incident_reminders_enabled?: boolean
}
export type ApplicationUpdateStatus = {
  enabled: boolean
  status: 'up_to_date' | 'update_available' | 'ahead' | 'check_failed' | 'disabled' | 'development_build' | string
  available?: boolean
  current_version: string
  latest_version?: string
  release_url?: string
  release_name?: string
  published_at?: string
  last_checked_at?: string
  last_successful_check_at?: string
  stale?: boolean
  error?: string
}
export type DeploymentTelemetry = {
  collected_at: string
  /** The database size; with business units only the default unit reports it. */
  database_bytes?: number
  jobs: number
  scans: number
  host_observations: number
  effective_hosts: number
  events: number
  scan_cycles: number
  outbox_pending: number
  outbox_retrying: number
  outbox_failed: number
}

let csrf = ''
export function setCSRF(value: string) { csrf = value }
export class APIError extends Error {
  code?: string
  details?: Record<string, unknown>
  /** The HTTP status of the failed request. */
  status?: number
  /** Retry-After response header, normalized to seconds when available. */
  retryAfterSeconds?: number
  constructor(message: string, code?: string, details?: Record<string, unknown>, status?: number, retryAfterSeconds?: number) {
    super(message)
    this.name = 'APIError'
    this.code = code
    this.details = details
    this.status = status
    this.retryAfterSeconds = retryAfterSeconds
  }
}

function parseRetryAfter(value: string | null): number | undefined {
  if (!value) return undefined
  const header = value.trim()
  if (/^\d+$/.test(header)) {
    const seconds = Number(header)
    return Number.isFinite(seconds) ? seconds : undefined
  }
  const retryAt = Date.parse(header)
  if (!Number.isFinite(retryAt)) return undefined
  return Math.max(0, Math.ceil((retryAt - Date.now()) / 1000))
}
let forbiddenHandler: (() => Promise<unknown>) | null = null
/**
 * Sets what the signed-in console does when a request is refused with 403,
 * and returns a function that removes it again. A 403 can mean that the
 * session changed on the server: once a second business unit exists, an
 * administrator without TOTP holds only its own account, and an
 * administrator can change an account's role. The console re-reads its
 * session then, and api() waits for that before it reports the refusal, so
 * a page that the new session no longer offers is replaced, for example by
 * the forced TOTP enrolment, instead of showing the refusal first.
 */
export function setForbiddenHandler(handler: () => Promise<unknown>) {
  forbiddenHandler = handler
  return () => { if (forbiddenHandler === handler) forbiddenHandler = null }
}
export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers)
  if (init.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json')
  if (csrf && init.method && init.method !== 'GET') headers.set('X-CSRF-Token', csrf)
  const response = await fetch(`/api/v1${path}`, { ...init, headers, credentials: 'same-origin' })
  if (response.status === 204) return undefined as T
  const body = await response.json().catch(() => ({}))
  // A 401 normally means that the session has expired, but step-up
  // confirmation endpoints also use 401 for a rejected factor. Only the
  // structured unauthorized code represents an invalid session; rejected
  // passwords, TOTP codes, and other step-up factors must leave the current
  // page and its dialog intact.
  if (response.status === 401 && body?.error?.code === 'unauthorized') {
    // A session can expire while the console remains open. Let the shell
    // clear its cached principal and return to the login route instead of
    // leaving each page to render an authentication error independently.
    csrf = ''
    if (typeof window !== 'undefined') window.dispatchEvent(new Event('edgewatch:unauthorized'))
  }
  // The session read is exempt: it is the read the handler waits for, so a
  // refused session read must not wait for itself.
  if (response.status === 403 && path !== '/auth/session' && forbiddenHandler) await forbiddenHandler().catch(() => undefined)
  if (!response.ok) throw new APIError(body?.error?.message || 'Request failed', body?.error?.code, body?.error?.details, response.status, parseRetryAfter(response.headers.get('Retry-After')))
  return body as T
}
/** `platform_admin` is the platform administrator, who belongs to no business unit. */
export type Role = 'administrator' | 'operator' | 'viewer' | 'platform_admin'
/** The roles of an account inside a business unit. */
export type UnitRole = Exclude<Role, 'platform_admin'>
/** A business unit as sessions, audit entries, and listings name it. */
export type UnitRef = { id: string; name: string; slug: string }
// totp_enrollment_required is present only when the account must set up an
// authenticator before it may use anything but its own account settings.
// scope is "platform" for a platform administrator and "unit" otherwise,
// unit is the account's business unit (null for the platform), and
// multi_unit reports whether more than one unit exists.
export type SessionUser = { user_id: string; username: string; display_name?: string; role: Role; permissions: string[]; csrf_token: string; totp_enabled: boolean; totp_enrollment_required?: boolean; password_requirements: { minimum_length: number }; timezone?: string; scope: 'unit' | 'platform'; unit: UnitRef | null; multi_unit: boolean }
/**
 * The latest request from a proxy that web.trusted_proxies does not list but
 * that sent a client-address forwarding header. Every client behind it shares
 * the proxy's address for the sign-in limits and the audit.
 */
export type UntrustedProxy = { peer: string; header: string; last_seen_at: string }
// untrusted_proxy is present for the administrators of a deployment with one
// unit; with more, only the platform status has it.
export type AdminStatus = { configured?: boolean; username?: string; display_name?: string; role?: Role; permissions?: string[]; version: string; version_release_url?: string; legacy_yaml_jobs?: string[]; notification_destinations?: number; notifications?: NotificationStatus; retention?: string; max_concurrent_scans?: number; max_probe_count?: number; max_naabu_probe_count?: number; rdap_enabled?: boolean; public_dashboard_enabled?: boolean; live_updates?: { history_size: number; dropped_events: number }; updates?: ApplicationUpdateStatus; telemetry?: DeploymentTelemetry; untrusted_proxy?: UntrustedProxy }
// platform_setup_available is present once the first administrator exists,
// and true while the host's platform setup token can create the first
// platform administrator.
export const setupStatus = () => api<{ configured: boolean; setup_available?: boolean; public_dashboard_enabled?: boolean; password_requirements: { minimum_length: number }; platform_setup_available?: boolean }>('/setup/status')
export const adminStatus = () => api<AdminStatus>('/status')
// The session carries the deployment timezone from config.yaml; apply it before
// any signed-in page formats a timestamp.
export const getSession = async () => {
  const session = await api<SessionUser>('/auth/session')
  setDisplayTimeZone(session.timezone)
  return session
}
export const recordActivity = () => api<void>('/auth/activity', { method: 'POST' })
export const login = (password: string, otp?: string, recovery_code?: string, username = 'admin') => api<{ username: string; display_name?: string; role: Role; permissions: string[]; csrf_token: string; totp_required: boolean; totp_enrollment_required?: boolean }>('/auth/login', { method: 'POST', body: JSON.stringify({ username, password, otp, recovery_code }) })
export const setup = (token: string, password: string) => api('/setup', { method: 'POST', body: JSON.stringify({ token, password }) })
export const platformSetup = (token: string, username: string, password: string) => api<{ configured: boolean; username: string }>('/setup/platform', { method: 'POST', body: JSON.stringify({ token, username, password }) })
export const activate = (token: string, password: string) => api('/auth/activate', { method: 'POST', body: JSON.stringify({ token, password }) })
export const logout = () => api('/auth/logout', { method: 'POST' })
export const logoutAllSessions = () => api('/auth/sessions', { method: 'DELETE' })
export const updateDisplayName = (displayName: string) => api<{ display_name: string }>('/auth/display-name', { method: 'PUT', body: JSON.stringify({ display_name: displayName }) })
export const listJobs = (archived = false) => api<{ jobs: Job[] }>(`/jobs?include_archived=${archived}`)
export type ScheduleSuggestion = {
  suggested: boolean
  suggested_schedule?: string
  offset_minutes?: number
  nearest?: { id: string; name: string; schedule: string; timezone: string; next_run: string }
  draft_next_run?: string
  gap_minutes: number
}
export const scheduleSuggestion = (schedule: string, timezone: string) => api<ScheduleSuggestion>(`/jobs/schedule-suggestion?${new URLSearchParams({ schedule, timezone }).toString()}`)
export const getJob = (id: string) => api<Job>(`/jobs/${id}`)
export const createJob = (job: JobForm) => api<Job>('/jobs', { method: 'POST', body: JSON.stringify(job) })
export const updateJob = (id: string, revision: number, job: JobForm, confirm_rebaseline = false) => api<Job>(`/jobs/${id}`, { method: 'PUT', body: JSON.stringify({ ...job, revision, confirm_rebaseline }) })
export const archiveJob = (id: string, revision: number) => api(`/jobs/${id}/archive`, { method: 'POST', body: JSON.stringify({ revision }) })
export const restoreJob = (id: string, revision: number) => api(`/jobs/${id}/restore`, { method: 'POST', body: JSON.stringify({ revision }) })
export const deleteJob = (id: string, confirm_name: string) => api(`/jobs/${id}?permanent=true`, { method: 'DELETE', body: JSON.stringify({ confirm_name }) })
export const pauseJob = (id: string, revision: number) => api(`/jobs/${id}/pause`, { method: 'POST', body: JSON.stringify({ revision }) })
export const resumeJob = (id: string, revision: number) => api(`/jobs/${id}/resume`, { method: 'POST', body: JSON.stringify({ revision }) })
export const runJob = (id: string) => api<{ status: string; job_id: string; mode?: string; cycle_id?: string }>(`/jobs/${id}/run`, { method: 'POST' })
// Stable identifier of the built-in Naabu → Nmap profile. New jobs select it
// explicitly so legacy persisted jobs that omit a profile remain Nmap-only.
export const BUILTIN_NAABU_PROFILE_ID = '00000000-0000-0000-0000-000000000014'
export const scanCycle = (id: string) => api<{ cycle: import('./types').ScanCycle | null }>(`/jobs/${id}/scan-cycle`)
export const discardScanCycle = (jobId: string, cycleId: string) => api<void>(`/jobs/${jobId}/scan-cycle/${encodeURIComponent(cycleId)}`, { method: 'DELETE' })
export const cancelScan = (id: string) => api<{ status: string; scan_id: string }>(`/scans/${id}/cancel`, { method: 'POST' })
export const resetBaseline = (id: string, expectedBaselineScanID = '', expectedBaselineModified = false) => api(`/jobs/${id}/baseline/reset`, { method: 'POST', body: JSON.stringify({ expected_baseline_scan_id: expectedBaselineScanID, expected_baseline_modified: expectedBaselineModified }) })
export const approveBaseline = (jobId: string, scanId: string, expectedBaselineScanID = '', expectedBaselineModified = false) => api(`/jobs/${jobId}/baseline/approve`, { method: 'POST', body: JSON.stringify({ scan_id: scanId, expected_baseline_scan_id: expectedBaselineScanID, expected_baseline_modified: expectedBaselineModified }) })
export const jobScans = (id: string, offset = 0, limit = 20) => api<{ scans: ScanSummary[]; pagination: Pagination }>(`/jobs/${id}/scans?limit=${limit}&offset=${offset}`)
export const latestSuccessfulScan = (id: string) => api<{ scan: ScanSummary | null }>(`/jobs/${id}/scans/latest-successful`)
export const jobBaseline = (id: string, offset = 0, limit = 50) => api<{ job_id: string; job: string; revision: number; security_hash: string; baseline: Job['baseline']; snapshot: { units: Unit[]; scopes: { target: string; protocol: string; ports: string; service_detection: boolean }[]; dns?: Record<string, string[]> } | null; pagination: Pagination }>(`/jobs/${id}/baseline?limit=${limit}&offset=${offset}`)
export type HostFilters = { q?: string; protocol?: string; has_open_ports?: boolean; limit?: number; offset?: number; signal?: AbortSignal }
function hostQuery(filters: HostFilters = {}) {
  const params = new URLSearchParams()
  params.set('limit', String(filters.limit ?? 50))
  params.set('offset', String(filters.offset ?? 0))
  if (filters.q) params.set('q', filters.q)
  if (filters.protocol) params.set('protocol', filters.protocol)
  if (filters.has_open_ports !== undefined) params.set('has_open_ports', String(filters.has_open_ports))
  return params.toString()
}
export const baselineHosts = (id: string, filters: HostFilters = {}) => api<BaselineHostsResponse>(`/jobs/${id}/baseline/hosts?${hostQuery(filters)}`, filters.signal ? { signal: filters.signal } : undefined)
export const baselineHost = (id: string, address: string) => api<HostDetailResponse>(`/jobs/${id}/baseline/hosts/${encodeURIComponent(address)}`)
export const baselineHostRDAP = (id: string, address: string) => api<{ rdap: RdapResult }>(`/jobs/${id}/baseline/hosts/${encodeURIComponent(address)}/rdap`)
export const scanHosts = (jobId: string, scanId: string, filters: HostFilters = {}) => api<{ job_id: string; job: string; scan: ScanSummary; data_quality: string; hosts: import('./types').HostSummary[]; pagination: Pagination }>(`/jobs/${jobId}/scans/${encodeURIComponent(scanId)}/hosts?${hostQuery(filters)}`, filters.signal ? { signal: filters.signal } : undefined)
export const scanHost = (jobId: string, scanId: string, address: string) => api<HostDetailResponse>(`/jobs/${jobId}/scans/${encodeURIComponent(scanId)}/hosts/${encodeURIComponent(address)}`)
export const scanHostRDAP = (jobId: string, scanId: string, address: string) => api<{ rdap: RdapResult }>(`/jobs/${jobId}/scans/${encodeURIComponent(scanId)}/hosts/${encodeURIComponent(address)}/rdap`)
export const historicalScanHost = (scanId: string, address: string) => api<HostDetailResponse>(`/scans/${encodeURIComponent(scanId)}/hosts/${encodeURIComponent(address)}`)
export const historicalScanHostRDAP = (scanId: string, address: string) => api<{ rdap: RdapResult }>(`/scans/${encodeURIComponent(scanId)}/hosts/${encodeURIComponent(address)}/rdap`)
/**
 * Fetch a top-level historical scan.
 *
 * The server wraps this compatibility response in a `scan` envelope while
 * older clients treated it as a bare Scan. Decode the envelope at the API
 * boundary and continue accepting a bare payload so managed/legacy callers
 * remain compatible during rolling upgrades.
 */
export async function getScan(scanId: string): Promise<Scan> {
  const response = await api<Scan | { scan: Scan }>(`/scans/${encodeURIComponent(scanId)}`)
  if (response && typeof response === 'object' && 'scan' in response && response.scan) return response.scan
  return response as Scan
}
export const getScanSummary = (scanId: string) => api<{ scan: ScanSummary }>(`/scans/${encodeURIComponent(scanId)}/summary`)
export const historicalScanHosts = (scanId: string, filters: HostFilters = {}) => api<{ job_id?: string; job: string; scan: ScanSummary; data_quality: string; hosts: import('./types').HostSummary[]; pagination: Pagination }>(`/scans/${encodeURIComponent(scanId)}/hosts?${hostQuery(filters)}`, filters.signal ? { signal: filters.signal } : undefined)
export const scanDetail = (jobId: string, scanId: string, offset = 0, limit = 50) => api<{ scan: Scan; changes: Change[]; changes_pagination: Pagination; current_security_hash: string; comparison_source?: string; comparison_state?: 'compared' | 'not_compared' | string; baseline_scan_id?: string }>(`/jobs/${jobId}/scans/${scanId}?limit=${limit}&offset=${offset}`)
export const scanResults = (jobId: string, scanId: string, offset = 0, limit = 50) => api<{ results: Unit[]; pagination: Pagination }>(`/jobs/${jobId}/scans/${scanId}/results?limit=${limit}&offset=${offset}`)
export const scanChanges = (jobId: string, scanId: string, offset = 0, limit = 50) => api<{ changes: Change[]; pagination: Pagination }>(`/jobs/${jobId}/scans/${scanId}/changes?limit=${limit}&offset=${offset}`)
export const listScans = (offset = 0, limit = 20) => api<{ scans: ScanSummary[]; pagination: Pagination }>(`/scans?limit=${limit}&offset=${offset}`)
export const listHosts = (filters: HostFilters = {}) => api<GlobalHostsResponse>(`/hosts?${hostQuery(filters)}`, filters.signal ? { signal: filters.signal } : undefined)
export const activeScans = () => api<{ scans: ActiveScan[] }>('/scans/active')
export const listIncidents = (offset = 0, limit = 20) => api<{ incidents: Incident[]; pagination: Pagination }>(`/incidents?limit=${limit}&offset=${offset}`)
export const acceptIncident = (jobId: string, key: string, expectedChange: Change) => api<void>(`/jobs/${encodeURIComponent(jobId)}/incidents/accept`, { method: 'POST', body: JSON.stringify({ key, expected_change: expectedChange }) })
export const suppressIncident = (jobId: string, key: string, expectedChange: Change) => api<void>(`/jobs/${encodeURIComponent(jobId)}/incidents/suppress`, { method: 'POST', body: JSON.stringify({ key, expected_change: expectedChange }) })
export const listEvents = (offset = 0, limit = 20, jobId?: string) => api<{ events: unknown[]; pagination: Pagination }>(`/events?limit=${limit}&offset=${offset}${jobId ? `&job_id=${encodeURIComponent(jobId)}` : ''}`)
export const notificationTest = () => api<{ sent: number }>('/notifications/test', { method: 'POST' })
export const listNotificationDestinations = () => api<NotificationDestinationsResponse>('/notifications/destinations')
export const updateNotificationRouting = (destinations: string[], password: string) => api<NotificationUpdateRouting>('/notifications/update-routing', { method: 'PUT', body: JSON.stringify({ destinations, password }) })
export const toggleNotificationUpdateAlert = (destinationID: string, enabled: boolean, password: string) => api<NotificationUpdateRouting>('/notifications/update-routing', { method: 'PATCH', body: JSON.stringify({ destination_id: destinationID, enabled, password }) })
export const updateIncidentReminders = (enabled: boolean, password: string) => api<{ enabled: boolean }>('/notifications/incident-reminders', { method: 'PUT', body: JSON.stringify({ enabled, password }) })
export const getNotificationDestination = (id: string) => api<NotificationDestination>(`/notifications/destinations/${encodeURIComponent(id)}`)
export const createNotificationDestination = (name: string, url: string, password: string, enabled = true) => api<NotificationDestination>('/notifications/destinations', { method: 'POST', body: JSON.stringify({ name, url, password, enabled }) })
export const updateNotificationDestination = (id: string, revision: number, name: string, password: string, options: { url?: string; enabled?: boolean } = {}) => api<NotificationDestination>(`/notifications/destinations/${encodeURIComponent(id)}`, { method: 'PUT', body: JSON.stringify({ name, revision, password, ...options }) })
export const deleteNotificationDestination = (id: string, revision: number, password: string) => api<void>(`/notifications/destinations/${encodeURIComponent(id)}`, { method: 'DELETE', body: JSON.stringify({ revision, password }) })
export const testNotificationDestination = (id: string) => api<{ sent: number }>(`/notifications/destinations/${encodeURIComponent(id)}/test`, { method: 'POST' })

export type NumericBound = { min: number; max: number }
export type ScannerProfileDefinition = { engine: string; naabu: NaabuOptions; naabu_args?: string[]; nmap_args?: string[]; enrichment_args?: string[]; nse_profile?: string; nse_args?: Record<string, string>; operator_adjustable?: string[]; operator_bounds?: Record<string, NumericBound>; description?: string }
export type ScannerProfile = { id: string; name: string; description?: string; built_in: boolean; archived: boolean; revision: number; created_by?: string; updated_by?: string; created_at?: string; updated_at?: string; definition: ScannerProfileDefinition }
export type InvalidScannerProfile = { id: string; name?: string; archived: boolean; error: string }
export type ScannerProfilePayload = { name: string; description?: string; engine: string; naabu?: NaabuOptions; naabu_args?: string[]; nmap_args?: string[]; enrichment_args?: string[]; nse_profile?: string; nse_args?: Record<string, string>; operator_adjustable?: string[]; operator_bounds?: Record<string, NumericBound>; password?: string; revision?: number }
export type ScannerCapabilities = { engines: string[]; nmap: { path: string; version: string; available?: boolean }; naabu: { path: string; version: string; available: boolean; syn_supported: boolean } }
export const scannerCapabilities = () => api<ScannerCapabilities>('/scanner/capabilities')
export const listScannerProfiles = (includeArchived = false) => api<{ profiles: ScannerProfile[]; invalid_profiles?: InvalidScannerProfile[] }>(`/scanner-profiles?include_archived=${includeArchived}`)
export const getScannerProfile = (id: string) => api<ScannerProfile>(`/scanner-profiles/${encodeURIComponent(id)}`)
export const createScannerProfile = (value: ScannerProfilePayload) => api<ScannerProfile>('/scanner-profiles', { method: 'POST', body: JSON.stringify(value) })
export const updateScannerProfile = (id: string, value: ScannerProfilePayload, revision: number) => api<ScannerProfile>(`/scanner-profiles/${encodeURIComponent(id)}`, { method: 'PUT', body: JSON.stringify({ ...value, revision }) })
export const archiveScannerProfile = (id: string, revision: number, password: string) => api<void>(`/scanner-profiles/${encodeURIComponent(id)}`, { method: 'DELETE', body: JSON.stringify({ revision, password }) })
export const restoreScannerProfile = (id: string, revision: number, password: string) => api<void>(`/scanner-profiles/${encodeURIComponent(id)}/restore`, { method: 'POST', body: JSON.stringify({ revision, password }) })
export const validateScannerProfile = (value: ScannerProfilePayload) => api<{ valid: boolean; preview: { executable: string; args: string[] }[] }>('/scanner-profiles/validate', { method: 'POST', body: JSON.stringify(value) })

/** An account without its credentials. last_login_at is absent for an account that never signed in. */
export type UserSummary = { id: string; username: string; display_name: string; role: Role; enabled: boolean; pending: boolean; totp_enabled: boolean; created_at: string; updated_at: string; last_login_at?: string; revision: number }
export const listUsers = () => api<{ users: UserSummary[] }>('/users')
export const createUser = (username: string, display_name: string, role: Role, password = '') => api<{ user: UserSummary; activation_token: string; activation_path: string }>('/users', { method: 'POST', body: JSON.stringify({ username, display_name, role, password }) })
export const updateUser = (id: string, value: { display_name?: string; role?: Role; enabled?: boolean; revision?: number; password?: string }) => api<UserSummary>(`/users/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify(value) })
export const issueUserActivation = (id: string, password = '') => api<{ activation_token: string; activation_path: string; expires_at: string }>(`/users/${encodeURIComponent(id)}/activation`, { method: 'POST', body: JSON.stringify({ password }) })
export const revokeUserActivation = (id: string, password = '') => api<void>(`/users/${encodeURIComponent(id)}/activation`, { method: 'DELETE', body: JSON.stringify({ password }) })
export const revokeUserSessions = (id: string, password = '') => api<void>(`/users/${encodeURIComponent(id)}/sessions`, { method: 'DELETE', body: JSON.stringify({ password }) })

export type PublicDashboardHost = { job_id: string; address: string; created_at?: string }
export type PublicDashboardHostSelection = Pick<PublicDashboardHost, 'job_id' | 'address'>
export type PublicDashboardConfig = { enabled: boolean; title: string; introduction: string; updated_at: string; hosts: PublicDashboardHost[] }
export type PublicPort = { protocol: string; port: number; service?: string }
export type PublicHost = { job: string; address: string; address_family?: string; public: boolean; private: boolean; last_successful_scan?: string; open_ports?: PublicPort[]; open_filtered_ports?: PublicPort[]; rdap?: { status: string; network_name?: string; country?: string; registry?: string; organizations?: string[]; prefix?: string; source_url?: string; fetched_at?: string; stale?: boolean; message?: string } }
export type PublicDashboard = { title: string; introduction?: string; updated_at: string; hosts: PublicHost[] }
export const getPublicDashboardConfig = () => api<PublicDashboardConfig>('/public-dashboard')
// updated_at is the concurrency token from the loaded configuration; the
// server rejects a save based on an older value with a 409 conflict.
export const savePublicDashboardConfig = (value: { enabled: boolean; title: string; introduction: string; hosts: PublicDashboardHostSelection[]; updated_at: string }) => api<PublicDashboardConfig>('/public-dashboard', { method: 'PUT', body: JSON.stringify(value) })
// Without a slug the legacy public URL serves the default business unit's
// page; with one, the page of the business unit with that slug.
export async function getPublicDashboard(slug?: string): Promise<PublicDashboard> {
  const response = await fetch(slug ? `/api/public/v1/dashboard/${encodeURIComponent(slug)}` : '/api/public/v1/dashboard', { credentials: 'omit' })
  const body = await response.json().catch(() => ({}))
  if (!response.ok) throw new APIError(body?.error?.message || 'Public status is not available', body?.error?.code)
  return body as PublicDashboard
}

// Business units: the platform console's API. None of these responses holds
// a unit's jobs, scans, hosts, or incidents: a unit appears with its identity,
// state, and counts, and its accounts as summaries.
export type BusinessUnitStatus = 'active' | 'disabled' | 'deleting' | 'deleted'
/** A unit's scan slots. limit is present only in a unit's capacity. */
export type UnitSlots = { in_use: number; queued: number; limit?: number }
export type DeploymentLimits = { max_concurrent_scans: number; max_probe_count: number; max_naabu_probe_count: number; max_probe_count_limit: number }
/** jobs counts the jobs that are not archived; stored_scans counts every scan the unit's history holds, those of archived jobs included. */
export type BusinessUnit = UnitRef & { status: BusinessUnitStatus; is_default: boolean; revision: number; created_at: string; updated_at: string; state_changed_at: string; accounts: number; administrators: number; jobs: number; stored_scans: number; slots: UnitSlots; purge?: { phase: string; rows: number } }
/**
 * A unit's own capacity settings; null inherits the deployment's setting. A
 * high_cost_ceiling of highCostNotGranted means that no platform
 * administrator granted the unit a ceiling, so a high-cost approval raises
 * neither probe budget.
 */
export type UnitCapacitySettings = { max_concurrent_scans: number | null; max_probe_count: number | null; max_naabu_probe_count: number | null; high_cost_ceiling: number | null }
/** The high_cost_ceiling of a unit without a high-cost grant, which a new unit starts with. */
export const highCostNotGranted = 0
/** revision is the unit's revision, which a change of the capacity names. */
export type UnitCapacity = { unit_id: string; revision: number; capacity: UnitCapacitySettings; limits: DeploymentLimits; slots: UnitSlots }
export type UnitAccount = Omit<UserSummary, 'role'> & { role: UnitRole }
export type AccountInvitation<T> = { user: T; activation_token: string; activation_path: string }
/** totp_enrolled tells whether the account keeps its authenticator after the reset. */
export type PasswordResetLink = { activation_token: string; activation_path: string; expires_at: string; totp_enrolled: boolean }
export type PlatformStatus = { version: string; version_release_url?: string; updates?: ApplicationUpdateStatus; units: { total: number; active: number; disabled: number; deleting: number }; accounts: number; jobs: number; stored_scans: number; platform_admins: { total: number; enabled: number }; capacity: { limits: DeploymentLimits; slots: { capacity: number; in_use: number; queued: number } }; untrusted_proxy?: UntrustedProxy }
/** Who acted: a unit's account, a platform administrator, the host command line, or EdgeWatch itself. Records from before business units have no kind. */
export type AuditActorKind = 'unit' | 'platform' | 'host' | 'system' | ''
export type AuditEntry = { id: number; created_at: string; action: string; category: string; actor: { kind: AuditActorKind; user_id?: string; username?: string; display_name?: string }; detail: string; request_id?: string; source_ip?: string; unit?: UnitRef }
export type AuditPage = { entries: AuditEntry[]; next_before: number | null }
export type AuditQuery = { before?: number | null; limit?: number; unit?: string; action?: string; since?: string; until?: string }

const unitPath = (id: string) => `/platform/units/${encodeURIComponent(id)}`
const unitAccountPath = (id: string, accountID: string) => `${unitPath(id)}/accounts/${encodeURIComponent(accountID)}`
export const listUnits = () => api<{ units: BusinessUnit[]; limits: DeploymentLimits }>('/platform/units')
// Without a slug the server derives one from the name.
export const createUnit = (value: { name: string; slug?: string }) => api<BusinessUnit>('/platform/units', { method: 'POST', body: JSON.stringify(value) })
export const getUnit = (id: string) => api<BusinessUnit>(unitPath(id))
// revision is the concurrency token of the loaded unit; a stale one is a 409.
export const renameUnit = (id: string, value: { revision: number; name?: string; slug?: string }) => api<BusinessUnit>(unitPath(id), { method: 'PATCH', body: JSON.stringify(value) })
export const disableUnit = (id: string, revision: number, password: string) => api<BusinessUnit>(`${unitPath(id)}/disable`, { method: 'POST', body: JSON.stringify({ revision, password }) })
export const enableUnit = (id: string, revision: number, password: string) => api<BusinessUnit>(`${unitPath(id)}/enable`, { method: 'POST', body: JSON.stringify({ revision, password }) })
// Deleting needs a disabled unit, its typed name, and the caller's password.
// The unit answers in its deleting state while the purge runs in the
// background; getUnit reports the purge's progress.
export const deleteUnit = (id: string, confirmName: string, password: string) => api<BusinessUnit>(unitPath(id), { method: 'DELETE', body: JSON.stringify({ confirm_name: confirmName, password }) })
export const getUnitCapacity = (id: string) => api<UnitCapacity>(`${unitPath(id)}/capacity`)
// A key that is absent keeps the setting, null inherits the deployment's, and
// a number sets it; a high_cost_ceiling of highCostNotGranted grants none.
// The server refuses a change at a revision other than the unit's current one, as a conflict.
export const updateUnitCapacity = (id: string, revision: number, value: Partial<UnitCapacitySettings>) => api<UnitCapacity>(`${unitPath(id)}/capacity`, { method: 'PATCH', body: JSON.stringify({ ...value, revision }) })
export const listUnitAccounts = (id: string) => api<{ accounts: UnitAccount[] }>(`${unitPath(id)}/accounts`)
// The platform invites only a unit's administrators; they invite the unit's operators and viewers.
export const inviteUnitAdmin = (id: string, value: { username: string; display_name: string; password: string }) => api<AccountInvitation<UnitAccount>>(`${unitPath(id)}/accounts`, { method: 'POST', body: JSON.stringify({ ...value, role: 'administrator' }) })
// The platform resets only a unit's administrators.
export const resetUnitAdminPassword = (id: string, accountID: string, password: string) => api<PasswordResetLink>(`${unitAccountPath(id, accountID)}/password-reset`, { method: 'POST', body: JSON.stringify({ password }) })
export const revokeUnitAccountSessions = (id: string, accountID: string, password: string) => api<void>(`${unitAccountPath(id, accountID)}/sessions`, { method: 'DELETE', body: JSON.stringify({ password }) })
export const listPlatformAdmins = () => api<{ admins: UserSummary[] }>('/platform/admins')
export const invitePlatformAdmin = (value: { username: string; display_name: string; password: string }) => api<AccountInvitation<UserSummary>>('/platform/admins', { method: 'POST', body: JSON.stringify(value) })
export const setPlatformAdminEnabled = (id: string, enabled: boolean, revision: number, password: string) => api<UserSummary>(`/platform/admins/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify({ enabled, revision, password }) })
// A pending platform administrator is neither enabled nor disabled: revoking its invitation stops its activation link,
// renewing it returns a new one-time link once and stops every older one, and removing the account frees its username.
export const revokePlatformAdminInvitation = (id: string, password: string) => api<void>(`/platform/admins/${encodeURIComponent(id)}/activation`, { method: 'DELETE', body: JSON.stringify({ password }) })
export const renewPlatformAdminInvitation = (id: string, password: string) => api<AccountInvitation<UserSummary> & { expires_at: string }>(`/platform/admins/${encodeURIComponent(id)}/activation`, { method: 'POST', body: JSON.stringify({ password }) })
export const deletePendingPlatformAdmin = (id: string, password: string) => api<void>(`/platform/admins/${encodeURIComponent(id)}`, { method: 'DELETE', body: JSON.stringify({ password }) })
// The platform's own notification destinations. Like a unit's, their URLs are write-only.
export const listPlatformNotifications = () => api<NotificationDestinationsResponse>('/platform/notifications')
export const createPlatformNotification = (name: string, url: string, password: string, enabled = true) => api<NotificationDestination>('/platform/notifications', { method: 'POST', body: JSON.stringify({ name, url, password, enabled }) })
export const updatePlatformNotification = (id: string, revision: number, name: string, password: string, options: { url?: string; enabled?: boolean } = {}) => api<NotificationDestination>(`/platform/notifications/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify({ name, revision, password, ...options }) })
export const deletePlatformNotification = (id: string, revision: number, password: string) => api<void>(`/platform/notifications/${encodeURIComponent(id)}`, { method: 'DELETE', body: JSON.stringify({ revision, password }) })
export const updatePlatformNotificationRouting = (destinations: string[], password: string) => api<NotificationUpdateRouting>('/platform/notifications/update-routing', { method: 'PUT', body: JSON.stringify({ destinations, password }) })
export const togglePlatformNotificationUpdateAlert = (destinationID: string, enabled: boolean, password: string) => api<NotificationUpdateRouting>('/platform/notifications/update-routing', { method: 'PATCH', body: JSON.stringify({ destination_id: destinationID, enabled, password }) })
export const platformStatus = () => api<PlatformStatus>('/platform/status')

// Both audit views are paged newest first by keyset: pass the previous page's
// next_before to load older entries; null means the oldest entry was reached.
function auditQuery(query: AuditQuery) {
  const params = new URLSearchParams()
  if (query.before != null) params.set('before', String(query.before))
  params.set('limit', String(query.limit ?? 50))
  if (query.unit) params.set('unit', query.unit)
  if (query.action) params.set('action', query.action)
  if (query.since) params.set('since', query.since)
  if (query.until) params.set('until', query.until)
  return params.toString()
}
export const platformAudit = (query: AuditQuery = {}) => api<AuditPage>(`/platform/audit?${auditQuery(query)}`)
export const unitAudit = (query: AuditQuery = {}) => api<AuditPage>(`/audit?${auditQuery(query)}`)
