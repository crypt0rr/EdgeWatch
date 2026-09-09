import type { ActiveScan, BaselineHostsResponse, Change, GlobalHostsResponse, HostDetailResponse, Incident, Job, JobForm, Pagination, RdapResult, Scan, ScanSummary, Unit, NaabuOptions } from './types'

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
  delivery_pending?: number
  delivery_retrying?: number
  delivery_terminal_failures?: number
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
  database_bytes: number
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
  constructor(message: string, code?: string, details?: Record<string, unknown>) {
    super(message)
    this.name = 'APIError'
    this.code = code
    this.details = details
  }
}
export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers)
  if (init.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json')
  if (csrf && init.method && init.method !== 'GET') headers.set('X-CSRF-Token', csrf)
  const response = await fetch(`/api/v1${path}`, { ...init, headers, credentials: 'same-origin' })
  if (response.status === 204) return undefined as T
  const body = await response.json().catch(() => ({}))
  if (response.status === 401 && !/^\/(?:setup|auth\/(?:login|activate))(?:\/|\?|$)/.test(path)) {
    // A session can expire while the console remains open. Let the shell
    // clear its cached principal and return to the login route instead of
    // leaving each page to render an authentication error independently.
    csrf = ''
    if (typeof window !== 'undefined') window.dispatchEvent(new Event('edgewatch:unauthorized'))
  }
  if (!response.ok) throw new APIError(body?.error?.message || 'Request failed', body?.error?.code, body?.error?.details)
  return body as T
}
export type Role = 'administrator' | 'operator' | 'viewer'
export type SessionUser = { user_id: string; username: string; display_name?: string; role: Role; permissions: string[]; csrf_token: string; totp_enabled: boolean; password_requirements: { minimum_length: number } }
export type AdminStatus = { configured: boolean; username: string; display_name?: string; role?: Role; permissions?: string[]; version: string; legacy_yaml_jobs?: string[]; notification_destinations: number; notifications: NotificationStatus; retention: string; max_concurrent_scans: number; max_probe_count?: number; rdap_enabled?: boolean; public_dashboard_enabled?: boolean; live_updates?: { history_size: number; dropped_events: number }; updates?: ApplicationUpdateStatus; telemetry?: DeploymentTelemetry }
export const setupStatus = () => api<{ configured: boolean; setup_available?: boolean; public_dashboard_enabled?: boolean; version: string; password_requirements: { minimum_length: number } }>('/setup/status')
export const adminStatus = () => api<AdminStatus>('/status')
export const getSession = () => api<SessionUser>('/auth/session')
export const login = (password: string, otp?: string, recovery_code?: string, username = 'admin') => api<{ username: string; display_name?: string; role: Role; permissions: string[]; csrf_token: string; totp_required: boolean }>('/auth/login', { method: 'POST', body: JSON.stringify({ username, password, otp, recovery_code }) })
export const setup = (token: string, password: string) => api('/setup', { method: 'POST', body: JSON.stringify({ token, password }) })
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
export const resetBaseline = (id: string) => api(`/jobs/${id}/baseline/reset`, { method: 'POST' })
export const approveBaseline = (jobId: string, scanId: string) => api(`/jobs/${jobId}/baseline/approve`, { method: 'POST', body: JSON.stringify({ scan_id: scanId }) })
export const jobScans = (id: string, offset = 0, limit = 20) => api<{ scans: ScanSummary[]; pagination: Pagination }>(`/jobs/${id}/scans?limit=${limit}&offset=${offset}`)
export const jobBaseline = (id: string, offset = 0, limit = 50) => api<{ job_id: string; job: string; revision: number; security_hash: string; baseline: Job['baseline']; snapshot: { units: Unit[]; scopes: { target: string; protocol: string; ports: string; service_detection: boolean }[]; dns?: Record<string, string[]> } | null; pagination: Pagination }>(`/jobs/${id}/baseline?limit=${limit}&offset=${offset}`)
export type HostFilters = { q?: string; protocol?: string; has_open_ports?: boolean; limit?: number; offset?: number }
function hostQuery(filters: HostFilters = {}) {
  const params = new URLSearchParams()
  params.set('limit', String(filters.limit ?? 50))
  params.set('offset', String(filters.offset ?? 0))
  if (filters.q) params.set('q', filters.q)
  if (filters.protocol) params.set('protocol', filters.protocol)
  if (filters.has_open_ports !== undefined) params.set('has_open_ports', String(filters.has_open_ports))
  return params.toString()
}
export const baselineHosts = (id: string, filters: HostFilters = {}) => api<BaselineHostsResponse>(`/jobs/${id}/baseline/hosts?${hostQuery(filters)}`)
export const baselineHost = (id: string, address: string) => api<HostDetailResponse>(`/jobs/${id}/baseline/hosts/${encodeURIComponent(address)}`)
export const baselineHostRDAP = (id: string, address: string) => api<{ rdap: RdapResult }>(`/jobs/${id}/baseline/hosts/${encodeURIComponent(address)}/rdap`)
export const scanHosts = (jobId: string, scanId: string, filters: HostFilters = {}) => api<{ job_id: string; job: string; scan: ScanSummary; data_quality: string; hosts: import('./types').HostSummary[]; pagination: Pagination }>(`/jobs/${jobId}/scans/${encodeURIComponent(scanId)}/hosts?${hostQuery(filters)}`)
export const scanHost = (jobId: string, scanId: string, address: string) => api<HostDetailResponse>(`/jobs/${jobId}/scans/${encodeURIComponent(scanId)}/hosts/${encodeURIComponent(address)}`)
export const scanHostRDAP = (jobId: string, scanId: string, address: string) => api<{ rdap: RdapResult }>(`/jobs/${jobId}/scans/${encodeURIComponent(scanId)}/hosts/${encodeURIComponent(address)}/rdap`)
export const historicalScanHost = (scanId: string, address: string) => api<HostDetailResponse>(`/scans/${encodeURIComponent(scanId)}/hosts/${encodeURIComponent(address)}`)
export const historicalScanHostRDAP = (scanId: string, address: string) => api<{ rdap: RdapResult }>(`/scans/${encodeURIComponent(scanId)}/hosts/${encodeURIComponent(address)}/rdap`)
export const scanDetail = (jobId: string, scanId: string, offset = 0, limit = 50) => api<{ scan: Scan; changes: Change[]; changes_pagination: Pagination; current_security_hash: string; comparison_source?: string; baseline_scan_id?: string }>(`/jobs/${jobId}/scans/${scanId}?limit=${limit}&offset=${offset}`)
export const scanResults = (jobId: string, scanId: string, offset = 0, limit = 50) => api<{ results: Unit[]; pagination: Pagination }>(`/jobs/${jobId}/scans/${scanId}/results?limit=${limit}&offset=${offset}`)
export const scanChanges = (jobId: string, scanId: string, offset = 0, limit = 50) => api<{ changes: Change[]; pagination: Pagination }>(`/jobs/${jobId}/scans/${scanId}/changes?limit=${limit}&offset=${offset}`)
export const listScans = (offset = 0, limit = 20) => api<{ scans: ScanSummary[]; pagination: Pagination }>(`/scans?limit=${limit}&offset=${offset}`)
export const listHosts = (filters: HostFilters = {}) => api<GlobalHostsResponse>(`/hosts?${hostQuery(filters)}`)
export const activeScans = () => api<{ scans: ActiveScan[] }>('/scans/active')
export const listIncidents = (offset = 0, limit = 20) => api<{ incidents: Incident[]; pagination: Pagination }>(`/incidents?limit=${limit}&offset=${offset}`)
export const acceptIncident = (jobId: string, key: string) => api<void>(`/jobs/${encodeURIComponent(jobId)}/incidents/accept`, { method: 'POST', body: JSON.stringify({ key }) })
export const suppressIncident = (jobId: string, key: string) => api<void>(`/jobs/${encodeURIComponent(jobId)}/incidents/suppress`, { method: 'POST', body: JSON.stringify({ key }) })
export const listEvents = (offset = 0, limit = 20, jobId?: string) => api<{ events: unknown[]; pagination: Pagination }>(`/events?limit=${limit}&offset=${offset}${jobId ? `&job_id=${encodeURIComponent(jobId)}` : ''}`)
export const notificationTest = () => api<{ sent: number }>('/notifications/test', { method: 'POST' })
export const listNotificationDestinations = () => api<{ destinations: NotificationDestination[]; status: NotificationStatus }>('/notifications/destinations')
export const getNotificationDestination = (id: string) => api<NotificationDestination>(`/notifications/destinations/${encodeURIComponent(id)}`)
export const createNotificationDestination = (name: string, url: string, password: string, enabled = true) => api<NotificationDestination>('/notifications/destinations', { method: 'POST', body: JSON.stringify({ name, url, password, enabled }) })
export const updateNotificationDestination = (id: string, revision: number, name: string, password: string, options: { url?: string; enabled?: boolean } = {}) => api<NotificationDestination>(`/notifications/destinations/${encodeURIComponent(id)}`, { method: 'PUT', body: JSON.stringify({ name, revision, password, ...options }) })
export const deleteNotificationDestination = (id: string, revision: number, password: string) => api<void>(`/notifications/destinations/${encodeURIComponent(id)}`, { method: 'DELETE', body: JSON.stringify({ revision, password }) })
export const testNotificationDestination = (id: string) => api<{ sent: number }>(`/notifications/destinations/${encodeURIComponent(id)}/test`, { method: 'POST' })

export type NumericBound = { min: number; max: number }
export type ScannerProfileDefinition = { engine: string; naabu: NaabuOptions; naabu_args?: string[]; nmap_args?: string[]; enrichment_args?: string[]; nse_profile?: string; nse_args?: Record<string, string>; operator_adjustable?: string[]; operator_bounds?: Record<string, NumericBound>; description?: string }
export type ScannerProfile = { id: string; name: string; description?: string; built_in: boolean; archived: boolean; revision: number; created_by?: string; updated_by?: string; created_at?: string; updated_at?: string; definition: ScannerProfileDefinition }
export type ScannerProfilePayload = { name: string; description?: string; engine: string; naabu?: NaabuOptions; naabu_args?: string[]; nmap_args?: string[]; enrichment_args?: string[]; nse_profile?: string; nse_args?: Record<string, string>; operator_adjustable?: string[]; operator_bounds?: Record<string, NumericBound>; password?: string; revision?: number }
export type ScannerCapabilities = { engines: string[]; nmap: { path: string; version: string; available?: boolean }; naabu: { path: string; version: string; available: boolean; syn_supported: boolean } }
export const scannerCapabilities = () => api<ScannerCapabilities>('/scanner/capabilities')
export const listScannerProfiles = (includeArchived = false) => api<{ profiles: ScannerProfile[] }>(`/scanner-profiles?include_archived=${includeArchived}`)
export const getScannerProfile = (id: string) => api<ScannerProfile>(`/scanner-profiles/${encodeURIComponent(id)}`)
export const createScannerProfile = (value: ScannerProfilePayload) => api<ScannerProfile>('/scanner-profiles', { method: 'POST', body: JSON.stringify(value) })
export const updateScannerProfile = (id: string, value: ScannerProfilePayload, revision: number) => api<ScannerProfile>(`/scanner-profiles/${encodeURIComponent(id)}`, { method: 'PUT', body: JSON.stringify({ ...value, revision }) })
export const archiveScannerProfile = (id: string, revision: number, password: string) => api<void>(`/scanner-profiles/${encodeURIComponent(id)}`, { method: 'DELETE', body: JSON.stringify({ revision, password }) })
export const restoreScannerProfile = (id: string, revision: number, password: string) => api<void>(`/scanner-profiles/${encodeURIComponent(id)}/restore`, { method: 'POST', body: JSON.stringify({ revision, password }) })
export const validateScannerProfile = (value: ScannerProfilePayload) => api<{ valid: boolean; preview: { executable: string; args: string[] }[] }>('/scanner-profiles/validate', { method: 'POST', body: JSON.stringify(value) })

export type UserSummary = { id: string; username: string; display_name: string; role: Role; enabled: boolean; pending?: boolean; totp_enabled: boolean; created_at: string; updated_at: string; last_login_at?: string }
export const listUsers = () => api<{ users: UserSummary[] }>('/users')
export const createUser = (username: string, display_name: string, role: Role) => api<{ user: UserSummary; activation_token: string; activation_path: string }>('/users', { method: 'POST', body: JSON.stringify({ username, display_name, role }) })
export const updateUser = (id: string, value: { display_name?: string; role?: Role; enabled?: boolean }) => api<UserSummary>(`/users/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify(value) })
export const issueUserActivation = (id: string) => api<{ activation_token: string; activation_path: string; expires_at: string }>(`/users/${encodeURIComponent(id)}/activation`, { method: 'POST' })
export const revokeUserActivation = (id: string) => api<void>(`/users/${encodeURIComponent(id)}/activation`, { method: 'DELETE' })
export const revokeUserSessions = (id: string) => api<void>(`/users/${encodeURIComponent(id)}/sessions`, { method: 'DELETE' })

export type PublicDashboardHost = { job_id: string; address: string; created_at?: string }
export type PublicDashboardHostSelection = Pick<PublicDashboardHost, 'job_id' | 'address'>
export type PublicDashboardConfig = { enabled: boolean; title: string; introduction: string; updated_at: string; hosts: PublicDashboardHost[] }
export type PublicPort = { protocol: string; port: number; service?: string }
export type PublicHost = { job: string; address: string; address_family?: string; public: boolean; private: boolean; available: boolean; stale?: boolean; last_successful_scan?: string; open_ports?: PublicPort[]; open_filtered_ports?: PublicPort[]; rdap?: { status: string; network_name?: string; country?: string; registry?: string; organizations?: string[]; prefix?: string; source_url?: string; fetched_at?: string; stale?: boolean; message?: string } }
export type PublicDashboard = { title: string; introduction?: string; updated_at: string; hosts: PublicHost[] }
export const getPublicDashboardConfig = () => api<PublicDashboardConfig>('/public-dashboard')
export const savePublicDashboardConfig = (value: { enabled: boolean; title: string; introduction: string; hosts: PublicDashboardHostSelection[] }) => api<PublicDashboardConfig>('/public-dashboard', { method: 'PUT', body: JSON.stringify(value) })
export async function getPublicDashboard(): Promise<PublicDashboard> {
  const response = await fetch('/api/public/v1/dashboard', { credentials: 'omit' })
  const body = await response.json().catch(() => ({}))
  if (!response.ok) throw new APIError(body?.error?.message || 'Public status is not available', body?.error?.code)
  return body as PublicDashboard
}
