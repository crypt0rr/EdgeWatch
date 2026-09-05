import type { ActiveScan, BaselineHostsResponse, Change, HostDetailResponse, Incident, Job, JobForm, Pagination, RdapResult, Scan, ScanSummary, Unit } from './types'

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
}
export type NotificationStatus = {
  deployment: number
  managed: number
  active: number
  locked: number
  key_state: string
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
  if (!response.ok) throw new APIError(body?.error?.message || 'Request failed', body?.error?.code, body?.error?.details)
  return body as T
}
export type AdminStatus = { configured: boolean; username: string; legacy_yaml_jobs?: string[]; notification_destinations: number; notifications: NotificationStatus; retention: string; max_concurrent_scans: number; max_probe_count?: number; rdap_enabled?: boolean; live_updates?: { history_size: number; dropped_events: number } }
export const setupStatus = () => api<{ configured: boolean; setup_available?: boolean; password_requirements: { minimum_length: number } }>('/setup/status')
export const adminStatus = () => api<AdminStatus>('/status')
export const getSession = () => api<{ username: string; csrf_token: string; totp_enabled: boolean }>('/auth/session')
export const login = (password: string, otp?: string, recovery_code?: string) => api<{ username: string; csrf_token: string; totp_required: boolean }>('/auth/login', { method: 'POST', body: JSON.stringify({ password, otp, recovery_code }) })
export const setup = (token: string, password: string) => api('/setup', { method: 'POST', body: JSON.stringify({ token, password }) })
export const logout = () => api('/auth/logout', { method: 'POST' })
export const logoutAllSessions = () => api('/auth/sessions', { method: 'DELETE' })
export const listJobs = (archived = false) => api<{ jobs: Job[] }>(`/jobs?include_archived=${archived}`)
export const getJob = (id: string) => api<Job>(`/jobs/${id}`)
export const createJob = (job: JobForm) => api<Job>('/jobs', { method: 'POST', body: JSON.stringify(job) })
export const updateJob = (id: string, revision: number, job: JobForm, confirm_rebaseline = false) => api<Job>(`/jobs/${id}`, { method: 'PUT', body: JSON.stringify({ ...job, revision, confirm_rebaseline }) })
export const archiveJob = (id: string, revision: number) => api(`/jobs/${id}/archive`, { method: 'POST', body: JSON.stringify({ revision }) })
export const restoreJob = (id: string, revision: number) => api(`/jobs/${id}/restore`, { method: 'POST', body: JSON.stringify({ revision }) })
export const deleteJob = (id: string, confirm_name: string) => api(`/jobs/${id}?permanent=true`, { method: 'DELETE', body: JSON.stringify({ confirm_name }) })
export const pauseJob = (id: string, revision: number) => api(`/jobs/${id}/pause`, { method: 'POST', body: JSON.stringify({ revision }) })
export const resumeJob = (id: string, revision: number) => api(`/jobs/${id}/resume`, { method: 'POST', body: JSON.stringify({ revision }) })
export const runJob = (id: string) => api<{ status: string }>(`/jobs/${id}/run`, { method: 'POST' })
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
export const scanDetail = (jobId: string, scanId: string, offset = 0, limit = 50) => api<{ scan: Scan; changes: Change[]; changes_pagination: Pagination; current_security_hash: string; comparison_source?: string; baseline_scan_id?: string }>(`/jobs/${jobId}/scans/${scanId}?limit=${limit}&offset=${offset}`)
export const scanResults = (jobId: string, scanId: string, offset = 0, limit = 50) => api<{ results: Unit[]; pagination: Pagination }>(`/jobs/${jobId}/scans/${scanId}/results?limit=${limit}&offset=${offset}`)
export const scanChanges = (jobId: string, scanId: string, offset = 0, limit = 50) => api<{ changes: Change[]; pagination: Pagination }>(`/jobs/${jobId}/scans/${scanId}/changes?limit=${limit}&offset=${offset}`)
export const listScans = (offset = 0, limit = 20) => api<{ scans: ScanSummary[]; pagination: Pagination }>(`/scans?limit=${limit}&offset=${offset}`)
export const activeScans = () => api<{ scans: ActiveScan[] }>('/scans/active')
export const listIncidents = (offset = 0, limit = 20) => api<{ incidents: Incident[]; pagination: Pagination }>(`/incidents?limit=${limit}&offset=${offset}`)
export const listEvents = (offset = 0, limit = 20, jobId?: string) => api<{ events: unknown[]; pagination: Pagination }>(`/events?limit=${limit}&offset=${offset}${jobId ? `&job_id=${encodeURIComponent(jobId)}` : ''}`)
export const notificationTest = () => api<{ sent: number }>('/notifications/test', { method: 'POST' })
export const listNotificationDestinations = () => api<{ destinations: NotificationDestination[]; status: NotificationStatus }>('/notifications/destinations')
export const getNotificationDestination = (id: string) => api<NotificationDestination>(`/notifications/destinations/${encodeURIComponent(id)}`)
export const createNotificationDestination = (name: string, url: string, password: string, enabled = true) => api<NotificationDestination>('/notifications/destinations', { method: 'POST', body: JSON.stringify({ name, url, password, enabled }) })
export const updateNotificationDestination = (id: string, revision: number, name: string, password: string, options: { url?: string; enabled?: boolean } = {}) => api<NotificationDestination>(`/notifications/destinations/${encodeURIComponent(id)}`, { method: 'PUT', body: JSON.stringify({ name, revision, password, ...options }) })
export const deleteNotificationDestination = (id: string, revision: number, password: string) => api<void>(`/notifications/destinations/${encodeURIComponent(id)}`, { method: 'DELETE', body: JSON.stringify({ revision, password }) })
export const testNotificationDestination = (id: string) => api<{ sent: number }>(`/notifications/destinations/${encodeURIComponent(id)}/test`, { method: 'POST' })
