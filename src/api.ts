import type { Incident, Job, JobForm, Scan } from './types'

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
export const setupStatus = () => api<{ configured: boolean; setup_available?: boolean; legacy_yaml_jobs?: string[]; password_requirements: { minimum_length: number } }>('/setup/status')
export const getSession = () => api<{ username: string; csrf_token: string; totp_enabled: boolean }>('/auth/session')
export const login = (password: string, otp?: string, recovery_code?: string) => api<{ username: string; csrf_token: string; totp_required: boolean }>('/auth/login', { method: 'POST', body: JSON.stringify({ password, otp, recovery_code }) })
export const setup = (token: string, password: string) => api('/setup', { method: 'POST', body: JSON.stringify({ token, password }) })
export const logout = () => api('/auth/logout', { method: 'POST' })
export const logoutAllSessions = () => api('/auth/sessions', { method: 'DELETE' })
export const listJobs = (archived = false) => api<{ jobs: Job[] }>(`/jobs?include_archived=${archived}`)
export const getJob = (id: string) => api<Job>(`/jobs/${id}`)
export const createJob = (job: JobForm) => api<Job>('/jobs', { method: 'POST', body: JSON.stringify(job) })
export const updateJob = (id: string, revision: number, job: JobForm, confirm_rebaseline = false) => api<Job>(`/jobs/${id}`, { method: 'PUT', body: JSON.stringify({ ...job, revision, confirm_rebaseline }) })
export const archiveJob = (id: string) => api(`/jobs/${id}/archive`, { method: 'POST' })
export const restoreJob = (id: string) => api(`/jobs/${id}/restore`, { method: 'POST' })
export const deleteJob = (id: string, confirm_name: string) => api(`/jobs/${id}?permanent=true`, { method: 'DELETE', body: JSON.stringify({ confirm_name }) })
export const pauseJob = (id: string) => api(`/jobs/${id}/pause`, { method: 'POST' })
export const resumeJob = (id: string) => api(`/jobs/${id}/resume`, { method: 'POST' })
export const runJob = (id: string) => api<{ status: string }>(`/jobs/${id}/run`, { method: 'POST' })
export const resetBaseline = (id: string) => api(`/jobs/${id}/baseline/reset`, { method: 'POST' })
export const approveBaseline = (jobId: string, scanId: string) => api(`/jobs/${jobId}/baseline/approve`, { method: 'POST', body: JSON.stringify({ scan_id: scanId }) })
export const jobScans = (id: string) => api<{ scans: Scan[] }>(`/jobs/${id}/scans?limit=100`)
export const scanDetail = (jobId: string, scanId: string) => api<{ scan: Scan; changes?: { kind: string; target: string; protocol?: string; port?: number; old?: string; new?: string; severity: string }[]; current_security_hash: string }>(`/jobs/${jobId}/scans/${scanId}`)
export const listScans = () => api<{ scans: Scan[] }>('/scans?limit=20')
export const listIncidents = () => api<{ incidents: Incident[] }>('/incidents')
export const notificationTest = () => api<{ sent: number }>('/notifications/test', { method: 'POST' })
