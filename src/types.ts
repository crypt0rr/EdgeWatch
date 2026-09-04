export type Protocol = { ports: string; mode?: string; service_detection: boolean }
export type Pagination = { limit: number; offset: number; total: number; has_more: boolean; next_offset: number | null }
export type JobForm = {
  name: string; schedule: string; timezone: string; run_on_start?: boolean; assume_alive?: boolean
  targets: string[]; max_expanded_hosts: number; tcp?: Protocol; udp?: Protocol; timing: string
  timeout: string; baseline_samples: number; change_confirmations: number; enabled?: boolean; allow_high_cost?: boolean
}
export type WorkEstimate = { hosts: number; tcp_ports: number; udp_ports: number; probes: number; nmap_invocations: number; estimated_seconds: number; unknown_dns: number }
export type Job = { id: string; revision: number; enabled: boolean; archived: boolean; security_hash: string; created_at: string; updated_at: string; job: JobForm; baseline: { status: string; samples?: number; attempts?: number; scan_id?: string; incidents?: number; pending?: number }; scan_estimate?: WorkEstimate }
export type Scan = { id: string; job_id?: string; job: string; job_revision?: number; started_at: string; finished_at: string; status: string; error?: string; nmap_version?: string; config_hash: string; baseline_scan_id?: string; baseline_config_hash?: string; snapshot?: { units: Unit[]; scopes: Scope[]; dns?: Record<string, string[]> } }
export type ScanSummary = { id: string; job_id?: string; job: string; job_revision?: number; started_at: string; finished_at: string; status: string; error?: string; nmap_version?: string; config_hash: string; baseline_scan_id?: string; baseline_config_hash?: string }
export type ActiveScan = { id: string; job_id?: string; job: string; job_revision?: number; started_at: string; estimated_probes?: number; nmap_invocations?: number; estimated_seconds?: number }
export type Unit = { target: string; protocol: string; addresses?: string[]; ports?: { port: number; state: string; service?: string }[] }
export type Scope = { target: string; protocol: string; ports: string; service_detection: boolean }
export type Incident = { job_id: string; job: string; incident: { change: { key?: string; kind: string; target: string; protocol?: string; port?: number; old?: string; new?: string; severity: string }; opened_at: string; last_seen_at: string } }
export type Change = { key?: string; kind: string; target: string; protocol?: string; port?: number; old?: string; new?: string; severity: string }
