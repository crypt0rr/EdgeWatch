export type Protocol = { ports: string; mode?: string; service_detection: boolean }
export type Pagination = { limit: number; offset: number; total: number; has_more: boolean; next_offset: number | null }
export type JobForm = {
  name: string; schedule: string; timezone: string; run_on_start?: boolean; assume_alive?: boolean
  targets: string[]; max_expanded_hosts: number; tcp?: Protocol; udp?: Protocol; timing: string
  timeout: string; baseline_samples: number; change_confirmations: number; enabled?: boolean; allow_high_cost?: boolean
  resume_window?: string
}
export type WorkEstimate = { hosts: number; tcp_ports: number; udp_ports: number; probes: number; nmap_invocations: number; estimated_seconds: number; unknown_dns: number }
export type Job = { id: string; revision: number; enabled: boolean; archived: boolean; security_hash: string; created_at: string; updated_at: string; job: JobForm; baseline: { status: string; samples?: number; attempts?: number; scan_id?: string; incidents?: number; pending?: number; host_count?: number }; scan_estimate?: WorkEstimate; scan_cycle?: ScanCycle | null }
export type Scan = { id: string; job_id?: string; job: string; job_revision?: number; started_at: string; finished_at: string; status: string; error?: string; nmap_version?: string; config_hash: string; cycle_id?: string; cycle_attempt?: number; cycle_status?: string; resumable?: boolean; completed_probes?: number; total_probes?: number; completed_units?: number; total_units?: number; no_progress_attempts?: number; baseline_scan_id?: string; baseline_config_hash?: string; snapshot?: { units: Unit[]; scopes: Scope[]; dns?: Record<string, string[]>; hosts?: HostObservation[] } }
export type ScanSummary = { id: string; job_id?: string; job: string; job_revision?: number; started_at: string; finished_at: string; status: string; error?: string; nmap_version?: string; config_hash: string; cycle_id?: string; cycle_attempt?: number; cycle_status?: string; resumable?: boolean; completed_probes?: number; total_probes?: number; completed_units?: number; total_units?: number; no_progress_attempts?: number; baseline_scan_id?: string; baseline_config_hash?: string }
export type ActiveScan = {
  id: string; job_id?: string; job: string; job_revision?: number; started_at: string
  estimated_probes?: number; nmap_invocations?: number; estimated_seconds?: number
  completed_probes?: number; total_probes?: number; completed_invocations?: number
  total_invocations?: number; progress_percent: number; phase?: string; protocol?: string
  current_invocation?: number; total_batches?: number; process_progress_percent?: number
  elapsed_seconds?: number; last_output?: string; process_alive?: boolean
  cycle_id?: string; cycle_attempt?: number; cycle_status?: string; cycle_completed_probes?: number; cycle_total_probes?: number
  cycle_completed_units?: number; cycle_total_units?: number; cycle_no_progress_attempts?: number; current_unit?: number
  current_unit_ports?: string; current_unit_addresses?: number
}
export type ScanCycleUnit = { cycle_id: string; sequence: number; protocol: string; family: number; ports: string; port_count: number; addresses: number; probes: number; status: string; attempts: number; started_at?: string; finished_at?: string; last_error?: string }
export type ScanCycle = { id: string; job_id: string; job_revision: number; status: string; attempt_count: number; no_progress_attempts: number; total_units: number; completed_units: number; total_probes: number; completed_probes: number; started_at: string; updated_at: string; expires_at: string; finished_at?: string; last_error?: string; units?: ScanCycleUnit[] }
export type Unit = { target: string; protocol: string; addresses?: string[]; ports?: { port: number; state: string; service?: string }[] }
export type Scope = { target: string; protocol: string; ports: string; service_detection: boolean }
export type Incident = { job_id: string; job: string; incident: { change: { key?: string; kind: string; target: string; protocol?: string; port?: number; old?: string; new?: string; severity: string }; scan_id?: string; opened_at: string; last_seen_at: string; recovery_count?: number } }
export type Change = { key?: string; kind: string; target: string; protocol?: string; port?: number; old?: string; new?: string; severity: string }

export type StateReason = { reason: string; count: number }
export type StateSummary = { state: string; count: number; reasons?: StateReason[] }
export type ServiceObservation = {
  name?: string; product?: string; version?: string; extra_info?: string; method?: string
  confidence?: number; tunnel?: string; os_type?: string; device_type?: string; cpes?: string[]
}
export type PortObservation = { port: number; state: string; reason?: string; reason_ttl?: number; service?: ServiceObservation }
export type ProtocolObservation = {
  protocol: string; scan_type?: string; scanned_ports: string; scanned_port_count: number
  service_detection: boolean; ports?: PortObservation[]; state_summaries?: StateSummary[]
}
export type HostObservation = {
  address: string; source_targets?: string[]; dns_names?: string[]; address_family?: string; status?: string
  status_reason?: string; reason_ttl?: number; latency_ms?: number
  link_addresses?: { address: string; type?: string; vendor?: string }[]
  hostnames?: { name: string; type?: string }[]; protocols?: ProtocolObservation[]
}
export type HostProtocolSummary = {
  protocol: string; scan_type?: string; scanned_ports: string; scanned_port_count: number
  service_detection: boolean; open_ports: number; open_filtered_ports: number
}
export type HostSummary = {
  address: string; address_family?: string; source_targets?: string[]; dns_names?: string[]; protocols?: HostProtocolSummary[]
  open_ports: number; open_filtered_ports: number; has_open_ports: boolean; legacy?: boolean
}
export type GlobalHostSummary = HostSummary & {
  job_id?: string; job: string; scan_id: string; scanned_at: string; data_quality: string
}
export type GlobalHostsResponse = { hosts: GlobalHostSummary[]; pagination: Pagination }
export type BaselineHostsResponse = {
  job_id: string; job: string; source_scan?: ScanSummary | null; data_quality: string
  hosts: HostSummary[]; pagination: Pagination
}
export type HostDetailResponse = {
  job_id: string; job: string; data_quality: string; host: HostObservation
  expected?: HostObservation | null; source_scan?: ScanSummary | null; scan?: ScanSummary | null
}
export type RdapResult = {
  status: 'success' | 'cached' | 'stale' | 'private' | 'disabled' | 'unavailable' | string
  address: string; registry?: string; network_name?: string; handle?: string
  start_address?: string; end_address?: string; prefix?: string; country?: string
  allocation_type?: string; statuses?: string[]; organizations?: string[]
  events?: { action: string; date?: string }[]; source_url?: string
  fetched_at?: string; expires_at?: string; stale?: boolean; message?: string
}
