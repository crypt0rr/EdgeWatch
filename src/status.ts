/** User-facing labels and tones for recurring job, scan, and change states. */

export type StateTone = 'green' | 'amber' | 'gray' | 'red'

export function jobStatePresentation(archived: boolean, enabled: boolean): { label: string; tone: StateTone } {
  if (archived) return { label: 'Archived', tone: 'gray' }
  if (enabled) return { label: 'Scheduled', tone: 'green' }
  return { label: 'Paused', tone: 'amber' }
}

type ScanOutcome = string | { status: string; resumable?: boolean; cycle_status?: string }

/**
 * Success and failure are emphasized; canceled and incomplete scans stay
 * neutral. A resumable attempt that failed or timed out after saving its
 * progress also stays neutral, matching the scan-paused activity event.
 */
export function scanOutcomeTone(scan: ScanOutcome): 'success' | 'fail' | 'neutral' {
  const { status, resumable, cycle_status: cycleStatus } = typeof scan === 'string' ? { status: scan } : scan
  switch (status.trim().toLowerCase()) {
    case 'success': return 'success'
    case 'failed':
    case 'timed_out': return resumable && cycleStatus === 'paused' ? 'neutral' : 'fail'
    default: return 'neutral'
  }
}

export function changeKindLabel(kind: string, oldValue?: string, newValue?: string): string {
  const normalized = kind.trim().toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '')
  if (['port_open', 'port_opened'].includes(normalized)) return 'Port opened'
  if (['port_closed', 'port_removed'].includes(normalized)) return 'Port closed'
  if (['port', 'port_state', 'port_changed'].includes(normalized)) {
    const oldPositive = isPositivePortState(oldValue)
    const newPositive = isPositivePortState(newValue)
    if (newPositive && !oldPositive) return 'Port opened'
    if (oldPositive && !newPositive) return 'Port closed'
    return 'Port state'
  }
  // A port that opened or closed on one resolved address of a DNS target
  // while another address exposes it.
  if (normalized === 'port_address') {
    if (isPositivePortState(newValue) && !isPositivePortState(oldValue)) return 'Port opened on address'
    if (isPositivePortState(oldValue) && !isPositivePortState(newValue)) return 'Port closed on address'
    return 'Port on address'
  }
  if (normalized === 'dns' || normalized.startsWith('dns_')) return 'DNS'
  if (normalized === 'host' || normalized.startsWith('host_')) return 'Host state'
  if (normalized === 'service' || normalized.startsWith('service_')) return 'Service'
  return humanize(normalized || kind)
}

/** Names a change's target, followed by the resolved address for a change on one address of a DNS target. */
export function changeTargetLabel(change: { target: string; address?: string }): string {
  return change.address ? `${change.target} (${change.address})` : change.target
}

export function severityLabel(severity: string): string {
  const normalized = severity.trim().toLowerCase()
  if (normalized === 'critical') return 'Critical'
  if (normalized === 'warning') return 'Warning'
  if (normalized === 'info') return 'Info'
  return humanize(severity)
}

/** Give informational changes a neutral tone while retaining warning/critical emphasis. */
export function severityTone(severity: string): 'red' | 'amber' | 'gray' {
  switch (severity.trim().toLowerCase()) {
    case 'critical': return 'red'
    case 'info': return 'gray'
    case 'warning':
    default: return 'amber'
  }
}

export function hostStatusLabel(status: string): string {
  const normalized = status.trim().toLowerCase().replace(/[_-]+/g, ' ')
  if (normalized === 'no response') return 'No response'
  return humanize(normalized)
}

function isPositivePortState(state?: string) {
  const normalized = state?.trim().toLowerCase()
  return normalized === 'open' || normalized === 'open|filtered'
}

function humanize(value: string) {
  const words = value.trim().replace(/[_-]+/g, ' ').replace(/\s+/g, ' ')
  return words ? words[0].toUpperCase() + words.slice(1) : value
}
