/** User-facing labels and tones for recurring job, scan, and change states. */

export type StateTone = 'green' | 'amber' | 'gray' | 'red'

export function jobStatePresentation(archived: boolean, enabled: boolean): { label: string; tone: StateTone } {
  if (archived) return { label: 'Archived', tone: 'gray' }
  if (enabled) return { label: 'Scheduled', tone: 'green' }
  return { label: 'Paused', tone: 'amber' }
}

/** Success and failure are emphasized; canceled and incomplete scans stay neutral. */
export function scanOutcomeTone(status: string): 'success' | 'fail' | 'neutral' {
  switch (status.trim().toLowerCase()) {
    case 'success': return 'success'
    case 'failed':
    case 'error': return 'fail'
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
  if (normalized === 'dns' || normalized.startsWith('dns_')) return 'DNS'
  if (normalized === 'host' || normalized.startsWith('host_')) return 'Host state'
  if (normalized === 'service' || normalized.startsWith('service_')) return 'Service'
  return humanize(normalized || kind)
}

export function severityLabel(severity: string): string {
  const normalized = severity.trim().toLowerCase()
  if (normalized === 'critical') return 'Critical'
  if (normalized === 'warning') return 'Warning'
  if (normalized === 'info') return 'Info'
  return humanize(severity)
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
