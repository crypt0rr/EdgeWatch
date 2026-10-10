export function targetKind(value: string) {
  const target = value.trim()
  if (!target) return ''
  if (target.includes('/')) return 'CIDR'
  if (/^\d+(?:\.\d+)+$/.test(target)) {
    const octets = target.split('.')
    const validIPv4 = octets.length === 4 && octets.every(octet => /^(?:0|[1-9]\d{0,2})$/.test(octet) && Number(octet) <= 255)
    return validIPv4 ? 'IP' : 'Target'
  }
  if (target.includes(':') && /^[0-9a-f:]+$/i.test(target)) return 'IP'
  if (/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/i.test(target)) return 'DNS'
  return 'Target'
}

export function cidrWarning(value: string) {
  const target = value.trim()
  if (!target.includes('/')) return ''
  const prefix = Number(target.split('/')[1])
  if (!Number.isInteger(prefix)) return 'Check the CIDR prefix before saving this target.'
  const wide = target.includes(':') ? prefix < 120 : prefix < 24
  return wide ? 'This CIDR expands to many hosts; keep the expansion limit tight and consider a smaller range.' : 'This CIDR will be expanded and counted against the maximum host limit.'
}

export function duplicateTarget(values: string[]) {
  const seen = new Set<string>()
  return values.map((value) => value.trim()).filter(Boolean).find((value) => {
    const key = value.toLowerCase()
    if (seen.has(key)) return true
    seen.add(key)
    return false
  })
}

/** The addresses a target expands to: a CIDR's, one for an address or a DNS name, none for anything else. */
export function targetHosts(value: string) {
  const target = value.trim()
  const kind = targetKind(target)
  if (kind === 'IP' || kind === 'DNS') return 1
  if (kind !== 'CIDR') return 0
  const [address, prefixText] = target.split('/')
  const bits = address.includes(':') ? 128 : 32
  const prefix = Number(prefixText)
  if (!/^\d+$/.test(prefixText ?? '') || prefix > bits) return 0
  return 2 ** (bits - prefix)
}

/**
 * Warns when targets expand to more addresses than the deployment lets one job
 * scan, scanner.max_job_hosts, which the server reports: such a job's scans fail.
 */
export function hostCeilingWarning(targets: string[], ceiling?: number) {
  if (!ceiling) return ''
  const hosts = targets.reduce((total, target) => total + targetHosts(target), 0)
  return hosts > ceiling ? `These targets expand to more than the ${ceiling.toLocaleString()} hosts that one job may scan in this deployment (scanner.max_job_hosts), so their scans would fail. Split them into several jobs.` : ''
}
