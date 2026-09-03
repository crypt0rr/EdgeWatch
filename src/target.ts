export function targetKind(value: string) {
  const target = value.trim()
  if (!target) return ''
  if (target.includes('/')) return 'CIDR'
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(target)) return 'IP'
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
