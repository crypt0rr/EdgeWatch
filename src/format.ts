/**
 * Format the Go duration returned by the status API for human-facing copy.
 * Retention is configured and stored with full duration precision, but the
 * dashboard only needs whole days and remaining hours.
 */
export function formatRetention(value: string): string {
  const input = value.trim()
  const match = input.match(/^(?:(\d+(?:\.\d+)?)h)?(?:(\d+(?:\.\d+)?)m)?(?:(\d+(?:\.\d+)?)s)?$/)
  if (!match || !input) return input || 'Unknown'

  const totalHours = Math.floor((Number(match[1] ?? 0) * 3600 + Number(match[2] ?? 0) * 60 + Number(match[3] ?? 0)) / 3600)
  const days = Math.floor(totalHours / 24)
  const hours = totalHours % 24
  const parts: string[] = []
  if (days > 0) parts.push(`${days} day${days === 1 ? '' : 's'}`)
  if (hours > 0) parts.push(`${hours} hour${hours === 1 ? '' : 's'}`)
  return parts.join(' ') || '0 hours'
}
