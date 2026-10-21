import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { ExternalLink } from 'lucide-react'
import { APIError } from '../../api'
import type { PerimeterMonitorRef } from '../../generated/api-types'
import { formatDateTime } from '../../format'

// Presentation shared by the Perimeter page and its range detail. Every text
// here describes what the server reported; the console computes no coverage.

/**
 * The overview's query key. A range detail's key starts with it, so
 * invalidating it, as a perimeter.updated live update does, refreshes both.
 */
export const perimeterQueryKey = ['perimeter'] as const

/** The query key of one range's detail. */
export function perimeterRangeQueryKey(id: string) {
  return [...perimeterQueryKey, 'range', id] as const
}

/** The user guide of the Perimeter page. */
export const perimeterGuideURL = 'https://edgewatch.offsec.nl/user-guide/perimeter/'

/** The user guide's recipe for declaring the prefixes an ASN announces. */
export const perimeterDocsURL = `${perimeterGuideURL}#seed-the-perimeter-from-an-asn`

/** The user guide's explanation of how the report computes coverage. */
export const perimeterCoverageDocsURL = `${perimeterGuideURL}#how-coverage-is-computed`

/** The coverage buckets, in the order the report gives them, with what fills each. */
export const coverageBuckets = [
  { key: 'full_tcp', label: 'Full TCP', description: 'TCP with Naabu discovery and Nmap confirmation, or Nmap only over ports 1–65535.' },
  { key: 'any_tcp', label: 'Any TCP', description: 'TCP with any engine and any ports, full TCP included.' },
  { key: 'udp', label: 'UDP', description: 'UDP with any ports.' },
] as const
export type CoverageBucket = typeof coverageBuckets[number]['key']

/** Every address count of the perimeter API saturates here: a count at the limit means at least that many. */
const countLimit = Number.MAX_SAFE_INTEGER

/** An address count, marking one that saturated. */
export function formatCount(value: number): string {
  return value >= countLimit ? `at least ${value.toLocaleString()}` : value.toLocaleString()
}

/** A count with its noun: "1 address", "2 addresses". */
export function countLabel(value: number, singular: string, plural = `${singular}s`): string {
  return `${formatCount(value)} ${value === 1 ? singular : plural}`
}

/**
 * The share of total that covered is, rounded down to one decimal so that a
 * partial coverage never reads 100% and a covered address never reads 0%.
 */
export function formatShare(covered: number, total: number): string {
  if (total <= 0) return ''
  if (covered >= total) return '100%'
  if (covered <= 0) return '0%'
  // Multiplying first keeps an exact share exact: 29 of 100 is 29%, not 28.9%.
  const share = Math.floor((covered * 1000) / total) / 10
  return share < 0.1 ? '<0.1%' : `${share.toLocaleString(undefined, { maximumFractionDigits: 1 })}%`
}

/** The label of a declared range's kind. */
export function kindLabel(kind: string): string {
  return kind === 'prefix' ? 'Owned' : kind === 'authorized' ? 'Authorized' : kind
}

export function KindBadge({ kind }: { kind: string }) {
  return <span className={`pill ${kind === 'prefix' ? 'blue' : 'gray'}`}>{kindLabel(kind)}</span>
}

const stateLabels: Record<string, string> = {
  covering: 'Covering',
  paused: 'Paused',
  invalid_config: 'Invalid configuration',
  over_budget: 'Over probe budget',
  over_expansion: 'Over expansion limit',
  excluded_target: 'Excluded target',
}

/** The label of a monitor state. */
export function monitorStateLabel(state: string): string {
  return stateLabels[state] ?? state.replaceAll('_', ' ')
}

export function monitorStateTone(state: string): 'green' | 'gray' | 'amber' | 'red' {
  if (state === 'covering') return 'green'
  if (state === 'paused') return 'gray'
  if (state === 'invalid_config' || state === 'excluded_target') return 'red'
  return 'amber'
}

export function MonitorStatePill({ state }: { state: string }) {
  return <span className={`pill ${monitorStateTone(state)}`}>{monitorStateLabel(state)}</span>
}

const reasonDescriptions: Record<string, string> = {
  paused: 'Paused: scheduled runs do not start it.',
  invalid_config: 'Invalid configuration: the stored job no longer passes the scan work estimate.',
  over_budget: 'Over probe budget: its estimated probes exceed the unit’s probe budget, so scheduled runs are skipped.',
  over_expansion: 'Over expansion limit: its targets expand past its host expansion limit or scanner.max_job_hosts, so its scans fail.',
  excluded_target: 'Excluded target: a target contains an address in scanner.target_exclusions, so its scans fail.',
}

/** What a failing check means for a monitor. */
export function reasonDescription(reason: string): string {
  return reasonDescriptions[reason] ?? monitorStateLabel(reason)
}

/** The flag of a monitor whose assume_alive is false. */
export const hostDiscoveryText = 'Scans only hosts that answer host discovery'

const attemptLabels: Record<string, string> = {
  failed: 'Last attempt failed',
  timed_out: 'Last attempt timed out',
  incomplete: 'Last attempt incomplete',
}

/** A readable lower bound for a Full TCP scan at the built-in Naabu rate. */
export function formatMinimumScanDuration(seconds: number): string {
  const value = Math.max(0, Math.floor(seconds))
  const hours = Math.floor(value / 3600)
  const minutes = Math.floor((value % 3600) / 60)
  const remainder = value % 60
  return [hours ? `${hours}h` : '', minutes ? `${minutes}m` : '', remainder ? `${remainder}s` : ''].filter(Boolean).join(' ') || '0s'
}

/**
 * Why a covering monitor has not proven its coverage, as the report counts it
 * in totals.unproven_monitors: no successful scan exists, it is stale, its
 * security scope changed, its cycle is stalled, or its latest attempt failed,
 * timed out, or was incomplete without progressing resumable work. Only a
 * covering monitor carries these flags, so any other monitor gets none.
 */
export function unprovenReasons(monitor: PerimeterMonitorRef): string[] {
  if (monitor.state !== 'covering') return []
  const reasons: string[] = []
  if (!monitor.last_success_at) reasons.push('Not scanned yet')
  if (monitor.stale) {
    if (monitor.stale_reason === 'schedule never fires') {
      reasons.push('Schedule never fires')
      if (monitor.last_success_at) reasons.push(`Last successful scan ${formatDateTime(monitor.last_success_at)}`)
    } else if (monitor.last_success_at) {
      reasons.push(`No successful scan since ${formatDateTime(monitor.last_success_at)}`)
    }
  }
  if (monitor.stalled_cycle) reasons.push('Scan cycle stalled')
  if (monitor.scope_changed) reasons.push('Not scanned since its targets or protocols changed')
  const attempt = attemptLabels[monitor.last_attempt_status]
  if (attempt && !monitor.cycle_in_progress) reasons.push(attempt)
  return reasons
}

/** The prefix length of an IPv6 block of the given size, and whether the size is exactly that block. */
function ipv6Block(addresses: number) {
  let bits = 0
  while (bits < 128 && 2 ** (bits + 1) <= addresses) bits++
  return { prefix: 128 - bits, exact: 2 ** bits === addresses }
}

/**
 * Why IPv6 ranges show counts but no percentage and no suggestions: one job
 * scans at most scanner.max_job_hosts addresses, shown as the IPv6 block of
 * that size. maxJobHosts is unknown while the report has not loaded.
 */
export function ipv6Explanation(maxJobHosts?: number): string {
  const tail = 'so EdgeWatch cannot sweep an IPv6 prefix. IPv6 ranges show how many of their addresses covering monitors scan, with no percentage and no suggested monitors.'
  if (!maxJobHosts || maxJobHosts < 1) return `One monitor scans a limited number of addresses (scanner.max_job_hosts), ${tail}`
  const block = ipv6Block(maxJobHosts)
  const size = block.exact ? `a /${block.prefix}` : `more than a /${block.prefix} and less than a /${block.prefix - 1}`
  return `One monitor scans at most ${countLabel(maxJobHosts, 'address', 'addresses')} (scanner.max_job_hosts), ${size}, ${tail}`
}

/** A covered share with a bar and its text equivalent. total is the scannable addresses: the range's minus its excluded ones. */
export function CoverageShare({ label, covered, total }: { label?: string; covered: number; total: number }) {
  if (total <= 0) {
    return <div className="perimeter-coverage">
      {label && <span className="perimeter-coverage-label">{label}</span>}
      <strong className="perimeter-coverage-value">All addresses excluded</strong>
    </div>
  }
  return <div className="perimeter-coverage">
    {label && <span className="perimeter-coverage-label">{label}</span>}
    <strong className="perimeter-coverage-value">{formatShare(covered, total)}</strong>
    <meter className="perimeter-meter" min={0} max={total} value={Math.min(Math.max(covered, 0), total)} aria-hidden="true" />
    <small className="perimeter-coverage-count">{formatCount(covered)} of {countLabel(total, 'address', 'addresses')}</small>
  </div>
}

/** The IPv6 count of a bucket: the addresses covering monitors scan, with no percentage. */
export function MonitoredCount({ label, value }: { label?: string; value: number }) {
  return <div className="perimeter-coverage">
    {label && <span className="perimeter-coverage-label">{label}</span>}
    <strong className="perimeter-coverage-value">{formatCount(value)}</strong>
    <small className="perimeter-coverage-count">{value === 1 ? 'address monitored' : 'addresses monitored'}</small>
  </div>
}

/** A monitor's name, linked to its job when the session may read jobs. */
export function MonitorName({ jobID, name, canReadJobs }: { jobID: string; name: string; canReadJobs: boolean }) {
  return canReadJobs ? <Link className="perimeter-monitor-name" to={`/jobs/${encodeURIComponent(jobID)}`}>{name}</Link> : <strong className="perimeter-monitor-name">{name}</strong>
}

/** A monitor with its state and the lines that explain it. */
export function MonitorSummary({ monitor, canReadJobs, details, children }: { monitor: PerimeterMonitorRef; canReadJobs: boolean; details: string[]; children?: ReactNode }) {
  const lines = [...details]
  if (monitor.cycle_in_progress) lines.push(`Scan cycle in progress (${monitor.cycle_completed_units} of ${monitor.cycle_total_units} units)`)
  if (monitor.host_discovery) lines.push(hostDiscoveryText)
  return <>
    <div className="perimeter-monitor-heading"><MonitorName jobID={monitor.job_id} name={monitor.name} canReadJobs={canReadJobs} /><MonitorStatePill state={monitor.state} /></div>
    {lines.length > 0 && <ul className="perimeter-monitor-reasons">{lines.map(line => <li key={line}>{line}</li>)}</ul>}
    {children}
  </>
}

/** A link into the Perimeter guide, in a new tab: by default its recipe for seeding the perimeter from an ASN. */
export function PerimeterDocsLink({ children = 'Seed the perimeter from an ASN', href = perimeterDocsURL }: { children?: ReactNode; href?: string }) {
  return <a className="perimeter-docs-link" href={href} target="_blank" rel="noopener noreferrer">{children} <span className="sr-only">(opens in a new tab)</span><ExternalLink size={13} aria-hidden="true" /></a>
}

/**
 * What fills each coverage bucket, as visible text, so that keyboard, touch,
 * and phone users read it as well as pointer users.
 */
export function CoverageLegend() {
  return <dl className="perimeter-bucket-legend">
    {coverageBuckets.map(bucket => <div key={bucket.key}><dt>{bucket.label}</dt><dd>{bucket.description}</dd></div>)}
  </dl>
}

/** Reports a 404, which an unknown range and another unit's both answer. */
export function isNotFound(error: unknown): boolean {
  return error instanceof APIError && (error.status === 404 || error.code === 'not_found')
}
