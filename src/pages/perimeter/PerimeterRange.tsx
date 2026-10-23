import { useId, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { getPerimeter, getPerimeterRange, getSession } from '../../api'
import type { PerimeterBlocks, PerimeterMonitorRef, PerimeterRangeDetail, PerimeterSuggestion } from '../../generated/api-types'
import { ErrorNotice } from '../../components/ErrorNotice'
import { formatDateTime } from '../../format'
import { buildPerimeterPrefill, isPerimeterMode, perimeterModes, type PerimeterMode } from '../../perimeter-prefill'
import { countLabel, CoverageLegend, CoverageShare, coverageBuckets, formatCount, formatMinimumScanDuration, ipv6Explanation, isNotFound, KindBadge, MonitoredCount, MonitorSummary, perimeterQueryKey, perimeterRangeQueryKey, reasonDescription, unprovenReasons } from './presentation'

/** Above this many monitors, a mode states how many it needs instead of listing a Create monitor button for each. */
export const maxListedSuggestions = 16

const modeHeadings: Record<PerimeterMode, { title: string; fills: string }> = {
  full_tcp: { title: 'Full TCP', fills: 'Fills the full-TCP gaps: Naabu discovers every TCP port and Nmap confirms what it finds.' },
  selected_tcp: { title: 'Selected TCP ports', fills: 'Fills the any-TCP gaps with Nmap over a few selected TCP ports: partial coverage of the TCP surface.' },
  udp: { title: 'UDP', fills: 'Fills the UDP gaps with Nmap over common perimeter UDP services, with service detection.' },
}

/**
 * One declared range: the monitors that touch it, its uncovered blocks per
 * protocol, and the monitors suggested to fill its IPv4 gaps. Create monitor
 * opens the guided setup with a one-time prefill; nothing is created until a
 * person saves the monitor there.
 */
export function PerimeterRangeView() {
  const { id = '' } = useParams()
  const session = useQuery({ queryKey: ['session'], queryFn: getSession })
  const detail = useQuery({ queryKey: perimeterRangeQueryKey(id), queryFn: () => getPerimeterRange(id), enabled: !!id })
  const ipv6 = detail.data?.range.family === 6
  // The detail has no limits; an IPv6 range explains itself with the
  // overview's scanner.max_job_hosts, which is usually cached already.
  const overview = useQuery({ queryKey: perimeterQueryKey, queryFn: getPerimeter, enabled: ipv6 })
  const permissions = session.data?.permissions ?? []
  const canWriteJobs = permissions.includes('jobs.write')
  const canReadJobs = permissions.includes('jobs.read')

  // A range removed while it is open answers 404 on the next refresh: say so
  // instead of showing the last loaded detail as if it still existed.
  const notFound = detail.isError && isNotFound(detail.error)
  if (!detail.data || notFound) {
    if (detail.isError) {
      return <section className="page perimeter-range-page">
        <div className="page-heading">
          <div>
            <Link className="back-link" to="/perimeter">← Perimeter</Link>
            <p className="eyebrow">Declared range</p>
            <h1>Range unavailable</h1>
          </div>
        </div>
        <div className="perimeter-stack">
          <ErrorNotice message={notFound ? 'This range could not be found. It may have been removed.' : 'This range could not be loaded.'} onRetry={notFound ? undefined : () => detail.refetch()} />
        </div>
      </section>
    }
    return <div className="loading" role="status"><span className="spinner" />Loading range…</div>
  }

  const value = detail.data
  const range = value.range
  const scannable = Math.max(range.addresses - range.excluded, 0)
  return <section className="page perimeter-range-page">
    <div className="page-heading">
      <div>
        <Link className="back-link" to="/perimeter">← Perimeter</Link>
        <p className="eyebrow">Declared range</p>
        <h1 className="perimeter-range-title"><code>{range.value}</code></h1>
        <p className="perimeter-range-meta"><KindBadge kind={range.kind} />{range.label && <span>{range.label}</span>}<span className="muted">Declared {formatDateTime(range.created_at)}{range.created_by ? ` by ${range.created_by}` : ''}</span></p>
      </div>
    </div>
    <div className="perimeter-stack">
      {detail.isError && <div className="notice warning" role="status"><span>Could not refresh this range. Showing the last loaded detail.</span><button className="text-button" type="button" onClick={() => void detail.refetch()}>Retry refresh</button></div>}
      <section className="perimeter-summary" aria-label="Range coverage">
        {ipv6 ? <>
          <div className="summary-card"><span className="summary-label">Family</span><strong>IPv6</strong><span className="muted">Counts only, no percentage</span></div>
          {coverageBuckets.map(bucket => <div className="summary-card" key={bucket.key}><span className="summary-label">{bucket.label} monitored</span><MonitoredCount value={range.ipv6_monitored[bucket.key]} /></div>)}
        </> : <>
          <div className="summary-card"><span className="summary-label">Addresses</span><strong>{formatCount(range.addresses)}</strong><span className="muted">{range.excluded > 0 ? `${formatCount(range.excluded)} in scanner.target_exclusions` : 'None excluded'}</span></div>
          {coverageBuckets.map(bucket => <div className="summary-card" key={bucket.key}><span className="summary-label">{bucket.label} covered</span><CoverageShare covered={range.coverage[bucket.key]} total={scannable} /></div>)}
        </>}
      </section>
      {ipv6 && <p className="notice perimeter-ipv6-note" role="note"><span>{ipv6Explanation(overview.data?.limits.max_job_hosts)}</span></p>}
      <MonitorsPanel monitors={value.monitors ?? []} canReadJobs={canReadJobs} />
      <UncoveredPanel detail={value} />
      {!ipv6 && <SuggestionsPanel detail={value} scannable={scannable} canWriteJobs={canWriteJobs} />}
    </div>
  </section>
}

function monitorDetails(monitor: PerimeterMonitorRef): string[] {
  const lines = [...(monitor.reasons ?? []).map(reasonDescription), ...unprovenReasons(monitor)]
  if (monitor.dns_targets > 0) lines.push(`${countLabel(monitor.dns_targets, 'DNS-name target')}, which never ${monitor.dns_targets === 1 ? 'counts' : 'count'} as coverage`)
  return lines
}

const protocolLabels: Record<string, string> = { full_tcp: 'full TCP', any_tcp: 'any TCP', udp: 'UDP' }

/**
 * The buckets a monitor's settings fill. The report lists them in any state,
 * but only a covering monitor counts, so another one fills nothing yet.
 */
function monitorProtocolsText(monitor: PerimeterMonitorRef): string {
  const protocols = (monitor.protocols ?? []).map(protocol => protocolLabels[protocol] ?? protocol)
  if (!protocols.length) return 'Fills no coverage bucket'
  return monitor.state === 'covering' ? `Fills ${protocols.join(', ')}` : `Set up for ${protocols.join(', ')}; fills nothing while it cannot scan`
}

function MonitorsPanel({ monitors, canReadJobs }: { monitors: PerimeterMonitorRef[]; canReadJobs: boolean }) {
  return <section className="panel" aria-labelledby="perimeter-range-monitors-title">
    <div className="panel-heading"><div>
      <h2 id="perimeter-range-monitors-title">Monitors touching this range</h2>
      <p className="muted">Every unarchived monitor with an IP or CIDR target in this range, in any state. Only covering monitors count as coverage.</p>
    </div></div>
    {monitors.length ? <ul className="perimeter-monitor-list">{monitors.map(monitor => <li key={monitor.job_id}>
      <MonitorSummary monitor={monitor} canReadJobs={canReadJobs} details={monitorDetails(monitor)}>
        <p className="muted perimeter-monitor-protocols">{monitorProtocolsText(monitor)}</p>
      </MonitorSummary>
    </li>)}</ul> : <p className="inline-empty">No monitor scans any address of this range.</p>}
  </section>
}

/** How many uncovered blocks a bucket shows before Show all. */
const collapsedBlocks = 24

function UncoveredBlocks({ label, blocks }: { label: string; blocks: PerimeterBlocks }) {
  const [expanded, setExpanded] = useState(false)
  const listID = useId()
  const cidrs = blocks.cidrs ?? []
  const visible = expanded ? cidrs : cidrs.slice(0, collapsedBlocks)
  return <section className="perimeter-blocks" aria-label={`${label} uncovered blocks`}>
    <h3>{label}</h3>
    {blocks.total === 0 ? <p className="muted">No uncovered addresses.</p> : <>
      <p className="muted">{countLabel(blocks.total, 'uncovered block')}</p>
      <ul id={listID} className="perimeter-cidr-list">{visible.map(cidr => <li key={cidr}><code>{cidr}</code></li>)}</ul>
      {cidrs.length > collapsedBlocks && <button className="text-button" type="button" aria-expanded={expanded} aria-controls={listID} onClick={() => setExpanded(value => !value)}>{expanded ? 'Show fewer blocks' : `Show all ${cidrs.length.toLocaleString()} blocks`}</button>}
      {blocks.truncated && <p className="muted">The report lists {cidrs.length.toLocaleString()} of {blocks.total.toLocaleString()} blocks.</p>}
    </>}
  </section>
}

function UncoveredPanel({ detail }: { detail: PerimeterRangeDetail }) {
  return <section className="panel" aria-labelledby="perimeter-uncovered-title">
    <div className="panel-heading"><div>
      <h2 id="perimeter-uncovered-title">Uncovered blocks</h2>
      <p className="muted">The addresses of this range that no covering monitor scans, per protocol, as the fewest aligned CIDR blocks. Excluded addresses are left out.</p>
    </div></div>
    <CoverageLegend />
    <div className="perimeter-blocks-grid">{coverageBuckets.map(bucket => <UncoveredBlocks key={bucket.key} label={bucket.label} blocks={detail.uncovered[bucket.key]} />)}</div>
  </section>
}

function SuggestionsPanel({ detail, scannable, canWriteJobs }: { detail: PerimeterRangeDetail; scannable: number; canWriteJobs: boolean }) {
  const suggestions = detail.suggestions ?? []
  const coalescedSuggestions = detail.coalesced_suggestions ?? []
  return <section className="panel" aria-labelledby="perimeter-suggestions-title">
    <div className="panel-heading"><div>
      <h2 id="perimeter-suggestions-title">Suggested monitors</h2>
      <p className="muted">Monitors sized to this business unit’s probe budget that would fill this range’s gaps. Full TCP shows a lower-bound duration at the built-in Naabu rate; host response time, retries, and Nmap confirmation can make a scan take longer.</p>
    </div></div>
    <p className="notice warning perimeter-authorization-banner" role="note"><span>A declared range is not an authorization: confirm you may scan these addresses before you create a monitor. Create monitor opens the guided setup prefilled; you review and save each monitor there, and nothing is created in bulk.</span></p>
    {scannable === 0 ? <p className="inline-empty">All addresses excluded: there is nothing to suggest.</p>
      : <div className="perimeter-modes">{perimeterModes.map(mode => <ModeSuggestions key={mode} mode={mode} detail={detail} suggestions={suggestions.filter(suggestion => suggestion.mode === mode)} coalescedSuggestions={coalescedSuggestions.filter(suggestion => suggestion.mode === mode)} canWriteJobs={canWriteJobs} />)}</div>}
  </section>
}

function ModeSuggestions({ mode, detail, suggestions, coalescedSuggestions, canWriteJobs }: { mode: PerimeterMode; detail: PerimeterRangeDetail; suggestions: PerimeterSuggestion[]; coalescedSuggestions: PerimeterSuggestion[]; canWriteJobs: boolean }) {
  const heading = modeHeadings[mode]
  const perMonitor = detail.addresses_per_monitor[mode]
  const needed = detail.monitors_needed[mode]
  const coalescedNeeded = detail.coalesced_monitors_needed[mode]
  // The report compares only a complete coalesced plan with the gaps-only
  // one; a plan above 16 monitors is withheld uncompared.
  const coalescedTruncated = detail.coalesced_suggestions_truncated[mode]
  const headingID = `perimeter-mode-${mode}`
  return <section className="perimeter-mode" aria-labelledby={`${headingID}-title`}>
    <div className="perimeter-mode-heading">
      <h3 id={`${headingID}-title`}>{heading.title}</h3>
      {!detail.budget_too_low[mode] && <span className="muted">Up to {countLabel(perMonitor, 'address', 'addresses')} per monitor</span>}
    </div>
    <p className="muted">{heading.fills}</p>
    {detail.budget_too_low[mode]
      ? <p className="notice warning" role="status"><span>The unit’s probe budget is too small for one address in this mode.</span></p>
      : needed === 0
        ? <p className="muted">No gaps to fill in this mode.</p>
        : <>
          <SuggestionPlan title="Gaps-only option" id={`${headingID}-gaps`} mode={mode} detail={detail} needed={needed} truncated={detail.suggestions_truncated[mode]} suggestions={suggestions} canWriteJobs={canWriteJobs} />
          {coalescedNeeded > 0 && <div className="perimeter-suggestion-alternative">
            <p className="muted">{!coalescedTruncated && 'Offered because it needs fewer targets in total, or fewer monitors, than the gaps-only option. '}Targets may include already-covered addresses. Each target is at most a /24 (256 addresses), each monitor has at most 16 targets, and the probe budget still applies. The probe estimate includes repeated addresses.</p>
            <SuggestionPlan title="Coalesced alternative" id={`${headingID}-coalesced`} mode={mode} detail={detail} needed={coalescedNeeded} truncated={coalescedTruncated} suggestions={coalescedSuggestions} canWriteJobs={canWriteJobs} coalesced />
          </div>}
        </>}
  </section>
}

function SuggestionPlan({ title, id, mode, detail, needed, truncated, suggestions, canWriteJobs, coalesced = false }: { title?: string; id: string; mode: PerimeterMode; detail: PerimeterRangeDetail; needed: number; truncated: boolean; suggestions: PerimeterSuggestion[]; canWriteJobs: boolean; coalesced?: boolean }) {
  const navigate = useNavigate()
  const perMonitor = detail.addresses_per_monitor[mode]
  let body
  if (truncated && coalesced) body = <p className="perimeter-needs"><strong>Needs more than {maxListedSuggestions} monitors</strong> <span className="muted">The complete coalesced option is too large to list or to compare with the gaps-only option. Use the gaps-only option or declare smaller ranges.</span></p>
  else if (needed > maxListedSuggestions) body = <p className="perimeter-needs"><strong>Needs {needed.toLocaleString()} monitors</strong> <span className="muted">of up to {countLabel(perMonitor, 'address', 'addresses')} each. That is too many to list here: declare smaller ranges to work through this one in parts, or ask a platform administrator about the unit’s probe budget.</span></p>
  else body = <ol className="perimeter-suggestion-list">{suggestions.map((suggestion, index) => {
    const descriptionID = `${id}-${index}`
    const targets = suggestion.targets ?? []
    return <li key={targets.join(',') || index}>
      <div id={descriptionID} className="perimeter-suggestion-copy">
        <strong>Monitor {index + 1} of {suggestions.length}</strong>
        <ul className="perimeter-cidr-list">{targets.map(target => <li key={target}><code>{target}</code></li>)}</ul>
        <small className="muted">{countLabel(suggestion.addresses, 'address', 'addresses')} · {countLabel(suggestion.estimated_probes, 'estimated probe')} · {suggestion.protocol.protocol.toUpperCase()} ports {suggestion.protocol.ports}{suggestion.minimum_duration_seconds ? ` · at least ${formatMinimumScanDuration(suggestion.minimum_duration_seconds)} at the built-in Naabu rate` : ''}{suggestion.already_covered_addresses > 0 && <> · Includes {countLabel(suggestion.already_covered_addresses, 'already-covered address', 'already-covered addresses')}</>}</small>
      </div>
      {!canWriteJobs
        ? <small className="muted perimeter-suggestion-locked">Creating a monitor needs permission to write jobs.</small>
        : isPerimeterMode(suggestion.mode) && targets.length > 0 && <button className="button secondary" type="button" aria-describedby={`${id}-title ${descriptionID}`} onClick={() => navigate('/jobs/new', { state: { perimeterPrefill: buildPerimeterPrefill(suggestion, detail.range.value, index, suggestions.length) } })}>Create monitor</button>}
    </li>
  })}</ol>
  return <div className="perimeter-suggestion-plan">
    {title && <h4 id={`${id}-title`}>{title}</h4>}
    {body}
  </div>
}
