import { useEffect, useRef, useState, type MouseEvent } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useNavigate, type NavigateFunction } from 'react-router-dom'
import { Fence } from 'lucide-react'
import { APIError, deletePerimeterSeed, getPerimeter, getSession } from '../../api'
import type { PerimeterMonitorRef, PerimeterOutsideTarget, PerimeterOverview, PerimeterRange, PerimeterTotals } from '../../generated/api-types'
import { ActionDialog } from '../../components/ActionDialog'
import { ErrorNotice } from '../../components/ErrorNotice'
import { ScanSlotDemandNotice } from '../../components/ScanSlotDemand'
import { useIsMobile } from '../../components/navigation'
import { formatDateTime } from '../../format'
import { DeclareRanges, defaultMaxEntries } from './DeclareRanges'
import { countLabel, CoverageLegend, CoverageShare, coverageBuckets, formatCount, ipv6Explanation, isNotFound, KindBadge, kindLabel, monitorStateLabel, MonitorStatePill, MonitorSummary, MonitoredCount, MonitorName, perimeterCoverageDocsURL, PerimeterDocsLink, perimeterQueryKey, reasonDescription, unprovenReasons } from './presentation'

/**
 * The Perimeter page: the address space the unit declares, compared with
 * what its monitors will actually scan, per protocol. It answers which
 * declared space is not scanned, which monitors that touch it cannot scan or
 * have not proven their coverage, and which monitored targets lie outside
 * it. The page never scans, and never creates or changes a monitor.
 */
export function Perimeter() {
  const client = useQueryClient()
  const session = useQuery({ queryKey: ['session'], queryFn: getSession })
  const overview = useQuery({ queryKey: perimeterQueryKey, queryFn: getPerimeter })
  const permissions = session.data?.permissions ?? []
  const canManage = permissions.includes('perimeter.manage')
  const canReadJobs = permissions.includes('jobs.read')
  const [removing, setRemoving] = useState<PerimeterRange | null>(null)
  const [removeError, setRemoveError] = useState('')
  const [notice, setNotice] = useState('')
  const noticeRef = useRef<HTMLParagraphElement>(null)
  // The Remove button that opened the dialog, and where focus goes once the
  // dialog closes: back to that button on Cancel, or to the notice after a
  // removal, because the removed range's row and its button leave the page.
  const removeTrigger = useRef<HTMLElement | null>(null)
  const focusAfterDialog = useRef<HTMLElement | null>(null)

  // Runs after the dialog's cleanup has made the page interactive again.
  useEffect(() => {
    if (removing) return
    const target = focusAfterDialog.current
    focusAfterDialog.current = null
    if (target?.isConnected) target.focus()
  }, [removing])

  function closeRemoval(outcome: string) {
    focusAfterDialog.current = noticeRef.current
    setRemoving(null)
    setNotice(outcome)
  }

  async function remove(range: PerimeterRange) {
    setRemoveError('')
    try {
      await deletePerimeterSeed(range.id)
      closeRemoval(`Removed ${range.value} from the perimeter.`)
    } catch (cause) {
      if (isNotFound(cause)) {
        closeRemoval(`${range.value} was already removed.`)
      } else {
        setRemoveError(cause instanceof APIError && cause.code === 'audit_unavailable'
          ? 'The range was kept because the audit record could not be written. Try again later.'
          : cause instanceof Error && cause.message ? cause.message : 'The range could not be removed.')
        return
      }
    }
    await client.invalidateQueries({ queryKey: perimeterQueryKey })
  }

  const data = overview.data
  const ranges = data?.ranges ?? []
  return <section className="page perimeter-page">
    <div className="page-heading">
      <div>
        <p className="eyebrow">Discovery coverage</p>
        <h1>Perimeter</h1>
        <p className="muted">The address space this business unit declares, compared with what its monitors will actually scan, per protocol.</p>
      </div>
      <Fence className="muted-icon" size={24} aria-hidden="true" />
    </div>
    <div className="perimeter-stack">
      <ScanSlotDemandNotice />
      {/* Always mounted, so the live region exists before its text changes. */}
      <p ref={noticeRef} className="success-message perimeter-notice" role="status" tabIndex={-1} hidden={!notice}>{notice}</p>
      {!data && overview.isError ? <ErrorNotice message="Could not load the perimeter." onRetry={() => overview.refetch()} />
        : !data ? <div className="loading" role="status"><span className="spinner" />Loading perimeter…</div>
          : <>
            {overview.isError && <div className="notice warning" role="status"><span>Could not refresh the perimeter. Showing the last loaded report.</span><button className="text-button" type="button" onClick={() => void overview.refetch()}>Retry refresh</button></div>}
            {ranges.length === 0
              ? <EmptyPerimeter canManage={canManage} />
              : <PerimeterReport overview={data} canManage={canManage} canReadJobs={canReadJobs} onRemove={(range, trigger) => { removeTrigger.current = trigger; setRemoveError(''); setNotice(''); setRemoving(range) }} />}
            {/* The form keeps its place whether or not ranges exist, so its
                result and any typed text survive the first declaration and
                every live refresh. */}
            {canManage && <section className="panel" aria-labelledby="perimeter-declare-title">
              <div className="panel-heading"><div>
                <h2 id="perimeter-declare-title">Declare ranges</h2>
                <p className="muted">This business unit holds {countLabel(ranges.length, 'range')} of at most {data.limits.max_ranges.toLocaleString()}.</p>
              </div></div>
              <DeclareRanges maxEntries={data.limits.max_entries_per_request || defaultMaxEntries} headingID="perimeter-declare-title" />
            </section>}
          </>}
    </div>
    {removing && <ActionDialog title="Remove this range?" description={`Remove ${kindLabel(removing.kind).toLowerCase()} range ${removing.value}${removing.label ? ` (${removing.label})` : ''} from the perimeter? Its monitors are not changed; the page only stops comparing their coverage with it.`} confirmLabel="Remove range" destructive restoreFocus={false} onConfirm={() => remove(removing)} onCancel={() => { focusAfterDialog.current = removeTrigger.current; setRemoving(null); setRemoveError('') }} error={removeError} />}
  </section>
}

function EmptyPerimeter({ canManage }: { canManage: boolean }) {
  return <section className="panel perimeter-intro" aria-labelledby="perimeter-intro-title">
    <div className="panel-heading"><div>
      <h2 id="perimeter-intro-title">Declare the perimeter</h2>
      <p className="muted">No ranges are declared for this business unit yet.</p>
    </div></div>
    <p>Declare the IP ranges this business unit owns, and the third-party ranges it may scan. EdgeWatch then compares them with what your monitors will actually scan, per protocol: which declared space no monitor scans, which monitors that touch it cannot scan or have not proven their coverage, and which monitored targets lie outside it.</p>
    <p>Declaring a range does not authorize scanning it, and this page never scans or creates a monitor. For uncovered IPv4 space it suggests monitors sized to the unit’s probe budget, which you review and save in the guided setup.</p>
    {canManage ? <p className="muted">Declare the first ranges below. <PerimeterDocsLink /></p> : <p className="muted">An administrator of this business unit can declare its ranges. <PerimeterDocsLink /></p>}
  </section>
}

type RemoveHandler = (range: PerimeterRange, trigger: HTMLElement) => void

function PerimeterReport({ overview, canManage, canReadJobs, onRemove }: { overview: PerimeterOverview; canManage: boolean; canReadJobs: boolean; onRemove: RemoveHandler }) {
  const ranges = overview.ranges ?? []
  const monitors = overview.monitors ?? []
  // Only the monitors that touch a declared range count in the lists below,
  // as in the totals; the others are listed only for their outside targets.
  const touching = new Set(ranges.flatMap(range => range.monitor_ids ?? []))
  const touchingMonitors = monitors.filter(monitor => touching.has(monitor.job_id))
  const cannotScan = touchingMonitors.filter(monitor => monitor.state !== 'covering')
  const unproven = touchingMonitors.filter(monitor => unprovenReasons(monitor).length > 0)
  const hostDiscovery = touchingMonitors.filter(monitor => monitor.state === 'covering' && monitor.host_discovery)
  const hasIPv6 = ranges.some(range => range.family === 6)
  return <>
    <Summary totals={overview.totals} />
    <p className="muted perimeter-generated">Report generated {formatDateTime(overview.generated_at)}. Coverage comes from each monitor’s configuration, not from scan results. <PerimeterDocsLink href={perimeterCoverageDocsURL}>How coverage is computed</PerimeterDocsLink></p>
    {hostDiscovery.length > 0 && <div className="notice warning perimeter-host-discovery" role="note"><span><strong>{hostDiscovery.length === 1 ? '1 covering monitor scans' : `${hostDiscovery.length} covering monitors scan`} only hosts that answer host discovery:</strong> {hostDiscovery.map(monitor => monitor.name).join(', ')}. Declared addresses that drop discovery probes are not port-scanned by {hostDiscovery.length === 1 ? 'it' : 'them'}.</span></div>}
    <RangesPanel ranges={ranges} monitors={monitors} canManage={canManage} onRemove={onRemove} />
    {hasIPv6 && <p className="notice perimeter-ipv6-note" role="note"><span>{ipv6Explanation(overview.limits.max_job_hosts)}</span></p>}
    <section className="panel" aria-labelledby="perimeter-cannot-scan-title">
      <div className="panel-heading"><div>
        <h2 id="perimeter-cannot-scan-title">Monitors that cannot scan</h2>
        <p className="muted">These monitors touch the perimeter but cover nothing on schedule, so they never count as coverage.</p>
      </div></div>
      {cannotScan.length ? <ul className="perimeter-monitor-list">{cannotScan.map(monitor => <li key={monitor.job_id}><MonitorSummary monitor={monitor} canReadJobs={canReadJobs} details={(monitor.reasons ?? []).map(reasonDescription)} /></li>)}</ul>
        : <p className="inline-empty">Every monitor that touches the perimeter can scan.</p>}
    </section>
    <section className="panel" aria-labelledby="perimeter-unproven-title">
      <div className="panel-heading"><div>
        <h2 id="perimeter-unproven-title">Coverage not proven</h2>
        <p className="muted">These monitors count as coverage, but no recent successful scan proves it.</p>
      </div></div>
      {unproven.length ? <ul className="perimeter-monitor-list">{unproven.map(monitor => <li key={monitor.job_id}><MonitorSummary monitor={monitor} canReadJobs={canReadJobs} details={unprovenReasons(monitor)} /></li>)}</ul>
        : <p className="inline-empty">Every covering monitor that touches the perimeter has proven its coverage.</p>}
    </section>
    <OutsidePanel outside={overview.outside ?? []} truncated={overview.outside_truncated} total={overview.totals.outside_targets} canReadJobs={canReadJobs} />
  </>
}

function Summary({ totals }: { totals: PerimeterTotals }) {
  const scannable = Math.max(totals.declared_ipv4 - totals.excluded_ipv4, 0)
  const covered = { full_tcp: totals.covered_full_tcp, any_tcp: totals.covered_any_tcp, udp: totals.covered_udp }
  const declaredDetail = [
    totals.excluded_ipv4 > 0 ? `${formatCount(totals.excluded_ipv4)} excluded` : '',
    totals.ipv6_ranges > 0 ? `plus ${countLabel(totals.ipv6_ranges, 'IPv6 range')}` : '',
  ].filter(Boolean).join(' · ')
  return <section className="perimeter-summary" aria-label="Perimeter summary">
    <div className="summary-card"><span className="summary-label">Declared IPv4</span><strong>{formatCount(totals.declared_ipv4)}</strong><span className="muted">{totals.declared_ipv4 === 1 ? 'address' : 'addresses'}{declaredDetail ? ` · ${declaredDetail}` : ''}</span></div>
    {coverageBuckets.map(bucket => <div className="summary-card" key={bucket.key}>
      <span className="summary-label">{bucket.label} covered</span>
      {totals.declared_ipv4 === 0 ? <><strong>—</strong><span className="muted">No IPv4 ranges declared</span></> : <CoverageShare covered={covered[bucket.key]} total={scannable} />}
    </div>)}
    <div className="summary-card"><span className="summary-label">Cannot scan</span><strong>{totals.cannot_scan_monitors.toLocaleString()}</strong><span className="muted">{totals.cannot_scan_monitors === 1 ? 'monitor' : 'monitors'} touching the perimeter</span></div>
    <div className="summary-card"><span className="summary-label">Coverage not proven</span><strong>{totals.unproven_monitors.toLocaleString()}</strong><span className="muted">covering {totals.unproven_monitors === 1 ? 'monitor' : 'monitors'}</span></div>
    <div className="summary-card"><span className="summary-label">Outside the perimeter</span><strong>{totals.outside_targets.toLocaleString()}</strong><span className="muted">monitored {totals.outside_targets === 1 ? 'target' : 'targets'}</span></div>
  </section>
}

/** The states of the monitors that touch a range, counted. */
function MonitorStates({ range, monitors }: { range: PerimeterRange; monitors: Map<string, PerimeterMonitorRef> }) {
  const counts = new Map<string, number>()
  let unproven = 0
  for (const id of range.monitor_ids ?? []) {
    const monitor = monitors.get(id)
    if (!monitor) continue
    counts.set(monitor.state, (counts.get(monitor.state) ?? 0) + 1)
    if (unprovenReasons(monitor).length) unproven++
  }
  if (!counts.size) return <span className="muted">No monitors</span>
  return <ul className="perimeter-state-list" aria-label={`Monitors of ${range.value}`}>
    {[...counts].map(([state, count]) => <li key={state}><MonitorStatePill state={state} /> <span>{count.toLocaleString()}</span></li>)}
    {unproven > 0 && <li><span className="pill amber">Not proven</span> <span>{unproven.toLocaleString()}</span></li>}
  </ul>
}

function RangeCoverage({ range, bucket, label }: { range: PerimeterRange; bucket: typeof coverageBuckets[number]['key']; label?: string }) {
  if (range.family === 6) return <MonitoredCount label={label} value={range.ipv6_monitored[bucket]} />
  return <CoverageShare label={label} covered={range.coverage[bucket]} total={Math.max(range.addresses - range.excluded, 0)} />
}

function RangeName({ range }: { range: PerimeterRange }) {
  return <div className="perimeter-range-name">
    <KindBadge kind={range.kind} />
    <Link to={rangePath(range)}><code>{range.value}</code></Link>
    {range.label && <small>{range.label}</small>}
  </div>
}

function rangePath(range: PerimeterRange) {
  return `/perimeter/ranges/${encodeURIComponent(range.id)}`
}

/**
 * Selecting anywhere on a range's row opens its detail, for pointer users;
 * the range's link is the keyboard's way there. A click on another control,
 * or one that ends a text selection, does not navigate.
 */
function openRangeOnClick(navigate: NavigateFunction, range: PerimeterRange) {
  return (event: MouseEvent<HTMLElement>) => {
    if (event.target instanceof Element && event.target.closest('a, button')) return
    if (window.getSelection()?.toString()) return
    navigate(rangePath(range))
  }
}

function RangesPanel({ ranges, monitors, canManage, onRemove }: { ranges: PerimeterRange[]; monitors: PerimeterMonitorRef[]; canManage: boolean; onRemove: RemoveHandler }) {
  const mobile = useIsMobile()
  const navigate = useNavigate()
  const byID = new Map(monitors.map(monitor => [monitor.job_id, monitor]))
  const removeButton = (range: PerimeterRange) => <button className="button ghost perimeter-remove" type="button" aria-label={`Remove ${range.value}`} onClick={event => onRemove(range, event.currentTarget)}>Remove</button>
  return <section className="panel perimeter-ranges" aria-labelledby="perimeter-ranges-title">
    <div className="panel-heading"><div>
      <h2 id="perimeter-ranges-title">Declared ranges</h2>
      <p className="muted">Covered addresses per protocol, excluded addresses left out. Open a range for its gaps and suggested monitors.</p>
    </div></div>
    <CoverageLegend />
    {mobile
      ? <ul className="perimeter-range-cards" aria-label="Declared ranges">{ranges.map(range => <li key={range.id} className="perimeter-range-card" onClick={openRangeOnClick(navigate, range)}>
        <RangeName range={range} />
        <div className="perimeter-range-card-coverage">{coverageBuckets.map(bucket => <RangeCoverage key={bucket.key} range={range} bucket={bucket.key} label={bucket.label} />)}</div>
        <div className="perimeter-range-card-monitors"><span className="summary-label">Monitors</span><MonitorStates range={range} monitors={byID} /></div>
        {canManage && removeButton(range)}
      </li>)}</ul>
      : <div className="table-card perimeter-table-wrap" role="region" aria-label="Declared ranges table" tabIndex={0}>
        <table className="perimeter-table">
          <thead><tr>
            <th scope="col">Range</th>
            {coverageBuckets.map(bucket => <th scope="col" key={bucket.key}>{bucket.label}</th>)}
            <th scope="col">Monitors</th>
            {canManage && <th scope="col"><span className="sr-only">Actions</span></th>}
          </tr></thead>
          <tbody>{ranges.map(range => <tr key={range.id} className="perimeter-range-row" onClick={openRangeOnClick(navigate, range)}>
            <th scope="row"><RangeName range={range} /></th>
            {coverageBuckets.map(bucket => <td key={bucket.key}><RangeCoverage range={range} bucket={bucket.key} /></td>)}
            <td><MonitorStates range={range} monitors={byID} /></td>
            {canManage && <td>{removeButton(range)}</td>}
          </tr>)}</tbody>
        </table>
      </div>}
  </section>
}

function OutsidePanel({ outside, truncated, total, canReadJobs }: { outside: PerimeterOutsideTarget[]; truncated: boolean; total: number; canReadJobs: boolean }) {
  return <section className="panel" aria-labelledby="perimeter-outside-title">
    <div className="panel-heading"><div>
      <h2 id="perimeter-outside-title">Outside the perimeter</h2>
      <p className="muted">Monitored IP and CIDR targets that lie fully or partly outside the declared ranges. Confirm that you may scan them, or declare them.</p>
    </div></div>
    {truncated && <p className="notice perimeter-truncation" role="status">Showing {outside.length.toLocaleString()} of {total.toLocaleString()} targets outside the perimeter.</p>}
    {outside.length ? <ul className="perimeter-outside-list">{outside.map((target, index) => <li key={`${target.job_id}-${target.target}-${index}`}>
      <div className="perimeter-outside-target"><code>{target.target}</code><span className={`pill ${target.partial ? 'amber' : 'red'}`}>{target.partial ? 'Partly outside' : 'Fully outside'}</span></div>
      <span className="perimeter-outside-count">{countLabel(target.outside_addresses, 'address', 'addresses')} outside</span>
      <span className="perimeter-outside-monitor"><MonitorName jobID={target.job_id} name={target.job_name} canReadJobs={canReadJobs} /> <span className="muted">· {monitorStateLabel(target.state)}</span></span>
    </li>)}</ul>
      : <p className="inline-empty">Every monitored IP and CIDR target lies inside the declared ranges.</p>}
  </section>
}
