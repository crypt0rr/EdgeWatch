import { useQuery } from '@tanstack/react-query'
import { Globe2, Info, LoaderCircle, Network, Server, ShieldCheck } from 'lucide-react'
import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { baselineHost, baselineHostRDAP, scanHost, scanHostRDAP } from '../api'
import type { HostObservation, PortObservation, ProtocolObservation, RdapResult } from '../types'

function HostIdentity({ host }: { host: HostObservation }) {
  return <div className="host-identity"><div className="host-identity-icon"><Server size={25} /></div><div><h2>{host.address}</h2><div className="host-badges"><span className="pill blue">{host.address_family ?? (host.address.includes(':') ? 'IPv6' : 'IPv4')}</span><span className={host.status === 'up' ? 'pill green' : 'pill gray'}>{host.status ?? 'up'}</span>{host.status_reason && <span className="muted">{host.status_reason}{host.reason_ttl ? ` · TTL ${host.reason_ttl}` : ''}</span>}</div></div></div>
}

function ServiceText({ port }: { port: PortObservation }) {
  if (!port.service) return <span className="muted">No service fingerprint</span>
  const service = port.service
  const title = [service.name, service.product, service.version].filter(Boolean).join(' · ')
  const hints = [service.os_type && `OS ${service.os_type}`, service.device_type && `Device ${service.device_type}`].filter(Boolean)
  return <span className="service-cell"><strong>{title || 'Detected service'}</strong>{service.extra_info && <small>{service.extra_info}</small>}<small>{[service.method, service.confidence ? `confidence ${service.confidence}` : '', service.tunnel, ...hints].filter(Boolean).join(' · ')}</small>{service.cpes?.map(cpe => <code key={cpe}>{cpe}</code>)}</span>
}

type PortSortKey = 'port' | 'state' | 'reason' | 'service'

function serviceSortValue(port: PortObservation) {
  if (!port.service) return ''
  return [port.service.name, port.service.product, port.service.version, port.service.extra_info, port.service.method].filter(Boolean).join(' ')
}

function ProtocolCard({ protocol }: { protocol: ProtocolObservation }) {
  const [sortKey, setSortKey] = useState<PortSortKey>('port')
  const [descending, setDescending] = useState(false)
  const ports = [...(protocol.ports ?? [])].sort((left, right) => {
    let result = 0
    if (sortKey === 'port') result = left.port - right.port
    if (sortKey === 'state') result = left.state.localeCompare(right.state)
    if (sortKey === 'reason') result = (left.reason ?? '').localeCompare(right.reason ?? '')
    if (sortKey === 'service') result = serviceSortValue(left).localeCompare(serviceSortValue(right))
    if (result === 0) result = left.port - right.port
    return descending ? -result : result
  })
  function sortBy(next: PortSortKey) {
    if (next === sortKey) setDescending(value => !value)
    else { setSortKey(next); setDescending(false) }
  }
  function sortLabel(key: PortSortKey, label: string) {
    const active = sortKey === key
    return <button type="button" className="sort-button" onClick={() => sortBy(key)} aria-label={`Sort by ${label.toLowerCase()}`}>{label}{active && <span aria-hidden="true">{descending ? ' ↓' : ' ↑'}</span>}</button>
  }
  return <div className="protocol-card"><div className="protocol-heading"><div><h3>{protocol.protocol.toUpperCase()}</h3><p className="muted">{protocol.scan_type || protocol.protocol} · {protocol.scanned_ports} · {protocol.scanned_port_count.toLocaleString()} ports</p></div><span className="pill blue">{protocol.service_detection ? 'Service detection' : 'Port scan'}</span></div><div className="state-summary">{protocol.state_summaries?.map(summary => <div key={summary.state} className="state-summary-item"><strong>{summary.count.toLocaleString()}</strong><span>{summary.state}</span>{summary.reasons?.map(reason => <small key={reason.reason}>{reason.reason} · {reason.count}</small>)}</div>)}</div>{ports.length ? <div className="port-table-wrap"><table className="port-table"><thead><tr><th scope="col" aria-sort={sortKey === 'port' ? (descending ? 'descending' : 'ascending') : 'none'}>{sortLabel('port', 'Port')}</th><th scope="col" aria-sort={sortKey === 'state' ? (descending ? 'descending' : 'ascending') : 'none'}>{sortLabel('state', 'State')}</th><th scope="col" aria-sort={sortKey === 'reason' ? (descending ? 'descending' : 'ascending') : 'none'}>{sortLabel('reason', 'Reason')}</th><th scope="col" aria-sort={sortKey === 'service' ? (descending ? 'descending' : 'ascending') : 'none'}>{sortLabel('service', 'Service and evidence')}</th></tr></thead><tbody>{ports.map(port => <tr key={port.port}><td><code>{port.port}/{protocol.protocol}</code></td><td><span className={port.state === 'open' ? 'pill green' : 'pill amber'}>{port.state}</span></td><td>{port.reason || '—'}{port.reason_ttl ? <small className="table-sub">TTL {port.reason_ttl}</small> : null}</td><td><ServiceText port={port} /></td></tr>)}</tbody></table></div> : <div className="inline-empty">No open or open|filtered ports were recorded.</div>}<p className="nonopen-note"><Info size={14} /> Closed, filtered, and other non-open ports are summarized above rather than stored individually, even for a 65,535-port scope.</p></div>
}

function RdapPanel({ result, loading, error }: { result?: RdapResult; loading: boolean; error?: Error | null }) {
  if (loading) return <div className="rdap-box"><LoaderCircle className="spin" size={18} /><span>Looking up the authoritative registry…</span></div>
  if (error && !result) return <div className="rdap-box unavailable"><Info size={18} /><span>Registry lookup is temporarily unavailable. Local host evidence is unaffected.</span></div>
  if (!result) return null
  if (result.status === 'disabled') return <div className="rdap-box"><ShieldCheck size={18} /><span>RDAP lookups are disabled by deployment configuration.</span></div>
  if (result.status === 'private') return <div className="rdap-box"><Network size={18} /><span>Private or special-use addresses are not sent to an external registry.</span></div>
  if (result.status === 'unavailable') return <div className="rdap-box unavailable"><Info size={18} /><span>{result.message || 'No registry data is available.'}</span></div>
  return <div className="rdap-result"><div className="rdap-status"><Globe2 size={17} /><strong>{result.status === 'stale' ? 'Cached registry data (stale)' : result.status === 'cached' ? 'Cached registry data' : 'Registry data'}</strong>{result.fetched_at && <span className="muted">Fetched {new Date(result.fetched_at).toLocaleString()}</span>}</div><dl className="fact-grid">{[['Network', result.network_name], ['Handle', result.handle], ['Range', result.prefix || [result.start_address, result.end_address].filter(Boolean).join(' – ')], ['Country', result.country], ['Allocation', result.allocation_type], ['Registry', result.registry], ['Organizations', result.organizations?.join(', ')], ['Status', result.statuses?.join(', ')]].filter(([, value]) => value).map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>{result.events?.length ? <div className="rdap-events">{result.events.map(event => <span key={`${event.action}-${event.date}`}>{event.action}{event.date ? ` · ${new Date(event.date).toLocaleDateString()}` : ''}</span>)}</div> : null}{result.source_url && <a href={result.source_url} target="_blank" rel="noreferrer" className="back-link">Open authoritative record ↗</a>}</div>
}

export function HostDetail() {
  const params = useParams()
  const id = params.id ?? ''
  const address = params.address ?? ''
  const scanID = params.scanId
  const detail = useQuery({ queryKey: ['host-detail', id, scanID, address], queryFn: () => scanID ? scanHost(id, scanID, address) : baselineHost(id, address), enabled: !!id && !!address })
  const rdap = useQuery({ queryKey: ['host-rdap', id, scanID, address], queryFn: () => scanID ? scanHostRDAP(id, scanID, address) : baselineHostRDAP(id, address), enabled: !!id && !!address, retry: false })
  if (detail.isLoading) return <div className="loading"><span className="spinner" />Loading host evidence…</div>
  if (detail.error || !detail.data) return <section className="page"><div className="error-card">This host could not be found in the selected {scanID ? 'scan' : 'baseline'}.</div></section>
  const value = detail.data
  const host = value.host
  const protocols = host.protocols ?? []
  const back = scanID ? `/jobs/${id}` : `/jobs/${id}/baseline`
  return <section className="page host-detail-page"><div className="page-heading"><div><Link className="back-link" to={back}>← {scanID ? 'Job' : 'Baseline hosts'}</Link><p className="eyebrow">{scanID ? 'Historical scan host' : 'Baseline host'}</p><HostIdentity host={host} /></div></div>{value.data_quality === 'legacy' && <div className="legacy-banner" role="status"><Info size={17} /><span><strong>Legacy detail</strong> This host was derived from an older snapshot. Detailed Nmap evidence appears after a newer successful scan is approved.</span></div>}<div className="host-detail-grid"><div className="panel"><div className="panel-heading"><div><h2>Identity and coverage</h2><p className="muted">Configured target relationships and immutable scan context.</p></div></div><dl className="fact-grid">{[['Configured targets', host.source_targets?.join(', ') || '—'], ['Configured DNS', host.dns_names?.join(', ') || '—'], ['Hostnames', host.hostnames?.map(name => name.name).join(', ') || '—'], ['Latency', host.latency_ms ? `${host.latency_ms.toFixed(2)} ms` : 'Not reported'], ['Link address', host.link_addresses?.map(link => [link.address, link.vendor].filter(Boolean).join(' · ')).join(', ') || 'Not reported'], ['Source scan', (value.source_scan ?? value.scan)?.id || 'Legacy snapshot'], ['Completed', (value.source_scan ?? value.scan)?.finished_at ? new Date((value.source_scan ?? value.scan)!.finished_at).toLocaleString() : '—'], ['Job revision', String((value.source_scan ?? value.scan)?.job_revision ?? '—')], ['Nmap', (value.source_scan ?? value.scan)?.nmap_version || '—']].map(([label, item]) => <div key={label}><dt>{label}</dt><dd>{item}</dd></div>)}</dl></div><div className="panel"><div className="panel-heading"><div><h2>Network registration (RDAP/WHOIS)</h2><p className="muted">Loaded only when a single host is opened.</p></div></div><RdapPanel result={rdap.data?.rdap} loading={rdap.isLoading} error={rdap.error as Error | null} /></div></div>{scanID && value.expected && <div className="panel expected-panel"><div className="panel-heading"><div><h2>Baseline expectation</h2><p className="muted">Positive ports retained by the active baseline for this address.</p></div></div><div className="expected-protocols">{value.expected.protocols?.map(protocol => <span className="coverage-chip" key={protocol.protocol}><b>{protocol.protocol.toUpperCase()}</b> {protocol.ports?.map(port => port.port).join(', ') || 'No positive ports'}</span>)}</div></div>}<div className="protocol-stack">{protocols.length ? protocols.map(protocol => <ProtocolCard key={protocol.protocol} protocol={protocol} />) : <div className="panel inline-empty">No protocol evidence was recorded for this host.</div>}</div></section>
}
