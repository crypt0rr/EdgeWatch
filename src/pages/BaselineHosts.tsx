import { useQuery } from '@tanstack/react-query'
import { Search, Server, SlidersHorizontal } from 'lucide-react'
import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { baselineHosts } from '../api'
import type { HostSummary } from '../types'
import { Pagination } from '../components/Pagination'

function addressKind(address: string) {
  if (address.includes(':')) return 'IPv6'
  return 'IPv4'
}

function visibility(address: string) {
  const value = address.toLowerCase()
  if (value === 'localhost') return 'Private'
  if (value.includes(':')) {
    // Host addresses are normalized by the API, so these prefixes cover the
    // private, link-local, multicast, loopback, and unspecified IPv6 ranges.
    if (value === '::' || value === '::1' || value.startsWith('fc') || value.startsWith('fd') || value.startsWith('fe8') || value.startsWith('fe9') || value.startsWith('fea') || value.startsWith('feb') || value.startsWith('ff')) return 'Private'
    return 'Public'
  }
  const octets = value.split('.').map(Number)
  if (octets.length !== 4 || octets.some(octet => !Number.isInteger(octet) || octet < 0 || octet > 255)) return 'Public'
  const [first, second] = octets
  if (first === 0 || first === 10 || first === 127 || (first === 172 && second >= 16 && second <= 31) || (first === 192 && second === 168) || (first === 169 && second === 254) || (first === 100 && second >= 64 && second <= 127) || (first >= 224 && first <= 255)) return 'Private'
  return 'Public'
}

function HostRow({ host, jobID }: { host: HostSummary; jobID: string }) {
  return <Link className="host-row" to={`/jobs/${jobID}/baseline/hosts/${encodeURIComponent(host.address)}`}>
    <span className="host-address"><strong>{host.address}</strong><span className="host-badges"><span className="pill blue">{host.address_family ?? addressKind(host.address)}</span><span className={visibility(host.address) === 'Public' ? 'pill green' : 'pill gray'}>{visibility(host.address)}</span>{host.legacy && <span className="pill amber">Legacy detail</span>}</span></span>
    <span className="host-source">{host.source_targets?.join(', ') || 'Configured target'}</span>
    <span className="host-coverage">{host.protocols?.map(protocol => <span key={protocol.protocol} className="coverage-chip"><b>{protocol.protocol.toUpperCase()}</b> {protocol.open_ports} open{protocol.open_filtered_ports ? ` · ${protocol.open_filtered_ports} open|filtered` : ''}</span>)}</span>
    <span className="host-open-count">{host.open_ports + host.open_filtered_ports}<small> positive ports</small></span>
  </Link>
}

export function BaselineHosts() {
  const { id = '' } = useParams()
  const [q, setQ] = useState('')
  const [protocol, setProtocol] = useState('')
  const [open, setOpen] = useState('')
  const [offset, setOffset] = useState(0)
  const data = useQuery({ queryKey: ['baseline-hosts', id, q, protocol, open, offset], queryFn: () => baselineHosts(id, { q: q || undefined, protocol: protocol || undefined, has_open_ports: open === '' ? undefined : open === 'true', offset }), enabled: !!id })

  function updateSearch(value: string) { setQ(value); setOffset(0) }
  function updateProtocol(value: string) { setProtocol(value); setOffset(0) }
  function updateOpen(value: string) { setOpen(value); setOffset(0) }

  return <section className="page host-explorer-page">
    <div className="page-heading"><div><Link className="back-link" to={`/jobs/${id}`}>← Job</Link><p className="eyebrow">Current baseline</p><h1>Explore baseline</h1><p className="muted">Every effective address produced by this job, with protocol coverage and positive results.</p></div></div>
    {data.isLoading ? <div className="loading"><span className="spinner" />Loading hosts…</div> : data.error ? <div className="error-card">Could not load baseline hosts.</div> : <>
      {data.data?.data_quality === 'legacy' && <div className="legacy-banner" role="status"><Server size={17} /><span><strong>Older scan details</strong> This baseline predates detailed host evidence. Run and approve a newer successful scan for service, reason, and non-open summaries.</span></div>}
      {data.data?.data_quality === 'none' && <div className="empty"><div className="empty-icon"><Server size={23} /></div><h3>No active baseline</h3><p>Complete the configured baseline samples before exploring hosts.</p></div>}
      {data.data?.data_quality !== 'none' && <>
        <div className="host-toolbar"><label className="search-field"><Search size={16} /><span className="sr-only">Search hosts</span><input value={q} onChange={event => updateSearch(event.target.value)} placeholder="Search IP, DNS name, or target" /></label><label><SlidersHorizontal size={14} /><span className="sr-only">Protocol</span><select value={protocol} onChange={event => updateProtocol(event.target.value)}><option value="">All protocols</option><option value="tcp">TCP</option><option value="udp">UDP</option></select></label><label><span className="sr-only">Open ports filter</span><select value={open} onChange={event => updateOpen(event.target.value)}><option value="">Any result</option><option value="true">Has positive ports</option><option value="false">No positive ports</option></select></label></div>
        <div className="panel host-list-panel"><div className="panel-heading"><div><h2>Baseline hosts</h2><p className="muted">{data.data?.pagination.total ?? 0} effective address{data.data?.pagination.total === 1 ? '' : 'es'} · select a host for technical evidence</p></div></div>{data.data?.hosts.length ? <div className="host-list">{data.data.hosts.map(host => <HostRow key={host.address} host={host} jobID={id} />)}</div> : <div className="inline-empty">No hosts match these filters.</div>}<Pagination page={data.data?.pagination} onChange={setOffset} /></div>
      </>}
    </>}
  </section>
}
