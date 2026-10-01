import { useQuery } from '@tanstack/react-query'
import { Search, Server, SlidersHorizontal } from 'lucide-react'
import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { baselineHosts } from '../api'
import type { HostSummary } from '../types'
import { Pagination } from '../components/Pagination'
import { useDebouncedValue } from '../useDebouncedValue'

function addressKind(address: string) {
  if (address.includes(':')) return 'IPv6'
  return 'IPv4'
}

function visibilityLabel(visibility: HostSummary['visibility']) {
  if (visibility === 'public') return 'Public'
  if (visibility === 'non_public') return 'Non-public'
  return 'Unknown'
}

function HostRow({ host, jobID }: { host: HostSummary; jobID: string }) {
  const visibility = visibilityLabel(host.visibility)
  return <Link className="host-row" to={`/jobs/${jobID}/baseline/hosts/${encodeURIComponent(host.address)}`}>
    <span className="host-address"><strong title={host.address}>{host.address}</strong><span className="host-badges"><span className="pill blue">{host.address_family ?? addressKind(host.address)}</span><span className={host.visibility === 'public' ? 'pill green' : 'pill gray'}>{visibility}</span>{host.legacy && <span className="pill amber">Legacy detail</span>}</span></span>
    <span className="host-source" title={host.source_targets?.join(', ') || 'Configured target'}>{host.source_targets?.join(', ') || 'Configured target'}</span>
    <span className="host-coverage">{host.protocols?.map(protocol => <span key={protocol.protocol} className="coverage-chip"><b>{protocol.protocol.toUpperCase()}</b> {protocol.open_ports} open{protocol.open_filtered_ports ? ` · ${protocol.open_filtered_ports} open|filtered` : ''}</span>)}</span>
    <span className="host-open-count">{host.open_ports + host.open_filtered_ports}<small> positive ports</small></span>
  </Link>
}

export function BaselineHosts() {
  const { id = '' } = useParams()
  const [search, setSearch] = useState('')
  const q = useDebouncedValue(search)
  const [protocol, setProtocol] = useState('')
  const [open, setOpen] = useState('')
  const [offset, setOffset] = useState(0)
  const data = useQuery({ queryKey: ['baseline-hosts', id, q, protocol, open, offset], queryFn: ({ signal }) => baselineHosts(id, { q: q || undefined, protocol: protocol || undefined, has_open_ports: open === '' ? undefined : open === 'true', offset, signal }), enabled: !!id })
  const baseline = data.data

  function updateSearch(value: string) { setSearch(value); setOffset(0) }
  function updateProtocol(value: string) { setProtocol(value); setOffset(0) }
  function updateOpen(value: string) { setOpen(value); setOffset(0) }

  return <section className="page host-explorer-page">
    <div className="page-heading"><div><Link className="back-link" to={`/jobs/${id}`}>← Job</Link><p className="eyebrow">Current baseline</p><h1>Explore baseline</h1><p className="muted">Every effective address produced by this job, with protocol coverage and positive results.</p></div></div>
    {baseline?.data_quality !== 'none' && <div className="host-toolbar"><label className="search-field"><Search size={16} /><span className="sr-only">Search hosts</span><input value={search} onInput={event => updateSearch(event.currentTarget.value)} placeholder="Search IP, DNS name, or target" /></label><label><SlidersHorizontal size={14} /><span className="sr-only">Protocol</span><select value={protocol} onChange={event => updateProtocol(event.target.value)}><option value="">All protocols</option><option value="tcp">TCP</option><option value="udp">UDP</option></select></label><label><span className="sr-only">Open ports filter</span><select value={open} onChange={event => updateOpen(event.target.value)}><option value="">Any result</option><option value="true">Has positive ports</option><option value="false">No positive ports</option></select></label></div>}
    {data.isLoading && !baseline ? <div className="loading"><span className="spinner" />Loading hosts…</div> : data.error ? <div className="error-card" role="alert">Could not load baseline hosts. <button type="button" className="button ghost" onClick={() => void data.refetch()}>Retry</button></div> : !baseline ? <div className="loading"><span className="spinner" />Loading hosts…</div> : baseline.data_quality === 'none' ? <div className="empty"><div className="empty-icon"><Server size={23} /></div><h3>No active baseline</h3><p>Complete the configured baseline samples before exploring hosts.</p></div> : <>
      {baseline.data_quality === 'legacy' && <div className="legacy-banner" role="status"><Server size={17} /><span><strong>Older scan details</strong> This baseline predates detailed host evidence. Run and approve a newer successful scan for service, reason, and non-open summaries.</span></div>}
      <div className="panel host-list-panel" aria-busy={data.isFetching}><div className="panel-heading"><div><h2>Baseline hosts</h2><p className="muted">{baseline.pagination.total ?? 0} effective address{baseline.pagination.total === 1 ? '' : 'es'} · select a host for technical evidence</p></div></div>{baseline.hosts.length ? <div className="host-list">{baseline.hosts.map(host => <HostRow key={host.address} host={host} jobID={id} />)}</div> : <div className="inline-empty">No hosts match these filters.</div>}<Pagination page={baseline.pagination} onChange={setOffset} /></div>
    </>}
  </section>
}
