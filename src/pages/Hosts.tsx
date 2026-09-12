import { Search, Server, SlidersHorizontal } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { listHosts } from '../api'
import { Pagination } from '../components/Pagination'
import type { GlobalHostSummary } from '../types'
import { useDebouncedValue } from '../useDebouncedValue'

function addressKind(address: string) {
  return address.includes(':') ? 'IPv6' : 'IPv4'
}

function visibility(address: string) {
  const value = address.toLowerCase()
  if (value === 'localhost') return 'Private'
  if (value.includes(':')) {
    if (value === '::' || value === '::1' || value.startsWith('fc') || value.startsWith('fd') || value.startsWith('fe8') || value.startsWith('fe9') || value.startsWith('fea') || value.startsWith('feb') || value.startsWith('ff')) return 'Private'
    return 'Public'
  }
  const octets = value.split('.').map(Number)
  if (octets.length !== 4 || octets.some(octet => !Number.isInteger(octet) || octet < 0 || octet > 255)) return 'Public'
  const [first, second] = octets
  if (first === 0 || first === 10 || first === 127 || (first === 172 && second >= 16 && second <= 31) || (first === 192 && second === 168) || (first === 169 && second === 254) || (first === 100 && second >= 64 && second <= 127) || (first >= 224 && first <= 255)) return 'Private'
  return 'Public'
}

function HostRow({ host }: { host: GlobalHostSummary }) {
  const source = host.source_targets?.length ? host.source_targets.join(', ') : host.dns_names?.join(', ')
  const scannedAt = host.scanned_at ? new Date(host.scanned_at).toLocaleString() : 'Unknown time'
  return <Link className="host-row global-host-row" to={`/scans/${encodeURIComponent(host.scan_id)}/hosts/${encodeURIComponent(host.address)}`}>
    <span className="host-address"><strong>{host.address}</strong><span className="host-badges"><span className="pill blue">{host.address_family ?? addressKind(host.address)}</span><span className={visibility(host.address) === 'Public' ? 'pill green' : 'pill gray'}>{visibility(host.address)}</span>{host.legacy && <span className="pill amber">Legacy detail</span>}</span></span>
    <span className="host-source"><strong>{host.job || 'Legacy scan'}</strong><small>{scannedAt}</small><span>{source || 'Configured target'}</span></span>
    <span className="host-coverage">{host.protocols?.map(protocol => <span key={protocol.protocol} className="coverage-chip"><b>{protocol.protocol.toUpperCase()}</b> {protocol.open_ports} open{protocol.open_filtered_ports ? ` · ${protocol.open_filtered_ports} open|filtered` : ''}</span>)}</span>
    <span className="host-open-count">{host.open_ports + host.open_filtered_ports}<small> positive ports</small></span>
  </Link>
}

function HostGroup({ title, description, hosts }: { title: string; description: string; hosts: GlobalHostSummary[] }) {
  if (!hosts.length) return null
  return <section className="host-group" aria-labelledby={`host-group-${title.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`}>
    <div className="host-group-heading"><div><h3 id={`host-group-${title.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`}>{title}</h3><p className="muted">{description}</p></div></div>
    <div className="host-list">{hosts.map(host => <HostRow key={`${host.scan_id}-${host.address}`} host={host} />)}</div>
  </section>
}

export function Hosts() {
  const [search, setSearch] = useState('')
  const q = useDebouncedValue(search)
  const [protocol, setProtocol] = useState('')
  const [open, setOpen] = useState('')
  const [offset, setOffset] = useState(0)
  const data = useQueryHosts(q, protocol, open, offset)

  function updateSearch(value: string) { setSearch(value); setOffset(0) }
  function updateProtocol(value: string) { setProtocol(value); setOffset(0) }
  function updateOpen(value: string) { setOpen(value); setOffset(0) }

  return <section className="page host-explorer-page">
    <div className="page-heading"><div><p className="eyebrow">Discovered assets</p><h1>Hosts</h1><p className="muted">Every effective IP found by completed scans. Select a host to open its latest historical evidence.</p></div></div>
    <div className="host-toolbar"><label className="search-field"><Search size={16} /><span className="sr-only">Search hosts</span><input value={search} onInput={event => updateSearch(event.currentTarget.value)} placeholder="Search IP, DNS name, target, or job" /></label><label><SlidersHorizontal size={14} /><span className="sr-only">Protocol</span><select value={protocol} onChange={event => updateProtocol(event.target.value)}><option value="">All protocols</option><option value="tcp">TCP</option><option value="udp">UDP</option></select></label><label><span className="sr-only">Open ports filter</span><select value={open} onChange={event => updateOpen(event.target.value)}><option value="">Any result</option><option value="true">Has positive ports</option><option value="false">No positive ports</option></select></label></div>
    {data.isLoading && !data.data ? <div className="loading"><span className="spinner" />Loading hosts…</div> : data.error ? <div className="error-card" role="alert">Could not load scanned hosts.</div> : <div className="panel host-list-panel" aria-busy={data.isFetching}><div className="panel-heading"><div><h2>Scanned hosts</h2><p className="muted">{data.data?.pagination.total ?? 0} effective address{data.data?.pagination.total === 1 ? '' : 'es'} · latest successful result per IP</p></div><Server className="muted-icon" size={18} /></div>{data.data?.hosts.length ? <><HostGroup title="Active jobs" description="Hosts from scheduled, paused, or newly configured jobs." hosts={data.data.hosts.filter(host => !host.archived)} /><HostGroup title="Archived jobs" description="Historical host results retained from archived jobs." hosts={data.data.hosts.filter(host => host.archived)} /></> : <div className="inline-empty">No completed scans have produced effective hosts yet.</div>}<Pagination page={data.data?.pagination} onChange={setOffset} /></div>}
  </section>
}

function useQueryHosts(q: string, protocol: string, open: string, offset: number) {
  // Kept as a small wrapper so the page's query key stays explicit and every
  // filter change naturally resets the result cache and pagination.
  return useQuery({ queryKey: ['hosts', q, protocol, open, offset], queryFn: ({ signal }) => listHosts({ q: q || undefined, protocol: protocol || undefined, has_open_ports: open === '' ? undefined : open === 'true', offset, signal }) })
}
