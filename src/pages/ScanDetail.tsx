import { useQuery } from '@tanstack/react-query'
import { Link, useParams } from 'react-router-dom'
import { Clock3, Server } from 'lucide-react'
import { getScan, historicalScanHosts } from '../api'
import { Pagination } from '../components/Pagination'
import { useState } from 'react'

/**
 * A small detail view for legacy scans that do not have a managed job ID.
 * Managed scans use JobDetail so they retain the job-scoped diff and baseline
 * controls; this route keeps every dashboard activity row actionable.
 */
export function ScanDetail() {
  const { scanId = '' } = useParams()
  const [offset, setOffset] = useState(0)
  const scan = useQuery({ queryKey: ['scan', scanId], queryFn: () => getScan(scanId), enabled: !!scanId })
  const hosts = useQuery({ queryKey: ['scan-hosts', scanId, offset], queryFn: () => historicalScanHosts(scanId, { offset }), enabled: !!scanId })

  if (scan.isLoading) return <div className="loading"><span className="spinner" />Loading scan…</div>
  if (scan.error || !scan.data) return <section className="page"><div className="error-card" role="alert">This scan could not be found.</div></section>
  const value = scan.data
  return <section className="page">
    <div className="page-heading"><div><Link className="back-link" to="/">← Overview</Link><p className="eyebrow">Historical scan</p><h1>{value.job}</h1><p className="muted">Scan {value.id}</p></div><Clock3 className="muted-icon" size={24} /></div>
    <div className="detail-summary"><div className="summary-card"><span className="summary-label">Status</span><strong>{value.status}</strong><span className="muted">{value.error || 'Recorded scan result'}</span></div><div className="summary-card"><span className="summary-label">Started</span><strong>{new Date(value.started_at).toLocaleString()}</strong></div><div className="summary-card"><span className="summary-label">Finished</span><strong>{new Date(value.finished_at).toLocaleString()}</strong></div><div className="summary-card"><span className="summary-label">Scanner</span><strong>{value.scanner_engine === 'naabu_nmap' ? 'Naabu → Nmap' : 'Nmap'}</strong><span className="muted">{value.nmap_version || 'Version unavailable'}</span></div></div>
    <div className="panel"><div className="panel-heading"><div><h2>Effective hosts</h2><p className="muted">Open a host for its detailed port evidence.</p></div><Server className="muted-icon" size={19} /></div>{hosts.isLoading ? <div className="loading"><span className="spinner" />Loading hosts…</div> : hosts.error ? <div className="error-card" role="alert">Could not load hosts for this scan.</div> : hosts.data?.hosts.length ? <div className="result-list">{hosts.data.hosts.map(host => <Link className="result-row" to={`/scans/${encodeURIComponent(value.id)}/hosts/${encodeURIComponent(host.address)}`} key={host.address}><strong>{host.address}</strong><span className="pill blue">{host.protocols?.map(protocol => protocol.protocol.toUpperCase()).join(' + ') || 'HOST'}</span><span className="muted">{host.open_ports + host.open_filtered_ports} positive ports · View host details</span></Link>)}</div> : <div className="inline-empty">No effective hosts were recorded for this scan.</div>}<Pagination page={hosts.data?.pagination} onChange={setOffset} /></div>
  </section>
}
