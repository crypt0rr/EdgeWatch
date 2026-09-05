import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import {
  Archive,
  CheckCircle2,
  Clock3,
  Edit3,
  Play,
  RotateCcw,
  ShieldAlert,
  Server,
  TimerReset,
} from 'lucide-react'
import {
  approveBaseline,
  archiveJob,
  deleteJob,
  getJob,
  jobScans,
  resetBaseline,
  restoreJob,
  runJob,
  scanDetail,
  scanHosts,
} from '../api'
import { Pagination } from '../components/Pagination'
import { ActionDialog } from '../components/ActionDialog'

type JobDialog = 'reset' | 'approve' | 'archive' | 'delete'

export function JobDetail() {
  const { id = '' } = useParams()
  const navigate = useNavigate()
  const client = useQueryClient()
  const [selectedScan, setSelectedScan] = useState('')
  const [scanOffset, setScanOffset] = useState(0)
  const [changeOffset, setChangeOffset] = useState(0)
  const [resultsOffset, setResultsOffset] = useState(0)
  const [showResults, setShowResults] = useState(false)
  const [actionError, setActionError] = useState('')
  const [actionBusy, setActionBusy] = useState('')
  const [dialog, setDialog] = useState<JobDialog | null>(null)
  const job = useQuery({ queryKey: ['job', id], queryFn: () => getJob(id) })
  const scans = useQuery({
    queryKey: ['job-scans', id, scanOffset],
    queryFn: () => jobScans(id, scanOffset),
    enabled: !!id,
    refetchInterval: 10000,
  })
  const detail = useQuery({
    queryKey: ['scan-detail', id, selectedScan, changeOffset],
    queryFn: () => scanDetail(id, selectedScan, changeOffset),
    enabled: !!selectedScan,
  })
  const results = useQuery({
    queryKey: ['scan-results', id, selectedScan, resultsOffset],
    queryFn: () => scanHosts(id, selectedScan, { offset: resultsOffset }),
    enabled: !!selectedScan && showResults,
  })

  if (job.isLoading) {
    return <div className="loading"><span className="spinner" />Loading job…</div>
  }
  if (job.error || !job.data) {
    return <div className="error-card">This job could not be found.</div>
  }

  const value = job.data
  function reportActionError(err: unknown, fallback: string) {
    setActionError(err instanceof Error ? err.message : fallback)
  }
  async function run() {
    setActionError('')
    setActionBusy('run')
    try {
      await runJob(id)
      await client.invalidateQueries({ queryKey: ['job-scans', id] })
      await client.invalidateQueries({ queryKey: ['jobs'] })
    } catch (err) {
      reportActionError(err, 'Could not start the scan.')
    } finally {
      setActionBusy('')
    }
  }
  async function reset() {
    setActionError('')
    setActionBusy('reset')
    try {
      await resetBaseline(id)
      await client.invalidateQueries({ queryKey: ['job', id] })
      setDialog(null)
    } catch (err) {
      reportActionError(err, 'Could not reset the baseline.')
    } finally {
      setActionBusy('')
    }
  }
  async function approve() {
    if (!detail.data) return
    setActionError('')
    setActionBusy('approve')
    try {
      await approveBaseline(id, detail.data.scan.id)
      await client.invalidateQueries({ queryKey: ['job', id] })
      setSelectedScan('')
      setDialog(null)
    } catch (err) {
      reportActionError(err, 'Could not approve this baseline.')
    } finally {
      setActionBusy('')
    }
  }
  async function archive() {
    setActionError('')
    setActionBusy('archive')
    try {
      await archiveJob(id, value.revision)
      setDialog(null)
      navigate('/jobs')
    } catch (err) {
      reportActionError(err, 'Could not archive this job.')
      setActionBusy('')
    }
  }
  async function restore() {
    setActionError('')
    setActionBusy('restore')
    try {
      await restoreJob(id, value.revision)
      await client.invalidateQueries({ queryKey: ['job', id] })
      await client.invalidateQueries({ queryKey: ['jobs'] })
    } catch (err) {
      reportActionError(err, 'Could not restore this job.')
    } finally {
      setActionBusy('')
    }
  }
  async function permanentlyDelete(confirmation: string) {
    setActionError('')
    setActionBusy('delete')
    try {
      await deleteJob(id, confirmation)
      setDialog(null)
      navigate('/jobs')
    } catch (err) {
      reportActionError(err, 'Could not permanently delete this job.')
      setActionBusy('')
    }
  }

  const selectedScanCanBeBaseline = Boolean(
    detail.data
      && detail.data.scan.status === 'success'
      && detail.data.scan.config_hash === detail.data.current_security_hash,
  )

  return (
    <section className="page">
      <div className="page-heading">
        <div>
          <Link className="back-link" to="/jobs">← Jobs</Link>
          <div className="title-row">
            <h1>{value.job.name}</h1>
            <span className={value.archived ? 'pill gray' : value.enabled ? 'pill green' : 'pill amber'}>
              {value.archived ? 'Archived' : value.enabled ? 'Scheduled' : 'Paused'}
            </span>
          </div>
          <p className="muted">Revision {value.revision} · Updated {new Date(value.updated_at).toLocaleString()}</p>
        </div>
        <div className="heading-actions">
          <button className="button secondary" onClick={run} disabled={value.archived || !!actionBusy}>
            <Play size={16} /> {actionBusy === 'run' ? 'Starting…' : 'Scan now'}
          </button>
          <button className="button secondary" onClick={() => navigate(`/jobs/${id}/edit`)} disabled={!!actionBusy}>
            <Edit3 size={16} /> Edit
          </button>
          {value.archived ? <><button className="button secondary" onClick={restore} disabled={!!actionBusy}>{actionBusy === 'restore' ? 'Restoring…' : 'Restore'}</button><button className="button danger" onClick={() => { setActionError(''); setDialog('delete') }} disabled={!!actionBusy}>{actionBusy === 'delete' ? 'Deleting…' : 'Delete permanently'}</button></> : <button className="icon-button danger" aria-label="Archive job" onClick={() => { setActionError(''); setDialog('archive') }} disabled={!!actionBusy}><Archive size={17} /></button>}
        </div>
      </div>
      {actionError && <div className="form-error banner" role="alert">{actionError}</div>}

      <div className="detail-summary">
        <div className="summary-card">
          <span className="summary-label">Baseline</span>
          <strong>{value.baseline.status === 'complete' ? 'Ready' : 'Learning'}</strong>
          <span className="muted">
            {value.baseline.status === 'complete'
              ? `Established from ${value.baseline.scan_id?.slice(0, 8) ?? 'scan'}`
              : `${value.baseline.samples ?? 0} of ${value.job.baseline_samples} samples`}
          </span>
        </div>
        <div className="summary-card">
          <span className="summary-label">Targets</span>
          <strong>{value.job.targets.length}</strong>
          <span className="muted">
            {value.job.targets.slice(0, 2).join(', ')}
            {value.job.targets.length > 2 ? ` +${value.job.targets.length - 2} more` : ''}
          </span>
        </div>
        <div className="summary-card">
          <span className="summary-label">Schedule</span>
          <strong>{value.job.schedule}</strong>
          <span className="muted">{value.job.timezone}</span>
        </div>
        <div className="summary-card">
          <span className="summary-label">Scope</span>
          <strong>{[value.job.tcp && 'TCP', value.job.udp && 'UDP'].filter(Boolean).join(' + ')}</strong>
          <span className="muted">{scopeText(value)}</span>
        </div>
      </div>
      {value.scan_estimate && <div className="notice" role="status">Estimated per run: {value.scan_estimate.probes.toLocaleString()} probes across {value.scan_estimate.hosts.toLocaleString()} hosts ({value.scan_estimate.nmap_invocations.toLocaleString()} Nmap process{value.scan_estimate.nmap_invocations === 1 ? '' : 'es'}, roughly {formatEstimateDuration(value.scan_estimate.estimated_seconds)}).{value.scan_estimate.unknown_dns ? ` DNS expansion may increase this estimate for ${value.scan_estimate.unknown_dns} name${value.scan_estimate.unknown_dns === 1 ? '' : 's'}.` : ''}</div>}

      <div className="detail-columns">
        <div className="panel">
          <div className="panel-heading">
            <div>
              <h2>Recent scans</h2>
              <p className="muted">Successful scans feed the baseline and change engine.</p>
            </div>
            <Clock3 size={18} className="muted-icon" />
          </div>
          {scans.isLoading ? <div className="skeleton-list" /> : scans.data?.scans.length ? (
            <div className="scan-list">
              {scans.data.scans.map((scan) => (
                <button
                  className={selectedScan === scan.id ? 'scan-row selected' : 'scan-row'}
                  key={scan.id}
                  onClick={() => { setSelectedScan(scan.id); setChangeOffset(0); setResultsOffset(0); setShowResults(false) }}
                >
                  <span className={scan.status === 'success' ? 'activity-dot success' : 'activity-dot fail'} />
                  <div>
                    <strong>{new Date(scan.finished_at).toLocaleString()}</strong>
                    <span>
                      {scan.status === 'success'
                        ? 'Completed successfully · Open results to inspect the snapshot'
                        : scan.error}
                    </span>
                  </div>
                  <code>{scan.id.slice(0, 8)}</code>
                </button>
              ))}
            </div>
          ) : <div className="inline-empty">No scans have run yet.</div>}
          <Pagination page={scans.data?.pagination} onChange={setScanOffset} />

          {selectedScan && detail.data && (
            <div className="scan-detail">
              <div className="panel-heading">
                <div>
                  <h3>Scan diff</h3>
                  <p className="muted">{detail.data.changes_pagination?.total ?? detail.data.changes?.length ?? 0} {detail.data.comparison_source === 'scan_time' ? 'changes recorded at scan time.' : 'changes against the current baseline.'}</p>
                </div>
                <div className="heading-actions">
                  {detail.data.scan.status === 'success' && <button className="button ghost" onClick={() => { setShowResults((shown) => !shown); setResultsOffset(0) }}>{showResults ? 'Hide results' : 'View results'}</button>}
                  <button className="icon-button" onClick={() => setSelectedScan('')} aria-label="Close scan detail">×</button>
                </div>
              </div>
              {selectedScanCanBeBaseline && (
                <div className="baseline-approval">
                  <span className="muted">This successful scan matches the current security scope.</span>
                  <button className="button secondary" onClick={() => { setActionError(''); setDialog('approve') }} disabled={!!actionBusy}>{actionBusy === 'approve' ? 'Approving…' : 'Use as baseline'}</button>
                </div>
              )}
              {detail.data.changes?.length ? (
                <div className="change-list">
                  {detail.data.changes.map((change, index) => (
                    <div className="change-row" key={`${change.kind}-${index}`}>
                      <span className={`pill ${change.severity === 'critical' ? 'red' : 'amber'}`}>{change.kind}</span>
                      <strong>{change.target}{change.port ? ` · ${change.protocol}:${change.port}` : ''}</strong>
                      <span className="muted">{change.old ?? '—'} → {change.new ?? '—'}</span>
                    </div>
                  ))}
                </div>
              ) : <div className="inline-empty">No changes detected.</div>}
              <Pagination page={detail.data?.changes_pagination} onChange={setChangeOffset} />
                {showResults && <div className="scan-results">
                <div className="panel-heading"><div><h3>Snapshot results</h3><p className="muted">Loaded on demand; open an effective host for technical evidence.</p></div></div>
                {results.isLoading ? <div className="skeleton-list" /> : results.error ? <div className="form-error" role="alert">Could not load scan results.</div> : results.data?.hosts.length ? <div className="result-list">{results.data.hosts.map((host) => <Link className="result-row" to={`/jobs/${id}/scans/${selectedScan}/hosts/${encodeURIComponent(host.address)}`} key={host.address}><strong>{host.address}</strong><span className="pill blue">{host.protocols?.map(protocol => protocol.protocol.toUpperCase()).join(' + ') || 'HOST'}</span><span className="muted">{host.open_ports + host.open_filtered_ports} positive ports · View host details</span></Link>)}</div> : <div className="inline-empty">No effective hosts in this scan.</div>}
                <Pagination page={results.data?.pagination} onChange={setResultsOffset} />
              </div>}
            </div>
          )}
        </div>

        <div className="panel">
          <div className="panel-heading">
            <div>
              <h2>Baseline controls</h2>
              <p className="muted">Scope hash changes require a deliberate reset.</p>
            </div>
            <ShieldAlert size={18} className="muted-icon" />
          </div>
          <div className="baseline-box">
            {value.baseline.status === 'complete' ? (
              <>
                <CheckCircle2 className="green-icon" size={22} />
                <div>
                  <strong>Baseline is active</strong>
                  <span className="muted">
                    New changes will be confirmed after {value.job.change_confirmations} matching scan{value.job.change_confirmations === 1 ? '' : 's'}.
                  </span>
                </div>
              </>
            ) : (
              <>
                <TimerReset className="amber-icon" size={22} />
                <div>
                  <strong>Baseline is learning</strong>
                  <span className="muted">Keep the target stable while {value.job.baseline_samples} samples converge.</span>
                </div>
              </>
            )}
          </div>
          <button className="button secondary" onClick={() => { setActionError(''); setDialog('reset') }} disabled={!!actionBusy}><RotateCcw size={16} /> {actionBusy === 'reset' ? 'Resetting…' : 'Reset baseline'}</button>
          {value.baseline.status === 'complete' && <Link className="button secondary explore-button" to={`/jobs/${id}/baseline`}><Server size={16} /> Explore baseline <span className="button-count">{value.baseline.host_count ?? 'hosts'}</span></Link>}
        </div>
      </div>
      {dialog === 'reset' && <ActionDialog title="Reset this baseline?" description="New scans will be learned before changes are reported. Existing history is preserved." confirmLabel="Reset baseline" destructive onConfirm={() => reset()} onCancel={() => { setDialog(null); setActionError('') }} error={actionError} />}
      {dialog === 'approve' && <ActionDialog title="Use this scan as the baseline?" description="This successful scan matches the current security scope. Future scans will compare against its results." confirmLabel="Use as baseline" onConfirm={() => approve()} onCancel={() => { setDialog(null); setActionError('') }} error={actionError} />}
      {dialog === 'archive' && <ActionDialog title="Archive this job?" description="The job will stop running, but its history and incidents will be kept." confirmLabel="Archive job" destructive onConfirm={() => archive()} onCancel={() => { setDialog(null); setActionError('') }} error={actionError} />}
      {dialog === 'delete' && <ActionDialog title="Delete this archived job permanently?" description="All retained history for this job will be removed. Type the job name exactly to continue." confirmLabel="Delete permanently" destructive valueLabel={`Type “${value.job.name}” to confirm`} valueType="text" valueRequired expectedValue={value.job.name} placeholder={value.job.name} autoComplete="off" onConfirm={permanentlyDelete} onCancel={() => { setDialog(null); setActionError('') }} error={actionError} />}
    </section>
  )
}

function scopeText(value: { job: { tcp?: { ports: string }; udp?: { ports: string } } }) {
  return [value.job.tcp && value.job.tcp.ports, value.job.udp && value.job.udp.ports].filter(Boolean).join(' · ')
}

function formatEstimateDuration(seconds: number) {
  if (seconds < 60) return `${seconds}s`
  const minutes = Math.ceil(seconds / 60)
  if (minutes < 60) return `${minutes}m`
  return `${Math.ceil(minutes / 60)}h`
}
