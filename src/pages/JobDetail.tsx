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
} from '../api'
import { Pagination } from '../components/Pagination'

export function JobDetail() {
  const { id = '' } = useParams()
  const navigate = useNavigate()
  const client = useQueryClient()
  const [selectedScan, setSelectedScan] = useState('')
  const [scanOffset, setScanOffset] = useState(0)
  const [changeOffset, setChangeOffset] = useState(0)
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

  if (job.isLoading) {
    return <div className="loading"><span className="spinner" />Loading job…</div>
  }
  if (job.error || !job.data) {
    return <div className="error-card">This job could not be found.</div>
  }

  const value = job.data
  async function run() {
    await runJob(id)
    client.invalidateQueries({ queryKey: ['job-scans', id] })
    client.invalidateQueries({ queryKey: ['jobs'] })
  }
  async function reset() {
    if (!window.confirm('Reset this baseline? New scans will be learned before changes are reported.')) return
    await resetBaseline(id)
    client.invalidateQueries({ queryKey: ['job', id] })
  }
  async function approve() {
    if (!detail.data || !window.confirm('Use this successful scan as the baseline for the current scope?')) return
    await approveBaseline(id, detail.data.scan.id)
    client.invalidateQueries({ queryKey: ['job', id] })
    setSelectedScan('')
  }
  async function archive() {
    if (!window.confirm('Archive this job? History will be kept.')) return
    await archiveJob(id, value.revision)
    navigate('/jobs')
  }
  async function restore() {
    await restoreJob(id, value.revision)
    client.invalidateQueries({ queryKey: ['job', id] })
    client.invalidateQueries({ queryKey: ['jobs'] })
  }
  async function permanentlyDelete() {
    const confirmation = window.prompt(`Type ${value.job.name} to permanently delete this archived job and all retained history.`)
    if (confirmation !== value.job.name) return
    await deleteJob(id, confirmation)
    navigate('/jobs')
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
          <button className="button secondary" onClick={run} disabled={value.archived}>
            <Play size={16} /> Scan now
          </button>
          <button className="button secondary" onClick={() => navigate(`/jobs/${id}/edit`)}>
            <Edit3 size={16} /> Edit
          </button>
          {value.archived ? <><button className="button secondary" onClick={restore}>Restore</button><button className="button danger" onClick={permanentlyDelete}>Delete permanently</button></> : <button className="icon-button danger" aria-label="Archive job" onClick={archive}><Archive size={17} /></button>}
        </div>
      </div>

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
                  onClick={() => { setSelectedScan(scan.id); setChangeOffset(0) }}
                >
                  <span className={scan.status === 'success' ? 'activity-dot success' : 'activity-dot fail'} />
                  <div>
                    <strong>{new Date(scan.finished_at).toLocaleString()}</strong>
                    <span>
                      {scan.status === 'success'
                        ? `${scan.snapshot.units.reduce((n, unit) => n + (unit.ports?.length ?? 0), 0)} open ports observed`
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
                  <p className="muted">{detail.data.changes_pagination?.total ?? detail.data.changes?.length ?? 0} changes against the current baseline.</p>
                </div>
                <button className="icon-button" onClick={() => setSelectedScan('')} aria-label="Close scan detail">×</button>
              </div>
              {selectedScanCanBeBaseline && (
                <div className="baseline-approval">
                  <span className="muted">This successful scan matches the current security scope.</span>
                  <button className="button secondary" onClick={approve}>Use as baseline</button>
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
          <button className="button secondary" onClick={reset}><RotateCcw size={16} /> Reset baseline</button>
        </div>
      </div>
    </section>
  )
}

function scopeText(value: { job: { tcp?: { ports: string }; udp?: { ports: string } } }) {
  return [value.job.tcp && value.job.tcp.ports, value.job.udp && value.job.udp.ports].filter(Boolean).join(' · ')
}
