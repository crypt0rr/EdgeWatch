import { useEffect, useRef, useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, ChevronDown, Info, Plus, Save, Trash2, TriangleAlert } from 'lucide-react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { APIError, createJob, getJob, scheduleSuggestion, updateJob } from '../api'
import type { JobForm, Protocol } from '../types'
import { cidrWarning, duplicateTarget, targetKind } from '../target'
import { ActionDialog } from '../components/ActionDialog'

const blank: JobForm = {
  name: '',
  schedule: '0 */6 * * *',
  timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC',
  run_on_start: true,
  assume_alive: true,
  targets: [''],
  max_expanded_hosts: 256,
  timing: 'balanced',
  timeout: '1h',
  baseline_samples: 2,
  change_confirmations: 1,
  allow_high_cost: false,
  enabled: true,
}

const jobFormSchema = z.object({
  name: z.string().trim().min(1, 'A name is required.'),
  schedule: z.string().trim().min(1, 'A cron schedule is required.'),
  timezone: z.string().trim().min(1, 'A timezone is required.'),
  run_on_start: z.boolean().optional(),
  assume_alive: z.boolean().optional(),
  max_expanded_hosts: z.number().int('Use a whole number of hosts.').min(1, 'Use at least one host.').max(1_000_000, 'The expansion limit is too high.'),
  timing: z.string().refine((value) => ['conservative', 'balanced', 'fast'].includes(value), 'Choose a valid timing profile.'),
  timeout: z.string().trim().min(1, 'A scan timeout is required.'),
  baseline_samples: z.number().int('Use a whole number of samples.').min(1, 'Use at least one baseline sample.').max(100, 'Use no more than 100 baseline samples.'),
  change_confirmations: z.number().int('Use a whole number of confirmations.').min(1, 'Use at least one confirmation.').max(100, 'Use no more than 100 confirmations.'),
  allow_high_cost: z.boolean().optional(),
  enabled: z.boolean().optional(),
})
type JobFormFields = z.infer<typeof jobFormSchema>

export function JobEditor() {
  const { id } = useParams()
  const edit = !!id
  const navigate = useNavigate()
  const client = useQueryClient()
  const existing = useQuery({ queryKey: ['job', id], queryFn: () => getJob(id!), enabled: edit })
  const [targets, setTargets] = useState<string[]>(blank.targets)
  const [tcp, setTCP] = useState<Protocol | undefined>({ ports: '1-1024', mode: 'syn', service_detection: false })
  const [udp, setUDP] = useState<Protocol | undefined>()
  const [scheduleEnabled, setScheduleEnabled] = useState(true)
  const [error, setError] = useState('')
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})
  const [saving, setSaving] = useState(false)
  const [draftDirty, setDraftDirty] = useState(false)
  const [suggestionInput, setSuggestionInput] = useState({ schedule: blank.schedule, timezone: blank.timezone })
  const [dismissedSuggestion, setDismissedSuggestion] = useState('')
  const [remoteRevision, setRemoteRevision] = useState<number | null>(null)
  const [rebaselinePrompt, setRebaselinePrompt] = useState<{ values: JobFormFields; summary: string } | null>(null)
  const loadedRevision = useRef<{ id?: string; revision: number } | null>(null)
  const { register, handleSubmit, reset, watch, setValue, formState: { errors: formErrors, isDirty } } = useForm<JobFormFields>({
    defaultValues: blank,
    resolver: zodResolver(jobFormSchema),
  })
  const schedule = watch('schedule')
  const timezone = watch('timezone')
  const timing = watch('timing')

  useEffect(() => {
    if (edit) return
    const timer = window.setTimeout(() => setSuggestionInput({ schedule: schedule.trim(), timezone: timezone.trim() }), 350)
    return () => window.clearTimeout(timer)
  }, [edit, schedule, timezone])

  const suggestionReady = !edit && suggestionInput.schedule.split(/\s+/).length === 5 && !!suggestionInput.timezone
  const suggestionQuery = useQuery({
    queryKey: ['schedule-suggestion', suggestionInput.schedule, suggestionInput.timezone],
    queryFn: () => scheduleSuggestion(suggestionInput.schedule, suggestionInput.timezone),
    enabled: suggestionReady,
    staleTime: 15_000,
    retry: false,
  })
  const currentSuggestion = suggestionInput.schedule === schedule.trim() && suggestionInput.timezone === timezone.trim() ? suggestionQuery.data : undefined
  const suggestionKey = currentSuggestion?.nearest ? `${currentSuggestion.nearest.id}:${suggestionInput.schedule}:${suggestionInput.timezone}` : ''
  const showSuggestion = !!currentSuggestion?.suggested && suggestionKey !== dismissedSuggestion

  const hasDraftChanges = isDirty || draftDirty
  const applyServerJob = (data: NonNullable<typeof existing.data>) => {
    reset(data.job)
    setTargets(data.job.targets)
    setTCP(data.job.tcp)
    setUDP(data.job.udp)
    setScheduleEnabled(data.enabled)
    loadedRevision.current = { id, revision: data.revision }
    setRemoteRevision(null)
    setDraftDirty(false)
  }

  useEffect(() => {
    if (!existing.data) return
    if (!loadedRevision.current || loadedRevision.current.id !== id) {
      applyServerJob(existing.data)
      return
    }
    if (existing.data.revision === loadedRevision.current.revision) return
    if (hasDraftChanges) {
      setRemoteRevision(existing.data.revision)
      return
    }
    applyServerJob(existing.data)
  }, [existing.data, id, hasDraftChanges, reset])

  const save = async (values: JobFormFields, confirm = false) => {
    setFieldErrors({})
    const normalizedTargets = targets.map((value) => value.trim()).filter(Boolean)
    const duplicate = duplicateTarget(normalizedTargets)
    if (duplicate) {
      setFieldErrors({ targets: `Target ${duplicate} is listed more than once.` })
      setError(`Target ${duplicate} is listed more than once.`)
      return
    }
    if (!normalizedTargets.length) {
      setFieldErrors({ targets: 'Add at least one IP, CIDR, or DNS target.' })
      setError('Add at least one IP, CIDR, or DNS target.')
      return
    }
    if (!tcp && !udp) {
      setFieldErrors({ protocols: 'Enable TCP, UDP, or both scan types.' })
      setError('Enable TCP, UDP, or both scan types.')
      return
    }
    if (edit && remoteRevision !== null) {
      setError('This job changed in another tab. Reload the saved version before continuing.')
      return
    }
    const payload = { ...values, enabled: scheduleEnabled, targets: normalizedTargets, tcp, udp }
    setSaving(true)
    setError('')
    try {
      if (edit) {
        await updateJob(id!, loadedRevision.current?.revision ?? existing.data!.revision, payload, confirm)
      } else {
        await createJob(payload)
      }
      await client.invalidateQueries({ queryKey: ['jobs'] })
      navigate(edit ? `/jobs/${id}` : '/jobs')
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Could not save job'
      if (err instanceof APIError && err.code === 'validation_failed') {
        const details = Object.entries(err.details ?? {}).reduce<Record<string, string>>((out, [key, value]) => {
          if (typeof value === 'string') out[key] = value
          return out
        }, {})
        setFieldErrors(details)
      }
      if (!confirm && (message.includes('rebaseline') || (err instanceof APIError && err.code === 'rebaseline_confirmation_required'))) {
        const changes = err instanceof APIError && Array.isArray(err.details?.changes) ? err.details.changes.filter((change): change is string => typeof change === 'string') : []
        const summary = changes.length ? `\n\nScope changes:\n• ${changes.join('\n• ')}` : ''
        setRebaselinePrompt({ values, summary })
      } else {
        setError(message)
      }
    } finally {
      setSaving(false)
    }
  }

  if (edit && existing.isLoading) {
    return <div className="loading"><span className="spinner" />Loading job…</div>
  }

  return (
    <section className="page">
      <div className="page-heading">
        <div>
          <Link className="back-link" to={edit ? `/jobs/${id}` : '/jobs'}><ArrowLeft size={15} /> {edit ? 'Back to job' : 'Back to jobs'}</Link>
          <p className="eyebrow">{edit ? 'Edit configuration' : 'New configuration'}</p>
          <h1>{edit ? 'Tune your monitoring job' : 'Create a monitoring job'}</h1>
          <p className="muted">Choose a clear scope. EdgeWatch will validate targets before it saves.</p>
        </div>
      </div>

      <form className="editor" onSubmit={handleSubmit((values) => save(values))}>
        <div className="editor-main">
          <div className="panel form-panel">
            <div className="panel-heading"><div><h2>Basics</h2><p className="muted">A name and the systems this job should watch.</p></div></div>
            <label>Job name<input {...register('name')} placeholder="Production edge" />{(formErrors.name?.message || fieldErrors.name) && <small className="field-error">{formErrors.name?.message || fieldErrors.name}</small>}</label>
            <div className="field-section">
              <div className="field-title"><span>Targets</span><span className="field-help">IP · CIDR · DNS</span></div>
              <p className="helper">One target per row. CIDRs are expanded at scan time and DNS names are resolved for every scan.</p>
              <div className="target-list">
                {targets.map((target, index) => <TargetRow key={index} value={target} index={index} total={targets.length} onChange={(value) => { setDraftDirty(true); setTargets((items) => items.map((item, i) => i === index ? value : item)) }} onRemove={() => { setDraftDirty(true); setTargets((items) => items.filter((_, i) => i !== index)) }} />)}
              </div>
              <button type="button" className="text-button add-target" onClick={() => { setDraftDirty(true); setTargets((items) => [...items, '']) }}><Plus size={15} /> Add target</button>
              {targets.some((target) => cidrWarning(target)) && <div className="notice warning"><TriangleAlert size={16} /><span>{targets.map(cidrWarning).find(Boolean)}</span></div>}
              {(fieldErrors.targets || fieldErrors.target) && <small className="field-error">{fieldErrors.targets || fieldErrors.target}</small>}
            </div>
            <label className="inline-field">Maximum expanded hosts <span className="input-suffix"><input type="number" min={1} max={1000000} {...register('max_expanded_hosts', { valueAsNumber: true })} /><em>hosts</em></span>{(formErrors.max_expanded_hosts?.message || fieldErrors.max_expanded_hosts) && <small className="field-error">{formErrors.max_expanded_hosts?.message || fieldErrors.max_expanded_hosts}</small>}</label>
            <label className="switch-row"><input type="checkbox" {...register('allow_high_cost')} /><span><strong>Allow high-cost scans</strong><small>Override the deployment probe budget for deliberately broad scopes. The estimated cost is shown after saving.</small></span></label>
            <div className="notice"><Info size={16} /><span>Large CIDRs can take a long time to scan. The expansion limit protects the host from accidental wide scopes.</span></div>
          </div>

          <div className="panel form-panel">
            <div className="panel-heading"><div><h2>Scan types</h2><p className="muted">Enable one or both protocols and set their options independently.</p></div></div>
            <ProtocolCard label="TCP" enabled={!!tcp} onToggle={(enabled) => { setDraftDirty(true); setTCP(enabled ? { ports: '1-1024', mode: 'syn', service_detection: false } : undefined) }} protocol={tcp} setProtocol={(value) => { setDraftDirty(true); setTCP(value) }} />
            <ProtocolCard label="UDP" enabled={!!udp} onToggle={(enabled) => { setDraftDirty(true); setUDP(enabled ? { ports: '53', service_detection: true } : undefined) }} protocol={udp} setProtocol={(value) => { setDraftDirty(true); setUDP(value) }} />
            {fieldErrors.protocols && <small className="field-error">{fieldErrors.protocols}</small>}
            {fieldErrors.tcp && <small className="field-error">{fieldErrors.tcp}</small>}
            {fieldErrors.udp && <small className="field-error">{fieldErrors.udp}</small>}
            {fieldErrors.ports && <small className="field-error">{fieldErrors.ports}</small>}
          </div>

          <div className="panel form-panel">
            <div className="panel-heading"><div><h2>Baseline & change detection</h2><p className="muted">Stable samples prevent one-off network noise from becoming an incident.</p></div></div>
            <div className="two-fields">
              <label>Baseline samples<input type="number" min={1} max={100} {...register('baseline_samples', { valueAsNumber: true })} />{(formErrors.baseline_samples?.message || fieldErrors.baseline) && <small className="field-error">{formErrors.baseline_samples?.message || fieldErrors.baseline}</small>}<small>Scans required before the baseline is ready.</small></label>
              <label>Change confirmations<input type="number" min={1} max={100} {...register('change_confirmations', { valueAsNumber: true })} />{(formErrors.change_confirmations?.message || fieldErrors.confirmations) && <small className="field-error">{formErrors.change_confirmations?.message || fieldErrors.confirmations}</small>}<small>Matching scans before an incident opens.</small></label>
            </div>
          </div>
        </div>

        <aside className="editor-side">
          <div className="panel form-panel sticky">
            <div className="panel-heading"><div><h2>Schedule</h2><p className="muted">When should this job run?</p></div><ChevronDown size={17} className="muted-icon" /></div>
            <label>Preset<select value={presetFor(schedule)} onChange={(event) => { if (event.target.value !== 'custom') { setDraftDirty(true); setValue('schedule', event.target.value, { shouldDirty: true }) } }}><option value="0 */6 * * *">Every 6 hours</option><option value="0 * * * *">Every hour</option><option value="0 3 * * *">Daily at 03:00</option><option value="0 3 * * 0">Weekly on Sunday</option><option value="custom">Custom cron</option></select></label>
            <label>Five-field cron<input {...register('schedule')} placeholder="minute hour day month weekday" />{(formErrors.schedule?.message || fieldErrors.schedule) && <small className="field-error">{formErrors.schedule?.message || fieldErrors.schedule}</small>}<small>Uses the server’s standard cron parser.</small></label>
            <label>Timezone<input {...register('timezone')} placeholder="Europe/Amsterdam" />{(formErrors.timezone?.message || fieldErrors.timezone) && <small className="field-error">{formErrors.timezone?.message || fieldErrors.timezone}</small>}</label>
            {showSuggestion && currentSuggestion?.nearest && <div className="notice schedule-suggestion" role="status"><Info size={16} /><div className="schedule-suggestion-copy"><strong>Stagger scheduled scans</strong><span>{currentSuggestion.nearest.name} is next at {formatSuggestionTime(currentSuggestion.nearest.next_run)} ({currentSuggestion.nearest.timezone}; {formatGap(currentSuggestion.gap_minutes)}). Starting 30 minutes {currentSuggestion.offset_minutes && currentSuggestion.offset_minutes < 0 ? 'earlier' : 'later'} keeps scheduled work apart.</span><small>You can keep this schedule when overlapping runs are intentional.</small></div>{currentSuggestion.suggested_schedule && <button type="button" className="button secondary" onClick={() => { setDraftDirty(true); setDismissedSuggestion(suggestionKey); setValue('schedule', currentSuggestion.suggested_schedule!, { shouldDirty: true, shouldValidate: true }) }}>Use {currentSuggestion.offset_minutes && currentSuggestion.offset_minutes < 0 ? 'earlier' : 'later'} time</button>}</div>}
            <label className="switch-row"><input type="checkbox" checked={scheduleEnabled} onChange={(event) => { setDraftDirty(true); setScheduleEnabled(event.target.checked) }} /><span><strong>Schedule enabled</strong><small>Pause future scheduled runs without archiving this job.</small></span></label>
            <label className="switch-row"><input type="checkbox" {...register('run_on_start')} /><span><strong>Run on startup</strong><small>Start a scan when EdgeWatch launches.</small></span></label>
            <label className="switch-row"><input type="checkbox" {...register('assume_alive')} /><span><strong>Assume targets are alive</strong><small>Use Nmap <code>-Pn</code>. Turn off to use host discovery.</small></span></label>
            <label>Timing profile<select {...register('timing')}><option value="conservative">Conservative (T2)</option><option value="balanced">Balanced (T3)</option><option value="fast">Fast (T4)</option></select>{(formErrors.timing?.message || fieldErrors.timing) && <small className="field-error">{formErrors.timing?.message || fieldErrors.timing}</small>}</label>
            <label>Scan timeout<input {...register('timeout')} placeholder="1h" />{(formErrors.timeout?.message || fieldErrors.timeout) && <small className="field-error">{formErrors.timeout?.message || fieldErrors.timeout}</small>}<small>Examples: 30m, 1h, 2d.</small></label>
            {remoteRevision !== null && <div className="notice warning" role="alert"><TriangleAlert size={16} /><span>This job was saved elsewhere while you were editing. Your draft is preserved. <button type="button" className="link-button" onClick={() => existing.data && applyServerJob(existing.data)}>Reload saved version</button></span></div>}
            {timing === 'fast' && <div className="notice warning"><TriangleAlert size={16} /><span>Fast timing can miss responses on congested or filtered networks.</span></div>}
            {error && <div className="form-error" role="alert">{error}</div>}
            <button disabled={saving} className="button primary wide" type="submit"><Save size={16} />{saving ? 'Saving…' : edit ? 'Save changes' : 'Create job'}</button>
            <button type="button" className="button ghost wide" onClick={() => navigate(edit ? `/jobs/${id}` : '/jobs')}>Cancel</button>
          </div>
        </aside>
      </form>
      {rebaselinePrompt && <ActionDialog title="Confirm scan-scope change" description={`This changes the scan scope. The current baseline and active incidents will be cleared, and a new baseline will be learned.${rebaselinePrompt.summary}`} confirmLabel="Reset baseline and save" destructive onConfirm={async () => { await save(rebaselinePrompt.values, true) }} onCancel={() => { setRebaselinePrompt(null); setError('Scope change cancelled.') }} error={error} />}
    </section>
  )
}

function TargetRow({ value, index, total, onChange, onRemove }: { value: string; index: number; total: number; onChange: (value: string) => void; onRemove: () => void }) {
  return <div className="target-row"><input value={value} onChange={(event) => onChange(event.target.value)} placeholder={index === 0 ? '192.168.1.1 or 10.0.0.0/24 or router.example.com' : 'Add another target'} aria-label={`Target ${index + 1}`} /><span className="target-kind">{targetKind(value)}</span>{total > 1 && <button type="button" className="icon-button" aria-label="Remove target" onClick={onRemove}><Trash2 size={15} /></button>}</div>
}

function ProtocolCard({ label, enabled, onToggle, protocol, setProtocol }: { label: string; enabled: boolean; onToggle: (enabled: boolean) => void; protocol?: Protocol; setProtocol: (value: Protocol | undefined) => void }) {
  return <div className={enabled ? 'protocol-card enabled' : 'protocol-card'}><div className="protocol-header"><label className="switch-row protocol-toggle"><input type="checkbox" checked={enabled} onChange={(event) => onToggle(event.target.checked)} /><span><strong>{label} scan</strong><small>{enabled ? 'Included in this job' : 'Not included'}</small></span></label><span className={enabled ? 'pill blue' : 'pill gray'}>{enabled ? 'On' : 'Off'}</span></div>{enabled && protocol && <div className="protocol-options"><label>Ports<input value={protocol.ports} onChange={(event) => setProtocol({ ...protocol, ports: event.target.value })} placeholder="1-1024,8080" /><small>Ranges and comma-separated ports, 1–65535.</small></label>{label === 'TCP' && <label>Connection mode<select value={protocol.mode ?? 'syn'} onChange={(event) => setProtocol({ ...protocol, mode: event.target.value })}><option value="syn">SYN (requires NET_RAW)</option><option value="connect">TCP connect</option></select></label>}<label className="switch-row"><input type="checkbox" checked={protocol.service_detection} onChange={(event) => setProtocol({ ...protocol, service_detection: event.target.checked })} /><span><strong>Service detection</strong><small>Identify likely services on open ports.</small></span></label></div>}</div>
}

function presetFor(schedule: string) {
  return ['0 */6 * * *', '0 * * * *', '0 3 * * *', '0 3 * * 0'].includes(schedule) ? schedule : 'custom'
}

function formatSuggestionTime(value: string) {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return 'the next scheduled run'
  return date.toLocaleString(undefined, { weekday: 'short', hour: '2-digit', minute: '2-digit' })
}

function formatGap(minutes: number) {
  if (minutes <= 0) return 'at the same time'
  return `${minutes} minute${minutes === 1 ? '' : 's'} apart`
}
