import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Code2, LockKeyhole, Plus, RotateCcw, Save, ShieldCheck, Trash2 } from 'lucide-react'
import { APIError, archiveScannerProfile, createScannerProfile, listScannerProfiles, restoreScannerProfile, updateScannerProfile, validateScannerProfile } from '../api'
import type { ScannerProfile, ScannerProfilePayload } from '../api'
import { ActionDialog } from '../components/ActionDialog'

type PreviewCommand = { executable: string; args: string[] }

const defaultBounds: Record<string, { min: number; max: number }> = {
  rate: { min: 1, max: 100000 }, workers: { min: 1, max: 1024 }, retries: { min: 0, max: 10 },
  timeout_ms: { min: 100, max: 60000 }, warm_up_seconds: { min: 0, max: 60 }, address_batch_size: { min: 1, max: 256 },
}
const adjustable = [...Object.keys(defaultBounds), 'scan_type', 'verify']
const empty: ScannerProfilePayload = {
  name: '', description: '', engine: 'nmap',
  naabu: { scan_type: 'connect', rate: 1000, workers: 25, retries: 3, timeout_ms: 1000, warm_up_seconds: 2, verify: true, address_batch_size: 16 },
  nmap_args: [], naabu_args: [], enrichment_args: [], operator_adjustable: [], operator_bounds: {},
}

function formatCommand(command: PreviewCommand) {
  return [command.executable, ...command.args].map(value => /^[A-Za-z0-9_./:=+,-]+$/.test(value) ? value : JSON.stringify(value)).join(' ')
}

export function ScannerProfiles() {
  const client = useQueryClient()
  const profiles = useQuery({ queryKey: ['scanner-profiles', true], queryFn: () => listScannerProfiles(true) })
  const [draft, setDraft] = useState<ScannerProfilePayload>(empty)
  const [editing, setEditing] = useState<ScannerProfile | null>(null)
  const [password, setPassword] = useState('')
  const [args, setArgs] = useState({ nmap: '', naabu: '', enrichment: '' })
  const [nseArgs, setNSEArgs] = useState('')
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)
  const [preview, setPreview] = useState<PreviewCommand[]>([])
  const [pendingLifecycle, setPendingLifecycle] = useState<{ profile: ScannerProfile; action: 'archive' | 'restore' } | null>(null)

  function reset() {
    setEditing(null)
    setDraft({ ...empty, naabu: { ...empty.naabu }, operator_adjustable: [], operator_bounds: {} })
    setArgs({ nmap: '', naabu: '', enrichment: '' })
    setNSEArgs('')
    setPassword('')
    setError('')
    setMessage('')
    setPreview([])
    setPendingLifecycle(null)
  }

  function select(profile: ScannerProfile) {
    const definition = profile.definition
    setEditing(profile)
    setDraft({
      name: profile.name, description: profile.description, engine: definition.engine, naabu: definition.naabu,
      nmap_args: definition.nmap_args, naabu_args: definition.naabu_args, enrichment_args: definition.enrichment_args,
      nse_profile: definition.nse_profile, operator_adjustable: definition.operator_adjustable,
      operator_bounds: definition.operator_bounds ?? {},
    })
    setArgs({ nmap: (definition.nmap_args ?? []).join('\n'), naabu: (definition.naabu_args ?? []).join('\n'), enrichment: (definition.enrichment_args ?? []).join('\n') })
    setNSEArgs(Object.entries(definition.nse_args ?? {}).map(([key, value]) => `${key}=${value}`).join('\n'))
    setPassword('')
    setError('')
    setMessage('')
    setPreview([])
  }

  function payload(): ScannerProfilePayload {
    const lines = (value: string) => value.split('\n').map(item => item.trim()).filter(Boolean)
    const structured = nseArgs.split('\n').map(item => item.trim()).filter(Boolean).reduce<Record<string, string>>((out, item) => {
      const separator = item.indexOf('=')
      if (separator > 0) out[item.slice(0, separator).trim()] = item.slice(separator + 1).trim()
      return out
    }, {})
    return { ...draft, nmap_args: lines(args.nmap), naabu_args: lines(args.naabu), enrichment_args: lines(args.enrichment), nse_args: structured, password }
  }

  async function save() {
    setSaving(true)
    setError('')
    setMessage('')
    try {
      const value = payload()
      if (editing) await updateScannerProfile(editing.id, value, editing.revision)
      else await createScannerProfile(value)
      await client.invalidateQueries({ queryKey: ['scanner-profiles'] })
      reset()
      // reset clears transient form state as well as the editor selection. Set
      // the confirmation after it so a successful save remains visible.
      setMessage('Scanner profile saved. Jobs keep their pinned revision until explicitly upgraded.')
    } catch (err) {
      setError(err instanceof APIError ? err.message : 'The scanner profile could not be saved.')
    } finally {
      setSaving(false)
    }
  }

  async function validate() {
    setError('')
    setMessage('')
    try {
      const result = await validateScannerProfile(payload())
      setPreview(result.preview ?? [])
      setMessage(result.valid ? 'Profile is valid. The preview uses fixed EdgeWatch executables and no shell.' : 'Profile is invalid.')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Validation failed.')
    }
  }

  function requestLifecycle(profile: ScannerProfile, action: 'archive' | 'restore') {
    setError('')
    setPendingLifecycle({ profile, action })
  }

  async function confirmLifecycle(confirmation: string) {
    if (!pendingLifecycle) return
    const { profile, action } = pendingLifecycle
    try {
      if (action === 'archive') await archiveScannerProfile(profile.id, profile.revision, confirmation)
      else await restoreScannerProfile(profile.id, profile.revision, confirmation)
      await client.invalidateQueries({ queryKey: ['scanner-profiles'] })
      if (editing?.id === profile.id) reset()
      setPendingLifecycle(null)
      setMessage(action === 'archive' ? 'Scanner profile archived.' : 'Scanner profile restored. Jobs still keep their pinned revision until explicitly upgraded.')
    } catch (err) {
      setError(err instanceof Error ? err.message : `The profile could not be ${action}d.`)
    }
  }

  const updateNaabu = (field: string, value: number | string | boolean) => setDraft(current => ({ ...current, naabu: { ...current.naabu, [field]: value } }))
  const toggleAdjustable = (field: string, checked: boolean) => {
    const selected = draft.operator_adjustable ?? []
    const next = checked ? [...selected, field] : selected.filter(value => value !== field)
    const bounds = { ...(draft.operator_bounds ?? {}) }
    if (checked && defaultBounds[field] && !bounds[field]) bounds[field] = defaultBounds[field]
    if (!checked) delete bounds[field]
    setDraft({ ...draft, operator_adjustable: next, operator_bounds: bounds })
  }

  return <section className="page">
    <div className="page-heading"><div><p className="eyebrow">Administration</p><h1>Scanner profiles</h1><p className="muted">Tune fixed Naabu and Nmap executables with validated argument arrays. Profiles are revisioned and never execute through a shell.</p></div><button className="button primary" onClick={reset}><Plus size={16} /> New profile</button></div>
    {message && <div className="success-banner" role="status"><ShieldCheck size={16} />{message}</div>}
    {error && <div className="form-error banner" role="alert">{error}</div>}
    <div className="dashboard-columns">
      <div className="panel"><div className="panel-heading"><div><h2>Available profiles</h2><p className="muted">Built-ins are immutable. Archived profiles remain available to existing jobs.</p></div><Code2 className="muted-icon" size={18} /></div>
        {profiles.isLoading ? <div className="loading"><span className="spinner" />Loading profiles…</div> : <div className="activity-list">{profiles.data?.profiles.map(profile => <div className="activity-row" key={profile.id}><div><strong>{profile.name}</strong><span>{profile.definition.engine === 'naabu_nmap' ? 'Naabu full TCP → Nmap' : 'Nmap'} · revision {profile.revision}{profile.archived ? ' · archived' : ''}</span></div><span className={profile.built_in ? 'pill blue' : profile.archived ? 'pill gray' : 'pill green'}>{profile.built_in ? 'Built-in' : profile.archived ? 'Archived' : 'Managed'}</span>{!profile.built_in && <><button className="icon-button" aria-label={`Edit ${profile.name}`} onClick={() => select(profile)}><Save size={15} /></button>{profile.archived ? <button className="icon-button" aria-label={`Restore ${profile.name}`} onClick={() => requestLifecycle(profile, 'restore')}><RotateCcw size={15} /></button> : <button className="icon-button" aria-label={`Archive ${profile.name}`} onClick={() => requestLifecycle(profile, 'archive')}><Trash2 size={15} /></button>}</>}</div>)}</div>}
      </div>
      <div className="panel form-panel"><div className="panel-heading"><div><h2>{editing ? `Edit ${editing.name}` : 'Create profile'}</h2><p className="muted">Password confirmation is required for every mutation.</p></div><LockKeyhole className="muted-icon" size={18} /></div>
        <label>Name<input value={draft.name ?? ''} onChange={event => setDraft({ ...draft, name: event.target.value })} placeholder="Careful Naabu defaults" /></label>
        <label>Description<textarea value={draft.description ?? ''} onChange={event => setDraft({ ...draft, description: event.target.value })} /></label>
        <label>Engine<select value={draft.engine} onChange={event => setDraft({ ...draft, engine: event.target.value })}><option value="nmap">Nmap only</option><option value="naabu_nmap">Naabu discovery → Nmap</option></select></label>
        {draft.engine === 'naabu_nmap' && <div className="two-fields">
          <label>Discovery type<select value={draft.naabu?.scan_type ?? 'connect'} onChange={event => updateNaabu('scan_type', event.target.value)}><option value="connect">Connect</option><option value="syn">SYN (NET_ADMIN + NET_RAW)</option></select></label>
          <label>Rate<input type="number" min={1} max={100000} value={draft.naabu?.rate ?? 1000} onChange={event => updateNaabu('rate', Number(event.target.value))} /></label>
          <label>Workers<input type="number" min={1} max={1024} value={draft.naabu?.workers ?? 25} onChange={event => updateNaabu('workers', Number(event.target.value))} /></label>
          <label>Retries<input type="number" min={0} max={10} value={draft.naabu?.retries ?? 3} onChange={event => updateNaabu('retries', Number(event.target.value))} /></label>
          <label>Probe timeout (ms)<input type="number" min={100} max={60000} value={draft.naabu?.timeout_ms ?? 1000} onChange={event => updateNaabu('timeout_ms', Number(event.target.value))} /></label>
          <label>Warm-up (seconds)<input type="number" min={0} max={60} value={draft.naabu?.warm_up_seconds ?? 2} onChange={event => updateNaabu('warm_up_seconds', Number(event.target.value))} /></label>
          <label>Address batch size<input type="number" min={1} max={256} value={draft.naabu?.address_batch_size ?? 16} onChange={event => updateNaabu('address_batch_size', Number(event.target.value))} /></label>
          <label className="switch-row"><input type="checkbox" checked={draft.naabu?.verify ?? true} onChange={event => updateNaabu('verify', event.target.checked)} /><span><strong>Verify discoveries</strong><small>Ask Naabu to re-check discovered ports.</small></span></label>
        </div>}
        <label>NSE profile<select value={draft.nse_profile ?? ''} onChange={event => setDraft({ ...draft, nse_profile: event.target.value })}><option value="">No NSE scripts</option><option value="banner">banner</option><option value="http-title">http-title</option><option value="http-headers">http-headers</option><option value="ssl-cert">ssl-cert</option><option value="ssh-hostkey">ssh-hostkey</option><option value="dns-recursion">dns-recursion</option></select></label>
        <label>NSE arguments<textarea value={nseArgs} onChange={event => setNSEArgs(event.target.value)} placeholder="One safe key=value per line (optional)" /><small>Values are scalar and validated; paths, wildcards, boolean expressions, and @files are rejected.</small></label>
        <label>Nmap argument array<textarea value={args.nmap} onChange={event => setArgs({ ...args, nmap: event.target.value })} placeholder="Required placeholders: {address(es)}, {ports}, {structured_output}" /></label>
        {draft.engine === 'naabu_nmap' && <label>Naabu argument array<textarea value={args.naabu} onChange={event => setArgs({ ...args, naabu: event.target.value })} placeholder="Required placeholders: {targets_file}, {ports}, {structured_output}" /></label>}
        <label>Enrichment argument array<textarea value={args.enrichment} onChange={event => setArgs({ ...args, enrichment: event.target.value })} placeholder="Required placeholders: {address(es)}, {ports}, {structured_output}" /></label>
        <fieldset><legend>Operator-adjustable fields</legend><div className="two-fields">{adjustable.map(field => <label key={field} className="switch-row"><input type="checkbox" checked={(draft.operator_adjustable ?? []).includes(field)} onChange={event => toggleAdjustable(field, event.target.checked)} /><span><strong>{field}</strong><small>Permit job-level tuning within bounds</small></span></label>)}</div><p className="helper">Bounds use the product safety limits by default; the API validates any administrator changes.</p></fieldset>
        {preview.length > 0 && <div className="scanner-preview" role="region" aria-label="Effective command preview"><h3>Effective command preview</h3><p className="helper">Documentation-only examples use fixed EdgeWatch executables and safe sample values. They are never executed.</p>{preview.map((command, index) => <pre key={`${command.executable}-${index}`}><code>{formatCommand(command)}</code></pre>)}</div>}
        <label>Password confirmation<input type="password" value={password} onChange={event => setPassword(event.target.value)} autoComplete="current-password" /></label>
        <div className="heading-actions"><button className="button secondary" type="button" onClick={validate}>Validate & preview</button><button className="button primary" type="button" disabled={saving} onClick={save}><Save size={16} />{saving ? 'Saving…' : editing ? 'Save revision' : 'Create profile'}</button></div>
      </div>
    </div>
    {pendingLifecycle && <ActionDialog
      title={`${pendingLifecycle.action === 'archive' ? 'Archive' : 'Restore'} “${pendingLifecycle.profile.name}”?`}
      description={pendingLifecycle.action === 'archive' ? 'The profile will stop appearing for new jobs. Existing jobs keep their pinned revision.' : 'The profile will become available for new jobs again. Existing jobs keep their pinned revision.'}
      confirmLabel={pendingLifecycle.action === 'archive' ? 'Archive profile' : 'Restore profile'}
      destructive={pendingLifecycle.action === 'archive'}
      valueLabel="Administrator password"
      valueType="password"
      valueRequired
      autoComplete="current-password"
      onConfirm={confirmLifecycle}
      onCancel={() => { setPendingLifecycle(null); setError('') }}
      error={error}
    />}
  </section>
}
