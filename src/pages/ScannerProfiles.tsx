import { useEffect, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, Code2, LockKeyhole, Plus, RotateCcw, Save, ShieldCheck, Trash2 } from 'lucide-react'
import { APIError, archiveScannerProfile, createScannerProfile, getSession, listScannerProfiles, restoreScannerProfile, updateScannerProfile, validateScannerProfile } from '../api'
import type { ScannerProfile, ScannerProfilePayload } from '../api'
import { ActionDialog } from '../components/ActionDialog'
import { ErrorNotice } from '../components/ErrorNotice'
import { useServerDraft } from '../hooks/useServerDraft'

type PreviewCommand = { executable: string; args: string[] }
type ScannerEditorDraft = {
  payload: ScannerProfilePayload
  args: { nmap: string; naabu: string; enrichment: string }
  nseArgs: string
}

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

function emptyScannerEditorDraft(): ScannerEditorDraft {
  return { payload: { ...empty, naabu: { ...empty.naabu }, operator_adjustable: [], operator_bounds: {} }, args: { nmap: '', naabu: '', enrichment: '' }, nseArgs: '' }
}

function scannerEditorDraft(profile: ScannerProfile): ScannerEditorDraft {
  const definition = profile.definition
  return {
    payload: {
      name: profile.name, description: profile.description, engine: definition.engine, naabu: { ...definition.naabu },
      nmap_args: [...(definition.nmap_args ?? [])], naabu_args: [...(definition.naabu_args ?? [])], enrichment_args: [...(definition.enrichment_args ?? [])],
      nse_profile: definition.nse_profile, operator_adjustable: [...(definition.operator_adjustable ?? [])],
      operator_bounds: { ...(definition.operator_bounds ?? {}) },
    },
    args: { nmap: (definition.nmap_args ?? []).join('\n'), naabu: (definition.naabu_args ?? []).join('\n'), enrichment: (definition.enrichment_args ?? []).join('\n') },
    nseArgs: Object.entries(definition.nse_args ?? {}).map(([key, value]) => `${key}=${value}`).join('\n'),
  }
}

function formatCommand(command: PreviewCommand) {
  return [command.executable, ...command.args].map(value => /^[A-Za-z0-9_./:=+,-]+$/.test(value) ? value : JSON.stringify(value)).join(' ')
}

export function ScannerProfiles() {
  const client = useQueryClient()
  const session = useQuery({ queryKey: ['session'], queryFn: getSession })
  const canManage = session.data?.permissions.includes('scanner_profiles.manage') ?? false
  const profiles = useQuery({ queryKey: ['scanner-profiles', true], queryFn: () => listScannerProfiles(true) })
  const [editing, setEditing] = useState<ScannerProfile | null>(null)
  const editingServer = editing ? profiles.data?.profiles.find(profile => profile.id === editing.id) ?? editing : null
  const editorServer = editingServer ? scannerEditorDraft(editingServer) : emptyScannerEditorDraft()
  const editorState = useServerDraft<ScannerEditorDraft, ScannerEditorDraft, number>(editorServer, editingServer?.revision ?? 0, {
    mergeDraft: (_server, draft) => draft,
  })
  const { draft: editor, setDraft, baseRevision, rebase, adopt, markSaved } = editorState
  const remoteChanged = !!editingServer && editorState.hasDraft && baseRevision !== editingServer.revision
  const [password, setPassword] = useState('')
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)
  const [preview, setPreview] = useState<PreviewCommand[]>([])
  const [pendingLifecycle, setPendingLifecycle] = useState<{ profile: ScannerProfile; action: 'archive' | 'restore' } | null>(null)
  const feedbackRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (message || error) feedbackRef.current?.scrollIntoView?.({ block: 'nearest' })
  }, [message, error])

  function reset() {
    markSaved()
    setEditing(null)
    setPassword('')
    setError('')
    setMessage('')
    setPreview([])
    setPendingLifecycle(null)
  }

  function select(profile: ScannerProfile) {
    markSaved()
    setEditing(profile)
    setPassword('')
    setError('')
    setMessage('')
    setPreview([])
  }

  function payload(): ScannerProfilePayload {
    const lines = (value: string) => value.split('\n').map(item => item.trim()).filter(Boolean)
    const structured = editor.nseArgs.split('\n').map(item => item.trim()).filter(Boolean).reduce<Record<string, string>>((out, item) => {
      const separator = item.indexOf('=')
      if (separator > 0) out[item.slice(0, separator).trim()] = item.slice(separator + 1).trim()
      return out
    }, {})
    return { ...editor.payload, nmap_args: lines(editor.args.nmap), naabu_args: lines(editor.args.naabu), enrichment_args: lines(editor.args.enrichment), nse_args: structured, password }
  }

  async function save() {
    setSaving(true)
    setError('')
    setMessage('')
    try {
      const value = payload()
      if (editing) await updateScannerProfile(editing.id, value, baseRevision)
      else await createScannerProfile(value)
      await client.invalidateQueries({ queryKey: ['scanner-profiles'] })
      reset()
      // reset clears transient form state as well as the editor selection. Set
      // the confirmation after it so a successful save remains visible.
      setMessage('Scanner profile saved. Jobs keep their pinned revision until explicitly upgraded.')
    } catch (err) {
      if (editing && err instanceof APIError && err.status === 409) {
        // Refresh the server snapshot, but leave both the typed draft and its
        // pinned revision intact until the administrator chooses what to do.
        const refreshed = await client.fetchQuery({ queryKey: ['scanner-profiles', true], queryFn: () => listScannerProfiles(true), staleTime: 0 }).catch(() => undefined)
        const current = refreshed?.profiles.find(profile => profile.id === editing.id)
        if (current) {
          setError(`This profile changed elsewhere (now revision ${current.revision}). Your draft still uses revision ${baseRevision}; keep it or load the saved profile.`)
          return
        }
      }
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

  const updatePayload = (update: (current: ScannerProfilePayload) => ScannerProfilePayload) => setDraft(current => ({ ...current, payload: update(current.payload) }))
  const updateNaabu = (field: string, value: number | string | boolean) => updatePayload(current => ({ ...current, naabu: { ...current.naabu, [field]: value } }))
  const toggleAdjustable = (field: string, checked: boolean) => {
    const selected = editor.payload.operator_adjustable ?? []
    const next = checked ? [...selected, field] : selected.filter(value => value !== field)
    const bounds = { ...(editor.payload.operator_bounds ?? {}) }
    if (checked && defaultBounds[field] && !bounds[field]) bounds[field] = defaultBounds[field]
    if (!checked) delete bounds[field]
    updatePayload(current => ({ ...current, operator_adjustable: next, operator_bounds: bounds }))
  }
  const updateEditor = (update: (current: ScannerEditorDraft) => ScannerEditorDraft) => setDraft(update)

  function keepMyEdits() {
    if (!editingServer) return
    rebase(editingServer.revision)
    setError(`Your profile draft now uses revision ${editingServer.revision}. Review it and save again.`)
  }

  function loadTheirs() {
    if (!editingServer) {
      reset()
      setError('This scanner profile was removed elsewhere.')
      return
    }
    adopt()
    setEditing(editingServer)
    setPassword('')
    setPreview([])
    setError('The saved scanner profile is loaded.')
  }

  return <section className="page">
    <div className="page-heading"><div><p className="eyebrow">Administration</p><h1>Scanner profiles</h1><p className="muted">Tune fixed Naabu and Nmap executables with validated argument arrays. Profiles are revisioned and never execute through a shell.</p></div>{canManage && <button className="button primary" onClick={reset}><Plus size={16} /> New profile</button>}</div>
    <div className="dashboard-columns">
      <div className="panel"><div className="panel-heading"><div><h2>Available profiles</h2><p className="muted">Built-ins are immutable. Archived profiles remain available to existing jobs.</p></div><Code2 className="muted-icon" size={18} /></div>
        {profiles.isLoading ? <div className="loading"><span className="spinner" />Loading profiles…</div> : profiles.error ? <ErrorNotice message="Could not load scanner profiles." onRetry={() => profiles.refetch()} /> : <>{(profiles.data?.invalid_profiles?.length ?? 0) > 0 && <div className="notice warning" role="status"><AlertTriangle size={16} /><span><strong>{profiles.data?.invalid_profiles?.length} stored profile{profiles.data?.invalid_profiles?.length === 1 ? '' : 's'} need attention.</strong> Invalid definitions are hidden from selection until repaired or removed.</span></div>}{profiles.data?.profiles.length ? <div className="activity-list">{profiles.data.profiles.map(profile => <div className="activity-row" key={profile.id}><div><strong>{profile.name}</strong><span>{profile.definition.engine === 'naabu_nmap' ? 'Naabu full TCP → Nmap' : 'Nmap'} · revision {profile.revision}{profile.archived ? ' · archived' : ''}</span></div><span className={profile.built_in ? 'pill blue' : profile.archived ? 'pill gray' : 'pill green'}>{profile.built_in ? 'Built-in' : profile.archived ? 'Archived' : 'Managed'}</span>{canManage && !profile.built_in && <><button className="icon-button" aria-label={`Edit ${profile.name}`} onClick={() => select(profile)}><Save size={15} /></button>{profile.archived ? <button className="icon-button" aria-label={`Restore ${profile.name}`} onClick={() => requestLifecycle(profile, 'restore')}><RotateCcw size={15} /></button> : <button className="icon-button" aria-label={`Archive ${profile.name}`} onClick={() => requestLifecycle(profile, 'archive')}><Trash2 size={15} /></button>}</>}</div>)}</div> : <div className="inline-empty">No valid scanner profiles are configured.</div>}</>}
      </div>
      <div className="panel form-panel"><div className="panel-heading"><div><h2 title={editing ? `Edit ${editing.name}` : 'Create profile'}>{editing ? `Edit ${editing.name}` : 'Create profile'}</h2><p className="muted">{canManage ? 'Password confirmation is required for every mutation.' : 'Profiles are read-only for your account.'}</p></div><LockKeyhole className="muted-icon" size={18} /></div>{!canManage && <div className="notice notification-read-only" role="status"><LockKeyhole size={16} />Only administrators can create, validate, or revise scanner profiles.</div>}
        {remoteChanged && <div className="notice warning" role="status"><span>This profile changed elsewhere. Your edits are kept, and saves still use revision {baseRevision}.</span><button type="button" className="text-button" onClick={keepMyEdits}>Keep my edits</button><button type="button" className="text-button" onClick={loadTheirs}>Load theirs</button></div>}
        <label>Name<input value={editor.payload.name ?? ''} title={editor.payload.name ?? ''} onChange={event => updatePayload(current => ({ ...current, name: event.target.value }))} placeholder="Careful Naabu defaults" /></label>
        <label>Description<textarea value={editor.payload.description ?? ''} onChange={event => updatePayload(current => ({ ...current, description: event.target.value }))} /></label>
        <label>Engine<select value={editor.payload.engine} onChange={event => updatePayload(current => ({ ...current, engine: event.target.value as ScannerProfilePayload['engine'] }))}><option value="nmap">Nmap only</option><option value="naabu_nmap">Naabu discovery → Nmap</option></select></label>
        {editor.payload.engine === 'naabu_nmap' && <div className="two-fields">
          <label>Discovery type<select value={editor.payload.naabu?.scan_type ?? 'connect'} onChange={event => updateNaabu('scan_type', event.target.value)}><option value="connect">Connect</option><option value="syn">SYN (NET_ADMIN + NET_RAW)</option></select></label>
          <label>Rate<input type="number" min={1} max={100000} value={editor.payload.naabu?.rate ?? 1000} onChange={event => updateNaabu('rate', Number(event.target.value))} /></label>
          <label>Workers<input type="number" min={1} max={1024} value={editor.payload.naabu?.workers ?? 25} onChange={event => updateNaabu('workers', Number(event.target.value))} /></label>
          <label>Retries<input type="number" min={0} max={10} value={editor.payload.naabu?.retries ?? 3} onChange={event => updateNaabu('retries', Number(event.target.value))} /></label>
          <label>Probe timeout (ms)<input type="number" min={100} max={60000} value={editor.payload.naabu?.timeout_ms ?? 1000} onChange={event => updateNaabu('timeout_ms', Number(event.target.value))} /></label>
          <label>Warm-up (seconds)<input type="number" min={0} max={60} value={editor.payload.naabu?.warm_up_seconds ?? 2} onChange={event => updateNaabu('warm_up_seconds', Number(event.target.value))} /></label>
          <label>Address batch size<input type="number" min={1} max={256} value={editor.payload.naabu?.address_batch_size ?? 16} onChange={event => updateNaabu('address_batch_size', Number(event.target.value))} /></label>
          <label className="switch-row"><input type="checkbox" checked={editor.payload.naabu?.verify ?? true} onChange={event => updateNaabu('verify', event.target.checked)} /><span><strong>Verify discoveries</strong><small>Ask Naabu to re-check discovered ports.</small></span></label>
        </div>}
        <label>NSE profile<select value={editor.payload.nse_profile ?? ''} onChange={event => updatePayload(current => ({ ...current, nse_profile: event.target.value }))}><option value="">No NSE scripts</option><option value="banner">banner</option><option value="http-title">http-title</option><option value="http-headers">http-headers</option><option value="ssl-cert">ssl-cert</option><option value="ssh-hostkey">ssh-hostkey</option><option value="dns-recursion">dns-recursion</option></select></label>
        <label>NSE arguments<textarea value={editor.nseArgs} onChange={event => updateEditor(current => ({ ...current, nseArgs: event.target.value }))} placeholder="One safe key=value per line (optional)" /><small>Values are scalar and validated; paths, wildcards, boolean expressions, and @files are rejected.</small></label>
        <label>Nmap argument array<textarea rows={6} value={editor.args.nmap} onChange={event => updateEditor(current => ({ ...current, args: { ...current.args, nmap: event.target.value } }))} placeholder="Required placeholders: {address(es)}, {ports}, {structured_output}" /></label>
        {editor.payload.engine === 'naabu_nmap' && <label>Naabu argument array<textarea rows={6} value={editor.args.naabu} onChange={event => updateEditor(current => ({ ...current, args: { ...current.args, naabu: event.target.value } }))} placeholder="Required placeholders: {targets_file}, {ports}, {structured_output}" /></label>}
        <label>Enrichment argument array<textarea rows={6} value={editor.args.enrichment} onChange={event => updateEditor(current => ({ ...current, args: { ...current.args, enrichment: event.target.value } }))} placeholder="Required placeholders: {address(es)}, {ports}, {structured_output}" /></label>
        <fieldset><legend>Operator-adjustable fields</legend><div className="two-fields">{adjustable.map(field => <label key={field} className="switch-row"><input type="checkbox" checked={(editor.payload.operator_adjustable ?? []).includes(field)} onChange={event => toggleAdjustable(field, event.target.checked)} /><span><strong>{field}</strong><small>Permit job-level tuning within bounds</small></span></label>)}</div><p className="helper">Bounds use the product safety limits by default; the API validates any administrator changes.</p></fieldset>
        {preview.length > 0 && <div className="scanner-preview" role="region" aria-label="Effective command preview"><h3>Effective command preview</h3><p className="helper">Documentation-only examples use fixed EdgeWatch executables and safe sample values. They are never executed.</p>{preview.map((command, index) => <pre key={`${command.executable}-${index}`}><code>{formatCommand(command)}</code></pre>)}</div>}
        {canManage && <><label>Password confirmation<input type="password" value={password} onChange={event => setPassword(event.target.value)} autoComplete="current-password" /></label><div className="heading-actions"><button className="button secondary" type="button" onClick={validate}>Validate & preview</button><button className="button primary" type="button" disabled={saving} onClick={save}><Save size={16} />{saving ? 'Saving…' : editing ? 'Save revision' : 'Create profile'}</button></div></>}
        {(message || error) && <div ref={feedbackRef} className="profile-save-feedback save-feedback">{message && <div className="success-banner" role="status"><ShieldCheck size={16} />{message}</div>}{error && !pendingLifecycle && <div className="form-error" role="alert">{error}</div>}</div>}
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
