import { useEffect, useMemo, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, ArrowRight, Bell, Check, CircleHelp, Info, Network, Radar, ShieldCheck, Timer, TriangleAlert } from 'lucide-react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { APIError, createJob, createNotificationDestination, getSession, listNotificationDestinations, listScannerProfiles, previewJob, scannerCapabilities, scheduleSuggestion, testNotificationDestination } from '../api'
import type { NotificationDestination, NotificationDestinationsResponse } from '../api'
import type { Job, JobForm, JobPreview, Protocol } from '../types'
import { ActionDialog } from '../components/ActionDialog'
import { ErrorNotice } from '../components/ErrorNotice'
import { NotificationDestinationCreateForm } from '../components/NotificationDestinationCreateForm'
import { cidrWarning, duplicateTarget, hostCeilingWarning, targetKind } from '../target'
import { formatDateTime, getDisplayTimeZone } from '../format'
import { cloneProtocol, defaultTCP, defaultUDP, payloadFromCreationDraft, presetFor } from '../job-form'
import { useJobCreationDraft } from '../job-creation-draft'
import { issueFirstScanIntent } from '../firstScanIntent'

type SetupStep = 'targets' | 'coverage' | 'schedule' | 'review'
const steps: { id: SetupStep; label: string }[] = [
  { id: 'targets', label: 'Targets' },
  { id: 'coverage', label: 'Coverage' },
  { id: 'schedule', label: 'Schedule and alerts' },
  { id: 'review', label: 'Review' },
]

type PreviewState = { signature: string; status: 'loading' | 'ready' | 'error'; data?: JobPreview; message?: string }

export function MonitorSetup() {
  const { draft, dirty, updateDraft, clearDraft, createOutcomeUnknown, markCreateOutcomeUnknown } = useJobCreationDraft()
  const navigate = useNavigate()
  const location = useLocation()
  const client = useQueryClient()
  const session = useQuery({ queryKey: ['session'], queryFn: getSession })
  const destinations = useQuery({ queryKey: ['notifications'], queryFn: listNotificationDestinations, staleTime: 30_000 })
  const profiles = useQuery({ queryKey: ['scanner-profiles'], queryFn: () => listScannerProfiles(false), staleTime: 60_000 })
  const capabilities = useQuery({ queryKey: ['scanner-capabilities'], queryFn: scannerCapabilities, staleTime: 5 * 60_000, retry: false })
  const [step, setStep] = useState<SetupStep>('targets')
  const [fieldError, setFieldError] = useState('')
  const [actionError, setActionError] = useState('')
  const [saving, setSaving] = useState(false)
  const [discardNavigation, setDiscardNavigation] = useState<{ destination: string; historyPop: boolean } | null>(null)
  const [scheduleInput, setScheduleInput] = useState({ schedule: draft.fields.schedule, timezone: draft.fields.timezone })
  const [addedDestination, setAddedDestination] = useState('')
  const [createDestinationOpen, setCreateDestinationOpen] = useState(false)
  const [preview, setPreview] = useState<PreviewState | null>(null)
  const [previewAttempt, setPreviewAttempt] = useState(0)
  const previewSequence = useRef(0)
  const createLock = useRef(false)
  const currentHistoryEntry = useRef<{ path: string; state: unknown } | null>(null)
  const allowHistoryPop = useRef(false)
  const headingRef = useRef<HTMLHeadingElement>(null)

  const activeStepIndex = steps.findIndex(item => item.id === step)
  const suggestionReady = scheduleInput.schedule.trim().split(/\s+/).length === 5 && !!scheduleInput.timezone.trim()
  const suggestion = useQuery({
    queryKey: ['schedule-suggestion', scheduleInput.schedule, scheduleInput.timezone],
    queryFn: () => scheduleSuggestion(scheduleInput.schedule, scheduleInput.timezone),
    enabled: suggestionReady,
    staleTime: 15_000,
    retry: false,
  })
  useEffect(() => {
    const timer = window.setTimeout(() => setScheduleInput({ schedule: draft.fields.schedule.trim(), timezone: draft.fields.timezone.trim() }), 350)
    return () => window.clearTimeout(timer)
  }, [draft.fields.schedule, draft.fields.timezone])
  const currentSuggestion = scheduleInput.schedule === draft.fields.schedule.trim() && scheduleInput.timezone === draft.fields.timezone.trim() ? suggestion.data : undefined
  const showSuggestion = !!currentSuggestion?.suggested && !!currentSuggestion.nearest
  const availableDestinationIDs = new Set(destinations.data?.destinations.map(item => item.id) ?? [])
  const payload = useMemo(() => payloadFromCreationDraft(draft, !!destinations.data, destinations.data ? availableDestinationIDs : undefined), [draft, destinations.data, destinations.dataUpdatedAt])
  const previewSignature = JSON.stringify(payload)
  const previewIsCurrent = preview?.signature === previewSignature && preview.status === 'ready'
  const previewData = previewIsCurrent ? preview.data : undefined
  const previewJob = previewData?.job
  const reviewJob = previewIsCurrent && previewJob ? previewJob : payload
  const previewBudget = previewData?.scan_budget
  const previewEstimate = previewData?.scan_estimate
  const isOverBudget = previewBudget?.exceeded === true
  const selectedProfile = draft.tcp?.profile_id ? profiles.data?.profiles.find(profile => profile.id === draft.tcp?.profile_id) : undefined
  const missingDestinationIDs = draft.notificationIDs.filter(id => !availableDestinationIDs.has(id))

  useEffect(() => {
    if (!destinations.data || draft.notificationSelectionTouched || draft.notificationIDs.length > 0) return
    const defaults = destinations.data.destinations.filter(destination => destination.enabled && !destination.locked).map(destination => destination.id)
    if (!defaults.length) return
    updateDraft(current => ({ ...current, notificationIDs: defaults }), false)
  }, [destinations.data, draft.notificationIDs.length, draft.notificationSelectionTouched, updateDraft])

  useEffect(() => {
    if (step !== 'review') {
      setPreview(null)
      return
    }
    const controller = new AbortController()
    const sequence = ++previewSequence.current
    const signature = previewSignature
    setPreview({ signature, status: 'loading' })
    void previewJobRequest(payload, controller.signal).then(data => {
      if (controller.signal.aborted || previewSequence.current !== sequence) return
      setPreview({ signature, status: 'ready', data })
      setActionError('')
    }).catch(error => {
      if (controller.signal.aborted || previewSequence.current !== sequence) return
      setPreview({ signature, status: 'error', message: errorText(error, 'The configuration preview is unavailable.') })
    })
    return () => {
      controller.abort()
      if (previewSequence.current === sequence) previewSequence.current++
    }
  }, [step, previewAttempt, previewSignature])

  useEffect(() => {
    currentHistoryEntry.current = { path: `${location.pathname}${location.search}${location.hash}`, state: window.history.state }
  }, [location.hash, location.key, location.pathname, location.search])

  useEffect(() => {
    headingRef.current?.focus()
  }, [step])

  useEffect(() => {
    if (!dirty && !saving) return
    const currentPath = `${location.pathname}${location.search}${location.hash}`
    const onInternalLinkClick = (event: MouseEvent) => {
      if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return
      const target = event.target
      if (!(target instanceof Element)) return
      const anchor = target.closest<HTMLAnchorElement>('a[href]')
      if (!anchor || anchor.hasAttribute('download') || (anchor.target && anchor.target !== '_self')) return
      const destination = new URL(anchor.href, window.location.href)
      if (destination.origin !== window.location.origin) return
      const nextPath = `${destination.pathname}${destination.search}${destination.hash}`
      if (nextPath === currentPath) return
      if (saving) {
        event.preventDefault()
        event.stopPropagation()
        return
      }
      if (isCreationPath(nextPath)) return
      event.preventDefault()
      event.stopPropagation()
      setDiscardNavigation({ destination: nextPath, historyPop: false })
    }
    const onPopState = (event: PopStateEvent) => {
      if (allowHistoryPop.current) {
        allowHistoryPop.current = false
        return
      }
      const nextPath = `${window.location.pathname}${window.location.search}${window.location.hash}`
      if (nextPath === currentPath) return
      if (saving) {
        event.stopImmediatePropagation()
        const current = currentHistoryEntry.current
        if (current) window.history.pushState(current.state, '', current.path)
        return
      }
      if (isCreationPath(nextPath)) return
      event.stopImmediatePropagation()
      const current = currentHistoryEntry.current
      setDiscardNavigation({ destination: nextPath, historyPop: true })
      if (current) window.history.pushState(current.state, '', current.path)
    }
    const onBeforeUnload = (event: BeforeUnloadEvent) => {
      event.preventDefault()
      event.returnValue = ''
    }
    document.addEventListener('click', onInternalLinkClick, true)
    window.addEventListener('popstate', onPopState, true)
    window.addEventListener('beforeunload', onBeforeUnload)
    return () => {
      document.removeEventListener('click', onInternalLinkClick, true)
      window.removeEventListener('popstate', onPopState, true)
      window.removeEventListener('beforeunload', onBeforeUnload)
    }
  }, [dirty, location.hash, location.pathname, location.search, saving])

  function updateFields(values: Partial<typeof draft.fields>) {
    updateDraft(current => ({ ...current, fields: { ...current.fields, ...values } }))
    setFieldError('')
  }

  function updateTargets(targets: string[]) {
    updateDraft(current => ({ ...current, targets }))
    setFieldError('')
  }

  function requestNavigation(destination: string) {
    if (saving) return
    if (isCreationPath(destination)) {
      navigate(destination)
      return
    }
    if (dirty) {
      setDiscardNavigation({ destination, historyPop: false })
      return
    }
    navigate(destination)
  }

  function goTo(next: SetupStep) {
    if (saving) return
    setFieldError('')
    setActionError('')
    setStep(next)
  }

  function retryPreview() {
    setPreview({ signature: previewSignature, status: 'loading' })
    setPreviewAttempt(value => value + 1)
  }

  function continueFromTargets() {
    const name = draft.fields.name.trim()
    if (!name) {
      setFieldError('A monitor name is required.')
      return
    }
    if (Array.from(name).length > 200 || /\p{Cc}/u.test(name)) {
      setFieldError('Use a name of up to 200 characters without control characters.')
      return
    }
    const normalizedTargets = draft.targets.map(value => value.trim()).filter(Boolean)
    const duplicate = duplicateTarget(normalizedTargets)
    if (duplicate) {
      setFieldError(`Target ${duplicate} is listed more than once.`)
      return
    }
    if (!normalizedTargets.length) {
      setFieldError('Add at least one IP address, CIDR, or DNS name.')
      return
    }
    updateDraft(current => ({ ...current, fields: { ...current.fields, name }, targets: normalizedTargets }), false)
    goTo('coverage')
  }

  function continueFromCoverage() {
    if (!draft.tcp && !draft.udp) {
      setFieldError('Include TCP, UDP, or both scan types.')
      return
    }
    if (draft.tcp && !draft.tcp.ports.trim()) {
      setFieldError('Choose TCP ports for Nmap.')
      return
    }
    if (draft.udp && !draft.udp.ports.trim()) {
      setFieldError('Choose UDP ports for Nmap.')
      return
    }
    goTo('schedule')
  }

  function continueFromSchedule() {
    if (!draft.fields.schedule.trim() || draft.fields.schedule.trim().split(/\s+/).length !== 5) {
      setFieldError('Enter a five-field cron schedule.')
      return
    }
    if (!draft.fields.timezone.trim()) {
      setFieldError('Enter a timezone such as Europe/Amsterdam or UTC.')
      return
    }
    if (!draft.notificationSelectionTouched) {
      if (draft.notificationIDs.length === 0) {
        setFieldError('Select notification destinations or choose explicitly to continue without alerts.')
        return
      }
      // Enabled defaults are already visible as checked. Advancing from this
      // step confirms that selection instead of forcing an uncheck/recheck.
      updateDraft(current => ({ ...current, notificationSelectionTouched: true }))
    }
    goTo('review')
  }

  function setTCPEnabled(enabled: boolean) {
    updateDraft(current => {
      if (!enabled) return { ...current, lastTCP: cloneProtocol(current.tcp), tcp: undefined }
      return { ...current, tcp: cloneProtocol(current.lastTCP) ?? defaultTCP() }
    })
  }

  function setUDPEnabled(enabled: boolean) {
    updateDraft(current => {
      if (!enabled) return { ...current, lastUDP: cloneProtocol(current.udp), udp: undefined }
      return { ...current, udp: cloneProtocol(current.lastUDP) ?? defaultUDP() }
    })
  }

  function setTCPCoverage(mode: 'full' | 'selected') {
    updateDraft(current => {
      const currentIsFull = current.tcp?.engine === 'naabu_nmap'
      const fullSnapshot = currentIsFull ? cloneProtocol(current.tcp) : cloneProtocol(current.tcpFullSnapshot)
      const selectedSnapshot = current.tcp && !currentIsFull ? cloneProtocol(current.tcp) : cloneProtocol(current.tcpSelectedSnapshot)
      const fullTCP = fullSnapshot?.engine === 'naabu_nmap' ? fullSnapshot : defaultTCP()
      const selectedTCP = selectedSnapshot && selectedSnapshot.engine !== 'naabu_nmap'
        ? selectedSnapshot
        : currentIsFull && current.tcp
          ? selectedTCPFromFull(current.tcp)
          : defaultSelectedTCP()
      return {
        ...current,
        tcp: mode === 'full' ? cloneProtocol(fullTCP) : cloneProtocol(selectedTCP),
        tcpFullSnapshot: cloneProtocol(fullTCP),
        tcpSelectedSnapshot: cloneProtocol(selectedTCP),
      }
    })
  }

  function updateNotificationSelection(id: string, checked: boolean) {
    updateDraft(current => ({
      ...current,
      notificationSelectionTouched: true,
      notificationIDs: checked ? [...new Set([...current.notificationIDs, id])] : current.notificationIDs.filter(value => value !== id),
    }))
    setAddedDestination('')
  }

  function chooseNoAlerts() {
    updateDraft(current => ({ ...current, notificationSelectionTouched: true, notificationIDs: [] }))
    setAddedDestination('')
  }

  async function createMonitor(start: boolean) {
    if (createLock.current || saving || createOutcomeUnknown || !previewIsCurrent || !previewJob) return
    if (start && !canDispatchFirstScan) return
    createLock.current = true
    setSaving(true)
    setActionError('')
    try {
      let created: Job
      try {
        // Save the exact normalized configuration shown by the current preview,
        // including a profile revision resolved by the server.
        created = await createJob(previewJob)
      } catch (error) {
        const knownResponse = error instanceof APIError && error.status !== undefined && error.status < 500
        if (!knownResponse) {
          markCreateOutcomeUnknown()
          setActionError('EdgeWatch did not confirm whether this monitor was created. Check Jobs before taking another action; this draft will not be submitted again from this page.')
        } else {
          const stalePreview = error instanceof APIError && error.status === 409 && error.code === 'profile_conflict'
          setActionError(stalePreview ? 'The scanner profile changed after preview. A fresh preview is being requested before another create attempt.' : errorText(error, 'Could not create the monitor. Your draft is still here.'))
          if (stalePreview) retryPreview()
        }
        return
      }
      if (!created?.id?.trim()) {
        markCreateOutcomeUnknown()
        setActionError('The create response did not include a job ID. Check Jobs before taking another action; this draft will not be submitted again from this page.')
        return
      }
      client.setQueryData<Job>(['job', created.id], created)
      void client.invalidateQueries({ queryKey: ['jobs'] }).catch(() => undefined)
      clearDraft()
      const state = start ? { startFirstScanToken: issueFirstScanIntent(created.id) } : undefined
      navigate(`/jobs/${encodeURIComponent(created.id)}`, { state })
    } finally {
      createLock.current = false
      setSaving(false)
    }
  }

  async function onDestinationCreated(destination: NotificationDestination) {
    updateDraft(current => ({ ...current, notificationSelectionTouched: true, notificationIDs: [...new Set([...current.notificationIDs, destination.id])] }))
    setAddedDestination(destination.name)
    client.setQueryData<NotificationDestinationsResponse>(['notifications'], current => current
      ? { ...current, destinations: [...current.destinations.filter(item => item.id !== destination.id), destination], status: { ...current.status, managed: current.status.managed + (current.destinations.some(item => item.id === destination.id) ? 0 : 1), active: current.status.active + (!current.destinations.some(item => item.id === destination.id) && destination.enabled && !destination.locked ? 1 : 0) } }
      : undefined)
    await client.invalidateQueries({ queryKey: ['notifications'] })
  }

  const capabilityData = capabilities.data
  const requiresNmap = !!draft.tcp || !!draft.udp
  const requiresNaabu = draft.tcp?.engine === 'naabu_nmap'
  const scannerMissing = !!capabilityData && (
    (requiresNmap && capabilityData.nmap.available === false) || (requiresNaabu && capabilityData.naabu.available === false)
  )
  const naabuSynUnavailable = !!draft.tcp && draft.tcp.engine === 'naabu_nmap' && draft.tcp.naabu?.scan_type === 'syn' && capabilityData?.naabu.syn_supported !== true
  const scannerAvailabilityUnverified = !capabilities.isSuccess || !!capabilities.error || (requiresNmap && typeof capabilityData?.nmap.available !== 'boolean') || (requiresNaabu && typeof capabilityData?.naabu.available !== 'boolean')
  const canDispatchFirstScan = previewIsCurrent && !!previewJob && previewBudget?.exceeded === false && !scannerMissing && !scannerAvailabilityUnverified && !naabuSynUnavailable
  const createStartDisabled = saving || createOutcomeUnknown || !canDispatchFirstScan
  const createDisabled = saving || createOutcomeUnknown || !previewIsCurrent || !previewJob

  return <section className="page monitor-setup">
    <div className="page-heading">
      <div>
        {activeStepIndex > 0
          ? <button className="back-link monitor-previous-link" type="button" disabled={saving} onClick={() => goTo(steps[activeStepIndex - 1].id)}><ArrowLeft size={15} /> Previous step</button>
          : <Link className="back-link" to="/jobs" onClick={event => { event.preventDefault(); requestNavigation('/jobs') }}><ArrowLeft size={15} /> Back to jobs</Link>}
        <p className="eyebrow">Monitor setup · Step {activeStepIndex + 1} of {steps.length}</p>
        <h1 ref={headingRef} tabIndex={-1}>{stepHeading(step)}</h1>
        <p className="muted">Set the authorized network scope, review what EdgeWatch will scan, then choose when it should run.</p>
      </div>
      <Link className={`button secondary${saving ? ' disabled' : ''}`} aria-disabled={saving} to="/jobs/new/advanced" onClick={event => { if (saving) event.preventDefault() }}><CircleHelp size={16} /> Open full editor</Link>
    </div>

    <nav className="monitor-steps" aria-label="Monitor setup steps">
      {steps.map((item, index) => <button key={item.id} type="button" className={`monitor-step${item.id === step ? ' active' : ''}${index < activeStepIndex ? ' complete' : ''}`} aria-current={item.id === step ? 'step' : undefined} onClick={() => index <= activeStepIndex ? goTo(item.id) : undefined} disabled={saving || index > activeStepIndex}>
        <span>{index < activeStepIndex ? <Check size={15} /> : index + 1}</span>{item.label}
      </button>)}
    </nav>

    <fieldset className="monitor-step-fields" disabled={saving} aria-busy={saving}>
    <legend className="sr-only">Current monitor setup fields</legend>
    {step === 'targets' && <div className="monitor-step-content">
      <div className="panel form-panel">
        <div className="panel-heading"><div><h2>Name and authorized targets</h2><p className="muted">Use systems you own or have permission to monitor.</p></div><Network className="muted-icon" size={19} /></div>
        <label>Monitor name<input value={draft.fields.name} autoComplete="off" placeholder="Production edge" onChange={event => updateFields({ name: event.currentTarget.value })} aria-describedby="monitor-name-help" />{fieldError && !draft.fields.name.trim() && <small className="field-error">{fieldError}</small>}<small id="monitor-name-help">A clear name helps operators recognize this scope.</small></label>
        <div className="field-section">
          <div className="field-title"><span>Targets</span><span className="field-help">IP · CIDR · DNS</span></div>
          <p className="helper">One address or network per row. CIDRs expand at scan time; DNS names resolve before each scan. The server applies configured exclusions.</p>
          <div className="target-list">{draft.targets.map((target, index) => <div className="target-row" key={index}>
            <input value={target} onChange={event => updateTargets(draft.targets.map((value, row) => row === index ? event.currentTarget.value : value))} placeholder={index === 0 ? '192.168.1.1 or 10.0.0.0/24 or router.example.com' : 'Add another target'} aria-label={`Target ${index + 1}`} />
            <span className="target-kind">{targetKind(target)}</span>
            {draft.targets.length > 1 && <button type="button" className="icon-button" aria-label={`Remove target ${index + 1}`} onClick={() => updateTargets(draft.targets.filter((_, row) => row !== index))}>×</button>}
          </div>)}</div>
          <button type="button" className="text-button add-target" onClick={() => updateTargets([...draft.targets, ''])}>＋ Add target</button>
          {draft.targets.some(value => cidrWarning(value)) && <div className="notice warning"><TriangleAlert size={16} /><span>{draft.targets.map(cidrWarning).find(Boolean)}</span></div>}
          {hostCeilingWarning(draft.targets, capabilities.data?.max_job_hosts) && <div className="notice warning" role="status"><TriangleAlert size={16} /><span>{hostCeilingWarning(draft.targets, capabilities.data?.max_job_hosts)}</span></div>}
          {fieldError && (fieldError.includes('Target') || fieldError.startsWith('Add at least')) && <small className="field-error" role="alert">{fieldError}</small>}
        </div>
        <label className="inline-field">Maximum expanded hosts <span className="input-suffix"><input type="number" min={1} max={1000000} value={draft.fields.max_expanded_hosts} onChange={event => updateFields({ max_expanded_hosts: Number(event.currentTarget.value) })} /><em>hosts</em></span><small className="helper">This limit protects the host from accidentally wide CIDR ranges.</small></label>
      </div>
      <div className="notice"><ShieldCheck size={16} /><span>Only add targets that you are authorized to scan. Preview estimates CIDR expansion without resolving DNS or sending probes.</span></div>
      {fieldError && !fieldError.includes('Target') && !fieldError.startsWith('Add at least') && <div className="form-error" role="alert">{fieldError}</div>}
      <div className="monitor-actions"><span /> <button type="button" className="button primary" onClick={continueFromTargets}>Continue to coverage <ArrowRight size={16} /></button></div>
    </div>}

    {step === 'coverage' && <div className="monitor-step-content">
      <div className="panel form-panel">
        <div className="panel-heading"><div><h2>Choose scan coverage</h2><p className="muted">The scan estimate will reflect the engines and ports selected here.</p></div><Radar className="muted-icon" size={19} /></div>
        <label className="switch-row"><input type="checkbox" checked={!!draft.tcp} onChange={event => setTCPEnabled(event.currentTarget.checked)} /><span><strong>Include TCP</strong><small>New monitors discover the full TCP port range by default.</small></span></label>
        {draft.tcp && <div className="coverage-choice-list">
          <label className="coverage-choice"><input type="radio" name="tcp-coverage" checked={draft.tcp.engine === 'naabu_nmap'} onChange={() => setTCPCoverage('full')} /><span><strong>Full TCP range</strong><small>Naabu discovers ports 1–65535, then Nmap confirms findings. Only confirmed ports affect the baseline.</small></span></label>
          <label className="coverage-choice"><input type="radio" name="tcp-coverage" checked={draft.tcp.engine !== 'naabu_nmap'} onChange={() => setTCPCoverage('selected')} /><span><strong>Selected TCP ports</strong><small>Use Nmap directly for the listed ports. This is partial coverage of the TCP surface.</small></span></label>
          {draft.tcp.engine !== 'naabu_nmap' && <label>TCP ports<input value={draft.tcp.ports} onChange={event => { const ports = event.currentTarget.value; updateDraft(current => ({ ...current, tcp: current.tcp ? { ...current.tcp, ports, engine: 'nmap' } : current.tcp })) }} placeholder="22,80,443,8000-8100" /><small>Port numbers and ranges from 1 to 65535.</small></label>}
          {draft.tcp.engine === 'naabu_nmap' && <div className="notice"><Info size={16} /><span>Full-range discovery is fixed at TCP 1–65535. A Naabu profile's enrichment ports do not restrict discovery.</span></div>}
          {draft.tcp.engine === 'naabu_nmap' && selectedProfile && <small className="helper">Using {selectedProfile.name}; {draft.tcp.profile_revision ? `revision ${draft.tcp.profile_revision} is pinned` : 'the current profile revision will be resolved when previewed'}.</small>}
          {draft.tcp.engine === 'naabu_nmap' && !selectedProfile && profiles.isError && <ErrorNotice message="Scanner profiles could not be loaded. The built-in profile can still be previewed; retry if you need to choose a managed profile in the full editor." onRetry={() => profiles.refetch()} />}
        </div>}
        <div className="field-section">
          <label className="switch-row"><input type="checkbox" checked={!!draft.udp} onChange={event => setUDPEnabled(event.currentTarget.checked)} /><span><strong>Include UDP</strong><small>UDP always uses Nmap and is disabled by default.</small></span></label>
          {draft.udp && <label>UDP ports<input value={draft.udp.ports} onChange={event => { const ports = event.currentTarget.value; updateDraft(current => ({ ...current, udp: current.udp ? { ...current.udp, ports } : current.udp })) }} placeholder="53,123,161" /><small>UDP probes can take much longer than TCP; begin with the ports your service uses.</small></label>}
        </div>
        {fieldError && <small className="field-error" role="alert">{fieldError}</small>}
        {capabilities.isLoading ? <p className="helper" role="status">Checking scanner availability…</p> : capabilities.error ? <ErrorNotice message="Scanner availability could not be verified. Retry before starting a scan; you can still create the monitor without starting it." onRetry={() => capabilities.refetch()} /> : <div className="capability-summary" role="status"><span className={capabilities.data?.nmap.available ? 'pill green' : 'pill red'}>Nmap {capabilities.data?.nmap.available ? 'available' : 'unavailable'}</span>{draft.tcp?.engine === 'naabu_nmap' && <span className={capabilities.data?.naabu.available ? 'pill green' : 'pill red'}>Naabu {capabilities.data?.naabu.available ? 'available' : 'unavailable'}</span>}{draft.tcp?.engine === 'naabu_nmap' && draft.tcp.naabu?.scan_type === 'syn' && <span className={capabilities.data?.naabu.syn_supported ? 'pill green' : 'pill amber'}>Naabu SYN {capabilities.data?.naabu.syn_supported ? 'available' : 'unavailable'}</span>}</div>}
      </div>
      <div className="monitor-actions"><button type="button" className="button ghost" onClick={() => goTo('targets')}><ArrowLeft size={16} /> Back</button><button type="button" className="button primary" onClick={continueFromCoverage}>Continue to schedule <ArrowRight size={16} /></button></div>
    </div>}

    {step === 'schedule' && <div className="monitor-step-content">
      <div className="panel form-panel">
        <div className="panel-heading"><div><h2>Schedule future scans</h2><p className="muted">A schedule controls recurring scans. It does not start this monitor's first scan.</p></div><Timer className="muted-icon" size={19} /></div>
        <label>Cadence preset<select value={presetFor(draft.fields.schedule)} onChange={event => {
          if (event.currentTarget.value === 'custom') return
          updateFields({ schedule: event.currentTarget.value })
        }}><option value="0 */6 * * *">Every 6 hours</option><option value="0 * * * *">Every hour</option><option value="0 3 * * *">Daily at 03:00</option><option value="0 3 * * 0">Weekly on Sunday</option><option value="custom">Custom cron</option></select></label>
        <label>Five-field cron<input value={draft.fields.schedule} onChange={event => updateFields({ schedule: event.currentTarget.value })} placeholder="minute hour day month weekday" aria-label="Five-field cron" /><small>Uses the deployment's standard cron parser.</small></label>
        <label>Timezone<input value={draft.fields.timezone} onChange={event => updateFields({ timezone: event.currentTarget.value })} placeholder="Europe/Amsterdam" /><small>Default: {getDisplayTimeZone() || Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'}. Skipped local times do not run during daylight-saving transitions; repeated fall-back times may run twice.</small></label>
        {draft.scheduleEnabled && currentSuggestion?.draft_next_run && <div className="notice"><Info size={16} /><span>With this schedule, the first scheduled scan is expected at {formatRunInZone(currentSuggestion.draft_next_run, draft.fields.timezone)}. A scan can also be started separately after creation.</span></div>}
        {showSuggestion && currentSuggestion?.nearest && <div className="notice schedule-suggestion" role="status"><Info size={16} /><span>{currentSuggestion.nearest.name} is next at {formatRunInZone(currentSuggestion.nearest.next_run, currentSuggestion.nearest.timezone)}. {currentSuggestion.suggested_schedule ? 'Use the suggested offset to keep scheduled work apart.' : 'The schedules already have a useful gap.'}</span>{currentSuggestion.suggested_schedule && <button type="button" className="button secondary" onClick={() => updateFields({ schedule: currentSuggestion.suggested_schedule! })}>Use suggested time</button>}</div>}
        {suggestion.error && <ErrorNotice message="Schedule suggestions could not be loaded. Your schedule can still be saved and will be revalidated." onRetry={() => suggestion.refetch()} />}
        <label className="switch-row"><input type="checkbox" checked={draft.scheduleEnabled} onChange={event => { const enabled = event.currentTarget.checked; updateDraft(current => ({ ...current, scheduleEnabled: enabled })) }} /><span><strong>Schedule enabled</strong><small>Turn off to create this monitor without future scheduled scans.</small></span></label>
      </div>

      <div className="panel form-panel job-notification-panel">
        <div className="panel-heading"><div><h2>Alerts for this monitor</h2><p className="muted">Choose destinations for this monitor's incidents and scan events.</p></div><Bell className="muted-icon" size={19} /></div>
        {destinations.isLoading ? <div className="loading"><span className="spinner" />Loading destinations…</div> : destinations.error ? <ErrorNotice message="Notification destinations could not be loaded. Retry to select a destination, or choose explicitly to continue without alerts." onRetry={() => destinations.refetch()} /> : destinations.data?.destinations.length ? <div className="job-notification-list">
          {destinations.data.destinations.map(destination => <label className="switch-row job-notification-option" key={destination.id}>
            <input type="checkbox" checked={draft.notificationIDs.includes(destination.id)} onChange={event => updateNotificationSelection(destination.id, event.currentTarget.checked)} />
            <span><strong title={destination.name}>{destination.name}</strong><small>{destination.provider || 'unknown provider'} · {destination.source === 'deployment' ? 'deployment-managed' : 'web-managed'}{destination.locked ? ' · credentials locked' : !destination.enabled ? ' · paused' : ''}</small></span>
            <span className={destination.locked ? 'pill amber' : destination.enabled ? 'pill green' : 'pill gray'}>{destination.locked ? 'Locked' : destination.enabled ? 'Enabled' : 'Paused'}</span>
          </label>)}
        </div> : <div className="inline-empty">No notification destinations are configured.</div>}
        {missingDestinationIDs.length > 0 && <div className="notice warning"><TriangleAlert size={16} /><span>These saved destination IDs are unavailable and will not be sent to the server: {missingDestinationIDs.join(', ')}. Remove them or select a current destination.</span><button type="button" className="text-button" onClick={() => updateDraft(current => ({ ...current, notificationIDs: current.notificationIDs.filter(id => availableDestinationIDs.has(id)), notificationSelectionTouched: true }))}>Remove missing selections</button></div>}
        {draft.notificationIDs.length === 0 && draft.notificationSelectionTouched && <p className="helper" role="status">This monitor will not send notifications.</p>}
        {draft.notificationIDs.some(id => destinations.data?.destinations.some(destination => destination.id === id && (!destination.enabled || destination.locked))) && <div className="notice warning" role="status"><TriangleAlert size={16} /><span>A selected destination is paused or locked. Alerts may not be delivered through it until an administrator enables it or unlocks its credentials in Notifications.</span></div>}
        {addedDestination && <div className="success-banner" role="status"><Check size={16} />{addedDestination} was created and selected. It is a separate resource and will remain in Notifications if you cancel this monitor.</div>}
        <div className="notification-setup-actions">
          <button type="button" className="button secondary" onClick={chooseNoAlerts}>Continue without alerts</button>
          {session.data?.permissions.includes('notifications.manage') && <button type="button" className="button secondary" onClick={() => setCreateDestinationOpen(value => !value)}>{createDestinationOpen ? 'Close destination form' : 'Add destination'}</button>}
          {!session.data?.permissions.includes('notifications.manage') && <p className="helper">An administrator can add destinations in Notifications. Operators can select available destinations or continue without alerts.</p>}
        </div>
        {createDestinationOpen && session.data?.permissions.includes('notifications.manage') && <div className="notification-inline-create"><h3>Add a notification destination</h3><p className="muted">The account password confirms this separate change. Credentials are encrypted and cannot be read back.</p><NotificationDestinationCreateForm idPrefix="monitor-destination" create={createNotificationDestination} onCreated={onDestinationCreated} onTest={destination => testNotificationDestination(destination.id)} onCancel={() => setCreateDestinationOpen(false)} createLabel="Save and select destination" /></div>}
      </div>
      {fieldError && <div className="form-error" role="alert">{fieldError}</div>}
      <div className="monitor-actions"><button type="button" className="button ghost" onClick={() => goTo('coverage')}><ArrowLeft size={16} /> Back</button><button type="button" className="button primary" onClick={continueFromSchedule}>Review monitor <ArrowRight size={16} /></button></div>
    </div>}

    {step === 'review' && <div className="monitor-step-content">
      {preview?.signature === previewSignature && preview.status === 'loading' && <div className="panel preview-loading" role="status"><span className="spinner" />Checking current scanner profile, routing, exclusions, and probe budget…</div>}
      {preview?.signature === previewSignature && preview.status === 'error' && <div className="panel"><ErrorNotice message={preview.message ?? 'The configuration preview is unavailable.'} onRetry={retryPreview} /><p className="helper">Your monitor draft is still available. Retry to check the current profile, routing, exclusions, and budget.</p></div>}
      <div className="panel form-panel review-panel">
        <div className="panel-heading"><div><h2>Monitor configuration</h2><p className="muted">Review the effective scope returned by the current server preview.</p></div><Radar className="muted-icon" size={19} /></div>
        {!previewIsCurrent && <div className="notice" role="status"><Info size={16} /><span>The current preview is not ready. Values below show your draft and may change after the server validates the selected profile and configuration.</span></div>}
        <dl className="monitor-review-list">
          <div><dt>Name</dt><dd>{reviewJob.name || 'Name required'}</dd></div>
          <div><dt>Targets</dt><dd>{reviewJob.targets.join(', ') || 'No targets'}</dd></div>
          <div><dt>DNS comparison</dt><dd>{reviewJob.dns_comparison_mode === 'aggregate' ? 'Aggregate logical port and service surface' : 'Address-sensitive per-answer comparison'}</dd></div>
          <div><dt>Coverage</dt><dd>{coverageSummary(reviewJob.tcp, reviewJob.udp)}</dd></div>
          <div><dt>TCP engine</dt><dd>{reviewJob.tcp ? `${reviewJob.tcp.engine === 'naabu_nmap' ? 'Naabu discovery → Nmap confirmation' : 'Nmap only'}${reviewJob.tcp.engine === 'nmap' ? ` · ports ${reviewJob.tcp.ports}` : ' · full range 1–65535'}` : 'Disabled'}</dd></div>
          {reviewJob.tcp?.profile_id && <div><dt>TCP profile revision</dt><dd>{reviewJob.tcp.profile_revision ? `${reviewJob.tcp.profile_id} · revision ${reviewJob.tcp.profile_revision}${previewIsCurrent ? ' (resolved for this preview)' : ' (pinned)'}` : `${reviewJob.tcp.profile_id} · current revision will resolve at creation`}</dd></div>}
          {reviewJob.udp && <div><dt>UDP engine</dt><dd>Nmap · ports {reviewJob.udp.ports}</dd></div>}
          <div><dt>Schedule</dt><dd>{reviewJob.enabled ? `${reviewJob.schedule} · ${reviewJob.timezone}` : `Paused · ${reviewJob.schedule} · ${reviewJob.timezone}`}</dd></div>
          <div><dt>Initial scan</dt><dd>Separate action after creation; the schedule does not mark the baseline complete.</dd></div>
          <div><dt>Alerts</dt><dd>{reviewJob.notification_destinations === undefined ? 'Deployment default routing' : reviewJob.notification_destinations.length ? reviewJob.notification_destinations.map(id => destinations.data?.destinations.find(item => item.id === id)?.name ?? id).join(', ') : 'No alerts'}</dd></div>
        </dl>
      </div>

      <div className="panel form-panel review-panel">
        <div className="panel-heading"><div><h2>Coverage and scan cost</h2><p className="muted">An estimate is not a DNS lookup or a scan.</p></div></div>
        {previewEstimate ? <div className="estimate-grid">
          <Estimate label="Expanded hosts" value={previewEstimate.hosts.toLocaleString()} detail={previewEstimate.unknown_dns ? `${previewEstimate.unknown_dns} DNS target${previewEstimate.unknown_dns === 1 ? '' : 's'} remain unknown until scan time` : 'Known from IP and CIDR input'} />
          <Estimate label="Estimated probes" value={previewEstimate.probes.toLocaleString()} detail={`${previewEstimate.tcp_ports.toLocaleString()} TCP · ${previewEstimate.udp_ports.toLocaleString()} UDP ports`} />
          <Estimate label="Scanner work" value={`${previewEstimate.nmap_invocations.toLocaleString()} Nmap`} detail={`${previewEstimate.naabu_invocations ?? 0} Naabu discovery invocation${previewEstimate.naabu_invocations === 1 ? '' : 's'}`} />
        </div> : <p className="helper">The current preview will show estimated probes and known host expansion here.</p>}
        {previewBudget && <div className={previewBudget.exceeded ? 'notice warning scan-budget-warning' : 'success-banner'} role="status"><Timer size={16} /><span>{previewBudget.exceeded ? budgetMessage(previewBudget) : `Estimated work is within the current probe budget${previewBudget.limit ? ` of ${previewBudget.limit.toLocaleString()} probes` : ''}.`}</span></div>}
        {previewIsCurrent && !previewBudget && <div className="notice warning" role="status"><TriangleAlert size={16} /><span>The current preview did not confirm a scan budget. Retry the preview before requesting a first scan.</span></div>}
        {previewData?.warnings.map((warning, index) => <div className="notice warning" role="status" key={`${warning.code}-${warning.field ?? ''}-${index}`}><TriangleAlert size={16} /><span>{warning.field ? `${warning.field}: ` : ''}{warning.message}</span></div>)}
        {scannerAvailabilityUnverified && <div className="notice warning" role="status"><TriangleAlert size={16} /><span>Scanner availability is unverified. Retry the capability check before starting; preview only validates configuration and budget.</span></div>}
        {scannerMissing && <div className="notice warning" role="alert"><TriangleAlert size={16} /><span>A selected scanner is unavailable in this deployment. Review scanner installation and capabilities before starting a scan.</span></div>}
        {naabuSynUnavailable && <div className="notice warning" role="alert"><TriangleAlert size={16} /><span>Naabu SYN needs the deployment's SYN capability override. Switch to connect mode or ask an administrator to enable the required capabilities.</span></div>}
        {previewEstimate?.unknown_dns ? <p className="helper">DNS answers, routed addresses, actual exclusions, and data-dependent confirmation work can change the final scan work. The scanner checks the current policy again before it runs.</p> : null}
      </div>

      <details className="panel form-panel advanced-review">
        <summary>Advanced configuration included in this monitor</summary>
        <dl className="monitor-review-list">
          <div><dt>Host expansion limit</dt><dd>{draft.fields.max_expanded_hosts.toLocaleString()} hosts</dd></div>
          <div><dt>Host discovery</dt><dd>{draft.fields.assume_alive === false ? 'Enabled' : 'Assume targets are alive (-Pn)'}</dd></div>
          <div><dt>DNS comparison</dt><dd>{draft.fields.dns_comparison_mode ?? 'address_sensitive'}</dd></div>
          <div><dt>Timing and timeout</dt><dd>{draft.fields.timing} · {draft.fields.timeout}</dd></div>
          <div><dt>Resume window</dt><dd>{draft.fields.resume_window}</dd></div>
          <div><dt>Baseline and confirmations</dt><dd>{draft.fields.baseline_samples} samples · {draft.fields.change_confirmations} matching scans</dd></div>
          <div><dt>Run at daemon startup</dt><dd>{draft.fields.run_on_start ? 'Yes' : 'No'}</dd></div>
          <div><dt>High-cost approval</dt><dd>{draft.fields.allow_high_cost ? 'Enabled' : 'Not enabled'}</dd></div>
          {reviewJob.tcp && <div><dt>TCP protocol options</dt><dd>{protocolDetails(reviewJob.tcp)}</dd></div>}
          {reviewJob.udp && <div><dt>UDP protocol options</dt><dd>{protocolDetails(reviewJob.udp)}</dd></div>}
        </dl>
      </details>

      {createOutcomeUnknown
        ? <div className="form-error" role="alert">EdgeWatch did not confirm whether this monitor was created. Do not submit this draft again; <Link to="/jobs" target="_blank" rel="noreferrer">open Jobs in another tab</Link> to check.</div>
        : actionError && <div className="form-error" role="alert">{actionError}</div>}
      {isOverBudget && <div className="notice warning" role="status"><TriangleAlert size={16} /><span>Create without starting remains available. To start this scan, narrow the scope or ask an administrator to approve high-cost scans in the full editor, then request a new preview.</span></div>}
      {preview?.status === 'ready' && preview.signature === previewSignature && <div className="monitor-actions review-actions">
        <button type="button" className="button ghost" onClick={() => goTo('schedule')}><ArrowLeft size={16} /> Back</button>
        <div><button type="button" className="button secondary" disabled={createDisabled} onClick={() => void createMonitor(false)}>{saving ? 'Creating…' : 'Create without starting'}</button><button type="button" className="button primary" disabled={createStartDisabled} onClick={() => void createMonitor(true)}>{saving ? 'Creating…' : 'Create and start first scan'}</button></div>
      </div>}
    </div>}
    </fieldset>

    {discardNavigation && <ActionDialog title="Discard monitor changes?" description="This monitor configuration has not been saved. Leave the setup and discard the draft? A destination created from this flow is a separate resource and will remain in Notifications." confirmLabel="Discard changes" destructive onConfirm={() => {
      const navigation = discardNavigation
      setDiscardNavigation(null)
      if (navigation.historyPop) {
        allowHistoryPop.current = true
        window.history.back()
      } else navigate(navigation.destination)
    }} onCancel={() => {
      const navigation = discardNavigation
      setDiscardNavigation(null)
      if (navigation.historyPop) {
        const current = currentHistoryEntry.current
        if (current) window.history.replaceState(current.state, '', current.path)
      }
    }} />}
  </section>
}

async function previewJobRequest(payload: JobForm, signal: AbortSignal) {
  return previewJob(payload, signal)
}

function Estimate({ label, value, detail }: { label: string; value: string; detail: string }) {
  return <div className="monitor-estimate"><span>{label}</span><strong>{value}</strong><small>{detail}</small></div>
}

function stepHeading(step: SetupStep) {
  switch (step) {
    case 'targets': return 'Choose targets'
    case 'coverage': return 'Set scan coverage'
    case 'schedule': return 'Set schedule and alerts'
    default: return 'Review and create'
  }
}

function coverageSummary(tcp?: Protocol, udp?: Protocol) {
  if (!tcp && !udp) return 'No protocols selected'
  const parts = [
    tcp && (tcp.engine === 'naabu_nmap' ? 'Full TCP surface · Naabu discovers ports 1–65535 and Nmap confirms findings' : `Partial TCP coverage · ports ${tcp.ports} through Nmap`),
    udp && `UDP ports ${udp.ports} through Nmap`,
  ].filter(Boolean)
  return parts.join(' · ')
}

function defaultSelectedTCP(): Protocol {
  return { ports: '22,443', mode: 'connect', service_detection: false, engine: 'nmap' }
}

function selectedTCPFromFull(protocol: Protocol): Protocol {
  const selected = cloneProtocol(protocol)!
  delete selected.profile_id
  delete selected.profile_revision
  delete selected.naabu
  delete selected.naabu_args
  delete selected.enrichment_args
  return { ...selected, ports: '22,443', mode: protocol.mode ?? 'connect', service_detection: protocol.service_detection, engine: 'nmap' }
}

function protocolDetails(protocol: Protocol) {
  const options = {
    engine: protocol.engine ?? 'nmap',
    ports: protocol.ports,
    mode: protocol.mode,
    service_detection: protocol.service_detection,
    profile_id: protocol.profile_id,
    profile_revision: protocol.profile_revision,
    naabu: protocol.naabu,
    naabu_args: protocol.naabu_args,
    nmap_args: protocol.nmap_args,
    enrichment_args: protocol.enrichment_args,
    nse_profile: protocol.nse_profile,
    nse_args: protocol.nse_args,
  }
  return <code>{JSON.stringify(options)}</code>
}

function formatRunInZone(value: string, zone: string) {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return `the next scheduled run (${zone})`
  try {
    return `${date.toLocaleString(undefined, { weekday: 'short', hour: '2-digit', minute: '2-digit', timeZone: zone })} (${zone})`
  } catch {
    return `${formatDateTime(date)} (${getDisplayTimeZone() || zone})`
  }
}

function budgetMessage(budget: NonNullable<JobPreview['scan_budget']>) {
  const estimate = budget.estimated_probes?.toLocaleString() ?? 'The estimated'
  const limit = budget.limit?.toLocaleString() ?? 'this unit’s limit'
  return budget.approval_would_fit
    ? `About ${estimate} probes exceed this unit’s budget of ${limit}. An administrator’s high-cost approval would allow the scan.`
    : `About ${estimate} probes exceed the maximum allowed for this scope (${limit}); narrow targets or ports before starting.`
}

function errorText(error: unknown, fallback: string) {
  if (error instanceof APIError && error.details) {
    const details = Object.values(error.details).filter((value): value is string => typeof value === 'string')
    if (details.length > 0) return details.join(' ')
  }
  return error instanceof Error ? error.message : fallback
}

function isCreationPath(path: string) {
  const pathname = path.split(/[?#]/, 1)[0]
  return pathname === '/jobs/new' || pathname.startsWith('/jobs/new/')
}
