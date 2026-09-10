import { useEffect, useId, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { AlertTriangle, LockKeyhole } from 'lucide-react'

type ActionDialogProps = {
  title: string
  description: string
  confirmLabel: string
  onConfirm: (value: string) => void | Promise<void>
  onCancel: () => void
  destructive?: boolean
  valueLabel?: string
  valueType?: 'password' | 'text'
  valueRequired?: boolean
  expectedValue?: string
  placeholder?: string
  autoComplete?: string
  error?: string
}

const focusableSelector = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(',')

/**
 * A small, dependency-free modal used for credentials and destructive actions.
 * It owns focus, scroll locking, validation, and the async submit state so all
 * sensitive flows behave consistently on desktop and mobile browsers.
 */
export function ActionDialog({
  title,
  description,
  confirmLabel,
  onConfirm,
  onCancel,
  destructive = false,
  valueLabel,
  valueType = 'text',
  valueRequired = false,
  expectedValue,
  placeholder,
  autoComplete,
  error,
}: ActionDialogProps) {
  const dialogRef = useRef<HTMLElement>(null)
  const valueRef = useRef<HTMLInputElement>(null)
  const previousFocusRef = useRef<HTMLElement | null>(null)
  const [value, setValue] = useState('')
  const [busy, setBusy] = useState(false)
  const [validationError, setValidationError] = useState('')
  const titleID = useId()
  const descriptionID = useId()
  const errorID = useId()
  const onCancelRef = useRef(onCancel)
  const busyRef = useRef(busy)

  useEffect(() => {
    onCancelRef.current = onCancel
  }, [onCancel])
  useEffect(() => {
    busyRef.current = busy
  }, [busy])

  useEffect(() => {
    previousFocusRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null
    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'

    // The dialog is portalled to document.body, so the application shell can
    // be made inert without also hiding the dialog from assistive technology.
    // Keep the previous state because another modal implementation or a
    // browser accessibility polyfill may already have set these attributes.
    const appShell = document.querySelector<HTMLElement>('.app-shell')
    const wasInert = appShell?.hasAttribute('inert') ?? false
    const previousAriaHidden = appShell?.getAttribute('aria-hidden') ?? null
    if (appShell) {
      appShell.inert = true
      appShell.setAttribute('inert', '')
      appShell.setAttribute('aria-hidden', 'true')
    }

    const dialog = dialogRef.current
    const focusables = () => Array.from(dialog?.querySelectorAll<HTMLElement>(focusableSelector) ?? [])
    const first = () => focusables()[0]
    const last = () => focusables().at(-1)
    ;(valueRef.current ?? first())?.focus({ preventScroll: true })

    function onKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        event.preventDefault()
        if (!busyRef.current) onCancelRef.current()
        return
      }
      if (event.key !== 'Tab') return
      const items = focusables()
      if (!items.length) {
        event.preventDefault()
        return
      }
      const active = document.activeElement
      if (event.shiftKey && (active === first() || !dialog?.contains(active))) {
        event.preventDefault()
        last()?.focus()
      } else if (!event.shiftKey && (active === last() || !dialog?.contains(active))) {
        event.preventDefault()
        first()?.focus()
      }
    }

    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('keydown', onKeyDown)
      document.body.style.overflow = previousOverflow
      if (appShell) {
        appShell.inert = wasInert
        if (wasInert) appShell.setAttribute('inert', '')
        else appShell.removeAttribute('inert')
        if (previousAriaHidden === null) appShell.removeAttribute('aria-hidden')
        else appShell.setAttribute('aria-hidden', previousAriaHidden)
      }
      const previous = previousFocusRef.current
      if (previous && document.contains(previous)) previous.focus({ preventScroll: true })
    }
  }, [])

  async function submit() {
    if (valueRequired && !value.trim()) {
      setValidationError(`${valueLabel ?? 'This value'} is required.`)
      return
    }
    if (expectedValue !== undefined && value !== expectedValue) {
      setValidationError('The confirmation text does not match.')
      valueRef.current?.focus({ preventScroll: true })
      return
    }
    setValidationError('')
    setBusy(true)
    try {
      await onConfirm(value)
    } finally {
      setBusy(false)
    }
  }

  const dialog = <div className="modal-backdrop" role="presentation">
    <section ref={dialogRef} className="action-dialog" role="dialog" aria-modal="true" aria-busy={busy} aria-labelledby={titleID} aria-describedby={descriptionID}>
      <div className={destructive ? 'action-dialog-icon destructive' : 'action-dialog-icon'}>{destructive ? <AlertTriangle size={19} /> : <LockKeyhole size={19} />}</div>
      <h2 id={titleID}>{title}</h2>
      <p id={descriptionID}>{description}</p>
      <div className="sr-only" role="status" aria-live="polite" aria-atomic="true">{busy ? `${confirmLabel} in progress.` : ''}</div>
      <form className="action-dialog-form" onSubmit={event => { event.preventDefault(); void submit() }}>
        {valueLabel && <label>{valueLabel}<input ref={valueRef} type={valueType} value={value} onChange={event => { setValue(event.target.value); setValidationError('') }} placeholder={placeholder} autoComplete={autoComplete} aria-invalid={!!(validationError || error)} aria-describedby={validationError || error ? errorID : undefined} required={valueRequired} /></label>}
        {(validationError || error) && <div id={errorID} className="form-error" role="alert">{validationError || error}</div>}
        <div className="action-dialog-actions"><button className="button ghost" type="button" onClick={onCancel} disabled={busy}>Cancel</button><button className={destructive ? 'button danger' : 'button primary'} type="submit" disabled={busy || (valueRequired && !value.trim())}>{busy ? 'Working…' : confirmLabel}</button></div>
      </form>
    </section>
  </div>

  // Keep modal content outside the shell so inert/aria-hidden never masks the
  // dialog itself. This also prevents stacking-context and overflow styles on
  // a page from trapping the fixed backdrop.
  return createPortal(dialog, document.body)
}
