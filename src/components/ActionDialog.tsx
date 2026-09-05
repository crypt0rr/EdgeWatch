import { useEffect, useId, useRef, useState } from 'react'
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

  return <div className="modal-backdrop" role="presentation">
    <section ref={dialogRef} className="action-dialog" role="dialog" aria-modal="true" aria-labelledby={titleID} aria-describedby={descriptionID}>
      <div className={destructive ? 'action-dialog-icon destructive' : 'action-dialog-icon'}>{destructive ? <AlertTriangle size={19} /> : <LockKeyhole size={19} />}</div>
      <h2 id={titleID}>{title}</h2>
      <p id={descriptionID}>{description}</p>
      <form className="action-dialog-form" onSubmit={event => { event.preventDefault(); void submit() }}>
        {valueLabel && <label>{valueLabel}<input ref={valueRef} type={valueType} value={value} onChange={event => { setValue(event.target.value); setValidationError('') }} placeholder={placeholder} autoComplete={autoComplete} aria-invalid={!!(validationError || error)} aria-describedby={validationError || error ? errorID : undefined} required={valueRequired} /></label>}
        {(validationError || error) && <div id={errorID} className="form-error" role="alert">{validationError || error}</div>}
        <div className="action-dialog-actions"><button className="button ghost" type="button" onClick={onCancel} disabled={busy}>Cancel</button><button className={destructive ? 'button danger' : 'button primary'} type="submit" disabled={busy || (valueRequired && !value.trim())}>{busy ? 'Working…' : confirmLabel}</button></div>
      </form>
    </section>
  </div>
}
