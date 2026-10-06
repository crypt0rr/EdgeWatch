import { useEffect, useRef, useState } from 'react'
import { AlertTriangle, Check, Copy } from 'lucide-react'
import './OneTimeLink.css'

type OneTimeLinkProps = {
  title: string
  path: string
  note: string
  warning?: string
  focusOnMount?: boolean
  onDismiss: () => void
}

/** A one-time account link, shown only after the server issues it. */
export function OneTimeLink({ title, path, note, warning, focusOnMount = false, onDismiss }: OneTimeLinkProps) {
  const [copied, setCopied] = useState(false)
  const [copyError, setCopyError] = useState('')
  const sectionRef = useRef<HTMLElement>(null)
  const url = `${window.location.origin}${path}`

  useEffect(() => {
    if (!focusOnMount) return
    // A confirmation dialog may still mark the app shell inert in this effect
    // pass. Focus after its cleanup restores the shell, and scroll the newly
    // issued link into view for the account row that triggered it.
    const frame = window.requestAnimationFrame(() => {
      const section = sectionRef.current
      section?.focus()
      section?.scrollIntoView?.({ block: 'center' })
    })
    return () => window.cancelAnimationFrame(frame)
  }, [focusOnMount])

  async function copy() {
    setCopyError('')
    setCopied(false)
    if (!navigator.clipboard?.writeText) {
      setCopyError('Clipboard access is unavailable. Select and copy the link manually.')
      return
    }
    try {
      await navigator.clipboard.writeText(url)
      setCopied(true)
    } catch {
      setCopyError('The link could not be copied. Select and copy it manually.')
    }
  }

  return <section ref={sectionRef} className="panel activation-token one-time-link" aria-label="One-time link details" tabIndex={focusOnMount ? -1 : undefined}>
    <div className="one-time-link-copy">
      <strong>{title}</strong>
      <p className="muted">{note}</p>
      {warning && <div className="notice warning one-time-warning" role="alert"><AlertTriangle size={14} /><span><strong>{warning}</strong></span></div>}
    </div>
    <code aria-label={title}>{url}</code>
    <div className="one-time-link-actions">
      <button type="button" className="button secondary" onClick={() => void copy()}>{copied ? <Check size={16} /> : <Copy size={16} />} {copied ? 'Copied' : 'Copy link'}</button>
      <button type="button" className="button ghost" onClick={onDismiss}>Done</button>
    </div>
    {copyError && <p className="one-time-link-error" role="status">{copyError}</p>}
  </section>
}
