import { useState } from 'react'
import { AlertTriangle, Check, Copy } from 'lucide-react'
import './OneTimeLink.css'

type OneTimeLinkProps = {
  title: string
  path: string
  note: string
  warning?: string
  onDismiss: () => void
}

/** A one-time account link, shown only after the server issues it. */
export function OneTimeLink({ title, path, note, warning, onDismiss }: OneTimeLinkProps) {
  const [copied, setCopied] = useState(false)
  const [copyError, setCopyError] = useState('')
  const url = `${window.location.origin}${path}`

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

  return <section className="panel activation-token one-time-link">
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
