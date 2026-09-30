import { useState } from 'react'
import { AlertTriangle, Check, Copy } from 'lucide-react'
import { APIError } from '../../api'
import type { BusinessUnitStatus, UnitRole } from '../../api'
import { formatDateTime } from '../../format'

const statusPresentation: Record<BusinessUnitStatus, { label: string; tone: string }> = {
  active: { label: 'Active', tone: 'green' },
  disabled: { label: 'Disabled', tone: 'gray' },
  deleting: { label: 'Deleting', tone: 'red' },
  deleted: { label: 'Deleted', tone: 'gray' },
}

export function UnitStatusPill({ status }: { status: BusinessUnitStatus }) {
  const presentation = statusPresentation[status] ?? { label: status, tone: 'gray' }
  return <span className={`pill ${presentation.tone}`}>{presentation.label}</span>
}

export const unitRoleLabels: Record<UnitRole, string> = { administrator: 'Administrator', operator: 'Operator', viewer: 'Viewer' }

export function formatCount(value: number) {
  return value.toLocaleString()
}

export function plural(count: number, singular: string, pluralForm = `${singular}s`) {
  return `${count.toLocaleString()} ${count === 1 ? singular : pluralForm}`
}

// The slugs that name the console's own paths, which the server refuses.
const reservedSlugs = new Set(['admin', 'api', 'app', 'assets', 'auth', 'events', 'health', 'healthz', 'login', 'logout', 'platform', 'public', 'setup', 'static', 'status', 'stream', 'v1'])

/** Mirrors the server's slug rule so a problem is explained before the request. */
export function slugProblem(slug: string) {
  if (!/^[a-z0-9-]{2,40}$/.test(slug)) return 'Use 2 to 40 lowercase letters, digits, or hyphens.'
  if (reservedSlugs.has(slug)) return `“${slug}” is reserved for the console. Choose another slug.`
  return ''
}

/** The address of a unit's public status page. */
export function publicPath(slug: string) {
  return `/public/${encodeURIComponent(slug)}`
}

export function publicURL(slug: string) {
  return `${window.location.origin}${publicPath(slug)}`
}

/**
 * The last sign-in of an account row, or nothing for an account that never
 * signed in. The API leaves last_login_at out for such an account; an older
 * server sent the zero time, so a time before 1970 is no sign-in either.
 */
export function lastSignIn(value?: string) {
  const time = value ? Date.parse(value) : Number.NaN
  return time > 0 ? ` · last sign-in ${formatDateTime(time)}` : ''
}

/** The message of a failed request: the field details when the server names them. */
export function errorMessage(error: unknown, fallback: string) {
  if (error instanceof APIError && error.details) {
    const details = Object.values(error.details).filter((value): value is string => typeof value === 'string' && value !== '')
    if (details.length) return details.join(' ')
  }
  return error instanceof Error && error.message ? error.message : fallback
}

export function isConflict(error: unknown) {
  return error instanceof APIError && error.code === 'conflict'
}

// The refusals that report the target's current state: it moved to a new
// revision, its state or its unit's no longer allows the change, it is no
// longer of the kind the change needs, or it is gone.
const changedElsewhereCodes = new Set(['conflict', 'not_found', 'not_permitted', 'unit_state', 'unit_not_active', 'user_disabled'])

/**
 * Whether a refused change may have been refused because its account or unit
 * changed elsewhere. The page then reloads it, and offers the change again
 * only when the reloaded account or unit still allows it.
 */
export function isChangedElsewhere(error: unknown) {
  return error instanceof APIError && changedElsewhereCodes.has(error.code ?? '')
}

export function Loading({ label }: { label: string }) {
  return <div className="loading"><span className="spinner" />{label}</div>
}

/**
 * A one-time activation or password-reset link. The server returns it once,
 * so the console shows it until it is dismissed and never fetches it again.
 * It says "Copied" only after the clipboard took this link, so a page renders
 * each new link with its path as the key, which starts it as not copied.
 */
export function OneTimeLink({ title, path, note, warning, onDismiss }: { title: string; path: string; note: string; warning?: string; onDismiss: () => void }) {
  const [copied, setCopied] = useState(false)
  const url = `${window.location.origin}${path}`
  async function copy() {
    // Without a clipboard, as on a page that is not served over HTTPS,
    // nothing is copied.
    if (!navigator.clipboard) return
    try {
      await navigator.clipboard.writeText(url)
      setCopied(true)
    } catch {
      setCopied(false)
    }
  }
  return <div className="panel activation-token one-time-link">
    <div><strong>{title}</strong><p className="muted">{note}</p>{warning && <div className="notice warning one-time-warning" role="alert"><AlertTriangle size={14} /><span><strong>{warning}</strong></span></div>}</div>
    <code aria-label={title}>{url}</code>
    <div className="heading-actions"><button type="button" className="button secondary" onClick={() => void copy()}>{copied ? <Check size={16} /> : <Copy size={16} />} {copied ? 'Copied' : 'Copy link'}</button><button type="button" className="button ghost" onClick={onDismiss}>Done</button></div>
  </div>
}
