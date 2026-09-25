import { useState } from 'react'
import { AlertTriangle, Check, Copy } from 'lucide-react'
import { APIError } from '../../api'
import type { BusinessUnitStatus, UnitRole } from '../../api'

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

/** Derive a readable public-URL slug from a unit name. */
export function slugify(name: string) {
  return name.normalize('NFKD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+/, '').slice(0, 40).replace(/-+$/, '')
}

/** Mirrors the server's slug rule so problems are explained before a request. */
export function slugProblem(slug: string) {
  if (!slug) return 'Enter a slug for the unit’s public link.'
  if (!/^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$/.test(slug)) return 'Use 1 to 40 lowercase letters, digits, or hyphens, starting and ending with a letter or digit.'
  return ''
}

export function publicURL(slug: string) {
  return `${window.location.origin}/public/${slug}`
}

export function errorMessage(error: unknown, fallback: string) {
  return error instanceof Error && error.message ? error.message : fallback
}

export function isConflict(error: unknown) {
  return error instanceof APIError && error.code === 'conflict'
}

export function Loading({ label }: { label: string }) {
  return <div className="loading"><span className="spinner" />{label}</div>
}

/**
 * A one-time activation or reset link. The server returns it once, so the
 * console shows it until dismissed and never fetches it again.
 */
export function OneTimeLink({ title, path, note, warning, onDismiss }: { title: string; path: string; note: string; warning?: string; onDismiss: () => void }) {
  const [copied, setCopied] = useState(false)
  const url = `${window.location.origin}${path}`
  async function copy() {
    try {
      await navigator.clipboard?.writeText(url)
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
