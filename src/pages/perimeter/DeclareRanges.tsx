import { useId, useMemo, useState, type FormEvent } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { APIError, declarePerimeterSeeds, perimeterLineErrors, type PerimeterKind } from '../../api'
import type { PerimeterDeclareResult } from '../../generated/api-types'
import { PerimeterDocsLink } from './presentation'

/** The most entries one declaration holds, unless the report states the limit. */
export const defaultMaxEntries = 256

/** One non-blank line of the bulk paste: its 1-based line number, value, and label. */
export type PerimeterLine = { line: number; value: string; label: string }

function trimPerimeterWhitespace(value: string): string {
  let start = 0
  let end = value.length
  const isEdgeWhitespace = (character: string) => character !== '\u000b' && character !== '\u000c' && /\s/u.test(character)
  while (start < end && isEdgeWhitespace(value[start])) start++
  while (end > start && isEdgeWhitespace(value[end - 1])) end--
  return value.slice(start, end)
}

/**
 * Parses the bulk paste, one `<cidr-or-ip> [label]` per line. The value is
 * the text before the first whitespace character and the label is the rest
 * of the line, with ordinary edge whitespace trimmed and runs of spaces,
 * tabs, and Unicode space, line, and paragraph separators collapsed to one
 * space. Vertical tabs and form feeds are preserved for server validation;
 * blank lines are skipped but keep their numbers, so a refused entry is
 * reported on the line it came from. The server validates every value and
 * label.
 */
export function parsePerimeterLines(text: string): PerimeterLine[] {
  const parsed: PerimeterLine[] = []
  text.split(/\r\n|\r|\n/).forEach((raw, index) => {
    const line = trimPerimeterWhitespace(raw)
    if (!line) return
    const [value] = line.split(/\s/, 1)
    const label = trimPerimeterWhitespace(line.slice(value.length)).replace(/[\t\p{Zs}\u2028\u2029]+/gu, ' ')
    parsed.push({ line: index + 1, value, label })
  })
  return parsed
}

/** What an accepted declaration did. */
export function declareResultMessage(result: PerimeterDeclareResult): string {
  const skipped = result.skipped > 0 ? `${result.skipped} already declared ${result.skipped === 1 ? 'entry was' : 'entries were'} skipped.` : ''
  if (result.created === 0) return `No new ranges were declared.${skipped ? ` ${skipped}` : ''}`
  return `Declared ${result.created} new range${result.created === 1 ? '' : 's'}.${skipped ? ` ${skipped}` : ''}`
}

function detailNumber(details: Record<string, unknown> | undefined, key: string): number | undefined {
  const value = details?.[key]
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined
}

/** Why a declaration was refused as a whole; nothing of it was saved. */
export function declareErrorMessage(cause: unknown): string {
  if (cause instanceof APIError) {
    if (cause.code === 'perimeter_limit') {
      const limit = detailNumber(cause.details, 'limit')
      const held = detailNumber(cause.details, 'held')
      const added = detailNumber(cause.details, 'new')
      if (limit !== undefined && held !== undefined && added !== undefined) return `Nothing was saved. A business unit holds at most ${limit.toLocaleString()} ranges; this one holds ${held.toLocaleString()}, and this declaration would add ${added.toLocaleString()}.`
      return `Nothing was saved. ${cause.message}`
    }
    if (cause.code === 'validation_failed') {
      const limit = detailNumber(cause.details, 'limit')
      return limit !== undefined ? `Nothing was saved. Declare between 1 and ${limit.toLocaleString()} entries at a time.` : `Nothing was saved. ${cause.message}`
    }
    if (cause.code === 'audit_unavailable') return 'Nothing was saved because the audit record could not be written. Try again later.'
    return cause.message || 'The ranges could not be declared.'
  }
  return cause instanceof Error && cause.message ? cause.message : 'The ranges could not be declared.'
}

type LineError = { line: number; value: string; reason: string }

/**
 * The declare form: a kind and a bulk paste. A declaration is all or
 * nothing, so when the server refuses any entry, each refused entry is shown
 * on its textarea line and nothing is saved.
 */
export function DeclareRanges({ maxEntries = defaultMaxEntries, headingID }: { maxEntries?: number; headingID?: string }) {
  const client = useQueryClient()
  const id = useId()
  const [kind, setKind] = useState<PerimeterKind>('prefix')
  const [text, setText] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  // An empty submission is the textarea's own error: it marks the textarea
  // invalid, describes it, and clears as soon as the text changes.
  const [emptyError, setEmptyError] = useState(false)
  const [lineErrors, setLineErrors] = useState<LineError[]>([])
  const [result, setResult] = useState('')
  const lines = useMemo(() => parsePerimeterLines(text), [text])
  const tooMany = lines.length > maxEntries
  const helpID = `${id}-help`
  const countID = `${id}-count`
  const errorsID = `${id}-errors`
  const emptyID = `${id}-empty`

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy) return
    setResult('')
    if (!lines.length) {
      setError('')
      setEmptyError(true)
      setLineErrors([])
      return
    }
    if (tooMany) return
    const submitted = lines
    setBusy(true)
    setError('')
    setLineErrors([])
    try {
      const outcome = await declarePerimeterSeeds(submitted.map(entry => ({ kind, value: entry.value, ...(entry.label ? { label: entry.label } : {}) })))
      setText('')
      setResult(declareResultMessage(outcome))
      await client.invalidateQueries({ queryKey: ['perimeter'] })
    } catch (cause) {
      const refused = perimeterLineErrors(cause)
      if (refused.length) {
        setLineErrors(refused.map(entry => ({ line: submitted[entry.index]?.line ?? entry.index + 1, value: entry.value, reason: entry.reason })))
        setError(`Nothing was saved: ${refused.length === 1 ? '1 line was' : `${refused.length} lines were`} refused. Fix ${refused.length === 1 ? 'it' : 'them'} and declare again.`)
      } else {
        setError(declareErrorMessage(cause))
      }
    } finally {
      setBusy(false)
    }
  }

  const describedBy = [helpID, countID, emptyError ? emptyID : '', lineErrors.length ? errorsID : ''].filter(Boolean).join(' ')
  return <form className="perimeter-declare-form" onSubmit={event => void submit(event)} aria-labelledby={headingID} aria-busy={busy}>
    <fieldset className="perimeter-kind-choice" disabled={busy}>
      <legend>Kind</legend>
      <label><input type="radio" name={`${id}-kind`} value="prefix" checked={kind === 'prefix'} onChange={() => setKind('prefix')} /><span><strong>Owned</strong><small>Address space this business unit owns.</small></span></label>
      <label><input type="radio" name={`${id}-kind`} value="authorized" checked={kind === 'authorized'} onChange={() => setKind('authorized')} /><span><strong>Authorized</strong><small>Third-party space the team may scan but does not own, such as cloud or partner ranges.</small></span></label>
    </fieldset>
    <label>Ranges, one per line
      <textarea value={text} rows={6} spellCheck={false} autoCapitalize="off" autoComplete="off" disabled={busy} placeholder={'203.0.113.0/24 DC1 edge\n198.51.100.7'} aria-invalid={emptyError || lineErrors.length > 0 || tooMany} aria-describedby={describedBy} onChange={event => { setText(event.currentTarget.value); setResult(''); setEmptyError(false) }} />
    </label>
    <div className="perimeter-declare-meta">
      <small id={helpID}>Write an IP address or CIDR prefix, then an optional label after a space. Blank lines are ignored. <PerimeterDocsLink /></small>
      <small id={countID} aria-live="polite" className={tooMany ? 'over-limit' : undefined}>{lines.length.toLocaleString()} of at most {maxEntries.toLocaleString()} entries</small>
    </div>
    {tooMany && <p className="form-error" role="alert">Declare at most {maxEntries.toLocaleString()} entries at a time; this paste has {lines.length.toLocaleString()}. Split it into several declarations.</p>}
    {emptyError && <p id={emptyID} className="form-error" role="alert">Enter at least one IP address or CIDR prefix.</p>}
    {error && <p className="form-error" role="alert">{error}</p>}
    {lineErrors.length > 0 && <ul id={errorsID} className="perimeter-line-errors" aria-label="Refused lines">
      {lineErrors.map(entry => <li key={`${entry.line}-${entry.reason}`}><strong>Line {entry.line}</strong> <code>{entry.value}</code>: {entry.reason}</li>)}
    </ul>}
    {result && <p className="success-message" role="status">{result}</p>}
    <p className="muted perimeter-authorization">A declared range states ownership or permission. It does not authorize a scan, and declaring one never scans, creates, or changes a monitor.</p>
    <div className="perimeter-declare-actions"><button className="button primary" type="submit" disabled={busy || tooMany}>{busy ? 'Declaring…' : kind === 'prefix' ? 'Declare owned ranges' : 'Declare authorized ranges'}</button></div>
  </form>
}
