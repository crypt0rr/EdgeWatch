import type { Pagination as PaginationInfo } from '../types'
import { MAX_PAGINATION_OFFSET } from '../pagination'

/**
 * Small, keyboard-accessible offset paginator shared by history views. It
 * stays visible on any later page, even after the list shrank to a single
 * page, so Previous always leads back to the remaining rows.
 */
export function Pagination({ page, onChange, label = 'Pagination' }: { page?: PaginationInfo; onChange: (offset: number) => void; label?: string }) {
  if (!page || (page.total <= page.limit && page.offset === 0)) return null
  const first = page.total === 0 ? 0 : page.offset + 1
  const last = Math.min(page.offset + page.limit, page.total)
  const nextOffset = page.next_offset
  const nextOffsetUnavailable = page.has_more && nextOffset !== null && nextOffset > MAX_PAGINATION_OFFSET
  const canGoNext = page.has_more && nextOffset !== null && nextOffset <= MAX_PAGINATION_OFFSET
  return (
    <nav className="pagination" aria-label={label}>
      <span className="muted" role={nextOffsetUnavailable ? 'status' : undefined}>{page.offset >= page.total ? `${page.total} total` : `${first}–${last} of ${page.total}`}{nextOffsetUnavailable ? ' · Maximum page offset reached. Further results are unavailable. Use Previous to return to earlier results.' : ''}</span>
      <div className="pagination-actions">
        <button type="button" className="button ghost" disabled={page.offset === 0} onClick={() => onChange(Math.max(0, page.offset - page.limit))}>Previous</button>
        <button type="button" className="button ghost" disabled={!canGoNext} onClick={() => canGoNext && nextOffset !== null && onChange(nextOffset)}>Next</button>
      </div>
    </nav>
  )
}
