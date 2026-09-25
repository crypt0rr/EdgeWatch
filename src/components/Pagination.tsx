import type { Pagination as PaginationInfo } from '../types'

/**
 * Small, keyboard-accessible offset paginator shared by history views. It
 * stays visible on any later page, even after the list shrank to a single
 * page, so Previous always leads back to the remaining rows.
 */
export function Pagination({ page, onChange }: { page?: PaginationInfo; onChange: (offset: number) => void }) {
  if (!page || (page.total <= page.limit && page.offset === 0)) return null
  const first = page.total === 0 ? 0 : page.offset + 1
  const last = Math.min(page.offset + page.limit, page.total)
  return (
    <nav className="pagination" aria-label="Pagination">
      <span className="muted">{page.offset >= page.total ? `${page.total} total` : `${first}–${last} of ${page.total}`}</span>
      <div className="pagination-actions">
        <button type="button" className="button ghost" disabled={page.offset === 0} onClick={() => onChange(Math.max(0, page.offset - page.limit))}>Previous</button>
        <button type="button" className="button ghost" disabled={!page.has_more || page.next_offset == null} onClick={() => page.next_offset != null && onChange(page.next_offset)}>Next</button>
      </div>
    </nav>
  )
}
