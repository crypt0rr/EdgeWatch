import type { Pagination as PaginationInfo } from '../types'

/** Small, keyboard-accessible offset paginator shared by history views. */
export function Pagination({ page, onChange }: { page?: PaginationInfo; onChange: (offset: number) => void }) {
  if (!page || page.total <= page.limit) return null
  const first = page.total === 0 ? 0 : page.offset + 1
  const last = Math.min(page.offset + page.limit, page.total)
  return (
    <nav className="pagination" aria-label="Pagination">
      <span className="muted">{first}–{last} of {page.total}</span>
      <div className="pagination-actions">
        <button type="button" className="button ghost" disabled={page.offset === 0} onClick={() => onChange(Math.max(0, page.offset - page.limit))}>Previous</button>
        <button type="button" className="button ghost" disabled={!page.has_more || page.next_offset == null} onClick={() => page.next_offset != null && onChange(page.next_offset)}>Next</button>
      </div>
    </nav>
  )
}
