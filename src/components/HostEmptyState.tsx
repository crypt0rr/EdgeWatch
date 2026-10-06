type HostEmptyStateProps = {
  search: string
  protocol: string
  open: string
  emptyMessage: string
  onClearSearch: () => void
  onResetFilters: () => void
}

export function HostEmptyState({ search, protocol, open, emptyMessage, onClearSearch, onResetFilters }: HostEmptyStateProps) {
  const hasSearch = search.trim().length > 0
  const hasFilters = Boolean(protocol || open)
  const criteria = [
    hasSearch ? `“${search.trim()}”` : '',
    protocol ? protocol.toUpperCase() : '',
    open ? open === 'true' ? 'hosts with positive ports' : 'hosts with no positive ports' : '',
  ].filter(Boolean)

  return <div className="inline-empty host-empty-results" role="status">
    <p>{criteria.length ? `No hosts match ${criteria.join(' and ')}.` : emptyMessage}</p>
    {(hasSearch || hasFilters) && <div className="host-empty-actions">
      {hasSearch && <button type="button" className="button secondary" onClick={onClearSearch}>Clear search</button>}
      {hasFilters && <button type="button" className="button secondary" onClick={onResetFilters}>Reset filters</button>}
    </div>}
  </div>
}
