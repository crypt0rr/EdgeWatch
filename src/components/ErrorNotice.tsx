type ErrorNoticeProps = {
  message: string
  onRetry?: () => void | Promise<unknown>
  retryLabel?: string
}

/** A consistent, recoverable presentation for failed reads and mutations. */
export function ErrorNotice({ message, onRetry, retryLabel = 'Retry' }: ErrorNoticeProps) {
  return <div className="error-card" role="alert">
    <span>{message}</span>
    {onRetry && <button type="button" className="button secondary" onClick={() => void onRetry()}>{retryLabel}</button>}
  </div>
}
