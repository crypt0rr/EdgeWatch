export type BaselineStatusInfo = {
  status: string
  samples?: number
  incomplete_attempts?: number
}

export type BaselinePresentation = {
  /** `complete` means an active baseline, including one whose scope is updating. */
  status: 'complete' | 'stalled' | 'learning'
  label: 'Ready' | 'Ready (updating scope)' | 'Stalled' | 'Learning'
  tone: 'green' | 'red' | 'amber'
  marker: '●' | '⚠' | '◌'
}

/** Keep baseline state labels and emphasis consistent across the application. */
export function baselinePresentation(baseline: BaselineStatusInfo): BaselinePresentation {
  if (baseline.status === 'complete') return { status: 'complete', label: 'Ready', tone: 'green', marker: '●' }
  // The API reports "updating" while an existing baseline is still keyed to an
  // older spelling of the job's scope (for example ports "443,80"). It stays
  // fully in effect until the next finalized scan or job save re-keys it.
  if (baseline.status === 'updating') return { status: 'complete', label: 'Ready (updating scope)', tone: 'green', marker: '●' }
  if (baseline.status === 'stalled') return { status: 'stalled', label: 'Stalled', tone: 'red', marker: '⚠' }
  return { status: 'learning', label: 'Learning', tone: 'amber', marker: '◌' }
}
