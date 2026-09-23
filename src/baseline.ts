export type BaselineStatusInfo = {
  status: string
  samples?: number
  incomplete_attempts?: number
}

export type BaselinePresentation = {
  status: 'complete' | 'stalled' | 'learning'
  label: 'Ready' | 'Stalled' | 'Learning'
  tone: 'green' | 'red' | 'amber'
  marker: '●' | '⚠' | '◌'
}

/** Keep baseline state labels and emphasis consistent across the application. */
export function baselinePresentation(baseline: BaselineStatusInfo): BaselinePresentation {
  if (baseline.status === 'complete') return { status: 'complete', label: 'Ready', tone: 'green', marker: '●' }
  if (baseline.status === 'stalled') return { status: 'stalled', label: 'Stalled', tone: 'red', marker: '⚠' }
  return { status: 'learning', label: 'Learning', tone: 'amber', marker: '◌' }
}
