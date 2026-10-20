import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from 'react'
import { cloneJobCreationDraft, newJobCreationDraft, type JobCreationDraft } from './job-form'

/**
 * What became of a Perimeter prefill: applied to the fresh draft, or refused
 * because the draft already had changes. source is the declared range.
 */
export type PerimeterPrefillOutcome = { source: string; applied: boolean }

type CreationDraftContextValue = {
  draft: JobCreationDraft
  dirty: boolean
  createOutcomeUnknown: boolean
  /** Kept with the draft, so the guided setup still shows it after a round trip through the full editor. */
  perimeterPrefill: PerimeterPrefillOutcome | null
  updateDraft: (updater: (draft: JobCreationDraft) => JobCreationDraft, markDirty?: boolean) => void
  markCreateOutcomeUnknown: () => void
  setPerimeterPrefillOutcome: (outcome: PerimeterPrefillOutcome | null) => void
  clearDraft: () => void
}

const CreationDraftContext = createContext<CreationDraftContextValue | null>(null)

type CreationDraftState = Pick<CreationDraftContextValue, 'draft' | 'dirty' | 'createOutcomeUnknown' | 'perimeterPrefill'>

function newCreationDraftState(): CreationDraftState {
  return { draft: newJobCreationDraft(), dirty: false, createOutcomeUnknown: false, perimeterPrefill: null }
}

/** Owns only one in-memory creation journey and is mounted around its routes. */
export function JobCreationDraftProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState(newCreationDraftState)
  const updateDraft = useCallback((updater: (draft: JobCreationDraft) => JobCreationDraft, markDirty = true) => {
    setState(current => ({
      ...current,
      draft: cloneJobCreationDraft(updater(cloneJobCreationDraft(current.draft))),
      dirty: current.dirty || markDirty,
    }))
  }, [])
  const markCreateOutcomeUnknown = useCallback(() => setState(current => ({ ...current, createOutcomeUnknown: true })), [])
  const setPerimeterPrefillOutcome = useCallback((outcome: PerimeterPrefillOutcome | null) => setState(current => ({ ...current, perimeterPrefill: outcome })), [])
  const clearDraft = useCallback(() => setState(newCreationDraftState()), [])
  const value = useMemo(() => ({ ...state, updateDraft, markCreateOutcomeUnknown, setPerimeterPrefillOutcome, clearDraft }), [state, updateDraft, markCreateOutcomeUnknown, setPerimeterPrefillOutcome, clearDraft])
  return <CreationDraftContext.Provider value={value}>{children}</CreationDraftContext.Provider>
}

/** Optional because JobEditor is also used directly by focused legacy tests. */
export function useOptionalJobCreationDraft() {
  return useContext(CreationDraftContext)
}

export function useJobCreationDraft() {
  const value = useOptionalJobCreationDraft()
  if (!value) throw new Error('Job creation draft provider is missing.')
  return value
}
