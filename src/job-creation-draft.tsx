import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from 'react'
import { cloneJobCreationDraft, newJobCreationDraft, type JobCreationDraft } from './job-form'

type CreationDraftContextValue = {
  draft: JobCreationDraft
  dirty: boolean
  createOutcomeUnknown: boolean
  updateDraft: (updater: (draft: JobCreationDraft) => JobCreationDraft, markDirty?: boolean) => void
  markCreateOutcomeUnknown: () => void
  clearDraft: () => void
}

const CreationDraftContext = createContext<CreationDraftContextValue | null>(null)

/** Owns only one in-memory creation journey and is mounted around its routes. */
export function JobCreationDraftProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState(() => ({ draft: newJobCreationDraft(), dirty: false, createOutcomeUnknown: false }))
  const updateDraft = useCallback((updater: (draft: JobCreationDraft) => JobCreationDraft, markDirty = true) => {
    setState(current => ({
      draft: cloneJobCreationDraft(updater(cloneJobCreationDraft(current.draft))),
      dirty: current.dirty || markDirty,
      createOutcomeUnknown: current.createOutcomeUnknown,
    }))
  }, [])
  const markCreateOutcomeUnknown = useCallback(() => setState(current => ({ ...current, createOutcomeUnknown: true })), [])
  const clearDraft = useCallback(() => setState({ draft: newJobCreationDraft(), dirty: false, createOutcomeUnknown: false }), [])
  const value = useMemo(() => ({ ...state, updateDraft, markCreateOutcomeUnknown, clearDraft }), [state, updateDraft, markCreateOutcomeUnknown, clearDraft])
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
