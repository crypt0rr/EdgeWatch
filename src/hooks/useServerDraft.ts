import { useRef, useState, type Dispatch, type SetStateAction } from 'react'

export type ServerDraftSnapshot<TDraft, TRevision> = {
  value: TDraft
  baseRevision: TRevision
}

type ControlledDraft<TDraft, TRevision> = {
  snapshot: ServerDraftSnapshot<TDraft, TRevision> | null | undefined
  onChange: (snapshot: ServerDraftSnapshot<TDraft, TRevision> | null) => void
}

type ServerDraftOptions<TServer, TDraft, TRevision, TView> = {
  createDraft?: (server: TServer) => TDraft
  mergeDraft?: (server: TServer, draft: TDraft) => TView
  captureDraft?: (server: TServer, view: TView) => TDraft
  controlled?: ControlledDraft<TDraft, TRevision>
}

/**
 * Keeps a user's edits separate from refreshed server data. A draft remains
 * pinned to the revision where editing began until it is explicitly rebased,
 * adopted from the server, discarded, or marked saved. `mergeDraft` lets
 * partially edited forms keep following server updates for untouched fields.
 */
export function useServerDraft<TServer, TDraft = TServer, TRevision = string, TView = TServer>(
  server: TServer,
  revision: TRevision,
  options: ServerDraftOptions<TServer, TDraft, TRevision, TView> = {},
) {
  const [internalSnapshot, setInternalSnapshot] = useState<ServerDraftSnapshot<TDraft, TRevision> | null>(null)
  const controlled = options.controlled
  const snapshot = controlled ? controlled.snapshot ?? null : internalSnapshot
  const createDraft = options.createDraft ?? ((value: TServer) => value as unknown as TDraft)
  const mergeDraft = options.mergeDraft ?? ((_server: TServer, draft: TDraft) => draft as unknown as TView)
  const captureDraft = options.captureDraft ?? ((_server: TServer, view: TView) => view as unknown as TDraft)
  const draft = mergeDraft(server, snapshot ? snapshot.value : createDraft(server))
  const baseRevision = snapshot?.baseRevision ?? revision
  const remoteChanged = snapshot !== null && !Object.is(snapshot.baseRevision, revision)

  const latest = useRef({ server, revision, snapshot, controlled, createDraft, mergeDraft, captureDraft })
  latest.current = { server, revision, snapshot, controlled, createDraft, mergeDraft, captureDraft }

  const publish = (next: ServerDraftSnapshot<TDraft, TRevision> | null) => {
    latest.current.snapshot = next
    if (latest.current.controlled) latest.current.controlled.onChange(next)
    else setInternalSnapshot(next)
  }

  const setDraft: Dispatch<SetStateAction<TView>> = update => {
    const current = latest.current
    const previous = current.mergeDraft(current.server, current.snapshot ? current.snapshot.value : current.createDraft(current.server))
    const view = typeof update === 'function'
      ? (update as (value: TView) => TView)(previous)
      : update
    publish({ value: current.captureDraft(current.server, view), baseRevision: current.snapshot?.baseRevision ?? current.revision })
  }

  const clear = () => publish(null)
  const rebase = (nextRevision: TRevision = latest.current.revision) => {
    const current = latest.current.snapshot
    if (current) publish({ ...current, baseRevision: nextRevision })
  }

  return {
    draft,
    setDraft,
    baseRevision,
    remoteChanged,
    hasDraft: snapshot !== null,
    adopt: clear,
    discard: clear,
    markSaved: clear,
    rebase,
  }
}
