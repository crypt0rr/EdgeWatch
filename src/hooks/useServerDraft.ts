import { useRef, useState, type Dispatch, type SetStateAction } from 'react'

export type ServerDraftSnapshot<TDraft, TRevision> = {
  value: TDraft
  baseRevision: TRevision
}

type ControlledDraft<TDraft, TRevision> = {
  snapshot: ServerDraftSnapshot<TDraft, TRevision> | null | undefined
  onChange: (snapshot: ServerDraftSnapshot<TDraft, TRevision> | null) => void
}

type ServerDraftOptions<TServer, TDraft, TRevision> = {
  createDraft?: (server: TServer) => TDraft
  mergeDraft?: (server: TServer, draft: TDraft) => TServer
  controlled?: ControlledDraft<TDraft, TRevision>
}

/**
 * Keeps a user's edits separate from refreshed server data. A draft remains
 * pinned to the revision where editing began until it is explicitly rebased,
 * adopted from the server, discarded, or marked saved. `mergeDraft` lets
 * partially edited forms keep following server updates for untouched fields.
 */
export function useServerDraft<TServer, TDraft = TServer, TRevision = string>(
  server: TServer,
  revision: TRevision,
  options: ServerDraftOptions<TServer, TDraft, TRevision> = {},
) {
  const [internalSnapshot, setInternalSnapshot] = useState<ServerDraftSnapshot<TDraft, TRevision> | null>(null)
  const controlled = options.controlled
  const snapshot = controlled ? controlled.snapshot ?? null : internalSnapshot
  const createDraft = options.createDraft ?? ((value: TServer) => value as unknown as TDraft)
  const mergeDraft = options.mergeDraft ?? ((_server: TServer, draft: TDraft) => draft as unknown as TServer)
  const draft = snapshot ? mergeDraft(server, snapshot.value) : server
  const baseRevision = snapshot?.baseRevision ?? revision
  const remoteChanged = snapshot !== null && !Object.is(snapshot.baseRevision, revision)

  const latest = useRef({ server, revision, snapshot, controlled, createDraft })
  latest.current = { server, revision, snapshot, controlled, createDraft }

  const publish = (next: ServerDraftSnapshot<TDraft, TRevision> | null) => {
    latest.current.snapshot = next
    if (latest.current.controlled) latest.current.controlled.onChange(next)
    else setInternalSnapshot(next)
  }

  const setDraft: Dispatch<SetStateAction<TDraft>> = update => {
    const current = latest.current
    const previous = current.snapshot?.value ?? current.createDraft(current.server)
    const value = typeof update === 'function'
      ? (update as (value: TDraft) => TDraft)(previous)
      : update
    publish({ value, baseRevision: current.snapshot?.baseRevision ?? current.revision })
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
