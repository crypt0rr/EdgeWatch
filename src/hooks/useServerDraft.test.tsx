/** @vitest-environment jsdom */

import { act, renderHook } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { useServerDraft, type ServerDraftSnapshot } from './useServerDraft'

describe('useServerDraft', () => {
  it('follows clean server data and preserves edited fields while clean fields update', () => {
    const { result, rerender } = renderHook(
      ({ server, revision }) => useServerDraft(server, revision, {
        createDraft: () => ({}),
        mergeDraft: (latest, edits) => ({ ...latest, ...edits }),
        captureDraft: (latest, view) => {
          const edits: Partial<typeof latest> = {}
          if (latest.name !== view.name) edits.name = view.name
          if (latest.slug !== view.slug) edits.slug = view.slug
          return edits
        },
      }),
      { initialProps: { server: { name: 'Retail', slug: 'retail' }, revision: 3 } },
    )

    expect(result.current.draft).toEqual({ name: 'Retail', slug: 'retail' })
    act(() => result.current.setDraft(current => ({ ...current, name: 'My stores' })))
    expect(result.current.baseRevision).toBe(3)

    rerender({ server: { name: 'Another name', slug: 'shops' }, revision: 4 })
    expect(result.current.draft).toEqual({ name: 'My stores', slug: 'shops' })
    expect(result.current.remoteChanged).toBe(true)
    expect(result.current.baseRevision).toBe(3)

    act(() => result.current.adopt())
    expect(result.current.draft).toEqual({ name: 'Another name', slug: 'shops' })
    expect(result.current.remoteChanged).toBe(false)

    rerender({ server: { name: 'Third name', slug: 'third' }, revision: 5 })
    expect(result.current.draft).toEqual({ name: 'Third name', slug: 'third' })
  })

  it('keeps controlled drafts keyed by their owner and rebases only on request', () => {
    type Value = { note: string }
    let snapshot: ServerDraftSnapshot<Value, number> | null = null
    const onChange = vi.fn((next: ServerDraftSnapshot<Value, number> | null) => { snapshot = next })
    const props = () => ({ server: { note: 'Saved note' }, revision: 7, snapshot, onChange })
    const { result, rerender } = renderHook(
      ({ server, revision, snapshot: controlledSnapshot, onChange: changed }) => useServerDraft(server, revision, {
        controlled: { snapshot: controlledSnapshot, onChange: changed },
      }),
      { initialProps: props() },
    )

    act(() => result.current.setDraft(current => ({ ...current, note: 'My draft' })))
    expect(onChange).toHaveBeenLastCalledWith({ value: { note: 'My draft' }, baseRevision: 7 })
    rerender(props())
    expect(result.current.draft).toEqual({ note: 'My draft' })

    rerender({ ...props(), server: { note: 'Latest saved note' }, revision: 8 })
    expect(result.current.draft).toEqual({ note: 'My draft' })
    expect(result.current.remoteChanged).toBe(true)
    expect(result.current.baseRevision).toBe(7)

    act(() => result.current.rebase())
    expect(onChange).toHaveBeenLastCalledWith({ value: { note: 'My draft' }, baseRevision: 8 })
    rerender(props())
    expect(result.current.baseRevision).toBe(8)
    act(() => result.current.markSaved())
    expect(onChange).toHaveBeenLastCalledWith(null)
  })

  it('stores only edited fields while exposing a server-merged view', () => {
    const { result, rerender } = renderHook(
      ({ server, revision }) => useServerDraft<{ name: string; slug: string }, Partial<{ name: string; slug: string }>, number, { name: string; slug: string }>(server, revision, {
        createDraft: () => ({}),
        mergeDraft: (latest, edits) => ({ ...latest, ...edits }),
        captureDraft: (latest, view) => {
          const edits: Partial<typeof latest> = {}
          if (latest.name !== view.name) edits.name = view.name
          if (latest.slug !== view.slug) edits.slug = view.slug
          return edits
        },
      }),
      { initialProps: { server: { name: 'Retail', slug: 'retail' }, revision: 3 } },
    )

    act(() => result.current.setDraft(current => ({ ...current, name: 'My stores' })))
    rerender({ server: { name: 'Another name', slug: 'shops' }, revision: 4 })
    expect(result.current.draft).toEqual({ name: 'My stores', slug: 'shops' })
    expect(result.current.remoteChanged).toBe(true)
  })
})
