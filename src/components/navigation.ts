import { useEffect, useRef, useState } from 'react'
import { recordActivity } from '../api'

const navigationFocusableSelector = 'a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])'

export function useIsMobile() {
  const [mobile, setMobile] = useState(() => typeof window !== 'undefined' && typeof window.matchMedia === 'function' && window.matchMedia('(max-width: 760px)').matches)
  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return
    const media = window.matchMedia('(max-width: 760px)')
    const update = () => setMobile(media.matches)
    update()
    if (media.addEventListener) media.addEventListener('change', update)
    else media.addListener?.(update)
    return () => {
      if (media.removeEventListener) media.removeEventListener('change', update)
      else media.removeListener?.(update)
    }
  }, [])
  return mobile
}

/**
 * The mobile navigation drawer shared by the unit console and the platform
 * console: it closes on desktop widths, locks page scroll while open, moves
 * focus into the drawer and back to the menu button, and traps Tab/Escape.
 */
export function useNavigationDrawer() {
  const [open, setOpen] = useState(false)
  const isMobile = useIsMobile()
  const menuButtonRef = useRef<HTMLButtonElement>(null)
  const drawerRef = useRef<HTMLElement>(null)
  const wasOpenRef = useRef(false)
  useEffect(() => {
    if (!isMobile && open) setOpen(false)
  }, [isMobile, open])
  useEffect(() => {
    if (!isMobile || !open) return
    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => { document.body.style.overflow = previousOverflow }
  }, [isMobile, open])
  useEffect(() => {
    if (!isMobile) {
      wasOpenRef.current = false
      return
    }
    if (open && !wasOpenRef.current) {
      const first = drawerRef.current?.querySelector<HTMLElement>(navigationFocusableSelector)
      first?.focus({ preventScroll: true })
    } else if (!open && wasOpenRef.current) {
      menuButtonRef.current?.focus({ preventScroll: true })
    }
    wasOpenRef.current = open
  }, [isMobile, open])
  useEffect(() => {
    if (!isMobile || !open) return
    const drawer = drawerRef.current
    function focusables() {
      return Array.from(drawer?.querySelectorAll<HTMLElement>(navigationFocusableSelector) ?? [])
    }
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        event.preventDefault()
        setOpen(false)
        return
      }
      if (event.key !== 'Tab') return
      const items = focusables()
      if (!items.length) {
        event.preventDefault()
        return
      }
      const first = items[0]
      const last = items[items.length - 1]
      const active = document.activeElement
      if (event.shiftKey && (active === first || !drawer?.contains(active))) {
        event.preventDefault()
        last.focus()
      } else if (!event.shiftKey && (active === last || !drawer?.contains(active))) {
        event.preventDefault()
        first.focus()
      }
    }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [isMobile, open])
  return { open, setOpen, isMobile, menuButtonRef, drawerRef }
}

/** Refresh the session's idle timer on real user activity, at most once a minute. */
export function useActivityHeartbeat() {
  useEffect(() => {
    let lastSentAt = Number.NEGATIVE_INFINITY
    const noteActivity = () => {
      const now = Date.now()
      if (now - lastSentAt < 60_000) return
      lastSentAt = now
      // Activity refresh is best-effort; normal API reads remain independent
      // of this short, coalesced session write.
      void recordActivity().catch(() => undefined)
    }
    const activityEvents = ['pointerdown', 'click', 'keydown', 'wheel'] as const
    activityEvents.forEach(event => document.addEventListener(event, noteActivity, { passive: true }))
    return () => {
      activityEvents.forEach(event => document.removeEventListener(event, noteActivity))
    }
  }, [])
}
