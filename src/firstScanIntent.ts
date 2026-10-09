// Creation and the first run are separate requests. This in-memory token
// transfers the user's explicit start action to JobDetail without making it
// repeatable from a browser history entry after a reload or remount.
const pendingFirstScanIntents = new Map<string, string>()
let nextIntentID = 0

/** Issue a one-time first-scan intent for the newly created job. */
export function issueFirstScanIntent(jobID: string): string {
  nextIntentID += 1
  const entropy = typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
    ? crypto.randomUUID()
    : Math.random().toString(36).slice(2)
  const token = `${nextIntentID.toString(36)}-${entropy}`
  pendingFirstScanIntents.set(token, jobID)
  return token
}

/** Validate and consume the intent before any request that can start a scan. */
export function consumeFirstScanIntent(jobID: string, token: unknown): boolean {
  if (typeof token !== 'string' || token.length === 0) return false
  const intendedJobID = pendingFirstScanIntents.get(token)
  if (intendedJobID !== jobID) return false
  pendingFirstScanIntents.delete(token)
  return true
}
