import { execFileSync } from 'node:child_process'
import { pathToFileURL } from 'node:url'

const MiB = 1024 * 1024

/** Read every page; a failed API read aborts rather than reporting a partial total. */
export function readPages(repository, resource, api) {
  return api(`/repos/${repository}/actions/${resource}?per_page=100`, true)
    .flatMap(page => page[resource === 'caches' ? 'actions_caches' : resource])
}

export function storageSnapshot(caches, artifacts, runs, now = Date.now(), thresholdMiB = 8192) {
  const rows = [
    ...caches.map(cache => ({ kind: 'cache', id: cache.id, name: cache.key, bytes: cache.size_in_bytes,
      ref: cache.ref, event: cache.ref.startsWith('refs/pull/') ? 'pull_request' : 'branch',
      created: cache.created_at, lastUsed: cache.last_accessed_at })),
    ...artifacts.map(artifact => ({ kind: 'artifact', id: artifact.id, name: artifact.name, bytes: artifact.size_in_bytes,
      ref: artifact.workflow_run?.head_branch ?? 'unknown',
      event: runs[artifact.workflow_run?.id]?.event ?? 'unknown', created: artifact.created_at,
      expires: artifact.expires_at, expired: artifact.expired })),
  ].map(row => ({ ...row, ageDays: Math.max(0, (now - Date.parse(row.created)) / 86_400_000) }))
  const totals = { cacheBytes: caches.reduce((sum, row) => sum + row.size_in_bytes, 0),
    artifactBytes: artifacts.reduce((sum, row) => sum + row.size_in_bytes, 0) }
  return { capturedAt: new Date(now).toISOString(), thresholdMiB, ...totals,
    cleanupSuggested: totals.cacheBytes + totals.artifactBytes >= thresholdMiB * MiB,
    rows: rows.sort((a, b) => b.bytes - a.bytes || a.kind.localeCompare(b.kind) || a.id - b.id) }
}

export function main(args = process.argv.slice(2), api = githubAPI) {
  const [repository, threshold = '8192'] = args
  if (args.length > 2 || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository ?? '') ||
      repository.split('/').some(part => part === '.' || part === '..') ||
      !Number.isFinite(Number(threshold)) || Number(threshold) <= 0) {
    throw new Error('Usage: node scripts/actions-storage.mjs OWNER/REPO [cleanup-threshold-MiB]')
  }
  const caches = readPages(repository, 'caches', api)
  const artifacts = readPages(repository, 'artifacts', api)
  const runs = {}
  const pending = new Set(artifacts.map(row => row.workflow_run?.id).filter(Boolean))
  // Bulk pages avoid one API call per artifact/run on busy repositories.
  for (let page = 1; pending.size; page++) {
    const batch = api(`/repos/${repository}/actions/runs?per_page=100&page=${page}`, false).workflow_runs
    for (const run of batch) {
      if (pending.delete(run.id)) runs[run.id] = { event: run.event }
    }
    if (batch.length < 100) break
  }
  const report = storageSnapshot(caches, artifacts, runs, Date.now(), Number(threshold))
  process.stdout.write(`${JSON.stringify({ repository, ...report }, null, 2)}\n`)
}

function githubAPI(endpoint, paginate) {
  const output = execFileSync('gh', ['api', ...(paginate ? ['--paginate', '--jq', '@json'] : []), endpoint],
    { encoding: 'utf8', maxBuffer: 128 * MiB })
  return paginate ? output.trim().split('\n').filter(Boolean).map(line => JSON.parse(line)) : JSON.parse(output)
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { main() } catch (error) {
    console.error(error.message)
    process.exitCode = 1
  }
}
