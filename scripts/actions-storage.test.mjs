import assert from 'node:assert/strict'
import test from 'node:test'
import { main, readPages, storageSnapshot } from './actions-storage.mjs'

test('reads all pages and propagates API errors', () => {
  assert.deepEqual(readPages('owner/repo', 'caches', (path, paginate) => {
    assert.equal(path, '/repos/owner/repo/actions/caches?per_page=100')
    assert.equal(paginate, true)
    return [{ actions_caches: [{ id: 1 }] }, { actions_caches: [{ id: 2 }] }]
  }), [{ id: 1 }, { id: 2 }])
  assert.throws(() => readPages('owner/repo', 'artifacts', () => { throw Error('403') }), /403/)
})

test('distinguishes storage types and PR/main runs, with sizes, age, and a configurable threshold', () => {
  const report = storageSnapshot([
    { id: 1, key: 'go-cache', size_in_bytes: 1024 * 1024, ref: 'refs/heads/main', created_at: '2026-11-15T00:00:00Z', last_accessed_at: '2026-11-16T00:00:00Z' },
    { id: 2, key: 'node-cache', size_in_bytes: 3, ref: 'refs/pull/12/merge', created_at: '2026-11-16T00:00:00Z' },
  ], [{ id: 3, name: 'coverage', size_in_bytes: 99, created_at: '2026-11-16T00:00:00Z', workflow_run: { id: 9, head_branch: 'fix/example' }, expired: false }],
  { 9: { event: 'pull_request' } }, Date.parse('2026-11-17T00:00:00Z'), 1)
  assert.equal(report.cleanupSuggested, true)
  assert.equal(report.cacheBytes, 1024 * 1024 + 3)
  assert.equal(report.artifactBytes, 99)
  assert.deepEqual(report.rows.map(row => row.id), [1, 3, 2])
  assert.equal(report.rows[0].ageDays, 2)
  assert.equal(report.rows[1].event, 'pull_request')
  assert.equal(report.rows[1].ref, 'fix/example')
  assert.equal(report.rows[2].event, 'pull_request')
  assert.equal(storageSnapshot([], [], {}, Date.now(), 1).cleanupSuggested, false)
})

test('rejects invalid input before contacting GitHub', () => {
  for (const args of [[], ['../bad'], ['owner/repo', '0'], ['owner/repo', 'NaN'], ['owner/repo', '1', 'extra']]) {
    assert.throws(() => main(args, () => { throw Error('must not call') }), /Usage:/)
  }
})

test('CLI resolves run metadata in bulk and emits the complete report', () => {
  const calls = []
  const output = []
  const original = process.stdout.write
  process.stdout.write = value => { output.push(value); return true }
  try {
    main(['owner/repo', '1'], path => {
      calls.push(path)
      if (path.includes('/caches?')) return [{ actions_caches: [] }]
      if (path.includes('/artifacts?')) return [{ artifacts: [1, 2].map(id => ({
        id, name: 'coverage', size_in_bytes: 20, created_at: '2026-11-01T00:00:00Z', workflow_run: { id: 7, head_branch: 'main' },
      })) }]
      assert.equal(path, '/repos/owner/repo/actions/runs?per_page=100&page=1')
      return { workflow_runs: [{ id: 7, event: 'push' }] }
    })
  } finally { process.stdout.write = original }
  assert.equal(calls.filter(path => path.includes('/runs?')).length, 1)
  const report = JSON.parse(output.join(''))
  assert.equal(report.artifactBytes, 40)
  assert.equal(report.rows.length, 2)
  assert.ok(report.rows.every(row => row.event === 'push' && row.ref === 'main'))
})

test('run lookup continues onto later pages and leaves deleted runs unknown', () => {
  const calls = []
  const output = []
  const original = process.stdout.write
  process.stdout.write = value => { output.push(value); return true }
  try {
    main(['owner/repo'], path => {
      calls.push(path)
      if (path.includes('/caches?')) return [{ actions_caches: [] }]
      if (path.includes('/artifacts?')) return [{ artifacts: [101, 999].map(id => ({ id, name: 'coverage', size_in_bytes: 1, created_at: '2026-11-01T00:00:00Z', workflow_run: { id } })) }]
      if (path.endsWith('page=1')) return { workflow_runs: Array.from({ length: 100 }, (_, id) => ({ id, event: 'push' })) }
      return { workflow_runs: [{ id: 101, event: 'pull_request' }] }
    })
  } finally { process.stdout.write = original }
  assert.equal(calls.length, 4)
  assert.deepEqual(JSON.parse(output.join('')).rows.map(row => row.event), ['pull_request', 'unknown'])
})
