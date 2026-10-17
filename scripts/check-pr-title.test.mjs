import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { existsSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { randomUUID } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

import { isAllowedPullRequestTitle } from './check-pr-title.mjs'

const scriptDirectory = dirname(fileURLToPath(import.meta.url))
const checkerPath = resolve(scriptDirectory, 'check-pr-title.mjs')

test('PR title policy accepts each conventional type with optional scope', () => {
  for (const type of ['feat', 'fix', 'perf', 'test', 'docs', 'chore', 'refactor', 'ci', 'build']) {
    assert.equal(isAllowedPullRequestTitle(`${type}: describe the change`), true, type)
    assert.equal(isAllowedPullRequestTitle(`${type}(scanner/parser): describe the change`), true, `${type} scope`)
  }
})

test('PR title policy rejects absent, malformed, empty, and multiline prefixes', () => {
  for (const title of [
    undefined,
    '',
    'describe the change',
    'P3 fix: hide internal report ids',
    'Fix: uppercase types are not accepted',
    'unknown: unsupported type',
    'fix(scope):missing required space',
    'fix(): empty scopes are not accepted',
    'fix: ',
    'fix: first line\nsecond line',
    'fix: trailing newline\n',
  ]) {
    assert.equal(isAllowedPullRequestTitle(title), false, String(title))
  }
})

test('hostile title text remains data and is never evaluated by the checker', () => {
  const marker = join(tmpdir(), `edgewatch-pr-title-${randomUUID()}`)
  const runChecker = (title) => spawnSync(process.execPath, [checkerPath], {
    encoding: 'utf8',
    env: { ...process.env, PR_TITLE: title },
  })

  try {
    const commandLikeDescription = `fix: literal $(touch ${marker}) title text`
    const accepted = runChecker(commandLikeDescription)
    assert.equal(accepted.status, 0, accepted.stderr || accepted.stdout)
    assert.equal(existsSync(marker), false, 'command-like title text must not execute')

    const multilinePayload = `fix: title\n$(touch ${marker})`
    const rejected = runChecker(multilinePayload)
    assert.equal(rejected.status, 1, rejected.stderr || rejected.stdout)
    assert.equal(existsSync(marker), false, 'multiline title text must not execute')
    assert.doesNotMatch(rejected.stderr, /touch/, 'validation errors must not echo the untrusted title')
  } finally {
    rmSync(marker, { force: true })
  }
})
