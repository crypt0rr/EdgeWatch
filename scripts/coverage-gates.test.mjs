import { execFileSync } from 'node:child_process'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'
import assert from 'node:assert/strict'

const scriptsDir = dirname(fileURLToPath(import.meta.url))
const repoRoot = resolve(scriptsDir, '..')
const runScript = (script, args, cwd = repoRoot) => {
  const executable = script.endsWith('.sh') ? 'sh' : process.execPath
  const commandArgs = script.endsWith('.sh') ? [join(scriptsDir, script), ...args] : [join(scriptsDir, script), ...args]
  try {
    const stdout = execFileSync(executable, commandArgs, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] })
    return { status: 0, stdout, stderr: '' }
  } catch (error) {
    return { status: error.status ?? 1, stdout: error.stdout?.toString() ?? '', stderr: error.stderr?.toString() ?? '' }
  }
}

const percentage = (pct) => ({ total: 1, covered: pct === 100 ? 1 : 0, skipped: 0, pct })
const frontendReport = (overrides = {}) => {
  const files = [
    'src/api.ts',
    'src/baseline.ts',
    'src/components/ActionDialog.tsx',
    'src/components/AuditLog.tsx',
    'src/components/ErrorNotice.tsx',
    'src/components/navigation.ts',
    'src/components/OneTimeLink.tsx',
    'src/components/Pagination.tsx',
    'src/components/PortScopeDetails.tsx',
    'src/components/SurfaceUnitList.tsx',
    'src/components/UntrustedProxyBanner.tsx',
    'src/format.ts',
    'src/main.tsx',
    'src/pages/Audit.tsx',
    'src/pages/Auth.tsx',
    'src/pages/BaselineHosts.tsx',
    'src/pages/Dashboard.tsx',
    'src/pages/HostDetail.tsx',
    'src/pages/Hosts.tsx',
    'src/pages/JobDetail.tsx',
    'src/pages/JobEditor.tsx',
    'src/pages/Notifications.tsx',
    'src/pages/platform/common.tsx',
    'src/pages/platform/PlatformAdmins.tsx',
    'src/pages/platform/PlatformAudit.tsx',
    'src/pages/platform/PlatformNotifications.tsx',
    'src/pages/platform/PlatformShell.tsx',
    'src/pages/platform/PlatformStatus.tsx',
    'src/pages/platform/UnitAccounts.tsx',
    'src/pages/platform/UnitDetail.tsx',
    'src/pages/platform/Units.tsx',
    'src/pages/PublicDashboard.tsx',
    'src/pages/ScanDetail.tsx',
    'src/pages/ScannerProfiles.tsx',
    'src/pages/Security.tsx',
    'src/pages/TotpEnrollment.tsx',
    'src/pages/Users.tsx',
    'src/target.ts',
    'src/types.ts',
    'src/useDebouncedValue.ts',
  ]
  const report = { total: Object.fromEntries(['statements', 'lines', 'branches', 'functions'].map((metric) => [metric, percentage(100)])) }
  for (const file of files) {
    report[file] = { lines: percentage(100), branches: percentage(100), functions: percentage(100) }
  }
  return Object.assign(report, overrides)
}

const requiredPackages = execFileSync('go', ['list', '-f', '{{if .GoFiles}}{{.ImportPath}}{{end}}', './...'], { cwd: repoRoot, encoding: 'utf8' })
  .split('\n')
  .map((packageName) => packageName.trim())
  .filter(Boolean)

const goProfile = async (directory, count = 1) => {
  const entries = []
  for (const [index] of requiredPackages.entries()) {
    const file = join(directory, `file${index}.go`)
    await writeFile(file, `package fixture\n\nfunc Value${index}() int { return 1 }\n`)
    entries.push(`${file}:3.1,3.31 1 ${count}`)
  }
  return ['mode: atomic', ...entries, ''].join('\n')
}
const goSummary = (values = {}) => requiredPackages.map((pkg) => `ok   ${pkg}   coverage: ${values[pkg] ?? 100}.0% of statements`).join('\n') + '\n'

async function withTempDirectory(fn) {
  const directory = await mkdtemp(join(tmpdir(), 'edgewatch-coverage-'))
  try {
    return await fn(directory)
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
}

test('frontend coverage gates reject low aggregate and missing critical entries', async () => {
  await withTempDirectory(async (directory) => {
    const reportPath = join(directory, 'coverage.json')
    await writeFile(reportPath, JSON.stringify(frontendReport()))
    assert.equal(runScript('check-frontend-coverage.mjs', [reportPath]).status, 0)

    const low = frontendReport({ total: { statements: percentage(64), lines: percentage(100), branches: percentage(100), functions: percentage(100) } })
    await writeFile(reportPath, JSON.stringify(low))
    assert.notEqual(runScript('check-frontend-coverage.mjs', [reportPath]).status, 0)

    const missing = frontendReport()
    delete missing['src/pages/Users.tsx']
    await writeFile(reportPath, JSON.stringify(missing))
    assert.notEqual(runScript('check-frontend-coverage.mjs', [reportPath]).status, 0)

    const missingDefaultPage = frontendReport()
    delete missingDefaultPage['src/pages/Auth.tsx']
    await writeFile(reportPath, JSON.stringify(missingDefaultPage))
    assert.notEqual(runScript('check-frontend-coverage.mjs', [reportPath]).status, 0)

    const missingSource = frontendReport()
    delete missingSource['src/baseline.ts']
    await writeFile(reportPath, JSON.stringify(missingSource))
    assert.notEqual(runScript('check-frontend-coverage.mjs', [reportPath]).status, 0)

    const sourceRegression = frontendReport({
      'src/api.ts': { lines: percentage(100), branches: percentage(59), functions: percentage(100) },
    })
    await writeFile(reportPath, JSON.stringify(sourceRegression))
    assert.notEqual(runScript('check-frontend-coverage.mjs', [reportPath]).status, 0)

    const criticalRegression = frontendReport({
      'src/pages/JobDetail.tsx': { lines: percentage(69), branches: percentage(54) },
    })
    await writeFile(reportPath, JSON.stringify(criticalRegression))
    assert.notEqual(runScript('check-frontend-coverage.mjs', [reportPath]).status, 0)
  })
})

test('frontend page floors apply to top-level and nested pages', async () => {
  await withTempDirectory(async (directory) => {
    const reportPath = join(directory, 'coverage.json')
    // Only the page floor requires lines, so a page below it with passing
    // branches and functions must fail through the page loop.
    for (const page of ['src/pages/Audit.tsx', 'src/pages/platform/Units.tsx', 'src/pages/platform/common.tsx']) {
      await writeFile(reportPath, JSON.stringify(frontendReport({
        [page]: { lines: percentage(10), branches: percentage(100), functions: percentage(100) },
      })))
      const result = runScript('check-frontend-coverage.mjs', [reportPath])
      assert.notEqual(result.status, 0, `${page} passed with 10% lines`)
      assert.match(result.stderr, new RegExp(`${page.replaceAll('.', '\\.')} lines: 10% < 65%`))
    }
  })
})

test('Go coverage gates reject aggregate, package, and missing-package regressions', async () => {
  await withTempDirectory(async (directory) => {
    const profilePath = join(directory, 'coverage.out')
    const summaryPath = join(directory, 'summary.txt')
    await writeFile(profilePath, await goProfile(directory))
    await writeFile(summaryPath, goSummary())
    const passing = runScript('check-go-coverage.sh', [profilePath, summaryPath])
    assert.equal(passing.status, 0)
    assert.match(passing.stdout, new RegExp(`${requiredPackages.length} production packages checked`))

    await writeFile(profilePath, await goProfile(directory, 0))
    assert.notEqual(runScript('check-go-coverage.sh', [profilePath, summaryPath]).status, 0)

    await writeFile(profilePath, await goProfile(directory))
    await writeFile(summaryPath, goSummary({ 'github.com/crypt0rr/edgewatch/internal/app': 74 }))
    assert.notEqual(runScript('check-go-coverage.sh', [profilePath, summaryPath]).status, 0)

    await writeFile(summaryPath, goSummary({ 'github.com/crypt0rr/edgewatch/internal/config': 90 }))
    assert.notEqual(runScript('check-go-coverage.sh', [profilePath, summaryPath]).status, 0)

    await writeFile(summaryPath, goSummary({ 'github.com/crypt0rr/edgewatch/internal/webui': 83 }))
    assert.notEqual(runScript('check-go-coverage.sh', [profilePath, summaryPath]).status, 0)

    const missing = requiredPackages.slice(1).map((pkg) => `ok   ${pkg}   coverage: 100.0% of statements`).join('\n') + '\n'
    await writeFile(summaryPath, missing)
    assert.notEqual(runScript('check-go-coverage.sh', [profilePath, summaryPath]).status, 0)
  })
})

// The Go fixture is a real module so the gate can ask `go list` which package
// compiles each changed file. Its changed line holds three executable blocks.
const exampleGoSource = (value) => `package example\n\nfunc Value(ok bool) int { if ok { return 1 }; return ${value} }\n`

// Profile lines in the shape `go test -race -coverprofile` writes for the
// fixture: the import path prefixes the file name, and only statements inside
// function bodies are instrumented. The counts apply to the three blocks on the
// changed line in source order.
const exampleGoProfile = (counts) => [
  'mode: atomic',
  ...['3.27,3.33', '3.35,3.45', '3.47,3.55'].map((range, index) => `example.com/fixture/internal/example.go:${range} 1 ${counts[index]}`),
  '',
].join('\n')

async function createDiffFixture(directory) {
  execFileSync('git', ['init', '-q', '-b', 'main'], { cwd: directory })
  execFileSync('git', ['config', 'user.email', 'coverage@example.invalid'], { cwd: directory })
  execFileSync('git', ['config', 'user.name', 'Coverage Fixture'], { cwd: directory })
  await mkdir(join(directory, 'src'), { recursive: true })
  await mkdir(join(directory, 'internal'), { recursive: true })
  await writeFile(join(directory, 'go.mod'), 'module example.com/fixture\n\ngo 1.22\n')
  await writeFile(join(directory, 'src/example.ts'), 'export const value = 1\n')
  await writeFile(join(directory, 'internal/example.go'), exampleGoSource(0))
  execFileSync('git', ['add', '.'], { cwd: directory })
  execFileSync('git', ['-c', 'commit.gpgsign=false', 'commit', '-q', '-m', 'base'], { cwd: directory })
  await writeFile(join(directory, 'src/example.ts'), 'export const value = 2\n')
  await writeFile(join(directory, 'internal/example.go'), exampleGoSource(2))
  execFileSync('git', ['add', '.'], { cwd: directory })
  execFileSync('git', ['-c', 'commit.gpgsign=false', 'commit', '-q', '-m', 'change'], { cwd: directory })
}

function amendDiffFixture(directory) {
  execFileSync('git', ['add', '-A'], { cwd: directory })
  execFileSync('git', ['-c', 'commit.gpgsign=false', 'commit', '-q', '--amend', '--no-edit'], { cwd: directory })
}

test('diff coverage gates pass covered changes and reject uncovered changes', async () => {
  await withTempDirectory(async (directory) => {
    await createDiffFixture(directory)
    const frontendPath = join(directory, 'frontend.json')
    const goPath = join(directory, 'go.out')
    await writeFile(frontendPath, JSON.stringify({ 'src/example.ts': { statementMap: { 0: { start: { line: 1 }, end: { line: 1 } } }, s: { 0: 1 } } }))
    await writeFile(goPath, exampleGoProfile([2, 1, 1]))
    assert.equal(runScript('check-diff-coverage.mjs', ['--language', 'frontend', '--coverage', frontendPath, '--base', 'HEAD^'], directory).status, 0)
    assert.equal(runScript('check-diff-coverage.mjs', ['--language', 'go', '--coverage', goPath, '--base', 'HEAD^'], directory).status, 0)

    await writeFile(frontendPath, JSON.stringify({ 'src/example.ts': { statementMap: { 0: { start: { line: 1 }, end: { line: 1 } } }, s: { 0: 0 } } }))
    await writeFile(goPath, exampleGoProfile([0, 0, 0]))
    assert.notEqual(runScript('check-diff-coverage.mjs', ['--language', 'frontend', '--coverage', frontendPath, '--base', 'HEAD^'], directory).status, 0)
    assert.notEqual(runScript('check-diff-coverage.mjs', ['--language', 'go', '--coverage', goPath, '--base', 'HEAD^'], directory).status, 0)
  })
})

test('diff coverage rejects partially covered changed lines with multiple executable blocks', async () => {
  await withTempDirectory(async (directory) => {
    await createDiffFixture(directory)
    const frontendPath = join(directory, 'frontend.json')
    const goPath = join(directory, 'go.out')

    // Every statement and block overlaps the changed source line. A weakened
    // `.some()` predicate would incorrectly credit this line even though one
    // block did not execute, so this assertion acts as a mutation guard.
    await writeFile(frontendPath, JSON.stringify({
      'src/example.ts': {
        statementMap: {
          0: { start: { line: 1 }, end: { line: 1 } },
          1: { start: { line: 1 }, end: { line: 1 } },
        },
        s: { 0: 1, 1: 0 },
      },
    }))
    await writeFile(goPath, exampleGoProfile([1, 1, 0]))

    assert.notEqual(runScript('check-diff-coverage.mjs', ['--language', 'frontend', '--coverage', frontendPath, '--base', 'HEAD^'], directory).status, 0)
    assert.notEqual(runScript('check-diff-coverage.mjs', ['--language', 'go', '--coverage', goPath, '--base', 'HEAD^'], directory).status, 0)

    await writeFile(frontendPath, JSON.stringify({
      'src/example.ts': {
        statementMap: {
          0: { start: { line: 1 }, end: { line: 1 } },
          1: { start: { line: 1 }, end: { line: 1 } },
        },
        s: { 0: 1, 1: 1 },
      },
    }))
    await writeFile(goPath, exampleGoProfile([1, 1, 1]))

    assert.equal(runScript('check-diff-coverage.mjs', ['--language', 'frontend', '--coverage', frontendPath, '--base', 'HEAD^'], directory).status, 0)
    assert.equal(runScript('check-diff-coverage.mjs', ['--language', 'go', '--coverage', goPath, '--base', 'HEAD^'], directory).status, 0)
  })
})

test('diff coverage reads a diff larger than the default child-process buffer', async () => {
  await withTempDirectory(async (directory) => {
    await createDiffFixture(directory)
    // A release compares against the previous release, so its diff can span
    // many megabytes; Node's default 1 MiB buffer failed with ENOBUFS.
    const lines = Array.from({ length: 60000 }, (_, index) => `line ${index} ${'x'.repeat(40)}`).join('\n')
    await writeFile(join(directory, 'large.txt'), `${lines}\n`)
    amendDiffFixture(directory)
    const frontendPath = join(directory, 'frontend.json')
    const goPath = join(directory, 'go.out')
    await writeFile(frontendPath, JSON.stringify({ 'src/example.ts': { statementMap: { 0: { start: { line: 1 }, end: { line: 1 } } }, s: { 0: 1 } } }))
    await writeFile(goPath, exampleGoProfile([1, 1, 1]))
    const frontend = runScript('check-diff-coverage.mjs', ['--language', 'frontend', '--coverage', frontendPath, '--base', 'HEAD^', '--require-base'], directory)
    assert.equal(frontend.status, 0, frontend.stderr)
    const go = runScript('check-diff-coverage.mjs', ['--language', 'go', '--coverage', goPath, '--base', 'HEAD^', '--require-base'], directory)
    assert.equal(go.status, 0, go.stderr)
  })
})

test('Go diff coverage accepts a declaration-only file in a package from the coverage run', async () => {
  await withTempDirectory(async (directory) => {
    await createDiffFixture(directory)
    // `go test -coverprofile` instruments function bodies only, so a file that
    // holds only imports and package-level declarations has no profile lines
    // even though its package ran. Its changed lines are not executable.
    await writeFile(join(directory, 'internal/errors.go'), 'package example\n\nimport "errors"\n\n// ErrBusy reports a busy unit.\nvar ErrBusy = errors.New("busy")\n')
    amendDiffFixture(directory)
    const goPath = join(directory, 'go.out')
    const args = ['--language', 'go', '--coverage', goPath, '--base', 'HEAD^', '--require-base']

    await writeFile(goPath, exampleGoProfile([2, 1, 1]))
    const covered = runScript('check-diff-coverage.mjs', args, directory)
    assert.equal(covered.status, 0, covered.stderr)
    assert.match(covered.stdout, /1\/1 executable changed lines/)
    assert.match(covered.stdout, /internal\/errors\.go: no executable statements in example\.com\/fixture\/internal/)

    // The declaration-only file must not mask uncovered lines elsewhere.
    await writeFile(goPath, exampleGoProfile([1, 1, 0]))
    assert.notEqual(runScript('check-diff-coverage.mjs', args, directory).status, 0)
  })
})

test('Go diff coverage rejects changed files whose package was not in the coverage run', async () => {
  await withTempDirectory(async (directory) => {
    await createDiffFixture(directory)
    const goPath = join(directory, 'go.out')
    const args = ['--language', 'go', '--coverage', goPath, '--base', 'HEAD^', '--require-base']
    await writeFile(goPath, exampleGoProfile([1, 1, 1]))

    // A declaration-only file is accepted only when its own package appears
    // in the profile; another package's entries do not vouch for it.
    await mkdir(join(directory, 'other'))
    await writeFile(join(directory, 'other/errors.go'), 'package other\n\nimport "errors"\n\nvar ErrOther = errors.New("other")\n')
    amendDiffFixture(directory)
    const absent = runScript('check-diff-coverage.mjs', args, directory)
    assert.notEqual(absent.status, 0)
    assert.match(absent.stderr, /other\/errors\.go: no Go coverage entry; package example\.com\/fixture\/other is missing from the coverage run/)

    // A file that build constraints leave out of the run is reported as such.
    await rm(join(directory, 'other'), { recursive: true })
    await writeFile(join(directory, 'internal/example_ignored.go'), '//go:build ignore\n\npackage example\n\nfunc Ignored() int { return 3 }\n')
    amendDiffFixture(directory)
    const constrained = runScript('check-diff-coverage.mjs', args, directory)
    assert.notEqual(constrained.status, 0)
    assert.match(constrained.stderr, /internal\/example_ignored\.go: no Go coverage entry; build constraints exclude it from example\.com\/fixture\/internal/)

    // Without a package inventory the gate cannot tell a declaration-only
    // file from an untested package, so it keeps failing closed.
    await rm(join(directory, 'internal/example_ignored.go'))
    await writeFile(join(directory, 'internal/errors.go'), 'package example\n\nimport "errors"\n\nvar ErrBusy = errors.New("busy")\n')
    amendDiffFixture(directory)
    assert.equal(runScript('check-diff-coverage.mjs', args, directory).status, 0)
    await writeFile(join(directory, 'go.mod'), 'not a module file\n')
    const unlisted = runScript('check-diff-coverage.mjs', args, directory)
    assert.notEqual(unlisted.status, 0)
    assert.match(unlisted.stderr, /internal\/errors\.go: no Go coverage entry; go list failed/)
  })
})

test('required diff coverage bases reject empty and unresolvable refs', async () => {
  await withTempDirectory(async (directory) => {
    await createDiffFixture(directory)
    const frontendPath = join(directory, 'frontend.json')
    await writeFile(frontendPath, JSON.stringify({ 'src/example.ts': { statementMap: { 0: { start: { line: 1 }, end: { line: 1 } } }, s: { 0: 1 } } }))
    const required = ['--language', 'frontend', '--coverage', frontendPath, '--base', '', '--require-base']
    assert.notEqual(runScript('check-diff-coverage.mjs', required, directory).status, 0)
    const missing = ['--language', 'frontend', '--coverage', frontendPath, '--base', 'does-not-exist', '--require-base']
    assert.notEqual(runScript('check-diff-coverage.mjs', missing, directory).status, 0)
    const legacyFallback = ['--language', 'frontend', '--coverage', frontendPath, '--base', 'does-not-exist']
    assert.equal(runScript('check-diff-coverage.mjs', legacyFallback, directory).status, 0)
  })
})

test('coverage gate fixture remains self-contained', async () => {
  const packageJSON = JSON.parse(await readFile(join(repoRoot, 'package.json'), 'utf8'))
  assert.match(packageJSON.scripts['test:coverage'], /coverage-gates\.test\.mjs/)
})
