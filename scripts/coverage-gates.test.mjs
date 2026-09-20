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
  const files = ['src/main.tsx', 'src/pages/Security.tsx', 'src/pages/Users.tsx', 'src/pages/ScannerProfiles.tsx', 'src/pages/JobEditor.tsx', 'src/pages/JobDetail.tsx', 'src/pages/Notifications.tsx']
  const report = { total: Object.fromEntries(['statements', 'lines', 'branches', 'functions'].map((metric) => [metric, percentage(100)])) }
  for (const file of files) {
    report[file] = { lines: percentage(100), branches: percentage(100) }
  }
  return Object.assign(report, overrides)
}

const requiredPackages = [
  'github.com/crypt0rr/edgewatch/cmd/edgewatch',
  'github.com/crypt0rr/edgewatch/internal/app',
  'github.com/crypt0rr/edgewatch/internal/auth',
  'github.com/crypt0rr/edgewatch/internal/config',
  'github.com/crypt0rr/edgewatch/internal/engine',
  'github.com/crypt0rr/edgewatch/internal/model',
  'github.com/crypt0rr/edgewatch/internal/notify',
  'github.com/crypt0rr/edgewatch/internal/rdap',
  'github.com/crypt0rr/edgewatch/internal/scanner',
  'github.com/crypt0rr/edgewatch/internal/store',
  'github.com/crypt0rr/edgewatch/internal/updatecheck',
  'github.com/crypt0rr/edgewatch/internal/web',
  'github.com/crypt0rr/edgewatch/internal/webui',
]

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

    const criticalRegression = frontendReport({
      'src/pages/JobDetail.tsx': { lines: percentage(69), branches: percentage(54) },
    })
    await writeFile(reportPath, JSON.stringify(criticalRegression))
    assert.notEqual(runScript('check-frontend-coverage.mjs', [reportPath]).status, 0)
  })
})

test('Go coverage gates reject aggregate, package, and missing-package regressions', async () => {
  await withTempDirectory(async (directory) => {
    const profilePath = join(directory, 'coverage.out')
    const summaryPath = join(directory, 'summary.txt')
    await writeFile(profilePath, await goProfile(directory))
    await writeFile(summaryPath, goSummary())
    assert.equal(runScript('check-go-coverage.sh', [profilePath, summaryPath]).status, 0)

    await writeFile(profilePath, await goProfile(directory, 0))
    assert.notEqual(runScript('check-go-coverage.sh', [profilePath, summaryPath]).status, 0)

    await writeFile(profilePath, await goProfile(directory))
    await writeFile(summaryPath, goSummary({ 'github.com/crypt0rr/edgewatch/internal/app': 74 }))
    assert.notEqual(runScript('check-go-coverage.sh', [profilePath, summaryPath]).status, 0)

    const missing = requiredPackages.slice(1).map((pkg) => `ok   ${pkg}   coverage: 100.0% of statements`).join('\n') + '\n'
    await writeFile(summaryPath, missing)
    assert.notEqual(runScript('check-go-coverage.sh', [profilePath, summaryPath]).status, 0)
  })
})

async function createDiffFixture(directory) {
  execFileSync('git', ['init', '-q', '-b', 'main'], { cwd: directory })
  execFileSync('git', ['config', 'user.email', 'coverage@example.invalid'], { cwd: directory })
  execFileSync('git', ['config', 'user.name', 'Coverage Fixture'], { cwd: directory })
  await mkdir(join(directory, 'src'), { recursive: true })
  await mkdir(join(directory, 'internal'), { recursive: true })
  await writeFile(join(directory, 'src/example.ts'), 'export const value = 1\n')
  await writeFile(join(directory, 'internal/example.go'), 'package example\n\nvar Value = 1\n')
  execFileSync('git', ['add', '.'], { cwd: directory })
  execFileSync('git', ['-c', 'commit.gpgsign=false', 'commit', '-q', '-m', 'base'], { cwd: directory })
  await writeFile(join(directory, 'src/example.ts'), 'export const value = 2\n')
  await writeFile(join(directory, 'internal/example.go'), 'package example\n\nvar Value = 2\n')
  execFileSync('git', ['add', '.'], { cwd: directory })
  execFileSync('git', ['-c', 'commit.gpgsign=false', 'commit', '-q', '-m', 'change'], { cwd: directory })
}

test('diff coverage gates pass covered changes and reject uncovered changes', async () => {
  await withTempDirectory(async (directory) => {
    await createDiffFixture(directory)
    const frontendPath = join(directory, 'frontend.json')
    const goPath = join(directory, 'go.out')
    await writeFile(frontendPath, JSON.stringify({ 'src/example.ts': { statementMap: { 0: { start: { line: 1 }, end: { line: 1 } } }, s: { 0: 1 } } }))
    await writeFile(goPath, 'mode: atomic\ninternal/example.go:3.1,3.15 1 1\n')
    assert.equal(runScript('check-diff-coverage.mjs', ['--language', 'frontend', '--coverage', frontendPath, '--base', 'HEAD^'], directory).status, 0)
    assert.equal(runScript('check-diff-coverage.mjs', ['--language', 'go', '--coverage', goPath, '--base', 'HEAD^'], directory).status, 0)

    await writeFile(frontendPath, JSON.stringify({ 'src/example.ts': { statementMap: { 0: { start: { line: 1 }, end: { line: 1 } } }, s: { 0: 0 } } }))
    await writeFile(goPath, 'mode: atomic\ninternal/example.go:3.1,3.15 1 0\n')
    assert.notEqual(runScript('check-diff-coverage.mjs', ['--language', 'frontend', '--coverage', frontendPath, '--base', 'HEAD^'], directory).status, 0)
    assert.notEqual(runScript('check-diff-coverage.mjs', ['--language', 'go', '--coverage', goPath, '--base', 'HEAD^'], directory).status, 0)
  })
})

test('coverage gate fixture remains self-contained', async () => {
  const packageJSON = JSON.parse(await readFile(join(repoRoot, 'package.json'), 'utf8'))
  assert.match(packageJSON.scripts['test:coverage'], /coverage-gates\.test\.mjs/)
})
