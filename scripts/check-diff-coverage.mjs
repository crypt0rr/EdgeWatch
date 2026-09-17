import { execFileSync } from 'node:child_process'
import { readFile } from 'node:fs/promises'

const args = process.argv.slice(2)
const valueFor = (name, fallback) => {
  const index = args.indexOf(name)
  return index >= 0 && args[index + 1] ? args[index + 1] : fallback
}
const language = valueFor('--language')
const coveragePath = valueFor('--coverage', language === 'frontend' ? 'coverage/coverage-final.json' : 'coverage.out')
const baseRequested = valueFor('--base', process.env.COVERAGE_BASE || 'origin/main')
const minimum = 80

if (!['frontend', 'go'].includes(language)) {
  console.error('usage: node scripts/check-diff-coverage.mjs --language frontend|go [--coverage path] [--base ref]')
  process.exit(2)
}

function resolveBase() {
  try {
    return execFileSync('git', ['rev-parse', '--verify', `${baseRequested}^{commit}`], { encoding: 'utf8' }).trim()
  } catch {
    try {
      return execFileSync('git', ['rev-parse', '--verify', 'HEAD^'], { encoding: 'utf8' }).trim()
    } catch {
      return ''
    }
  }
}

const base = resolveBase()
if (!base) {
  console.log(`diff coverage: no merge base available for ${baseRequested}; skipped`)
  process.exit(0)
}

const diff = execFileSync('git', ['diff', '--unified=0', '--no-color', `${base}...HEAD`, '--'], { encoding: 'utf8' })
const changed = new Map()
let currentFile = ''
let nextLine = 0
let remaining = 0
for (const line of diff.split('\n')) {
  if (line.startsWith('+++ b/')) {
    currentFile = line.slice(6)
    continue
  }
  if (line.startsWith('@@ ')) {
    const match = line.match(/\+(\d+)(?:,(\d+))?/)
    if (!match) continue
    nextLine = Number(match[1])
    remaining = Number(match[2] ?? 1)
    continue
  }
  if (!currentFile || remaining <= 0) continue
  if (line.startsWith('+') && !line.startsWith('+++')) {
    const lines = changed.get(currentFile) ?? []
    lines.push(nextLine)
    changed.set(currentFile, lines)
    nextLine += 1
    remaining -= 1
  } else if (!line.startsWith('-')) {
    nextLine += 1
    remaining -= 1
  }
}

function isProductionFile(file) {
  if (language === 'frontend') return /^(src\/.*\.(?:ts|tsx))$/.test(file) && !/\.test\.(?:ts|tsx)$/.test(file) && !file.startsWith('src/test/')
  return file.endsWith('.go') && !file.endsWith('_test.go')
}

const productionChanges = [...changed.entries()].filter(([file]) => isProductionFile(file))
let executable = 0
let covered = 0
const missingCoverage = []

// A documentation-only change should be an explicit no-op, not an accidental
// 100% result caused by comparing a push to itself. Keeping the skipped file
// list in the output also makes the gate useful when it runs on main pushes.
if (productionChanges.length === 0) {
  const skipped = [...changed.keys()].filter((file) => !isProductionFile(file))
  console.log(`diff coverage (${language}): no executable changes (skipped: ${skipped.length ? skipped.join(', ') : 'none'})`)
  process.exit(0)
}

if (language === 'frontend') {
  const report = JSON.parse(await readFile(coveragePath, 'utf8'))
  for (const [file, lines] of productionChanges) {
    const key = Object.keys(report).find((candidate) => candidate === file || candidate.endsWith(`/${file}`))
    const entry = key ? report[key] : undefined
    if (!entry) {
      missingCoverage.push(`${file}: no frontend coverage entry`)
      continue
    }
    for (const line of lines) {
      const statementIDs = Object.entries(entry.statementMap)
        .filter(([, range]) => range.start.line <= line && range.end.line >= line)
        .map(([id]) => id)
      if (!statementIDs.length) continue
      executable += 1
      // A source line can contain more than one executable statement (for
      // example a covered condition and an untested error return). Credit the
      // line only when every overlapping statement was executed.
      if (statementIDs.every((id) => Number(entry.s[id]) > 0)) covered += 1
    }
  }
} else {
  const profile = await readFile(coveragePath, 'utf8')
  const entries = []
  for (const line of profile.split('\n')) {
    if (!line || line.startsWith('mode:')) continue
    const match = line.match(/^(.+\.go):(\d+)\.\d+,(\d+)\.\d+\s+\d+\s+(\d+)$/)
    if (match) entries.push({ file: match[1], start: Number(match[2]), end: Number(match[3]), count: Number(match[4]) })
  }
  for (const [file, lines] of productionChanges) {
    const ranges = entries.filter((entry) => entry.file === file || entry.file.endsWith(`/${file}`))
    if (!ranges.length) {
      missingCoverage.push(`${file}: no Go coverage entry`)
      continue
    }
    for (const line of lines) {
      const matching = ranges.filter((entry) => entry.start <= line && entry.end >= line)
      if (!matching.length) continue
      executable += 1
      // Go coverage ranges may overlap on a single source line. All of the
      // overlapping executable blocks must have run for that line to count.
      if (matching.every((entry) => entry.count > 0)) covered += 1
    }
  }
}

const percent = executable ? (covered / executable) * 100 : 100
console.log(`diff coverage (${language}): ${covered}/${executable} executable changed lines (${percent.toFixed(2)}%)`)
if (missingCoverage.length) {
  console.error('diff coverage gate failed:')
  for (const failure of missingCoverage) console.error(`- ${failure}`)
  process.exitCode = 1
} else if (executable && percent < minimum) {
  console.error(`diff coverage gate failed: ${percent.toFixed(2)}% < ${minimum}%`)
  process.exitCode = 1
}
