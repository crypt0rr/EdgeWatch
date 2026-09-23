import { readdir, readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const summaryPath = process.argv[2] ?? 'coverage/coverage-summary.json'
const minimums = {
  // Ratcheted 2026-09-23 to two points below the measured main-branch
  // coverage. Raise these floors with normal PRs; lowering one requires a
  // written justification in the change description.
  statements: 86,
  lines: 89,
  branches: 73,
  functions: 83,
}
const critical = {
  'src/main.tsx': { lines: 70, branches: 60, functions: 65 },
  'src/pages/Security.tsx': { lines: 75, branches: 60, functions: 65 },
  'src/pages/Users.tsx': { lines: 75, branches: 60, functions: 65 },
  'src/pages/ScannerProfiles.tsx': { lines: 75, branches: 60, functions: 65 },
  'src/pages/JobEditor.tsx': { lines: 65, branches: 60, functions: 65 },
  'src/pages/JobDetail.tsx': { lines: 65, branches: 60, functions: 65 },
  'src/pages/Notifications.tsx': { lines: 65, branches: 60, functions: 65 },
  'src/pages/BaselineHosts.tsx': { lines: 80, branches: 60, functions: 65 },
  'src/pages/Dashboard.tsx': { lines: 80, branches: 60, functions: 65 },
  'src/pages/Hosts.tsx': { lines: 80, branches: 60, functions: 65 },
  'src/pages/HostDetail.tsx': { lines: 80, branches: 60, functions: 65 },
  'src/pages/PublicDashboard.tsx': { lines: 80, branches: 60, functions: 65 },
  'src/pages/ScanDetail.tsx': { lines: 80, branches: 60, functions: 65 },
}
const pageDefaults = { lines: 65, branches: 60, functions: 65 }

// Keep intentional exceptions visible and reviewable instead of silently
// excluding a source file from the per-file floor.
const sourceFloorAllowList = {
  // 'src/path.ts': { branches: 55, functions: 60 },
}
const sourceDefaults = { branches: 60, functions: 65 }

const report = JSON.parse(await readFile(summaryPath, 'utf8'))
const failures = []
const total = report.total

for (const [metric, minimum] of Object.entries(minimums)) {
  const actual = Number(total?.[metric]?.pct ?? 0)
  if (actual < minimum) failures.push(`global ${metric}: ${actual}% < ${minimum}%`)
}

function findFile(relative) {
  const key = Object.keys(report).find((value) => value === relative || value.endsWith(`/${relative}`))
  return key ? report[key] : undefined
}

async function listSourceFiles(directory, prefix = 'src') {
  const entries = await readdir(directory, { withFileTypes: true })
  const files = []
  for (const entry of entries) {
    const relative = `${prefix}/${entry.name}`
    if (entry.isDirectory()) {
      if (relative === 'src/test' || relative.startsWith('src/test/')) continue
      files.push(...await listSourceFiles(join(directory, entry.name), relative))
      continue
    }
    if (/\.(?:ts|tsx)$/.test(entry.name) && !/\.test\.(?:ts|tsx)$/.test(entry.name)) files.push(relative)
  }
  return files
}

const sourceFiles = await listSourceFiles(fileURLToPath(new URL('../src/', import.meta.url)))
for (const relative of sourceFiles) {
  const file = findFile(relative)
  if (!file) {
    failures.push(`${relative}: coverage entry is missing`)
    continue
  }
  const limits = { ...sourceDefaults, ...sourceFloorAllowList[relative] }
  for (const [metric, minimum] of Object.entries(limits)) {
    const actual = Number(file[metric]?.pct ?? 0)
    if (actual < minimum) failures.push(`${relative} ${metric}: ${actual}% < ${minimum}%`)
  }
}

const pageFiles = (await readdir(new URL('../src/pages/', import.meta.url)))
  .filter((file) => file.endsWith('.tsx') && !file.endsWith('.test.tsx'))
  .map((file) => `src/pages/${file}`)

for (const relative of pageFiles) {
  const limits = { ...pageDefaults, ...critical[relative] }
  const file = findFile(relative)
  if (!file) {
    failures.push(`${relative}: coverage entry is missing`)
    continue
  }
  for (const [metric, minimum] of Object.entries(limits)) {
    const actual = Number(file[metric]?.pct ?? 0)
    if (actual < minimum) failures.push(`${relative} ${metric}: ${actual}% < ${minimum}%`)
  }
}

console.log(`frontend coverage: statements ${total.statements.pct}%, lines ${total.lines.pct}%, branches ${total.branches.pct}%, functions ${total.functions.pct}%`)
if (failures.length) {
  console.error('frontend coverage gate failed:')
  for (const failure of failures) console.error(`- ${failure}`)
  process.exitCode = 1
} else {
  console.log('frontend coverage gates passed')
}
