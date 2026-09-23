import { readdir, readFile } from 'node:fs/promises'

const summaryPath = process.argv[2] ?? 'coverage/coverage-summary.json'
const minimums = {
  statements: 65,
  lines: 65,
  branches: 55,
  functions: 60,
}
const critical = {
  'src/main.tsx': { lines: 70, branches: 55, functions: 65 },
  'src/pages/Security.tsx': { lines: 75, branches: 55, functions: 65 },
  'src/pages/Users.tsx': { lines: 75, branches: 55, functions: 65 },
  'src/pages/ScannerProfiles.tsx': { lines: 75, branches: 55, functions: 65 },
  'src/pages/JobEditor.tsx': { lines: 65, branches: 55, functions: 65 },
  'src/pages/JobDetail.tsx': { lines: 65, branches: 55, functions: 65 },
  'src/pages/Notifications.tsx': { lines: 65, branches: 55, functions: 65 },
  'src/pages/BaselineHosts.tsx': { lines: 80, branches: 60, functions: 65 },
  'src/pages/Dashboard.tsx': { lines: 80, branches: 60, functions: 65 },
  'src/pages/Hosts.tsx': { lines: 80, branches: 60, functions: 65 },
  'src/pages/HostDetail.tsx': { lines: 80, branches: 60, functions: 65 },
  'src/pages/PublicDashboard.tsx': { lines: 80, branches: 60, functions: 65 },
  'src/pages/ScanDetail.tsx': { lines: 80, branches: 60, functions: 65 },
}
const pageDefaults = { lines: 65, branches: 55, functions: 60 }

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
