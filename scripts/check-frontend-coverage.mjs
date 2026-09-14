import { readFile } from 'node:fs/promises'

const summaryPath = process.argv[2] ?? 'coverage/coverage-summary.json'
const minimums = {
  statements: 65,
  lines: 65,
  branches: 55,
  functions: 60,
}
const critical = {
  'src/main.tsx': { lines: 70, branches: 55 },
  'src/pages/Security.tsx': { lines: 75, branches: 55 },
  'src/pages/Users.tsx': { lines: 75, branches: 55 },
  'src/pages/ScannerProfiles.tsx': { lines: 75, branches: 55 },
  'src/pages/JobEditor.tsx': { lines: 65, branches: 55 },
  'src/pages/JobDetail.tsx': { lines: 65, branches: 55 },
  'src/pages/Notifications.tsx': { lines: 65, branches: 55 },
}

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

for (const [relative, limits] of Object.entries(critical)) {
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
