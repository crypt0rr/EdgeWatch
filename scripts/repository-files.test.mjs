import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { lstat, open, readFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')

// Build output belongs in release archives and images, not in the source
// tree; .gitignore lists what `go build` and `make build` write. These checks
// read every tracked file, so a binary that is committed anyway fails CI.
// The largest tracked file is the 2 MB documentation demo video.
const maxTrackedFileBytes = 10 * 1024 * 1024

// The headers of native executables and libraries: ELF, PE (its MS-DOS
// stub), and Mach-O in each word size and byte order, single or universal.
const executableHeaders = [
  { format: 'ELF', bytes: [0x7f, 0x45, 0x4c, 0x46] },
  { format: 'PE', bytes: [0x4d, 0x5a] },
  { format: 'Mach-O', bytes: [0xfe, 0xed, 0xfa, 0xce] },
  { format: 'Mach-O', bytes: [0xfe, 0xed, 0xfa, 0xcf] },
  { format: 'Mach-O', bytes: [0xce, 0xfa, 0xed, 0xfe] },
  { format: 'Mach-O', bytes: [0xcf, 0xfa, 0xed, 0xfe] },
  { format: 'universal Mach-O', bytes: [0xca, 0xfe, 0xba, 0xbe] },
]

function executableFormat(header) {
  const match = executableHeaders.find(({ bytes }) => header.length >= bytes.length && bytes.every((byte, index) => header[index] === byte))
  return match?.format ?? ''
}

function trackedFiles() {
  return execFileSync('git', ['ls-files', '-z'], { cwd: repositoryRoot, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 })
    .split('\0')
    .filter(Boolean)
}

async function readHeader(path) {
  const file = await open(path, 'r')
  try {
    const header = Buffer.alloc(4)
    const { bytesRead } = await file.read(header, 0, header.length, 0)
    return header.subarray(0, bytesRead)
  } finally {
    await file.close()
  }
}

function insideWorkTree() {
  try {
    return execFileSync('git', ['rev-parse', '--is-inside-work-tree'], { cwd: repositoryRoot, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim() === 'true'
  } catch {
    return false
  }
}

test('the executable header check recognizes native binaries and leaves text alone', () => {
  assert.equal(executableFormat(Buffer.from([0x7f, 0x45, 0x4c, 0x46])), 'ELF')
  assert.equal(executableFormat(Buffer.from('MZ\x90\x00', 'latin1')), 'PE')
  assert.equal(executableFormat(Buffer.from([0xcf, 0xfa, 0xed, 0xfe])), 'Mach-O')
  assert.equal(executableFormat(Buffer.from([0xca, 0xfe, 0xba, 0xbe])), 'universal Mach-O')
  for (const text of ['#!/u', 'pack', '{\n  ', '', 'M']) {
    assert.equal(executableFormat(Buffer.from(text)), '', `${JSON.stringify(text)} is not an executable`)
  }
})

test('the console unit tests run these checks, so CI and the release do', async () => {
  const packageJSON = JSON.parse(await readFile(resolve(repositoryRoot, 'package.json'), 'utf8'))
  assert.match(packageJSON.scripts['test:coverage'], /scripts\/repository-files\.test\.mjs/)
})

test('no compiled binary or oversized file is committed', { skip: !insideWorkTree() && 'not a Git work tree' }, async () => {
  const problems = []
  for (const path of trackedFiles()) {
    const absolute = resolve(repositoryRoot, path)
    let stats
    try {
      stats = await lstat(absolute)
    } catch (error) {
      // A tracked file deleted from the work tree has nothing to check.
      if (error.code === 'ENOENT') continue
      throw error
    }
    if (!stats.isFile()) continue
    const format = executableFormat(await readHeader(absolute))
    if (format) problems.push(`${path} is a ${format} executable`)
    if (stats.size > maxTrackedFileBytes) problems.push(`${path} is ${stats.size} bytes, more than ${maxTrackedFileBytes}`)
  }
  assert.deepEqual(problems, [], 'remove build output from Git and keep it ignored in .gitignore')
})
