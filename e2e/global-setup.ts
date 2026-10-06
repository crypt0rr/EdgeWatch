import { execFile } from 'node:child_process'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'

const run = promisify(execFile)

export default async function globalSetup() {
  const directory = await mkdtemp(join(tmpdir(), 'edgewatch-e2e-build-'))
  const binary = join(directory, 'edgewatch')
  try {
    console.info('Building the EdgeWatch daemon once for real-stack browser tests')
    await run('go', ['build', '-o', binary, './cmd/edgewatch'], { cwd: process.cwd() })
    process.env.EDGEWATCH_E2E_BINARY = binary
  } catch (error) {
    await rm(directory, { recursive: true, force: true })
    throw error
  }

  return async () => {
    delete process.env.EDGEWATCH_E2E_BINARY
    await rm(directory, { recursive: true, force: true })
  }
}
