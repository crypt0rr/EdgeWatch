import { execFile } from 'node:child_process'
import { mkdir, rm, writeFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)
const outputDirectory = resolve('internal/webui/dist')
const marker = resolve(outputDirectory, '.gitkeep')

// Vite's normal emptyOutDir behavior removes .gitkeep, which makes a clean
// checkout fail Go's //go:embed pattern. Clean explicitly, recreate the
// marker, and let Vite write into the now-empty directory without deleting it.
await rm(outputDirectory, { recursive: true, force: true })
await mkdir(dirname(marker), { recursive: true })
await writeFile(marker, '')

const npx = process.platform === 'win32' ? 'npx.cmd' : 'npx'
await execFileAsync(npx, ['--no-install', 'vite', 'build'], { stdio: 'inherit' })
