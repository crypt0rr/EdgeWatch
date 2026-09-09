import { spawn } from 'node:child_process'
import { mkdir, rm, writeFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'

const outputDirectory = resolve('internal/webui/dist')
const marker = resolve(outputDirectory, '.gitkeep')

// Vite's normal emptyOutDir behavior removes .gitkeep, which makes a clean
// checkout fail Go's //go:embed pattern. Clean explicitly, recreate the
// marker, and let Vite write into the now-empty directory without deleting it.
await rm(outputDirectory, { recursive: true, force: true })
await mkdir(dirname(marker), { recursive: true })
await writeFile(marker, '')

const npx = process.platform === 'win32' ? 'npx.cmd' : 'npx'
await new Promise((resolveBuild, rejectBuild) => {
  const child = spawn(npx, ['--no-install', 'vite', 'build'], { stdio: 'inherit' })
  child.on('error', rejectBuild)
  child.on('close', (code, signal) => {
    if (code === 0) {
      resolveBuild()
      return
    }
    rejectBuild(new Error(`frontend build exited with ${signal ? `signal ${signal}` : `status ${code}`}`))
  })
})
