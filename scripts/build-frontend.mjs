import { spawn } from 'node:child_process'
import { mkdir, rm, writeFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'

const outputDirectory = resolve('internal/webui/dist')
const marker = resolve(outputDirectory, '.gitkeep')
const staleTypeScriptArtifacts = [resolve('vite.config.js'), resolve('vite.config.d.ts'), resolve('tsconfig.tsbuildinfo'), resolve('tsconfig.node.tsbuildinfo')]

// Vite's normal emptyOutDir behavior removes .gitkeep, which makes a clean
// checkout fail Go's //go:embed pattern. Clean explicitly, recreate the
// marker, and let Vite write into the now-empty directory without deleting it.
// Older TypeScript builds also left ignored config and build-info files beside
// the sources; remove those once so local builds converge to the same state as
// clean CI checkouts.
await rm(outputDirectory, { recursive: true, force: true })
await Promise.all(staleTypeScriptArtifacts.map((path) => rm(path, { force: true })))
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
