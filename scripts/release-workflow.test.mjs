import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const scriptDirectory = dirname(fileURLToPath(import.meta.url))
const repositoryRoot = resolve(scriptDirectory, '..')
const workflowPath = resolve(repositoryRoot, '.github', 'workflows', 'release.yml')
const workflow = await readFile(workflowPath, 'utf8')

function jobBlock(name) {
  const marker = `  ${name}:\n`
  const start = workflow.indexOf(marker)
  assert.notEqual(start, -1, `release workflow is missing the ${name} job`)
  const bodyStart = start + marker.length
  const nextJob = /^  [A-Za-z0-9_-]+:/gm
  nextJob.lastIndex = bodyStart
  const next = nextJob.exec(workflow)
  return workflow.slice(bodyStart, next?.index ?? workflow.length)
}

test('release images are staged under unique candidate tags', () => {
  assert.match(workflow, /CANDIDATE_IMAGE: ghcr\.io\/crypt0rr\/edgewatch:candidate-\$\{\{ github\.run_id \}\}-\$\{\{ github\.run_attempt \}\}/)

  const image = jobBlock('image')
  assert.match(image, /needs: verify/)
  assert.match(image, /push: true/)
  assert.match(image, /tags: \$\{\{ env\.CANDIDATE_IMAGE \}\}/)
  assert.doesNotMatch(image, /type=semver/)
  assert.doesNotMatch(image, /REGISTRY_IMAGE\}:/)
})

test('smoke tests consume the candidate before semver promotion', () => {
  const smoke = jobBlock('smoke')
  assert.match(smoke, /Pull and inspect the candidate image/)
  assert.match(smoke, /image="\$\{\{ env\.CANDIDATE_IMAGE \}\}"/)

  const promoteSemver = jobBlock('promote-semver')
  assert.match(promoteSemver, /needs: \[smoke, publish-release\]/)
  assert.match(promoteSemver, /docker buildx imagetools create --tag "\$semver_image" "\$CANDIDATE"/)

  const promoteLatest = jobBlock('promote-latest')
  assert.match(promoteLatest, /needs: \[promote-semver, publish-release\]/)
  assert.match(promoteLatest, /needs\.promote-semver\.result == 'success'/)
})

test('release reruns replace only an abandoned draft', () => {
  const binaries = jobBlock('binaries')
  assert.match(binaries, /gh api --paginate "repos\/\$GITHUB_REPOSITORY\/releases\?per_page=100"/)
  assert.match(binaries, /select\(\.tag_name == env\.RELEASE_TAG\)/)
  assert.match(binaries, /jq -r '\.draft'/)
  assert.match(binaries, /gh api --method DELETE "repos\/\$GITHUB_REPOSITORY\/releases\/\$release_id"/)
  assert.match(binaries, /already published; refusing a mixed rerun/)
})
