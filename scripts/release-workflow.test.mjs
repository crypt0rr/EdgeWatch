import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const scriptDirectory = dirname(fileURLToPath(import.meta.url))
const repositoryRoot = resolve(scriptDirectory, '..')
const workflowPath = resolve(repositoryRoot, '.github', 'workflows', 'release.yml')
const workflow = await readFile(workflowPath, 'utf8')

const jobsStart = workflow.indexOf('\njobs:\n')
assert.notEqual(jobsStart, -1, 'release workflow is missing its jobs')
const workflowHeader = workflow.slice(0, jobsStart)
const jobsSection = workflow.slice(jobsStart)
const jobNames = [...jobsSection.matchAll(/^ {2}([A-Za-z0-9_-]+):\n/gm)].map((match) => match[1])

function jobBlock(name) {
  const marker = `\n  ${name}:\n`
  const start = jobsSection.indexOf(marker)
  assert.notEqual(start, -1, `release workflow is missing the ${name} job`)
  const bodyStart = start + marker.length
  const nextJob = /^ {2}[A-Za-z0-9_-]+:/gm
  nextJob.lastIndex = bodyStart
  const next = nextJob.exec(jobsSection)
  return jobsSection.slice(bodyStart, next?.index ?? jobsSection.length)
}

function stepBlock(job, name) {
  const marker = `      - name: ${name}\n`
  const start = job.indexOf(marker)
  assert.notEqual(start, -1, `release workflow is missing the step ${name}`)
  const next = job.indexOf('\n      - ', start + marker.length)
  return job.slice(start, next === -1 ? job.length : next)
}

function needsOf(job) {
  const match = /^ {4}needs: (?:\[([^\]]*)\]|(\S+))$/m.exec(job)
  if (!match) return []
  return (match[1] ?? match[2]).split(',').map((need) => need.trim()).filter(Boolean)
}

test('release images are staged under unique candidate tags', () => {
  const image = jobBlock('image')
  assert.deepEqual(needsOf(image), ['verify'])
  assert.match(image, /CANDIDATE_IMAGE: ghcr\.io\/crypt0rr\/edgewatch:candidate-\$\{\{ github\.run_id \}\}-\$\{\{ github\.run_attempt \}\}/)
  assert.match(image, /push: true/)
  assert.match(image, /tags: \$\{\{ env\.CANDIDATE_IMAGE \}\}/)
  assert.doesNotMatch(image, /type=semver/)
  assert.doesNotMatch(image, /REGISTRY_IMAGE\}:/)
})

test('release image reads platform-matched CI caches without writing tag-scoped caches', () => {
  const image = jobBlock('image')
  const build = stepBlock(image, 'Build and push image')
  assert.match(build, /cache-from:\s*\|\n\s+type=gha,scope=container-multiarch\n\s+type=gha,scope=container-prebuilt-amd64\n\s+type=gha,scope=container-prebuilt-arm64/)
  assert.doesNotMatch(build, /^\s+cache-to:/m)
})

test('release verification keeps schema, scanner, build, and race gates current', () => {
  const verify = jobBlock('verify')
  assert.match(verify, /Runs the complete race-enabled Go suite/)
  assert.doesNotMatch(verify, /see the CI test job for its budget/)
  assert.match(stepBlock(verify, 'Verify schema documentation'), /\.\/scripts\/check-schema-docs\.sh/)
  assert.match(stepBlock(verify, 'Verify pinned Naabu release'), /\.\/scripts\/verify-naabu-pin\.sh/)
  assert.match(stepBlock(verify, 'Build'), /go build -trimpath \.\/cmd\/edgewatch/)
  assert.match(stepBlock(verify, 'Test'), /go test -race -timeout=25m -coverprofile=coverage\.out \.\/\.\.\./)
})

// A partial re-run ("Re-run failed jobs") does not repeat the image job, and
// github.run_attempt grows with every re-run. A candidate reference recomputed
// in a later job would name a tag that was never pushed, so the reference must
// flow from the image job's output, which GitHub keeps for jobs not re-run.
test('the image job publishes the pushed candidate as a digest-pinned output', () => {
  const image = jobBlock('image')
  assert.match(image, /^ {4}outputs:\n {6}candidate: \$\{\{ steps\.candidate\.outputs\.reference \}\}$/m)
  const record = stepBlock(image, 'Record the pushed candidate')
  assert.match(record, /id: candidate/)
  assert.match(record, /DIGEST: \$\{\{ steps\.push\.outputs\.digest \}\}/)
  assert.match(record, /\^sha256:\[0-9a-f\]\{64\}\$/)
  assert.match(record, /echo "reference=\$IMAGE@\$DIGEST" >> "\$GITHUB_OUTPUT"/)
  assert.ok(image.indexOf('id: push') < image.indexOf('id: candidate'), 'the candidate is recorded after the push')
})

test('every candidate consumer reads the image job output', () => {
  const consumers = jobNames.filter((name) => jobBlock(name).includes('needs.image.outputs.candidate'))
  assert.deepEqual(consumers, ['smoke', 'promote-semver'])
  for (const name of consumers) {
    const job = jobBlock(name)
    assert.ok(needsOf(job).includes('image'), `${name} must need the image job to read its output`)
    assert.match(job, /CANDIDATE: \$\{\{ needs\.image\.outputs\.candidate \}\}/)
    // The consumer refuses anything but a digest of the release repository.
    assert.match(job, /\$\{CANDIDATE#"\$REGISTRY_IMAGE@"\}|\$\{CANDIDATE#"\$IMAGE@"\}/)
    assert.match(job, /did not provide a digest-pinned candidate/)
  }

  const smoke = stepBlock(jobBlock('smoke'), 'Pull and inspect the candidate image')
  assert.match(smoke, /image="\$CANDIDATE"/)
  assert.match(smoke, /docker pull "\$image"/)

  const promote = stepBlock(jobBlock('promote-semver'), 'Promote candidate after smoke verification')
  assert.match(promote, /docker buildx imagetools create --tag "\$semver_image" "\$CANDIDATE"/)
})

test('no job other than image recomputes the attempt-scoped candidate', () => {
  // Job-level env and step scripts are the only places a job could rebuild
  // the tag; the workflow-level env is evaluated again in every job.
  assert.doesNotMatch(workflowHeader, /run_attempt|RUN_ATTEMPT|CANDIDATE_IMAGE|candidate-/)
  assert.ok(jobNames.includes('image'))
  for (const name of jobNames.filter((job) => job !== 'image')) {
    const job = jobBlock(name)
    assert.doesNotMatch(job, /run_attempt|RUN_ATTEMPT/i, `${name} must not read the run attempt`)
    assert.doesNotMatch(job, /CANDIDATE_IMAGE/, `${name} must not read the image job's candidate tag`)
    assert.doesNotMatch(job, /candidate-/, `${name} must not build a candidate tag`)
  }
})

test('smoke tests consume the candidate before semver promotion', () => {
  const smoke = jobBlock('smoke')
  assert.deepEqual(needsOf(smoke), ['binaries', 'image'])
  assert.match(smoke, /Pull and inspect the candidate image/)

  // Publication stays ahead of promotion (#711): the semver and latest tags
  // are created only after smoke and publication succeed.
  const publish = jobBlock('publish-release')
  assert.deepEqual(needsOf(publish), ['binaries', 'image', 'smoke'])

  const promoteSemver = jobBlock('promote-semver')
  assert.deepEqual(needsOf(promoteSemver), ['image', 'smoke', 'publish-release'])
  assert.match(promoteSemver, /needs\.smoke\.result == 'success' && needs\.publish-release\.result == 'success'/)

  const promoteLatest = jobBlock('promote-latest')
  assert.deepEqual(needsOf(promoteLatest), ['promote-semver', 'publish-release'])
  assert.match(promoteLatest, /needs\.promote-semver\.result == 'success'/)
})

test('a semver re-run finishes the promotion without overwriting another image', () => {
  const promote = stepBlock(jobBlock('promote-semver'), 'Promote candidate after smoke verification')
  // An existing tag is accepted only when it already names the candidate
  // digest, as after a job that failed once the tag was created.
  assert.match(promote, /candidate_digest="\$\{CANDIDATE#"\$IMAGE@"\}"/)
  assert.match(promote, /docker buildx imagetools inspect "\$semver_image" --format '\{\{json \.Manifest\}\}'/)
  assert.match(promote, /jq -r '\.digest'/)
  assert.match(promote, /= "\$candidate_digest"/)
  assert.match(promote, /already points to the verified candidate/)
  assert.match(promote, /image tag already exists; refusing to overwrite \$semver_image/)
  const accepted = promote.indexOf('already points to the verified candidate')
  const refused = promote.indexOf('refusing to overwrite')
  const created = promote.indexOf('docker buildx imagetools create')
  assert.ok(accepted < refused && refused < created, 'the overwrite guard runs before the tag is created')
})

test('the workflow documents the re-run procedure for a failed release', () => {
  assert.match(workflowHeader, /Re-run failed jobs/)
  assert.match(workflowHeader, /promote-semver/)
  assert.match(workflowHeader, /Re-run all jobs/)
})

test('release reruns replace only an abandoned draft', () => {
  const binaries = jobBlock('binaries')
  assert.match(binaries, /gh api --paginate "repos\/\$GITHUB_REPOSITORY\/releases\?per_page=100"/)
  assert.match(binaries, /select\(\.tag_name == env\.RELEASE_TAG\)/)
  assert.match(binaries, /jq -r '\.draft'/)
  assert.match(binaries, /gh api --method DELETE "repos\/\$GITHUB_REPOSITORY\/releases\/\$release_id"/)
  assert.match(binaries, /already published; refusing a mixed rerun/)
})
