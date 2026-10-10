import assert from 'node:assert/strict'
import { readdir, readFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const scriptDirectory = dirname(fileURLToPath(import.meta.url))
const repositoryRoot = resolve(scriptDirectory, '..')
const workflowPath = resolve(repositoryRoot, '.github', 'workflows', 'release.yml')
const workflow = await readFile(workflowPath, 'utf8')
const ciWorkflowPath = resolve(repositoryRoot, '.github', 'workflows', 'ci.yml')
const ciWorkflow = await readFile(ciWorkflowPath, 'utf8')
const workflowsDirectory = resolve(repositoryRoot, '.github', 'workflows')
const workflows = await Promise.all(
  (await readdir(workflowsDirectory))
    .filter((file) => /\.ya?ml$/.test(file))
    .sort()
    .map(async (file) => ({ file: `.github/workflows/${file}`, text: await readFile(resolve(workflowsDirectory, file), 'utf8') })),
)
const readRepositoryFile = (path) => readFile(resolve(repositoryRoot, path), 'utf8')
const dockerfile = await readRepositoryFile('Dockerfile')
const makefile = await readRepositoryFile('Makefile')
const renovate = JSON.parse(await readRepositoryFile('renovate.json'))
const scanScriptPath = 'scripts/scan-image-vulnerabilities.sh'
const scanScript = await readRepositoryFile(scanScriptPath)
const naabuAllowlist = await readRepositoryFile('scripts/naabu-vulncheck-allowlist.txt')
const grypeConfig = await readRepositoryFile('.grype.yaml')
const composeScript = await readRepositoryFile('scripts/verify-compose-deployment.sh')

const jobsStart = workflow.indexOf('\njobs:\n')
assert.notEqual(jobsStart, -1, 'release workflow is missing its jobs')
const workflowHeader = workflow.slice(0, jobsStart)
const jobsSection = workflow.slice(jobsStart)
const jobNames = [...jobsSection.matchAll(/^ {2}([A-Za-z0-9_-]+):\n/gm)].map((match) => match[1])
const ciJobsStart = ciWorkflow.indexOf('\njobs:\n')
assert.notEqual(ciJobsStart, -1, 'CI workflow is missing its jobs')
const ciJobsSection = ciWorkflow.slice(ciJobsStart)

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

function ciJobBlock(name) {
  const marker = `\n  ${name}:\n`
  const start = ciJobsSection.indexOf(marker)
  assert.notEqual(start, -1, `CI workflow is missing the ${name} job`)
  const bodyStart = start + marker.length
  const nextJob = /^ {2}[A-Za-z0-9_-]+:/gm
  nextJob.lastIndex = bodyStart
  const next = nextJob.exec(ciJobsSection)
  return ciJobsSection.slice(bodyStart, next?.index ?? ciJobsSection.length)
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

// jobsOf, stepsOf, and permissionsOf read any workflow with the two-space
// indentation that these workflows use.
function jobsOf(text) {
  const start = text.indexOf('\njobs:\n')
  assert.notEqual(start, -1, 'workflow is missing its jobs')
  const section = text.slice(start)
  const keys = [...section.matchAll(/^ {2}([A-Za-z0-9_-]+):\n/gm)]
  return keys.map((key, index) => ({
    name: key[1],
    block: section.slice(key.index + key[0].length, keys[index + 1]?.index ?? section.length),
  }))
}

function stepsOf(job) {
  return job.split(/^(?= {6}- )/m).filter((step) => step.startsWith('      - '))
}

// The permissions block at the given indentation: an object of scopes, or
// the string of a shorthand such as write-all. null when there is none.
function permissionsOf(text, indent) {
  const pad = ' '.repeat(indent)
  const match = new RegExp(`^${pad}permissions:(.*)$`, 'm').exec(text)
  if (!match) return null
  if (match[1].trim()) return match[1].trim()
  const scopes = {}
  for (const line of text.slice(match.index + match[0].length + 1).split('\n')) {
    if (new RegExp(`^${pad}  #`).test(line)) continue
    const scope = new RegExp(`^${pad}  ([a-z-]+): (read|write|none)$`).exec(line)
    if (!scope) break
    scopes[scope[1]] = scope[2]
  }
  return scopes
}

function writeScopes(permissions) {
  if (typeof permissions === 'string') return permissions === 'read-all' || permissions === '{}' ? [] : [permissions]
  return Object.entries(permissions).filter(([, level]) => level === 'write').map(([scope]) => scope)
}

function withoutComments(text) {
  return text.replace(/^\s*#.*$/gm, '')
}

// The dependencies that Renovate's custom managers extract from a file.
function renovateDependencies(file, text) {
  const dependencies = []
  for (const manager of renovate.customManagers) {
    const patterns = manager.managerFilePatterns.map((pattern) => {
      const match = /^\/(.*)\/([a-z]*)$/.exec(pattern)
      assert.ok(match, `managerFilePatterns entry ${pattern} is not a /regex/`)
      return new RegExp(match[1], match[2])
    })
    if (!patterns.some((pattern) => pattern.test(file))) continue
    for (const matchString of manager.matchStrings) {
      for (const { groups } of text.matchAll(new RegExp(matchString, 'g'))) {
        dependencies.push({
          datasource: manager.datasourceTemplate,
          depName: groups.depName ?? manager.depNameTemplate,
          currentValue: groups.currentValue,
          currentDigest: groups.currentDigest,
        })
      }
    }
  }
  return dependencies
}

function dockerfileArg(name) {
  const match = new RegExp(`^ARG ${name}=(\\S+)$`, 'm').exec(dockerfile)
  assert.ok(match, `Dockerfile is missing ARG ${name}`)
  return match[1]
}

test('release images are staged under unique candidate tags', () => {
  const image = jobBlock('image')
  assert.deepEqual(needsOf(image), ['verify', 'ci-status'])
  assert.match(image, /CANDIDATE_IMAGE: ghcr\.io\/crypt0rr\/edgewatch:candidate-\$\{\{ github\.run_id \}\}-\$\{\{ github\.run_attempt \}\}/)
  assert.match(image, /push: true/)
  assert.match(image, /tags: \$\{\{ env\.CANDIDATE_IMAGE \}\}/)
  assert.doesNotMatch(image, /type=semver/)
  assert.doesNotMatch(image, /REGISTRY_IMAGE\}:/)
})

// A cache hit returns a stored layer instead of running the instruction, so
// an imported cache could put a layer that this release never built into the
// attested image (#1297). Every cache that a release could import is written
// outside the release run.
test('the published image is built from scratch without imported caches', () => {
  const image = jobBlock('image')
  const build = stepBlock(image, 'Build and push image')
  assert.match(image, /^ {4}permissions:\n {6}contents: read\n {6}actions: read\n {6}packages: write$/m)
  assert.match(build, /^ {10}push: true$/m)
  assert.match(build, /^ {10}no-cache: true$/m)
  assert.match(build, /^ {10}platforms: linux\/amd64,linux\/arm64$/m)
  assert.match(build, /build-args:\s*\|\n\s+VERSION=v0\.0\.0-ci\n\s+PREBUILT_FRONTEND=1\n\s+PREBUILT_EDGEWATCH=1/)
  assert.match(build, /^ {10}provenance: mode=max$/m)
  assert.doesNotMatch(image, /cache-from|cache-to|type=registry|type=gha/)
  assert.equal([...image.matchAll(/uses: docker\/build-push-action@/g)].length, 1, 'the image job builds only the image it pushes')
  for (const { file, text } of workflows) {
    assert.doesNotMatch(text, /type=registry|:buildcache\b|:releasecache\b/, `${file} must not read or write registry build caches`)
  }
  for (const { name, block } of jobsOf(ciWorkflow)) {
    assert.deepEqual(writeScopes(permissionsOf(block, 4) ?? {}), [], `CI job ${name} must not hold a write scope`)
  }
})

// The verify job builds the release binaries and the frontend that the image
// embeds, so no release job restores an Actions cache either.
test('no release job restores an Actions cache', () => {
  assert.doesNotMatch(workflow, /uses: actions\/cache@/)
  let setups = 0
  for (const { name, block } of jobsOf(workflow)) {
    for (const step of stepsOf(block)) {
      if (/uses: actions\/setup-go@/.test(step)) {
        setups++
        assert.match(step, /^ {10}cache: false$/m, `${name}: setup-go caches unless cache is false`)
      }
      if (/uses: actions\/setup-node@/.test(step)) {
        setups++
        assert.doesNotMatch(step, /^ {10}cache:/m, `${name}: setup-node must not restore an npm cache`)
        assert.match(step, /^ {10}package-manager-cache: false$/m, `${name}: setup-node must not cache automatically`)
      }
    }
  }
  assert.ok(setups >= 4, 'expected the release jobs to set up Go and Node')
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
  assert.deepEqual([...consumers].sort(), ['promote-semver', 'scan', 'smoke', 'smoke-arm64'])
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
  assert.deepEqual(needsOf(smoke), ['binaries', 'image', 'frontend-rebuild'])
  assert.match(smoke, /Pull and inspect the candidate image/)

  // Publication stays ahead of promotion (#711): the semver and latest tags
  // are created only after the scan, both smoke jobs, and publication
  // succeed.
  const publish = jobBlock('publish-release')
  assert.deepEqual(needsOf(publish), ['binaries', 'image', 'scan', 'smoke', 'smoke-arm64'])

  const promoteSemver = jobBlock('promote-semver')
  assert.deepEqual(needsOf(promoteSemver), ['image', 'scan', 'smoke', 'smoke-arm64', 'publish-release'])
  assert.match(promoteSemver, /^ {4}if: \$\{\{ needs\.scan\.result == 'success' && needs\.smoke\.result == 'success' && needs\.smoke-arm64\.result == 'success' && needs\.publish-release\.result == 'success' \}\}$/m)

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

// npm packages run code from their authors, including native binaries that
// the frontend build loads. In a job with a write scope that code could use
// the job token, for example to push :latest or replace release assets
// (#1296), so such jobs consume artifacts that read-only jobs built.
test('no job that holds a write scope runs npm packages', () => {
  const thirdPartyBuild = /\bnpm (?:ci|install|i|run|exec|test|rebuild)\b|\bnpx\b|\bmake (?:build|frontend|check)\b|uses: actions\/setup-node@/
  let writers = 0
  for (const { file, text } of workflows) {
    const workflowPermissions = permissionsOf(text.slice(0, text.indexOf('\njobs:\n')), 0)
    assert.equal(typeof workflowPermissions, 'object', `${file} must set its default permissions explicitly`)
    assert.notEqual(workflowPermissions, null, `${file} must set its default permissions explicitly`)
    assert.deepEqual(writeScopes(workflowPermissions), [], `${file} must default to read-only permissions`)
    for (const { name, block } of jobsOf(text)) {
      const writes = writeScopes(permissionsOf(block, 4) ?? workflowPermissions)
      if (writes.length === 0) continue
      writers++
      assert.doesNotMatch(withoutComments(block), thirdPartyBuild, `${file} job ${name} holds ${writes.join(', ')} write access and must not run npm packages`)
    }
  }
  assert.ok(writers >= 6, `expected the six release jobs that publish to hold write scopes, found ${writers}`)
  assert.deepEqual(permissionsOf(jobBlock('verify'), 4), { contents: 'read' })
})

test('every checkout leaves the job token out of the Git configuration', () => {
  let checkouts = 0
  for (const { file, text } of workflows) {
    for (const { name, block } of jobsOf(text)) {
      for (const step of stepsOf(block)) {
        if (!/uses: actions\/checkout@/.test(step)) continue
        checkouts++
        assert.match(step, /^ {8}with:$/m, `${file} job ${name} checks out without persist-credentials: false`)
        assert.match(step, /^ {10}persist-credentials: false$/m, `${file} job ${name} checks out without persist-credentials: false`)
      }
    }
  }
  assert.ok(checkouts >= 14, `expected every workflow job to check out, found ${checkouts}`)
})

const pinnedImage = (repository, tag) => new RegExp(`^docker\\.io/${repository.replace('/', '\\/')}:${tag}@sha256:[0-9a-f]{64}$`)

// setup-qemu-action otherwise runs docker.io/tonistiigi/binfmt:latest
// privileged, and setup-buildx-action starts moby/buildkit:buildx-stable-1,
// which builds and pushes the attested image (#1331).
test('the QEMU, BuildKit, and SBOM generator images are pinned by digest', () => {
  const binfmt = new Set()
  const buildkit = new Set()
  for (const { file, text } of workflows) {
    for (const { name, block } of jobsOf(text)) {
      for (const step of stepsOf(block)) {
        if (/uses: docker\/setup-qemu-action@/.test(step)) {
          const image = /^ {10}image: (\S+)$/m.exec(step)?.[1]
          assert.match(image ?? '', pinnedImage('tonistiigi/binfmt', 'qemu-v\\d+\\.\\d+\\.\\d+'), `${file} job ${name} must pin the binfmt image`)
          assert.match(step, /^ {10}cache-image: false$/m, `${file} job ${name} must pull binfmt from the registry, not an Actions cache`)
          binfmt.add(image)
        }
        if (/uses: docker\/setup-buildx-action@/.test(step)) {
          const image = /^ {10}driver-opts: image=(\S+)$/m.exec(step)?.[1]
          assert.match(image ?? '', pinnedImage('moby/buildkit', 'v\\d+\\.\\d+\\.\\d+'), `${file} job ${name} must pin the BuildKit image`)
          buildkit.add(image)
        }
      }
    }
  }
  assert.equal(binfmt.size, 1, `every workflow must use one binfmt pin: ${[...binfmt]}`)
  assert.equal(buildkit.size, 1, `every workflow must use one BuildKit pin: ${[...buildkit]}`)
  const sbom = /^ {10}sbom: generator=(\S+)$/m.exec(stepBlock(jobBlock('image'), 'Build and push image'))?.[1]
  assert.match(sbom ?? '', pinnedImage('docker/buildkit-syft-scanner', '\\d+\\.\\d+\\.\\d+'))
  for (const job of ['image', 'promote-semver', 'promote-latest']) {
    assert.match(jobBlock(job), /uses: docker\/setup-buildx-action@/, `${job} sets up the pinned BuildKit`)
  }
})

test('Renovate updates every pinned image, package, and the Naabu release', () => {
  const pinnedFiles = [...workflows, { file: scanScriptPath, text: scanScript }]
  let images = 0
  for (const { file, text } of pinnedFiles) {
    const pinned = [...text.matchAll(/docker\.io\/[^\s:@]+:[^\s@]+@sha256:[0-9a-f]{64}/g)].map((match) => match[0])
    images += pinned.length
    const extracted = renovateDependencies(file, text)
      .filter((dependency) => dependency.datasource === 'docker')
      .map(({ depName, currentValue, currentDigest }) => `${depName}:${currentValue}@${currentDigest}`)
    assert.deepEqual(extracted.sort(), pinned.sort(), `Renovate must update every digest-pinned image in ${file}`)
  }
  assert.ok(images >= 9, `expected the digest-pinned images, found ${images}`)
  assert.match(scanScript, /^grype_image=docker\.io\/anchore\/grype:v\d+\.\d+\.\d+@sha256:[0-9a-f]{64}$/m)

  const binfmtVersioning = renovate.packageRules.find((rule) => rule.matchDepNames?.includes('docker.io/tonistiigi/binfmt'))?.versioning
  assert.match(binfmtVersioning ?? '', /^regex:/)
  for (const { currentValue } of renovateDependencies('.github/workflows/release.yml', workflow).filter((dependency) => dependency.depName === 'docker.io/tonistiigi/binfmt')) {
    assert.match(currentValue, new RegExp(binfmtVersioning.slice('regex:'.length)))
  }

  // The tag and the commit change together, so the Dockerfile's check and
  // scripts/verify-naabu-pin.sh keep passing on a Renovate update.
  assert.deepEqual(renovateDependencies('Dockerfile', dockerfile).filter((dependency) => dependency.datasource === 'github-tags'), [
    { datasource: 'github-tags', depName: 'projectdiscovery/naabu', currentValue: dockerfileArg('NAABU_VERSION'), currentDigest: dockerfileArg('NAABU_COMMIT') },
  ])
  const apkPins = [...dockerfile.matchAll(/^RUN apk add --no-cache ([^\n\\]*)/gm)].flatMap((match) => match[1].trim().split(/\s+/))
  const repology = renovateDependencies('Dockerfile', dockerfile).filter((dependency) => dependency.datasource === 'repology').map(({ depName, currentValue }) => `${depName}=${currentValue}`)
  assert.ok(apkPins.includes('zlib=1.3.2-r1') || apkPins.some((pin) => pin.startsWith('zlib=')), 'the image pins zlib')
  for (const pin of apkPins) {
    assert.match(pin, /^[a-z0-9.+-]+=[0-9][0-9A-Za-z.+~-]*$/, `apk package ${pin} must be pinned to a version`)
    assert.ok(repology.includes(pin), `Renovate must update the apk pin ${pin}`)
  }
  const govulncheck = /^GOVULNCHECK_VERSION \?= (\S+)$/m.exec(makefile)?.[1]
  assert.deepEqual(renovateDependencies('Makefile', makefile), [{ datasource: 'go', depName: 'golang.org/x/vuln', currentValue: govulncheck, currentDigest: undefined }])

  const npmAge = renovate.packageRules.find((rule) => rule.matchDatasources?.includes('npm') && rule.minimumReleaseAge)
  assert.equal(npmAge?.minimumReleaseAge, '3 days')
})

// verify runs on every v* tag, so it must refuse a tag on a commit that never
// reached main, and nothing is staged before CI has passed for the commit
// (#1332).
test('the release refuses a tagged commit that is not on main or has no passing CI run', () => {
  const verify = jobBlock('verify')
  assert.match(stepBlock(verify, 'Check out source'), /^ {10}fetch-depth: 0$/m)
  const onMain = stepBlock(verify, 'Require the tagged commit to be on main')
  assert.match(onMain, /git rev-parse --verify --quiet refs\/remotes\/origin\/main/)
  assert.match(onMain, /if ! git merge-base --is-ancestor "\$GITHUB_SHA" refs\/remotes\/origin\/main; then/)
  assert.ok(verify.indexOf(onMain) < verify.indexOf('      - name: Set up Go'), 'the main check runs before anything is built')

  const ciStatus = jobBlock('ci-status')
  assert.deepEqual(permissionsOf(ciStatus, 4), { actions: 'read' })
  assert.match(ciStatus, /actions\/workflows\/ci\.yml\/runs\?head_sha=\$GITHUB_SHA/)
  assert.match(ciStatus, /select\(\.event == "push" or \.event == "workflow_dispatch"\)/)
  assert.match(ciStatus, /\$2 == "completed" && \$3 == "success"/)
  assert.match(ciStatus, /gh workflow run ci\.yml --ref \$GITHUB_REF_NAME/)
  for (const name of ['binaries', 'image']) {
    assert.ok(needsOf(jobBlock(name)).includes('ci-status'), `${name} must wait for CI`)
  }
  // The runs that ci-status accepts exist only while CI runs on pushes to
  // main and by hand.
  assert.match(ciWorkflow, /^name: CI\n/)
  assert.match(ciWorkflow, /^on:\n {2}push:\n {4}branches: \[main\]\n/m)
  assert.match(ciWorkflow, /^ {2}workflow_dispatch:$/m)
})

test('an ARM64 runner runs the ARM64 candidate and archive before publication', () => {
  const arm = jobBlock('smoke-arm64')
  const ciArm = ciJobBlock('arm64-sandbox')
  const runner = (job) => /^ {4}runs-on: (\S+)$/m.exec(job)?.[1]
  assert.match(runner(arm) ?? '', /-arm$/)
  assert.equal(runner(arm), runner(ciArm), 'the release and CI use the same ARM64 runner')
  assert.deepEqual(needsOf(arm), ['verify', 'image'])
  assert.deepEqual(writeScopes(permissionsOf(arm, 4)), [])
  const archive = stepBlock(arm, 'Run the ARM64 release archive natively')
  assert.match(archive, /archives=\(dist\/\*_linux_arm64\.tar\.gz\)/)
  assert.match(archive, /test "\$\("\$binary" version\)" = "EdgeWatch \$\{GITHUB_REF_NAME#v\}"/)
  const pull = stepBlock(arm, 'Pull and inspect the ARM64 candidate image')
  assert.match(pull, /docker pull --platform linux\/arm64 "\$image"/)
  assert.match(pull, /= aarch64$/m)
  // CI runs each check on its own ARM64 image, so a check that the runner
  // cannot pass fails CI before it can fail a release.
  for (const [check, ciCheck] of [
    ['bash ./scripts/test-prebuilt-image.sh "$IMAGE" linux/arm64 "${GITHUB_REF_NAME#v}"', 'bash ./scripts/test-prebuilt-image.sh edgewatch:arm64 linux/arm64 v0.0.0-ci'],
    ['./scripts/verify-container-runtime.sh "$IMAGE"', './scripts/verify-container-runtime.sh edgewatch:arm64'],
    ['./scripts/verify-scanner-sandbox.sh "$IMAGE"', './scripts/verify-scanner-sandbox.sh edgewatch:arm64'],
    ['./scripts/verify-compose-deployment.sh "$IMAGE"', './scripts/verify-compose-deployment.sh edgewatch:arm64'],
  ]) {
    assert.ok(arm.includes(`run: ${check}\n`), `smoke-arm64 must run ${check}`)
    assert.ok(ciArm.includes(`run: ${ciCheck}\n`), `arm64-sandbox must run ${ciCheck}`)
  }
})

test('the image is scanned for known vulnerabilities in CI and before publication', () => {
  const ciScan = stepBlock(ciJobBlock('container'), 'Scan images for known vulnerabilities')
  assert.match(ciScan, /scan-image-vulnerabilities\.sh edgewatch:prebuilt-amd64 linux\/amd64/)
  assert.match(ciScan, /scan-image-vulnerabilities\.sh edgewatch:prebuilt-arm64 linux\/arm64/)

  const scan = jobBlock('scan')
  assert.deepEqual(needsOf(scan), ['image'])
  assert.deepEqual(writeScopes(permissionsOf(scan, 4)), [])
  const step = stepBlock(scan, 'Scan both platforms of the candidate')
  assert.match(step, /for platform in linux\/amd64 linux\/arm64; do/)
  assert.match(step, /docker pull --platform "\$platform" "\$CANDIDATE"/)
  assert.match(step, /\.\/scripts\/scan-image-vulnerabilities\.sh "\$CANDIDATE" "\$platform" \|\| status=1/)

  // govulncheck reads the symbols of the bundled Naabu, and Grype fails on a
  // fixed vulnerability of high or critical severity in the Alpine packages.
  assert.match(scanScript, /docker cp "\$container:\/usr\/local\/bin\/naabu" "\$workdir\/naabu"/)
  assert.match(scanScript, /govulncheck@\$\{govulncheck_version\}" \\\n\s+-mode=binary -format json "\$workdir\/naabu"/)
  assert.match(scanScript, /--cap-drop ALL/)
  assert.match(scanScript, /--volume "\$workdir\/rootfs:\/image:ro"/)
  assert.match(scanScript, /"\$grype_image" --config \/etc\/grype\.yaml --only-fixed --fail-on high /)
  for (const line of naabuAllowlist.split('\n')) {
    if (line === '' || line.startsWith('#')) continue
    assert.match(line, /^GO-\d{4}-\d{4,} \S.*$/, `allowlist entries name an OSV ID and the reason: ${line}`)
  }
  // Grype ignores Go modules only because govulncheck checks the binaries.
  assert.match(grypeConfig, /^ {2}- package:\n {6}type: go-module\n/m)
  assert.doesNotMatch(grypeConfig, /^\s*(?:fail-on-severity|only-fixed|only-notfixed|ignore-wontfix|exclude):/m)
})

test('the release smoke starts the bundled compose.yaml with both sandboxes enforced', () => {
  const smoke = jobBlock('smoke')
  assert.match(stepBlock(smoke, 'Verify disposable Compose deployment'), /run: \.\/scripts\/verify-compose-deployment\.sh "\$IMAGE"$/m)
  assert.doesNotMatch(smoke, /services:|cap_add/, 'smoke must not write a Compose file of its own')
  assert.match(stepBlock(ciJobBlock('container'), 'Verify Compose deployment'), /verify-compose-deployment\.sh edgewatch:prebuilt-amd64/)

  assert.match(composeScript, /-f "\$repository\/compose\.yaml" -f "\$project_dir\/compose\.override\.yaml"\)/)
  const override = /cat > "\$project_dir\/compose\.override\.yaml" <<EOF\n([\s\S]*?)\nEOF\n/.exec(composeScript)?.[1]
  assert.equal(override, 'services:\n  edgewatch:\n    image: ${image}\n    container_name: ${project}', 'the override replaces only the image and container name')
  assert.match(composeScript, /^"\$\{compose\[@\]\}" config$/m)
  assert.match(composeScript, /\[\[ "\$health" == healthy \]\]/)
  assert.match(composeScript, /for sandbox in scanner_sandbox notification_sandbox; do/)
  assert.match(composeScript, /\[\[ "\$state" == enforced \]\]/)
})

test('smoke compares the published manifest with a frontend rebuilt without write scopes', () => {
  const rebuild = jobBlock('frontend-rebuild')
  assert.deepEqual(permissionsOf(rebuild, 4), { contents: 'read' })
  assert.match(stepBlock(rebuild, 'Rebuild frontend'), /run: npm ci && npm run build$/m)
  const upload = stepBlock(rebuild, 'Upload rebuilt frontend')
  assert.match(upload, /name: release-frontend-rebuild$/m)
  assert.match(upload, /path: internal\/webui\/dist$/m)

  const smoke = jobBlock('smoke')
  const download = stepBlock(smoke, 'Download rebuilt frontend for manifest verification')
  assert.match(download, /name: release-frontend-rebuild\n\s+path: rebuilt-frontend$/m)
  const archives = stepBlock(smoke, 'Verify release archive versions')
  assert.match(archives, /FRONTEND_DIST: rebuilt-frontend$/m)
  assert.match(archives, /\.\/scripts\/verify-release-artifacts\.sh "\$archive_dir" "\$archive_dir\/release-manifest\.json"/)
  assert.ok(smoke.indexOf(download) < smoke.indexOf(archives))
})
