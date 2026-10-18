import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { chmod, mkdir, mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
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
const golangciLintVersion = await readRepositoryFile('.golangci-lint-version')
const renovate = JSON.parse(await readRepositoryFile('renovate.json'))
const thirdPartyLicenses = await readRepositoryFile('THIRD_PARTY_LICENSES.md')
const releaseManifestScript = await readRepositoryFile('scripts/generate-release-manifest.sh')
const scanScriptPath = 'scripts/scan-image-vulnerabilities.sh'
const scanScript = await readRepositoryFile(scanScriptPath)
const naabuAllowlist = await readRepositoryFile('scripts/naabu-vulncheck-allowlist.txt')
const grypeConfig = await readRepositoryFile('.grype.yaml')
const composeScript = await readRepositoryFile('scripts/verify-compose-deployment.sh')
const binaryImageScript = await readRepositoryFile('scripts/verify-release-image-binary.sh')
const prebuiltFrontendTest = await readRepositoryFile('scripts/test-prebuilt-frontend-fails-closed.sh')
const lintBaseScript = await readRepositoryFile('scripts/resolve-lint-base.sh')
const scannerSandboxVerifier = await readRepositoryFile('scripts/verify-scanner-sandbox.sh')
const scannerPidSelector = await readRepositoryFile('scripts/scanner-pid-selector.sh')
const scannerProcessHold = await readRepositoryFile('scripts/scanner-process-hold.sh')

async function createLintBaseFixture({ withParent = true, originMain = 'head' } = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'edgewatch-lint-base-'))
  const scripts = join(directory, 'scripts')
  const fakeBin = join(directory, 'fake-bin')
  await mkdir(scripts)
  await mkdir(fakeBin)
  await writeFile(join(directory, 'Makefile'), await readRepositoryFile('Makefile'))
  await writeFile(join(directory, '.golangci-lint-version'), 'v2.14.0\n')
  const resolverPath = join(scripts, 'resolve-lint-base.sh')
  await writeFile(resolverPath, lintBaseScript)
  await chmod(resolverPath, 0o755)

  const fakeGo = join(fakeBin, 'go')
  await writeFile(fakeGo, [
    '#!/bin/sh',
    'if [ "${1:-}" = env ] && [ "${2:-}" = GOVERSION ]; then',
    '  printf "%s\\n" go1.27.2',
    '  exit 0',
    'fi',
    'printf "%s\\n" "$@" > "$CAPTURE_ARGS"',
    '',
  ].join('\n'))
  await chmod(fakeGo, 0o755)

  const git = (args) => execFileSync('git', args, { cwd: directory, encoding: 'utf8' }).trim()
  git(['init', '--quiet', '--initial-branch=main'])
  git(['config', 'user.email', 'lint-base@example.invalid'])
  git(['config', 'user.name', 'Lint Base Fixture'])
  await writeFile(join(directory, 'source.go'), 'package fixture\n')
  git(['add', 'source.go'])
  git(['-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'base'])
  const base = git(['rev-parse', 'HEAD'])
  let parent = base
  let head = base
  if (withParent) {
    await writeFile(join(directory, 'source.go'), 'package fixture\n\n// changed\n')
    git(['add', 'source.go'])
    git(['-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'change'])
    parent = git(['rev-parse', 'HEAD'])
    await writeFile(join(directory, 'source.go'), 'package fixture\n\n// changed again\n')
    git(['add', 'source.go'])
    git(['-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'second change'])
    head = git(['rev-parse', 'HEAD'])
  }
  const remoteMain = { base, parent, head }[originMain]
  if (!remoteMain) throw new Error(`unknown fixture origin/main: ${originMain}`)
  git(['update-ref', 'refs/remotes/origin/main', remoteMain])

  return {
    directory,
    base,
    parent,
    head,
    async run(base) {
      const capture = join(directory, 'go-args')
      const env = { ...process.env, PATH: `${fakeBin}:${process.env.PATH}`, CAPTURE_ARGS: capture }
      if (base === undefined) delete env.GOLANGCI_LINT_BASE
      else env.GOLANGCI_LINT_BASE = base
      const result = spawnSync('make', ['lint-go'], { cwd: directory, env, encoding: 'utf8' })
      let args = ''
      try {
        args = await readFile(capture, 'utf8')
      } catch (error) {
        if (error.code !== 'ENOENT') throw error
      }
      return { ...result, args }
    },
  }
}

async function assertLintBase(t, fixtureOptions, requestedBase, expectedCommit = 'parent') {
  const fixture = await createLintBaseFixture(fixtureOptions)
  t.after(() => rm(fixture.directory, { recursive: true, force: true }))
  const result = await fixture.run(requestedBase)
  const expectedBase = fixture[expectedCommit]
  assert.equal(result.status, 0, result.stderr || result.stdout)
  assert.ok(result.args.includes(`--new-from-rev=${expectedBase}`), `golangci-lint args were: ${result.args}`)
  assert.ok(!result.args.includes(`--new-from-rev=${fixture.head}`), 'the selected base must not be HEAD')
}

test('lint-go resolves a nonempty diff base for CI and local runs', async (t) => {
  await t.test('empty workflow_dispatch base with origin/main at HEAD uses HEAD^', async (t) => {
    await assertLintBase(t, {}, '', 'parent')
  })

  await t.test('unset base on a detached/local run uses HEAD^', async (t) => {
    const fixture = await createLintBaseFixture()
    t.after(() => rm(fixture.directory, { recursive: true, force: true }))
    const result = await fixture.run(undefined)
    assert.equal(result.status, 0, result.stderr || result.stdout)
    assert.ok(result.args.includes(`--new-from-rev=${fixture.parent}`), `golangci-lint args were: ${result.args}`)
  })

  await t.test('a pull request keeps its supplied base commit', async (t) => {
    const fixture = await createLintBaseFixture()
    t.after(() => rm(fixture.directory, { recursive: true, force: true }))
    const result = await fixture.run(fixture.base)
    assert.equal(result.status, 0, result.stderr || result.stdout)
    assert.ok(result.args.includes(`--new-from-rev=${fixture.base}`), `golangci-lint args were: ${result.args}`)
    assert.ok(!result.args.includes(`--new-from-rev=${fixture.head}`), 'the supplied PR base must not be HEAD')
  })

  await t.test('an unavailable push-before object uses the fetched main merge base', async (t) => {
    const fixture = await createLintBaseFixture({ originMain: 'base' })
    t.after(() => rm(fixture.directory, { recursive: true, force: true }))
    const result = await fixture.run('0000000000000000000000000000000000000000')
    assert.equal(result.status, 0, result.stderr || result.stdout)
    assert.ok(result.args.includes(`--new-from-rev=${fixture.base}`), `golangci-lint args were: ${result.args}`)
    assert.ok(!result.args.includes(`--new-from-rev=${fixture.head}`), 'the fallback must not resolve to HEAD')
  })

  await t.test('a root commit fails before invoking golangci-lint', async (t) => {
    const fixture = await createLintBaseFixture({ withParent: false })
    t.after(() => rm(fixture.directory, { recursive: true, force: true }))
    const result = await fixture.run('')
    assert.notEqual(result.status, 0)
    assert.match(result.stderr, /could not find a non-HEAD golangci-lint base; HEAD must have a parent commit/)
    assert.equal(result.args, '', 'the linter must not be called with an empty diff')
  })
})

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
function renovateDependencies(file, text, config = renovate) {
  const dependencies = []
  for (const manager of config.customManagers) {
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

function dockerfileArgFrom(source, name) {
  const matches = [...source.matchAll(new RegExp(`^ARG ${name}=(\\S+)$`, 'gm'))]
  assert.equal(matches.length, 1, `Dockerfile must define ARG ${name} exactly once`)
  return matches[0][1]
}

function dockerfileArg(name) {
  return dockerfileArgFrom(dockerfile, name)
}

function releaseImageBuildStep(workflowText = workflow) {
  const images = jobsOf(workflowText).filter(({ name }) => name === 'image')
  assert.equal(images.length, 1, 'release workflow must define exactly one image job')
  const image = images[0]
  const builds = stepsOf(image.block).filter((step) => /^ {6}- name: Build and push image$/m.test(step))
  assert.equal(builds.length, 1, 'release image job must define exactly one Build and push image step')
  assert.match(builds[0], /^ {8}uses: docker\/build-push-action@/m,
    'Build and push image must be the Docker image build action')
  const buildActions = [...image.block.matchAll(/docker\/build-push-action@/g)]
  assert.equal(buildActions.length, 1, 'release image job must define exactly one Docker image build action')
  return builds[0]
}

const reviewedReleaseImageInputNames = new Set([
  'context', 'push', 'no-cache', 'platforms', 'tags', 'labels', 'build-args',
  'provenance', 'sbom', 'target', 'file', 'dockerfile-inline',
])

function releaseImageActionInputs(workflowText = workflow) {
  const build = releaseImageBuildStep(workflowText)
  const stepLines = build.replace(/\r\n/g, '\n').split('\n')
  assert.equal(stepLines[0], '      - name: Build and push image',
    'release image build step must use the reviewed plain name field')
  const stepFields = new Map()
  let inputStart = -1
  let inputEnd = stepLines.length
  for (let index = 1; index < stepLines.length; index++) {
    const line = stepLines[index]
    if (!line.trim() || /^\s*#/.test(line)) continue
    if (inputStart > 0 && /^ {9,}\S/.test(line)) continue
    const field = /^ {8}([a-z][a-z0-9-]*):(?:[ \t]*(.*))?$/.exec(line)
    assert.ok(field, 'unsupported release image build step syntax at line: ' + line)
    const [, name, rawValue = ''] = field
    assert.ok(['uses', 'id', 'with'].includes(name), 'unreviewed release image build step field: ' + name)
    assert.ok(!stepFields.has(name), 'release image build step must not define duplicate ' + name + ' fields')
    const value = rawValue.replace(/[ \t]+#.*$/, '').trim()
    stepFields.set(name, value)
    if (name === 'with') {
      assert.equal(value, '', 'release image build step with field must use the reviewed block form')
      inputStart = index + 1
      inputEnd = stepLines.length
    }
  }
  assert.equal(stepFields.get('uses')?.startsWith('docker/build-push-action@'), true,
    'Build and push image must use the Docker image build action')
  assert.match(stepFields.get('uses'), /^docker\/build-push-action@[0-9a-f]{40}$/,
    'release image build action must use an immutable pinned revision')
  assert.equal(stepFields.get('id'), 'push', 'release image build step must retain its reviewed id')
  assert.ok(inputStart > 0, 'release image build action must define exactly one with block')
  for (let index = inputStart; index < stepLines.length; index++) {
    if (/^ {8}\S/.test(stepLines[index]) && !/^\s*#/.test(stepLines[index])) {
      inputEnd = index
      break
    }
  }
  const lines = stepLines.slice(inputStart, inputEnd)
  const inputs = new Map()
  let index = 0
  while (index < lines.length) {
    const line = lines[index]
    if (!line.trim() || /^\s*#/.test(line)) {
      index++
      continue
    }

    const entry = /^ {10}([a-z][a-z0-9-]*):(?:[ \t]*(.*))?$/.exec(line)
    assert.ok(entry, 'unsupported release image action input syntax at line: ' + line)
    const [, name, rawValue = ''] = entry
    assert.ok(reviewedReleaseImageInputNames.has(name), 'unreviewed release image action input: ' + name)
    assert.notEqual(name, 'dockerfile-inline', 'release image build must not add an inline Dockerfile input')
    assert.ok(!inputs.has(name), 'release image build action must not define duplicate ' + name + ' inputs')
    const value = rawValue.replace(/[ \t]+#.*$/, '').trim()

    if (name === 'build-args') {
      assert.equal(value, '|', 'release build-args must use the reviewed literal block form')
      const argumentLines = []
      index++
      while (index < lines.length && /^ {12}\S/.test(lines[index])) {
        const argument = lines[index].slice(12)
        assert.ok(!/["'&*]/.test(argument), 'quoted or aliased build-arg syntax is not reviewed')
        argumentLines.push(argument)
        index++
      }
      assert.ok(argumentLines.length > 0, 'release build-args block must not be empty')
      inputs.set(name, argumentLines.join('\n'))
      continue
    }

    assert.ok(!/^["'[{|>]/.test(value), 'quoted, flow, or multiline release action values are not reviewed: ' + name)
    assert.ok(!/(?:^|\s)[&*][A-Za-z0-9_-]+/.test(value), 'YAML anchors and aliases are not reviewed: ' + name)
    inputs.set(name, value)
    index++
  }
  return inputs
}

function releaseImageInput(workflowText, inputName) {
  return releaseImageActionInputs(workflowText).get(inputName)
}

function releaseImageDockerfilePath(workflowText = workflow) {
  const inputs = releaseImageActionInputs(workflowText)
  const context = inputs.get('context')
  assert.equal(context, '.', 'release image build must use the static repository root as its context')
  const file = inputs.get('file')
  assert.ok(file === undefined || file === 'Dockerfile',
    'release image build must use Dockerfile at the root of its repository context')
  assert.equal(inputs.get('dockerfile-inline'), undefined,
    'release image build must not add an inline Dockerfile input')
  return file ?? 'Dockerfile'
}

function releaseImageBuildArgs(workflowText = workflow) {
  const buildArgs = releaseImageActionInputs(workflowText).get('build-args')
  assert.ok(buildArgs, 'release image build must define its Docker build arguments')
  const entries = new Map()
  for (const line of buildArgs.split('\n')) {
    const entry = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line)
    assert.ok(entry, 'unreviewed release Docker build argument: ' + line)
    assert.ok(!entries.has(entry[1]), 'release image build must not define duplicate build argument ' + entry[1])
    entries.set(entry[1], entry[2])
  }
  assert.ok(entries.size > 0, 'release image build arguments must not be empty')
  return Object.fromEntries(entries)
}

function releaseImageTargetStage(workflowText = workflow) {
  const raw = releaseImageActionInputs(workflowText).get('target')
  if (raw === undefined) return undefined
  const target = unquoteDockerfileValue(raw)
  assert.match(target, /^(?:[A-Za-z0-9_.-]+|\d+)$/,
    'release image build target must be a static Dockerfile stage name or index')
  return target
}

function dockerfileInstructions(source) {
  const instructions = []
  let pending = ''
  let startLine = 0

  for (const [index, physicalLine] of source.replace(/\r\n/g, '\n').split('\n').entries()) {
    const line = physicalLine.trim()
    if (line.startsWith('#') || (!pending && !line)) continue
    if (!pending) startLine = index + 1

    const continues = /\\$/.test(line)
    pending = pending + (pending ? ' ' : '') + (continues ? line.slice(0, -1).trimEnd() : line)
    if (continues) continue

    const match = /^([A-Z]+)(?:\s+([\s\S]*))?$/.exec(pending)
    assert.ok(match, 'unrecognized Dockerfile instruction at line ' + startLine + ': ' + pending)
    instructions.push({ name: match[1], args: match[2] ?? '', line: startLine })
    pending = ''
    startLine = 0
  }

  assert.equal(pending, '', 'Dockerfile ends with an unfinished continuation')
  return instructions
}

function expandDockerfileValue(value, variables) {
  let unresolved = false
  const expanded = value.replace(/\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))/g, (_match, braced, plain) => {
    const name = braced ?? plain
    if (!variables.has(name) || variables.get(name) === undefined) {
      unresolved = true
      return ''
    }
    return String(variables.get(name))
  })
  return unresolved ? undefined : expanded
}

function unquoteDockerfileValue(value) {
  return value.replace(/^(['"])(.*)\1$/, '$2')
}

function dockerfileStageGraph(source, buildArgs) {
  const stages = []
  const aliases = new Map()
  const globalArgs = new Map()
  const globalArgDeclarations = []
  let currentStage = null

  for (const instruction of dockerfileInstructions(source)) {
    if (instruction.name === 'FROM') {
      const tokens = instruction.args.match(/"(?:[^"]*)"|'(?:[^']*)'|[^\s]+/g) ?? []
      let tokenIndex = 0
      while (tokens[tokenIndex]?.startsWith('--')) {
        tokenIndex++
        if (!tokens[tokenIndex - 1].includes('=')) tokenIndex++
      }
      const image = tokens[tokenIndex]
      assert.ok(image, 'FROM at line ' + instruction.line + ' has no image')
      const asIndex = tokens.findIndex((token, index) => index > tokenIndex && token.toLowerCase() === 'as')
      const alias = asIndex === -1 ? null : tokens[asIndex + 1]
      const stage = {
        index: stages.length,
        name: alias ?? '#' + stages.length,
        alias,
        dependencies: new Set(),
        variables: new Map(),
        argDeclarations: [],
        environmentDeclarations: [],
        shellDeclarations: [],
        dynamicBase: /\$/.test(image),
        dynamicDependency: false,
        runs: [],
        onbuildTriggers: [],
      }
      const baseStage = aliases.get(image.toLowerCase())
      if (baseStage) {
        stage.dependencies.add(baseStage)
        for (const trigger of baseStage.onbuildTriggers) {
          stage.runs.push({
            line: trigger.line,
            // A triggered ONBUILD instruction can execute code or add stage
            // dependencies (including RUN mounts and COPY sources). Reject
            // the inherited trigger instead of partially emulating Docker.
            command: '$UNSUPPORTED_ONBUILD_TRIGGER_' + trigger.name,
            args: new Map(stage.variables),
          })
        }
      }
      if (alias) {
        assert.ok(!aliases.has(alias.toLowerCase()), 'Dockerfile stage alias ' + alias + ' is duplicated')
        aliases.set(alias.toLowerCase(), stage)
      }
      stages.push(stage)
      currentStage = stage
      continue
    }

    if (instruction.name === 'ARG') {
      const match = /^([A-Za-z_][A-Za-z0-9_]*)(?:=(.*))?$/.exec(instruction.args.trim())
      assert.ok(match, 'invalid ARG at line ' + instruction.line + ': ' + instruction.args)
      const [, name, rawDefault] = match
      if (currentStage) {
        currentStage.argDeclarations.push({ name, rawDefault, line: instruction.line })
        const defaultValue = rawDefault === undefined ? undefined : expandDockerfileValue(unquoteDockerfileValue(rawDefault), currentStage.variables)
        const value = Object.hasOwn(buildArgs, name)
          ? String(buildArgs[name])
          : rawDefault !== undefined
            ? defaultValue
            : globalArgs.has(name) ? globalArgs.get(name) : dockerAutomaticArgs.has(name) ? undefined : ''
        currentStage.variables.set(name, value)
      } else {
        globalArgDeclarations.push({ name, rawDefault, line: instruction.line })
        const defaultValue = rawDefault === undefined ? undefined : expandDockerfileValue(unquoteDockerfileValue(rawDefault), globalArgs)
        const value = Object.hasOwn(buildArgs, name)
          ? String(buildArgs[name])
          : rawDefault !== undefined ? defaultValue : dockerAutomaticArgs.has(name) ? undefined : ''
        globalArgs.set(name, value)
      }
      continue
    }

    if (!currentStage) continue

    if (instruction.name === 'ONBUILD') {
      const trigger = /^([A-Z]+)(?:\s+([\s\S]*))?$/.exec(instruction.args.trim())
      assert.ok(trigger?.[2], 'invalid ONBUILD trigger at line ' + instruction.line + ': ' + instruction.args)
      assert.ok(!['FROM', 'ONBUILD'].includes(trigger[1]),
        'unsupported nested ONBUILD trigger at line ' + instruction.line + ': ' + instruction.args)
      currentStage.onbuildTriggers.push({ name: trigger[1], args: trigger[2], line: instruction.line })
      continue
    }

    if (instruction.name === 'ENV') {
      currentStage.environmentDeclarations.push({ args: instruction.args, line: instruction.line })
      const tokens = instruction.args.match(/"(?:[^"]*)"|'(?:[^']*)'|[^\s]+/g) ?? []
      const assignments = tokens.every((token) => /^[A-Za-z_][A-Za-z0-9_]*=/.test(token))
      if (assignments) {
        for (const token of tokens) {
          const separator = token.indexOf('=')
          const name = token.slice(0, separator)
          const value = expandDockerfileValue(unquoteDockerfileValue(token.slice(separator + 1)), currentStage.variables)
          currentStage.variables.set(name, value)
        }
      } else if (tokens.length >= 2 && /^[A-Za-z_][A-Za-z0-9_]*$/.test(tokens[0])) {
        const value = expandDockerfileValue(unquoteDockerfileValue(instruction.args.slice(tokens[0].length).trim()), currentStage.variables)
        currentStage.variables.set(tokens[0], value)
      } else {
        currentStage.variables.set('*UNRESOLVED_ENV*', undefined)
      }
      continue
    }

    if (instruction.name === 'SHELL') {
      currentStage.shellDeclarations.push({ args: instruction.args, line: instruction.line })
      continue
    }

    if (instruction.name === 'COPY') {
      const match = /(?:^|\s)--from(?:=|\s+)(?:"([^"]+)"|'([^']+)'|([^\s]+))/.exec(instruction.args)
      if (match) {
        const sourceStage = match[1] ?? match[2] ?? match[3]
        if (/\$/.test(sourceStage)) {
          currentStage.dynamicDependency = true
          continue
        }
        const dependency = /^\d+$/.test(sourceStage)
          ? stages[Number(sourceStage)]
          : aliases.get(sourceStage.toLowerCase())
        if (dependency) currentStage.dependencies.add(dependency)
      }
      continue
    }

    if (instruction.name === 'RUN') {
      for (const match of instruction.args.matchAll(/(?:^|\s)--mount(?:=|\s+)(?:"([^"]+)"|'([^']+)'|([^\s]+))/g)) {
        const mount = match[1] ?? match[2] ?? match[3]
        const from = /(?:^|,)from=([^,]+)/.exec(mount)?.[1]
        if (!from) continue
        if (/\$/.test(from)) {
          currentStage.dynamicDependency = true
          continue
        }
        const dependency = /^\d+$/.test(from) ? stages[Number(from)] : aliases.get(from.toLowerCase())
        if (dependency) currentStage.dependencies.add(dependency)
      }
      currentStage.runs.push({
        line: instruction.line,
        command: instruction.args,
        args: new Map(currentStage.variables),
      })
    }
  }

  assert.ok(stages.length > 0, 'Dockerfile has no build stages')
  return { stages, aliases, globalArgDeclarations }
}

const dockerAutomaticArgs = new Set([
  'BUILDPLATFORM', 'BUILDOS', 'BUILDARCH', 'BUILDVARIANT',
  'TARGETPLATFORM', 'TARGETOS', 'TARGETARCH', 'TARGETVARIANT',
])
const reviewedDockerfileSyntax = '# syntax=docker/dockerfile:1.28@sha256:bb22d9815c728170f72750f4e5b0d672e06176142e1d602c7e66c050100b7e5b'

function releaseShellBranch(command, args) {
  const guard = /\bif\s+\[\s*["']?\$([A-Za-z_][A-Za-z0-9_]*)["']?\s*(=|==|!=)\s*(["']?)([^"'\s\]]+)\3\s*\]\s*;\s*then\b([\s\S]*?)(?:;\s*else\b([\s\S]*?))?;\s*fi\b/g
  let active = command
  for (let iteration = 0; iteration < 20; iteration++) {
    let matched = false
    let changed = false
    active = active.replace(guard, (whole, name, operator, _quote, expected, thenBranch, elseBranch = '') => {
      matched = true
      if (!args.has(name) || args.get(name) === undefined) return whole
      changed = true
      const equal = String(args.get(name)) === expected
      return (operator === '!=' ? !equal : equal) ? thenBranch : elseBranch
    })
    if (!matched || !changed) break
  }
  return active
}

function expandedRunCommand(command, args) {
  return command.replace(/\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))/g,
    (whole, braced, plain) => {
      const name = braced ?? plain
      return args.has(name) && args.get(name) !== undefined ? String(args.get(name)) : whole
    })
}

const reviewedReleaseRunForms = new Map([
  ['frontend', [
    'if [ "$PREBUILT_FRONTEND" != "1" ]; then npm ci; fi',
    'if [ "$PREBUILT_FRONTEND" = "1" ]; then test -f ./prebuilt-dist/index.html || { echo "prebuilt frontend is missing index.html" >&2; exit 1; }; rm -rf ./internal/webui/dist && mkdir -p ./internal/webui/dist && cp -a ./prebuilt-dist/. ./internal/webui/dist/; else npm run build; fi',
  ]],
  ['naabu', [
    'apk add --no-cache ca-certificates=20260909-r0 git=2.54.0-r0',
    'git init . && git remote add origin https://github.com/projectdiscovery/naabu.git && git fetch --depth 1 origin ${NAABU_COMMIT} && git fetch --depth 1 origin refs/tags/${NAABU_VERSION}:refs/tags/${NAABU_VERSION} && test "$(git rev-parse ${NAABU_VERSION}^{commit})" = "${NAABU_COMMIT}" && git checkout --detach ${NAABU_COMMIT}',
    'case "${TARGETARCH}" in amd64) loader=/lib/ld-musl-x86_64.so.1 ;; arm64) loader=/lib/ld-musl-aarch64.so.1 ;; *) echo "no musl loader known for ${TARGETARCH}" >&2; exit 1 ;; esac && CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w -I ${loader}" -o /out/naabu ./cmd/naabu && printf \'%s\\n\' \'package main\' \'import ("debug/elf"; "fmt"; "os")\' \'func main() { f, err := elf.Open(os.Args[1]); if err != nil { panic(err) }; for _, p := range f.Progs { if p.Type == elf.PT_INTERP { b := make([]byte, p.Filesz); if _, err := p.ReadAt(b, 0); err != nil { panic(err) }; fmt.Print(string(b[:len(b)-1])) } } }\' >/tmp/interp.go && interp="$(go run /tmp/interp.go /out/naabu)" && if [ -n "${interp}" ] && [ "${interp}" != "${loader}" ]; then echo "naabu names ${interp}, not ${loader}" >&2; exit 1; fi',
  ]],
  ['build', [
    'apk add --no-cache ca-certificates=20260909-r0 git=2.54.0-r0',
    'go mod download',
    'if [ "$PREBUILT_EDGEWATCH" = "1" ]; then test -f "/src/release-binaries/linux_${TARGETARCH}/edgewatch" && mkdir -p /out && install -m 0755 "/src/release-binaries/linux_${TARGETARCH}/edgewatch" /out/edgewatch; else CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/edgewatch ./cmd/edgewatch; fi',
  ]],
  ['final', [
    'apk add --no-cache ca-certificates=20260909-r0 gcompat=1.1.0-r4 nmap=7.99-r0 nmap-scripts=7.99-r0 tzdata=2026e-r0 zlib=1.3.2-r1 && mkdir -p /etc/edgewatch /var/lib/edgewatch /run/secrets && chmod 0750 /etc/edgewatch /var/lib/edgewatch /run/secrets && addgroup -S -g 65532 edgewatch-scanner && adduser -S -D -H -u 65532 -G edgewatch-scanner -h /nonexistent -s /sbin/nologin edgewatch-scanner && addgroup -S -g 65531 edgewatch-notify && adduser -S -D -H -u 65531 -G edgewatch-notify -h /nonexistent -s /sbin/nologin edgewatch-notify',
  ]],
])

const reviewedStageArguments = new Map([
  ['frontend', new Map([
    ['PREBUILT_FRONTEND', { default: '0', value: /^(?:0|1)$/ }],
  ])],
  ['naabu', new Map([
    ['NAABU_VERSION', { default: /^v[0-9]+\.[0-9]+\.[0-9]+$/, value: /^v[0-9]+\.[0-9]+\.[0-9]+$/ }],
    ['NAABU_COMMIT', { default: /^[0-9a-f]{40}$/, value: /^[0-9a-f]{40}$/ }],
    ['TARGETOS', { automatic: true, value: /^linux$/ }],
    ['TARGETARCH', { automatic: true, value: /^(?:amd64|arm64)$/ }],
  ])],
  ['build', new Map([
    ['VERSION', { default: 'dev', value: /^(?:dev|v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$/ }],
    ['PREBUILT_EDGEWATCH', { default: '0', value: /^(?:0|1)$/ }],
    ['TARGETOS', { automatic: true, value: /^linux$/ }],
    ['TARGETARCH', { automatic: true, value: /^(?:amd64|arm64)$/ }],
  ])],
])

function reviewedStageKey(stage, stages) {
  if (stage.alias) return stage.name
  return stage.index === stages.length - 1 ? 'final' : stage.name
}

function reviewedStageInputs(stage, stageKey) {
  const expected = reviewedStageArguments.get(stageKey) ?? new Map()
  if (stage.argDeclarations.length !== expected.size) return false
  const seen = new Set()
  for (const declaration of stage.argDeclarations) {
    const policy = expected.get(declaration.name)
    if (!policy || seen.has(declaration.name)) return false
    seen.add(declaration.name)

    if (policy.automatic) {
      if (declaration.rawDefault !== undefined) return false
    } else {
      if (declaration.rawDefault === undefined) return false
      const defaultValue = unquoteDockerfileValue(declaration.rawDefault)
      const defaultIsValid = policy.default instanceof RegExp
        ? policy.default.test(defaultValue)
        : defaultValue === policy.default
      if (!defaultIsValid) return false
    }

    const resolvedValue = stage.variables.get(declaration.name)
    if (resolvedValue === undefined) {
      if (!policy.automatic) return false
      continue
    }
    if (!policy.value.test(String(resolvedValue))) return false
  }
  return seen.size === expected.size
}

function releaseDockerfileRunViolations(source, buildArgs, targetName) {
  const { stages, aliases, globalArgDeclarations } = dockerfileStageGraph(source, buildArgs)
  const target = targetName === undefined
    ? stages.at(-1)
    : /^\d+$/.test(targetName)
      ? stages[Number(targetName)]
      : aliases.get(targetName.toLowerCase())
  assert.ok(target, 'Dockerfile target stage ' + (targetName ?? '(final)') + ' does not exist')

  const reachable = new Set()
  function visit(stage) {
    if (reachable.has(stage)) return
    reachable.add(stage)
    for (const dependency of stage.dependencies) visit(dependency)
  }
  visit(target)

  const violations = []
  const firstLine = source.replace(/\r\n/g, '\n').split('\n', 1)[0]?.trim()
  const parserDirectives = source.replace(/\r\n/g, '\n').split('\n')
    .map((line) => line.trim())
    .filter((line) => /^#\s*(?:syntax|escape|check)\s*=/i.test(line))
  if (firstLine !== reviewedDockerfileSyntax || parserDirectives.length !== 1 ||
      parserDirectives[0] !== reviewedDockerfileSyntax) {
    violations.push({ stage: '#dockerfile', line: 1, command: 'unreviewed Dockerfile parser directive' })
  }
  for (const declaration of globalArgDeclarations) {
    violations.push({ stage: 'global', line: declaration.line, command: 'ARG ' + declaration.name })
  }
  for (const stage of stages) {
    if (!reachable.has(stage)) continue
    const stageKey = reviewedStageKey(stage, stages)
    if (stage.dynamicBase || stage.dynamicDependency) {
      violations.push({ stage: stage.name, line: stage.runs[0]?.line ?? 0, command: 'dynamic stage or dependency reference' })
    }
    if (stage.environmentDeclarations.length > 0 || stage.shellDeclarations.length > 0) {
      for (const declaration of [...stage.environmentDeclarations, ...stage.shellDeclarations]) {
        violations.push({ stage: stage.name, line: declaration.line, command: declaration.args })
      }
    }
    if (!reviewedStageInputs(stage, stageKey)) {
      violations.push({ stage: stage.name, line: stage.argDeclarations[0]?.line ?? 0, command: 'unreviewed ARG declarations or values' })
    }

    const expectedRuns = reviewedReleaseRunForms.get(stageKey) ?? []
    if (stage.runs.length !== expectedRuns.length) {
      violations.push({ stage: stage.name, line: stage.runs[0]?.line ?? 0, command: 'unreviewed reachable RUN count' })
    }
    for (let index = 0; index < Math.max(stage.runs.length, expectedRuns.length); index++) {
      const run = stage.runs[index]
      const expected = expectedRuns[index]
      if (!run || run.command !== expected) {
        violations.push({ stage: stage.name, line: run?.line ?? 0, command: run?.command.trim() ?? 'missing reviewed RUN' })
        continue
      }

      // Only exact reviewed instruction forms reach this small branch evaluator.
      // Input values have already passed the stage-specific allowlists above.
      const active = releaseShellBranch(run.command, run.args)
      const expanded = expandedRunCommand(active, run.args)
      if (/\b(?:npm|npx)\b/.test(expanded)) {
        violations.push({ stage: stage.name, line: run.line, command: active.trim() })
      }
    }
  }
  return violations
}

function apkPackagePins(source) {
  const logicalLines = source.replace(/\\\r?\n[ \t]*/g, ' ')
  return [...logicalLines.matchAll(/^RUN[ \t]+apk add --no-cache[ \t]+([^\n]*)/gm)].flatMap((match) => {
    const packageArguments = match[1].split(/[ \t]+&&[ \t]+/, 1)[0]
    return packageArguments.trim().split(/[ \t]+/).filter(Boolean)
  })
}

function assertApkPinsManaged(source, config = renovate) {
  const pins = apkPackagePins(source)
  assert.ok(pins.length > 0, 'Dockerfile must have at least one apk add package')
  const repologyPins = renovateDependencies('Dockerfile', source, config)
    .filter((dependency) => dependency.datasource === 'repology')
    .map(({ depName, currentValue }) => `${depName}=${currentValue}`)
  for (const pin of pins) {
    assert.match(pin, /^[a-z0-9.+-]+=[0-9][0-9A-Za-z.+~-]*$/, `apk package ${pin} must be pinned to a version`)
    assert.ok(repologyPins.includes(pin), `Renovate must update the apk pin ${pin}`)
  }
  return pins
}

function assertAlpineRepologyMatchesBases(source, config = renovate) {
  const images = [...source.matchAll(/^FROM[ \t]+(?:--platform=\S+[ \t]+)?(\S+)/gm)].map((match) => match[1])
  assert.ok(images.length > 0, 'Dockerfile must have Alpine FROM images')
  const repologyManagers = config.customManagers.filter((manager) => manager.datasourceTemplate === 'repology')
  assert.equal(repologyManagers.length, 1, 'Renovate must have exactly one Alpine repology package manager')
  const repository = /^alpine_3_(\d+)\/\{\{\{depName\}\}\}$/.exec(repologyManagers[0].packageNameTemplate ?? '')
  assert.ok(repository, 'Renovate must track apk packages in an alpine_3_<minor> repository')
  const repologyMinor = repository[1]
  const minors = images.map((image) => {
    const withoutDigest = image.split('@', 1)[0]
    const colon = withoutDigest.lastIndexOf(':')
    const name = colon < 0 ? '' : withoutDigest.slice(0, colon).split('/').at(-1)
    const tag = colon < 0 ? '' : withoutDigest.slice(colon + 1)
    const builderMinor = /(?:^|-)alpine3\.(\d+)(?:\.\d+)?$/.exec(tag)?.[1]
    const runtimeMinor = name === 'alpine' ? /^3\.(\d+)(?:\.\d+)?$/.exec(tag)?.[1] : undefined
    const minor = builderMinor ?? runtimeMinor
    assert.equal(minor, repologyMinor, `Dockerfile FROM ${image} must match Renovate's alpine_3_${repologyMinor} package repository`)
    return minor
  })
  assert.equal(new Set(minors).size, 1, 'all Dockerfile FROM images must use the same Alpine minor')
}

function assertNaabuNoticeMatches(source, notice) {
  const version = dockerfileArgFrom(source, 'NAABU_VERSION')
  const commit = dockerfileArgFrom(source, 'NAABU_COMMIT')
  const noticeVersion = [...notice.matchAll(/^\* \*\*Naabu (v[0-9]+\.[0-9]+\.[0-9]+)\*\*/gm)]
  assert.equal(noticeVersion.length, 1, 'third-party license notice must name Naabu exactly once')
  assert.equal(noticeVersion[0][1], version, 'third-party notice release version must match Dockerfile NAABU_VERSION')
  const sourceTags = [...notice.matchAll(/github\.com\/projectdiscovery\/naabu\/tree\/(v[0-9]+\.[0-9]+\.[0-9]+)/g)]
  assert.equal(sourceTags.length, 1, 'third-party notice must link the Naabu source tag exactly once')
  assert.equal(sourceTags[0][1], version, 'third-party notice source tag must match Dockerfile NAABU_VERSION')
  const noticeCommits = [...notice.matchAll(/immutable commit\s+`([0-9a-f]{40})`/gi)]
  assert.equal(noticeCommits.length, 1, 'third-party notice must name the immutable commit exactly once')
  assert.equal(noticeCommits[0][1], commit, 'third-party notice commit must match Dockerfile NAABU_COMMIT')
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

test('prebuilt Docker builds fail when frontend assets are missing', () => {
  const container = ciJobBlock('container')
  assert.match(stepBlock(container, 'Reject missing prebuilt frontend assets'), /test-prebuilt-frontend-fails-closed\.sh/)
  assert.match(prebuiltFrontendTest, /docker buildx build --no-cache --progress=plain --target frontend/)
  assert.match(prebuiltFrontendTest, /PREBUILT_FRONTEND=1/)
  assert.match(prebuiltFrontendTest, /prebuilt frontend is missing index\.html/)
})

test('release image accepts only reviewed RUN forms on its reachable Dockerfile stage graph', async () => {
  const dockerfilePath = releaseImageDockerfilePath()
  assert.equal(releaseImageInput(workflow, 'file'), undefined,
    'the current image action intentionally uses its default Dockerfile path')
  const sourceDockerfile = await readRepositoryFile(dockerfilePath)
  const replaceImageInput = (workflowText, input, replacement) => {
    const pattern = new RegExp(`^ {10}${input}:.*$`, 'm')
    assert.ok(pattern.test(workflowText), 'release image action input marker is missing: ' + input)
    return workflowText.replace(pattern, '          ' + input + ': ' + replacement)
  }
  const replaceImageBuildStep = (workflowText, replacement) => {
    const step = releaseImageBuildStep(workflowText)
    const start = workflowText.indexOf(step)
    assert.notEqual(start, -1, 'release image build step must be present before mutation')
    return workflowText.slice(0, start) + replacement(step) + workflowText.slice(start + step.length)
  }
  const staticUnsafeFile = workflow.replace(
    '          context: .\n',
    '          context: .\n          file: scripts/fixtures/Dockerfile-1517-ae82e4f\n',
  )
  assert.notEqual(staticUnsafeFile, workflow, 'static alternate Dockerfile mutation marker must exist')
  assert.throws(() => releaseImageDockerfilePath(staticUnsafeFile), /Dockerfile at the root/,
    'a static alternate Dockerfile with historical npm RUNs must fail closed')
  const quotedFile = workflow.replace(
    '          context: .\n',
    '          context: .\n          "file": scripts/fixtures/Dockerfile-1517-ae82e4f\n',
  )
  assert.throws(() => releaseImageDockerfilePath(quotedFile), /unsupported release image action input syntax/,
    'a quoted alternate file key must not be ignored')
  const dynamicFile = workflow.replace(
    '          context: .\n',
    '          context: .\n          file: ${{ inputs.dockerfile }}\n',
  )
  assert.throws(() => releaseImageDockerfilePath(dynamicFile), /Dockerfile at the root/,
    'a dynamic Dockerfile path must fail closed')
  assert.throws(() => releaseImageDockerfilePath(replaceImageInput(workflow, 'context', '${{ inputs.context }}')),
    /static repository root/, 'a dynamic Docker build context must fail closed')
  assert.throws(() => releaseImageDockerfilePath(replaceImageInput(workflow, 'context', 'scripts/fixtures')),
    /static repository root/, 'an alternate Docker build context must fail closed')
  assert.throws(() => releaseImageDockerfilePath(workflow.replace('          context: .', '          "context": .')),
    /unsupported release image action input syntax/, 'a quoted context key must not be ignored')
  assert.throws(() => releaseImageBuildArgs(workflow.replace('          build-args: |', '          "build-args": |')),
    /unsupported release image action input syntax/, 'a quoted build-args key must not be ignored')
  assert.throws(() => releaseImageActionInputs(replaceImageBuildStep(workflow,
    (step) => step.replace('        with:\n', '        "with":\n'))),
    /unsupported release image build step syntax/, 'a quoted step-level with key must not be ignored')
  assert.throws(() => releaseImageActionInputs(replaceImageBuildStep(workflow,
    (step) => step.replace('        with:\n', '        with:\n        with:\n'))),
  /duplicate with fields/, 'a duplicate step-level with key must fail closed')
  assert.throws(() => releaseImageActionInputs(workflow.replace(
    '        uses: docker/build-push-action@', '        "uses": docker/build-push-action@',
  )), /Build and push image must be the Docker image build action/,
  'a quoted step-level uses key must not be treated as a reviewed build action')
  assert.throws(() => releaseImageActionInputs(workflow.replace(
    '      - name: Build and push image', '      - "name": Build and push image',
  )), /exactly one Build and push image step/,
  'a quoted build step name must not be skipped while selecting the action inputs')
  assert.throws(() => releaseImageActionInputs(workflow.replace(
    '      - name: Build and push image', '      - name: Build image',
  )), /exactly one Build and push image step/,
  'renaming the build step must require updating the reviewed selector')
  assert.throws(() => releaseImageActionInputs(workflow.replace(
    '      - name: Build and push image\n',
    '      - { name: Hidden build, uses: docker/build-push-action@c3c9e263c25d99ce0380d002d59b67737d91b0dc, with: {context: ., file: scripts/fixtures/Dockerfile-1517-ae82e4f} }\n      - name: Build and push image\n',
  )), /exactly one Docker image build action/,
  'a flow-style second image build must not be skipped by the reviewed step selector')
  for (const [name, unsupported] of [
    ['flow-style with block', replaceImageBuildStep(workflow, (step) => step.replace('        with:\n', '        with: {context: ., push: true}\n'))],
    ['YAML anchor', replaceImageInput(workflow, 'context', '&root .')],
    ['YAML merge key', workflow.replace('          context: .\n', '          <<: *shared\n          context: .\n')],
    ['multiline input key', workflow.replace('          context: .\n', '          con\n          text: .\n')],
    ['unexpected indentation', workflow.replace('          context: .\n', '           context: .\n')],
    ['duplicate context key', workflow.replace('          context: .\n', '          context: .\n          context: .\n')],
  ]) {
    assert.notEqual(unsupported, workflow, name + ' mutation marker must exist')
    assert.throws(() => releaseImageActionInputs(unsupported), /with block|with field|unsupported|unreviewed|duplicate|anchors|aliases/,
      name + ' must fail closed rather than be skipped by the input parser')
  }
  assert.throws(() => releaseImageDockerfilePath(workflow.replace(
    '          context: .\n',
    '          context: .\n          dockerfile-inline: |\n            FROM node:24\n',
  )), /inline Dockerfile input/, 'unexpected inline Dockerfile input must fail closed')
  const explicitRootDockerfile = workflow.replace(
    '          context: .\n',
    '          context: .\n          file: Dockerfile\n',
  )
  assert.equal(releaseImageDockerfilePath(explicitRootDockerfile), 'Dockerfile',
    'an explicit root Dockerfile must resolve to the same reviewed source')
  const buildArgs = releaseImageBuildArgs()
  const targetStage = releaseImageTargetStage()
  assert.equal(targetStage, undefined, 'the image build must use Dockerfile default target when the build action omits target')
  const runViolations = (source, args = buildArgs, target = targetStage) => releaseDockerfileRunViolations(source, args, target)
  assert.deepEqual(runViolations(sourceDockerfile), [], 'the release image must not execute npm or npx')
  assert.match(buildArgs.VERSION, /^v?0\.0\.0-ci$/, 'the current snapshot release version must remain an allowed value')
  for (const TARGETARCH of ['amd64', 'arm64']) {
    assert.deepEqual(
      runViolations(sourceDockerfile, { ...buildArgs, TARGETOS: 'linux', TARGETARCH }),
      [],
      'current automatic platform values must remain allowed for linux/' + TARGETARCH,
    )
  }
  assert.ok(runViolations(sourceDockerfile, { ...buildArgs, TARGETOS: 'windows', TARGETARCH: 'amd64' }).length > 0,
    'unsupported automatic operating systems must fail closed')
  assert.ok(runViolations(sourceDockerfile.replace(reviewedDockerfileSyntax + '\n', '')).length > 0,
    'removing the reviewed Dockerfile syntax directive must fail closed')
  assert.ok(runViolations(sourceDockerfile.replace(reviewedDockerfileSyntax, '# escape=`')).length > 0,
    'changing the Dockerfile escape directive must fail closed')
  const defaultArgs = { ...buildArgs }
  delete defaultArgs.PREBUILT_FRONTEND
  assert.ok(
    runViolations(sourceDockerfile, defaultArgs).some((run) => run.stage === 'frontend'),
    'the frontend stage ARG default must select the local npm path when no release build arg is supplied',
  )

  const oldDockerfile = await readRepositoryFile('scripts/fixtures/Dockerfile-1517-ae82e4f')
  assert.ok(runViolations(oldDockerfile).length > 0, 'the historical Dockerfile must be rejected')

  function replaceOnce(source, marker, replacement, name) {
    assert.ok(source.includes(marker), name + ' mutation marker is missing')
    return source.replace(marker, replacement)
  }

  const npmInstall = 'RUN if [ "$PREBUILT_FRONTEND" != "1" ]; then npm ci; fi'
  const m1 = replaceOnce(
    sourceDockerfile,
    'COPY scripts/check-node-runtime.mjs ./scripts/check-node-runtime.mjs',
    'COPY scripts/check-node-runtime.mjs ./scripts/check-node-runtime.mjs\nRUN npx --yes license-checker-rseidelsohn --summary',
    'M1',
  )
  assert.ok(runViolations(m1).some((run) => run.stage === 'frontend'), 'M1 must be rejected in the reached frontend stage')

  const buildStage = 'FROM --platform=$BUILDPLATFORM golang:1.27.2-alpine3.24@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build'
  const auditStage = [
    'FROM --platform=$BUILDPLATFORM node:24.21.0-alpine3.24 AS frontend-audit',
    'WORKDIR /src',
    'COPY package.json package-lock.json ./',
    'RUN npm ci --no-audit && npm ls --all > /deps.txt',
    '',
  ].join('\n')
  let m2 = replaceOnce(sourceDockerfile, buildStage, auditStage + buildStage, 'M2')
  const frontendArtifactCopy = 'COPY --from=frontend /src/internal/webui/dist ./internal/webui/dist'
  m2 = replaceOnce(m2, frontendArtifactCopy, frontendArtifactCopy + '\nCOPY --from=frontend-audit /deps.txt ./release-dependencies.txt', 'M2 copy')
  const m2Runs = runViolations(m2)
  assert.ok(m2Runs.some((run) => run.stage === 'frontend-audit'), 'M2 must be rejected through its COPY --from dependency')
  let m2Mount = replaceOnce(sourceDockerfile, buildStage, auditStage + buildStage, 'M2 mount')
  const mountRun = 'RUN --mount=type=bind,from=frontend-audit,source=/deps.txt,target=/deps.txt,ro true'
  m2Mount = replaceOnce(m2Mount, frontendArtifactCopy, mountRun + '\n' + frontendArtifactCopy, 'M2 mount dependency')
  assert.ok(
    runViolations(m2Mount).some((run) => run.stage === 'frontend-audit'),
    'a RUN --mount=from dependency must also reach its source stage',
  )
  const m2IndexCopy = replaceOnce(
    m2,
    'COPY --from=frontend-audit /deps.txt ./release-dependencies.txt',
    'COPY --from=2 /deps.txt ./release-dependencies.txt',
    'M2 numeric stage reference',
  )
  assert.ok(
    runViolations(m2IndexCopy).some((run) => run.stage === 'frontend-audit'),
    'numeric COPY --from references must reach their source stage',
  )

  const m3 = replaceOnce(
    sourceDockerfile,
    '      test -f ./prebuilt-dist/index.html',
    '      npm ci --ignore-scripts && npm run lint; test -f ./prebuilt-dist/index.html',
    'M3',
  )
  assert.ok(runViolations(m3).length > 0, 'M3 must be rejected inside the active prebuilt branch')

  const unresolvedGuard = replaceOnce(
    sourceDockerfile,
    'ARG PREBUILT_FRONTEND=0',
    'ARG PREBUILT_FRONTEND=0\nRUN if [ "$UNKNOWN_RELEASE_FLAG" = "1" ]; then npm ci; fi',
    'unresolved argument guard',
  )
  assert.ok(
    runViolations(unresolvedGuard).length > 0,
    'a new conditional RUN must fail because its complete form is not reviewed',
  )
  const environmentOverride = replaceOnce(
    sourceDockerfile,
    'ARG PREBUILT_FRONTEND=0',
    'ARG PREBUILT_FRONTEND=0\nENV PREBUILT_FRONTEND=0',
    'ENV override',
  )
  assert.ok(
    runViolations(environmentOverride).some((run) => run.stage === 'frontend'),
    'an ENV declaration in a reached stage must fail closed',
  )

  for (const [name, instruction] of [
    ['PATH override', 'ENV PATH=/tmp'],
    ['BASH_ENV override', 'ENV BASH_ENV=/tmp/setup.sh'],
    ['custom shell', 'SHELL ["/bin/bash", "-c"]'],
    ['command alias ARG', 'ARG PM=npm'],
  ]) {
    const changedContext = replaceOnce(sourceDockerfile, 'WORKDIR /src', 'WORKDIR /src\n' + instruction, name)
    assert.ok(runViolations(changedContext).some((run) => run.stage === 'frontend'),
      name + ' must require explicit policy review in a reached stage')
  }

  const m4 = replaceOnce(
    sourceDockerfile,
    npmInstall + '\n',
    npmInstall + '\nRUN npm ci --no-audit\n',
    'M4',
  )
  assert.ok(runViolations(m4).length > 0, 'M4 must be rejected as an additional frontend RUN')
  const duplicatedRun = replaceOnce(sourceDockerfile, npmInstall + '\n', npmInstall + '\n' + npmInstall + '\n', 'duplicate reviewed RUN')
  assert.ok(runViolations(duplicatedRun).length > 0,
    'an extra copy of an otherwise reviewed RUN must fail closed')

  const finalStage = 'FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6'
  const unreachableNpmStage = [
    'FROM --platform=$BUILDPLATFORM node:24.21.0-alpine3.24 AS unused-audit',
    'RUN npm ci --no-audit',
    '',
  ].join('\n')
  const unusedStage = replaceOnce(sourceDockerfile, finalStage, unreachableNpmStage + finalStage, 'unreachable npm stage')
  assert.deepEqual(runViolations(unusedStage), [], 'unreachable stages must not affect the release target')

  const fromDependency = [
    'FROM node:24.21.0-alpine3.24 AS npm-source',
    'RUN npm ci --no-audit',
    'FROM npm-source AS inherited',
    'RUN true',
    'FROM alpine:3.24.2 AS final',
    'COPY --from=inherited /src /src',
  ].join('\n')
  assert.ok(
    runViolations(fromDependency).some((run) => run.stage === 'npm-source'),
    'FROM references to earlier stages must reach their source stage',
  )

  const argAlias = replaceOnce(
    sourceDockerfile,
    'ARG PREBUILT_FRONTEND=0',
    'ARG PREBUILT_FRONTEND=0\nARG PM=npm\nRUN $PM ci --no-audit',
    'ARG command alias',
  )
  assert.ok(runViolations(argAlias).some((run) => run.stage === 'frontend'), 'an ARG command alias for npm must be rejected')
  const envAlias = replaceOnce(
    sourceDockerfile,
    'ARG PREBUILT_FRONTEND=0',
    'ARG PREBUILT_FRONTEND=0\nENV PM=npx\nRUN "$PM" --yes license-checker-rseidelsohn',
    'ENV command alias',
  )
  assert.ok(runViolations(envAlias).some((run) => run.stage === 'frontend'), 'an ENV command alias for npx must be rejected')
  const opaqueSetupCopy = 'COPY scripts/fixtures/release-opaque-npm-setup.sh /var/tmp/setup.sh'
  const opaqueRunMutation = (command, name) => replaceOnce(
    sourceDockerfile,
    'WORKDIR /src',
    'WORKDIR /src\n' + opaqueSetupCopy + '\nRUN ' + command,
    name,
  )
  const wrapperCases = [
    ['reviewer find wrapper', 'find /var/tmp -maxdepth 1 -exec sh /var/tmp/setup.sh {} +'],
    ["xargs script wrapper", "printf '%s\\n' /var/tmp/setup.sh | xargs sh"],
    ['Python system wrapper', "python3 -c 'import os; os.system(\"npm ci\")'"],
    ['awk system wrapper', "awk 'BEGIN { system(\"npm ci\") }'"],
    ['direct script execution', '/var/tmp/setup.sh'],
  ]
  for (const [name, command] of wrapperCases) {
    assert.ok(runViolations(opaqueRunMutation(command, name)).length > 0,
      name + ' must fail because no complete RUN form was reviewed')
  }
  assert.ok(runViolations(opaqueRunMutation('echo harmless', 'unknown harmless RUN')).length > 0,
    'an unknown RUN form must fail even when its text contains no npm or npx')

  const unsafeNaabuVersion = replaceOnce(
    sourceDockerfile,
    'ARG NAABU_VERSION=v2.6.1',
    'ARG NAABU_VERSION=$(npm ci)',
    'Naabu version validation',
  )
  assert.ok(runViolations(unsafeNaabuVersion).some((run) => run.stage === 'naabu'),
    'an unchecked version value must not enter an approved command form')
  assert.ok(runViolations(sourceDockerfile, { ...buildArgs, VERSION: '$(npm ci)' }).some((run) => run.stage === 'build'),
    'an unchecked release version build argument must fail closed')
  assert.ok(runViolations(sourceDockerfile, { ...buildArgs, TARGETARCH: '$(npm ci)' }).some((run) => run.stage === 'naabu'),
    'an unchecked automatic architecture value must fail closed')

  const dynamicBase = replaceOnce(
    sourceDockerfile,
    'FROM --platform=$BUILDPLATFORM node:24.21.0-alpine3.24@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1 AS frontend',
    'FROM --platform=$BUILDPLATFORM $NODE_IMAGE AS frontend',
    'dynamic base image',
  )
  assert.ok(runViolations(dynamicBase).some((run) => run.stage === 'frontend'),
    'a dynamic base image must fail closed in a reachable stage')

  const onbuildNpm = [
    'FROM node:24.21.0-alpine3.24 AS npm-source',
    'ONBUILD RUN npm ci --no-audit',
    'FROM npm-source AS inherited',
    'RUN true',
    'FROM alpine:3.24.2 AS final',
    'COPY --from=inherited /out /out',
  ].join('\n')
  assert.ok(runViolations(onbuildNpm).some((run) => run.stage === 'inherited'),
    'an inherited ONBUILD RUN trigger must fail closed in the derived reachable stage')

  const onbuildMountDependency = [
    'FROM node:24.21.0-alpine3.24 AS npm-audit',
    'RUN npm ci --no-audit',
    'FROM alpine:3.24.2 AS trigger-source',
    'ONBUILD RUN --mount=type=bind,from=npm-audit,source=/deps,target=/deps,ro true',
    'FROM trigger-source AS inherited',
    'RUN true',
    'FROM alpine:3.24.2 AS final',
    'COPY --from=inherited /out /out',
  ].join('\n')
  assert.ok(runViolations(onbuildMountDependency).some((run) => run.stage === 'inherited'),
    'an inherited ONBUILD RUN mount trigger must fail closed without omitting its hidden source edge')

  const onbuildCopyDependency = [
    'FROM node:24.21.0-alpine3.24 AS npm-audit',
    'RUN npm ci --no-audit',
    'FROM alpine:3.24.2 AS trigger-source',
    'ONBUILD COPY --from=npm-audit /deps /deps',
    'FROM trigger-source AS inherited',
    'RUN true',
    'FROM alpine:3.24.2 AS final',
    'COPY --from=inherited /out /out',
  ].join('\n')
  assert.ok(runViolations(onbuildCopyDependency).some((run) => run.stage === 'inherited'),
    'an inherited ONBUILD COPY trigger must fail closed without omitting its hidden source edge')

  const dormantOnbuild = replaceOnce(
    sourceDockerfile,
    'ENTRYPOINT ["edgewatch"]',
    'ONBUILD RUN npm ci --no-audit\nENTRYPOINT ["edgewatch"]',
    'dormant ONBUILD trigger',
  )
  assert.deepEqual(runViolations(dormantOnbuild), [],
    'an ONBUILD trigger that no later FROM consumes is dormant and does not execute in this build')

  const unrelatedTarget = workflow.replace(
    '          images: ${{ env.REGISTRY_IMAGE }}',
    '          images: ${{ env.REGISTRY_IMAGE }}\n          target: release-audit-target',
  )
  assert.notEqual(unrelatedTarget, workflow, 'unrelated target mutation marker must exist')
  assert.equal(releaseImageTargetStage(unrelatedTarget), undefined,
    'target inputs on other actions must not select a Dockerfile stage')
  const unrelatedDockerfile = workflow.replace(
    '          images: ${{ env.REGISTRY_IMAGE }}',
    '          images: ${{ env.REGISTRY_IMAGE }}\n          file: scripts/fixtures/Dockerfile-1517-ae82e4f',
  )
  assert.notEqual(unrelatedDockerfile, workflow, 'unrelated Dockerfile input mutation marker must exist')
  assert.equal(releaseImageDockerfilePath(unrelatedDockerfile), 'Dockerfile',
    'Dockerfile inputs on other workflow actions must not select the analyzed source')

  const targetNpmStage = [
    'FROM --platform=$BUILDPLATFORM node:24.21.0-alpine3.24 AS release-audit-target',
    'RUN npm ci --no-audit',
    '',
  ].join('\n')
  const targetedDockerfile = replaceOnce(sourceDockerfile, finalStage, targetNpmStage + finalStage, 'release target mutation stage')
  const targetedWorkflow = workflow.replace(
    '          context: .\n          push: true',
    '          context: .\n          target: release-audit-target\n          push: true',
  )
  assert.notEqual(targetedWorkflow, workflow, 'image build target mutation marker must exist')
  assert.equal(releaseImageTargetStage(targetedWorkflow), 'release-audit-target')
  const quotedTargetWorkflow = targetedWorkflow.replace(
    '          target: release-audit-target',
    '          "target": release-audit-target',
  )
  assert.throws(() => releaseImageTargetStage(quotedTargetWorkflow), /unsupported release image action input syntax/,
    'a quoted target key must not be ignored while selecting the analyzed Dockerfile stage')
  assert.ok(runViolations(targetedDockerfile, buildArgs, releaseImageTargetStage(targetedWorkflow))
    .some((run) => run.stage === 'release-audit-target'),
  'the graph root must follow target from the exact image build action')
  const dynamicTargetWorkflow = targetedWorkflow.replace(
    'target: release-audit-target',
    'target: ${{ inputs.image_target }}',
  )
  assert.throws(() => releaseImageTargetStage(dynamicTargetWorkflow), /static Dockerfile stage name or index/,
    'an unresolved workflow target must fail closed')
})

test('release manifests bind archive members to extracted and image executables', () => {
  const verify = jobBlock('verify')
  const prepare = stepBlock(verify, 'Prepare binaries for the container build')
  const manifest = stepBlock(verify, 'Generate release manifest')
  const candidate = stepBlock(verify, 'Verify candidate artifacts')
  assert.match(prepare, /prepare-release-binaries\.sh/)
  assert.ok(verify.indexOf(prepare) < verify.indexOf(manifest))
  assert.ok(verify.indexOf(manifest) < verify.indexOf(candidate))
  assert.match(candidate, /verify-release-artifacts\.sh .*release-binaries$/)
  assert.match(binaryImageScript, /docker cp .*\/usr\/local\/bin\/edgewatch/)
  assert.match(binaryImageScript, /image EdgeWatch binary does not match the linux\/\$arch release archive digest/)

  const smoke = jobBlock('smoke')
  const archiveVerify = stepBlock(smoke, 'Verify release archive versions')
  assert.match(archiveVerify, /verify-release-artifacts\.sh .* -\n/)
  assert.match(archiveVerify, /VERIFIED_RELEASE_MANIFEST=\$archive_dir\/release-manifest\.json/)
  const amd64Image = stepBlock(smoke, 'Verify AMD64 image binary matches the release archive')
  assert.match(amd64Image, /verify-release-image-binary\.sh "\$IMAGE" "\$VERIFIED_RELEASE_MANIFEST" amd64 linux\/amd64/)
  assert.doesNotMatch(amd64Image, /gh release download/)
  assert.equal((smoke.match(/gh release download[^\n]*release-manifest\.json/g) ?? []).length, 1,
    'AMD64 image verification must reuse the manifest whose archive bindings were verified')

  const arm = jobBlock('smoke-arm64')
  const armCandidate = stepBlock(arm, 'Verify downloaded candidate')
  assert.match(armCandidate, /verify-release-artifacts\.sh .*release-binaries$/)
  const armImage = stepBlock(arm, 'Verify ARM64 image binary matches the release archive')
  assert.match(armImage, /verify-release-image-binary\.sh .* arm64 linux\/arm64/)
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

test('scanner sandbox verification selects the live Nmap scan and pins it while inspecting proc', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'edgewatch-scanner-pid-selector-'))
  t.after(() => rm(directory, { recursive: true, force: true }))
  const proc = join(directory, 'proc')
  const selector = join(directory, 'scanner-pid-selector.sh')
  await mkdir(proc)
  await writeFile(selector, scannerPidSelector, { mode: 0o755 })

  async function addProcess(pid, state, argv) {
    const process = join(proc, String(pid))
    await mkdir(process)
    await writeFile(join(process, 'status'), `Name:\tnmap\nState:\t${state}\n`)
    await writeFile(join(process, 'cmdline'), Buffer.from(`${argv.join('\0')}\0`))
  }
  // The first `nmap` process is only the version probe. The scan is held and
  // selected by its scan-only progress option; zombies are never selected.
  await addProcess(101, 'S (sleeping)', ['nmap', '--version'])
  await addProcess(202, 'T (stopped)', ['nmap', '-n', '--stats-every', '1s'])
  await addProcess(303, 'Z (zombie)', ['nmap', '--stats-every', '1s'])

  const byName = execFileSync(selector, [proc, 'nmap'], { encoding: 'utf8' }).trim()
  const activeScan = execFileSync(selector, [proc, 'nmap', '--stats-every'], { encoding: 'utf8' }).trim()
  assert.equal(byName, '101', 'a name-only lookup reproduces the version-probe ambiguity')
  assert.equal(activeScan, '202', 'the selector returns the live scan rather than the version probe or zombie')
  const absent = spawnSync(selector, [proc, 'nmap', '--missing-scan-argument'], { encoding: 'utf8' })
  assert.equal(absent.status, 1, 'the selector fails when no live Nmap scan matches the required argument')

  assert.match(scannerSandboxVerifier, /scanner_pid_selector_source=\$script_directory\/scanner-pid-selector\.sh/)
  const lifecycleStart = scannerSandboxVerifier.indexOf('# Keep one real Nmap invocation')
  assert.notEqual(lifecycleStart, -1, 'the shared-volume lifecycle acceptance has an explicit section')
  const nmapHoldCalls = (value) => value.match(/^hold_scanner_process nmap --stats-every$/gm) ?? []
  assert.equal(nmapHoldCalls(scannerSandboxVerifier.slice(0, lifecycleStart)).length, 4,
    'the scanner-mode Nmap /proc checks pin scans selected by their scan-only argument')
  const lifecycleVerifier = scannerSandboxVerifier.slice(lifecycleStart)
  assert.equal(nmapHoldCalls(lifecycleVerifier).length, 2,
    'lifecycle containers A and C each hold one live Nmap scan')
  assert.match(lifecycleVerifier, /read -r lifecycle_nmap_host_pid lifecycle_nmap_host_starttime < <\(python3/,
    'the live container PID is bound to a host PID and process starttime')
  assert.match(lifecycleVerifier, /lifecycle_lock_path=\/var\/lib\/edgewatch\/scanner-identities\/liveness\.lock/)
  assert.match(lifecycleVerifier, /assert-liveness-fd "\$lifecycle_lock_path" "\$lifecycle_nmap_pid" "\$lifecycle_lock_identity"/,
    'the actual live Nmap process is checked for the exact inherited liveness lock')
  assert.match(lifecycleVerifier, /after inherited liveness-FD inspection/,
    'the scanner starttime is rechecked after proc descriptor inspection')
  assert.match(lifecycleVerifier, /self-absent:\$lifecycle_lock_device:\$lifecycle_lock_inode/,
    'the descriptor inspector has an explicit missing-FD negative control')
  assert.match(lifecycleVerifier, /self-required:\$lifecycle_lock_device:\$lifecycle_lock_inode/,
    'the negative control must reject a missing descriptor as such')
  assert.match(lifecycleVerifier, /lifecycle_liveness_negative_status.*= 15/s,
    'the missing-FD control checks its dedicated failure status')
  const probeDriver = scannerSandboxVerifier.match(/cat >"\$workdir\/proc-fd-probe\.go" <<'GO'\n([\s\S]*?)\nGO\nCGO_ENABLED=0 go build/)?.[1]
  assert.ok(probeDriver, 'the verifier embeds the capability-scoped proc descriptor probe')
  assert.match(probeDriver, /func assertInheritedLivenessFD/)
  assert.match(probeDriver, /target != lockPath/)
  assert.match(probeDriver, /uint64\(stat\.Dev\) != dev \|\| stat\.Ino != ino/,
    'the descriptor check binds the lock by device and inode, not pathname alone')
  assert.match(probeDriver, /flags&uint64\(unix\.O_ACCMODE\) != uint64\(unix\.O_RDONLY\)/)
  assert.match(probeDriver, /flags&uint64\(unix\.O_CLOEXEC\) != 0/)
  assert.doesNotMatch(scannerSandboxVerifier, /scanner_pid\s+nmap(?:\s*\)|\s*\|)/,
    'the verifier must not select a Nmap PID by comm alone')
  assert.ok((scannerSandboxVerifier.match(/daemon_scan_limit=2/g) ?? []).length >= 2,
    'Landlock and identity-only runs allow the required concurrent Nmap/Naabu pair')
  assert.ok((scannerSandboxVerifier.match(/expect_private_nmap_xml\s+"\$nmap_pid"/g) ?? []).length >= 2,
    'both Landlock and identity-only modes verify the owner XML descriptor')
  assert.ok((scannerSandboxVerifier.match(/Nmap XML descriptor write-open/g) ?? []).length >= 2,
    'both modes check that a peer cannot reopen the XML descriptor for writing')
  assert.match(scannerSandboxVerifier, /case "open-write":/)
  assert.match(scannerSandboxVerifier, /resume_held_scanner\n?\s*cancelled=/)
  assert.doesNotMatch(scannerSandboxVerifier, /^\s*[A-Za-z_]\w*=\$\(\s*hold_scanner_process nmap --stats-every/m,
    'the mutable PID state must be set in the verifier shell, not a command-substitution subshell')

  const marker = join(directory, 'resumed-on-exit')
  const lifecycle = spawnSync('bash', ['-c', `
    set -euo pipefail
    source "$1"
    container=fixture
    mock_state=R
    scanner_pid() { printf '4242\\n'; }
    scanner_process_starttime() { printf '987654\\n'; }
    expect_scanner_starttime() { [ "$1" = 4242 ] && [ "$2" = 987654 ]; }
    scanner_process_state() { printf '%s\\n' "$mock_state"; }
    docker() {
      [ "$1" = exec ] && [ "$2" = fixture ] && [ "$3" = kill ] || return 90
      case "$4" in
        -STOP) mock_state=T ;;
        -CONT) mock_state=R ;;
        *) return 91 ;;
      esac
    }
    fail() { printf '%s\\n' "$*" >&2; exit 92; }
    cleanup() {
      local marker_path=$1
      resume_held_scanner
      [ "$mock_state" = R ] || exit 93
      [ -z "$held_scanner_pid" ] && [ -z "$held_scanner_starttime" ] || exit 94
      printf resumed > "$marker_path"
    }
    trap 'cleanup "$2"' EXIT
    hold_scanner_process nmap --stats-every
    nmap_pid=$held_scanner_pid
    [ "$nmap_pid" = 4242 ] && [ "$held_scanner_starttime" = 987654 ]
    false
  `, 'scanner-hold-regression', join(scriptDirectory, 'scanner-process-hold.sh'), marker], { encoding: 'utf8' })
  assert.equal(lifecycle.status, 1, `the harness must preserve the forced failure: ${lifecycle.stderr}`)
  assert.equal((await readFile(marker, 'utf8')), 'resumed', 'EXIT cleanup resumes the pinned process and clears state')
})

test('CI requires and merges the privileged sandbox coverage profile', () => {
  const container = ciJobBlock('container')
  const collect = container.indexOf('Collect privileged sandbox coverage')
  const upload = container.indexOf('Upload privileged sandbox coverage')
  assert.ok(collect >= 0 && upload > collect, 'the container job must collect before uploading the profile')
  assert.match(container, /collect-sandbox-privileged-coverage\.sh edgewatch:prebuilt-amd64/)
  assert.match(container, /name: go-coverage-container-sandbox/)
  assert.match(container, /if-no-files-found: error/)

  const aggregate = ciJobBlock('test')
  assert.ok(needsOf(aggregate).includes('container'), 'the required coverage job must wait for the container profile')
  assert.match(aggregate, /CONTAINER: \$\{\{ needs\.container\.result \}\}/)
  assert.match(aggregate, /\[ "\$CONTAINER" != success \]/)
  assert.match(aggregate, /pattern: go-coverage-\*/)
  assert.match(aggregate, /store-1 store-2 store-3 other container-sandbox/)
  assert.match(aggregate, /check-go-coverage\.sh coverage\.out go-coverage-summary\.txt/)
  assert.match(aggregate, /check-diff-coverage\.mjs --language go --coverage coverage\.out/)
})

test('pull request titles are checked on edit and gate the required CI check', () => {
  assert.match(ciWorkflow, /^ {2}pull_request:\n {4}types: \[opened, synchronize, reopened, ready_for_review, edited\]$/m,
    'title edits must rerun the workflow that produces the required CI check')

  const titleJob = ciJobBlock('pr-title')
  assert.deepEqual(permissionsOf(titleJob, 4), { contents: 'read' },
    'the title job must have read-only repository access')
  assert.match(titleJob, /^ {4}if: github\.event_name == 'pull_request'$/m)
  assert.match(titleJob, /node --test scripts\/check-pr-title\.test\.mjs/)
  const validateTitle = stepBlock(titleJob, 'Validate pull request title')
  assert.match(validateTitle, /^ {10}PR_TITLE: \$\{\{ github\.event\.pull_request\.title \}\}$/m,
    'the untrusted title must be passed as environment data')
  assert.match(validateTitle, /^ {8}run: node scripts\/check-pr-title\.mjs$/m)
  assert.doesNotMatch(titleJob, /npm (?:ci|install|run)/,
    'the title job must not install or run project packages')
  const titleActions = [...titleJob.matchAll(/^ {8}uses: ([^\s]+)/gm)].map(([, action]) => action)
  assert.deepEqual(titleActions, [
    'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',
    'actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1',
  ], 'the title job must use only pinned GitHub-maintained actions')
  assert.match(titleJob, /^ {10}persist-credentials: false$/m)
  assert.match(titleJob, /^ {10}package-manager-cache: false$/m)

  const aggregate = ciJobBlock('test')
  assert.ok(needsOf(aggregate).includes('pr-title'), 'the branch-protection aggregate must wait for the title check')
  assert.match(aggregate, /PR_TITLE_CHECK: \$\{\{ needs\.pr-title\.result \}\}/)
  assert.match(aggregate, /\[ \"\$GITHUB_EVENT_NAME\" = pull_request \] && \[ \"\$PR_TITLE_CHECK\" != success \]/)

  const gate = stepBlock(aggregate, 'Require Go checks and test shards')
  const shell = /^ {8}run: \|\n((?: {10}.*(?:\n|$))+)/m.exec(gate)
  assert.ok(shell, 'the required-check aggregate must have an executable gate step')
  const gateScript = shell[1].split('\n').map((line) => line.slice(10)).join('\n')
  const runGate = (eventName, titleResult) => spawnSync('bash', ['-c', gateScript], {
    encoding: 'utf8',
    env: {
      ...process.env,
      CHECKS: 'success',
      TESTS: 'success',
      CONTAINER: 'success',
      GITHUB_EVENT_NAME: eventName,
      PR_TITLE_CHECK: titleResult,
    },
  })
  assert.equal(runGate('pull_request', 'success').status, 0)
  assert.equal(runGate('pull_request', 'failure').status, 1,
    'the existing required check must fail when the title check fails')
  assert.equal(runGate('pull_request', 'skipped').status, 1,
    'the title check must not be skipped for a pull request')
  assert.equal(runGate('push', 'skipped').status, 0,
    'a skipped pull request-only title job must not fail a push check')
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
  const apkPins = assertApkPinsManaged(dockerfile)
  assert.ok(apkPins.includes('zlib=1.3.2-r1') || apkPins.some((pin) => pin.startsWith('zlib=')), 'the image pins zlib')
  assertAlpineRepologyMatchesBases(dockerfile)
  const govulncheck = /^GOVULNCHECK_VERSION \?= (\S+)$/m.exec(makefile)?.[1]
  assert.deepEqual(renovateDependencies('Makefile', makefile), [{ datasource: 'go', depName: 'golang.org/x/vuln', currentValue: govulncheck, currentDigest: undefined }])

  const npmAge = renovate.packageRules.find((rule) => rule.matchDatasources?.includes('npm') && rule.minimumReleaseAge)
  assert.equal(npmAge?.minimumReleaseAge, '3 days')
})

test('Renovate tracks golangci-lint from its GitHub Releases repository', () => {
  const version = golangciLintVersion.trim()
  assert.match(version, /^v[0-9]+\.[0-9]+\.[0-9]+$/)
  assert.deepEqual(renovateDependencies('.golangci-lint-version', golangciLintVersion), [
    { datasource: 'github-releases', depName: 'golangci-lint', currentValue: version, currentDigest: undefined },
  ])
  const manager = renovate.customManagers.find((entry) => entry.datasourceTemplate === 'github-releases' && entry.packageNameTemplate === 'golangci/golangci-lint')
  assert.ok(manager, 'Renovate must query golangci/golangci-lint GitHub releases')
  assert.equal(manager.depNameTemplate, 'golangci-lint', 'the dependency dashboard should show golangci-lint')
  assert.ok(manager.managerFilePatterns.some((pattern) => new RegExp(/^\/(.*)\/([a-z]*)$/.exec(pattern)?.[1] ?? 'a^').test('.golangci-lint-version')))
})

test('the Alpine package repository stays aligned with every Dockerfile base image', () => {
  assertAlpineRepologyMatchesBases(dockerfile)
  const mismatchedBase = dockerfile.replace('node:24.21.0-alpine3.24@', 'node:24.21.0-alpine3.25@')
  assert.notEqual(mismatchedBase, dockerfile, 'the mismatch fixture must change one actual Dockerfile base')
  assert.throws(() => assertAlpineRepologyMatchesBases(mismatchedBase), /must match Renovate's alpine_3_24 package repository/)
})

test('the apk pin check sees unpinned packages on Dockerfile continuation lines', () => {
  const wrappedInstall = [
    'FROM alpine:3.24.2',
    'RUN apk add --no-cache ca-certificates=20260909-r0 \\',
    '    git=2.54.0-r0 \\',
    '    new-package \\',
    '    && echo done',
  ].join('\n') + '\n'
  assert.throws(() => assertApkPinsManaged(wrappedInstall), /apk package new-package must be pinned to a version/)
})

test('the Naabu license notice matches the Dockerfile release and immutable commit', () => {
  assertNaabuNoticeMatches(dockerfile, thirdPartyLicenses)

  const newVersion = 'v9.8.7'
  const newCommit = '0123456789abcdef0123456789abcdef01234567'
  const oldVersion = dockerfileArg('NAABU_VERSION')
  const oldCommit = dockerfileArg('NAABU_COMMIT')
  const bumpedDockerfile = dockerfile
    .replace(`ARG NAABU_VERSION=${oldVersion}`, `ARG NAABU_VERSION=${newVersion}`)
    .replace(`ARG NAABU_COMMIT=${oldCommit}`, `ARG NAABU_COMMIT=${newCommit}`)
  assert.notEqual(bumpedDockerfile, dockerfile, 'the drift fixture must change both Dockerfile Naabu inputs')
  assert.throws(() => assertNaabuNoticeMatches(bumpedDockerfile, thirdPartyLicenses), /notice release version must match Dockerfile NAABU_VERSION/)
  const changedCommit = dockerfile.replace(`ARG NAABU_COMMIT=${oldCommit}`, `ARG NAABU_COMMIT=${newCommit}`)
  assert.throws(() => assertNaabuNoticeMatches(changedCommit, thirdPartyLicenses), /notice commit must match Dockerfile NAABU_COMMIT/)
  const updatedNotice = thirdPartyLicenses.replaceAll(oldVersion, newVersion).replace(oldCommit, newCommit)
  assert.doesNotThrow(() => assertNaabuNoticeMatches(bumpedDockerfile, updatedNotice))
})

test('the release manifest GoReleaser version follows the pinned release workflow tool', () => {
  const configuredVersions = [...workflowHeader.matchAll(/^  GORELEASER_VERSION: (v[0-9]+\.[0-9]+\.[0-9]+)\s*$/gm)].map((match) => match[1])
  assert.equal(configuredVersions.length, 1, 'release workflow must define one canonical GoReleaser version')
  const [version] = configuredVersions
  const actionSteps = stepsOf(jobBlock('verify')).filter((step) => /uses: goreleaser\/goreleaser-action@/.test(step))
  assert.ok(actionSteps.length > 0, 'release verification must install GoReleaser')
  for (const step of actionSteps) {
    assert.match(step, /^ {10}version: \$\{\{ env\.GORELEASER_VERSION \}\}$/m, 'the executed tool must use the canonical workflow pin')
  }
  assert.deepEqual(renovateDependencies('.github/workflows/release.yml', workflow).filter((entry) => entry.depName === 'goreleaser'), [
    { datasource: 'github-releases', depName: 'goreleaser', currentValue: version, currentDigest: undefined },
  ])
  assert.match(releaseManifestScript, /release_workflow=.*\.github\/workflows\/release\.yml/)
  assert.match(releaseManifestScript, /"\$release_workflow"/)
  assert.match(releaseManifestScript, /GORELEASER_VERSION=.*does not match \.github\/workflows\/release\.yml pin/)
  assert.doesNotMatch(releaseManifestScript, /GORELEASER_VERSION:-v[0-9]/, 'the manifest must not silently fall back to a stale version')
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
  // Each platform is pulled and scanned by its own manifest digest: pulling
  // the index digest a second time for another platform fails.
  assert.match(step, /docker buildx imagetools inspect --raw "\$CANDIDATE"/)
  assert.match(step, /platform_image="\$REGISTRY_IMAGE@\$platform_digest"/)
  assert.match(step, /docker pull "\$platform_image"/)
  assert.doesNotMatch(step, /docker pull --platform "\$platform" "\$CANDIDATE"/)
  assert.match(step, /\.\/scripts\/scan-image-vulnerabilities\.sh "\$platform_image" "\$platform" \|\| status=1/)

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
