import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

const repoRoot = new URL('..', import.meta.url).pathname
const policyScript = join(repoRoot, 'scripts', 'verify-compose-policy.sh')

const service = ({ syn = false } = {}) => ({
  image: 'ghcr.io/crypt0rr/edgewatch:latest',
  network_mode: 'host',
  cap_drop: ['ALL'],
  cap_add: ['NET_RAW', ...(syn ? ['NET_ADMIN'] : [])],
  security_opt: ['no-new-privileges:true'],
  read_only: true,
  tmpfs: ['/tmp:size=128m,mode=1777'],
  volumes: [{ target: '/var/lib/edgewatch' }],
})

const compose = (serviceDefinition) => JSON.stringify({ services: { edgewatch: serviceDefinition } })

async function withFixture(fn) {
  const directory = await mkdtemp(join(tmpdir(), 'edgewatch-compose-policy-'))
  const bin = join(directory, 'bin')
  const docker = join(bin, 'docker')
  await mkdir(bin)
  await writeFile(join(directory, 'base.json'), compose(service()))
  await writeFile(join(directory, 'syn.json'), compose(service({ syn: true })))
  await writeFile(docker, '#!/bin/sh\ncase "$*" in\n  *"-f compose.yaml -f compose.syn.yaml"*) cat "$COMPOSE_SYN_JSON" ;;\n  *) cat "$COMPOSE_BASE_JSON" ;;\nesac\n')
  await chmod(docker, 0o755)
  const env = {
    ...process.env,
    PATH: `${bin}:${process.env.PATH}`,
    COMPOSE_BASE_JSON: join(directory, 'base.json'),
    COMPOSE_SYN_JSON: join(directory, 'syn.json'),
  }
  try {
    return await fn({ directory, env })
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
}

function run(mode, env) {
  try {
    return { status: 0, output: execFileSync(policyScript, [mode], { env, encoding: 'utf8' }) }
  } catch (error) {
    return { status: error.status ?? 1, output: `${error.stdout ?? ''}${error.stderr ?? ''}` }
  }
}

test('the unmodified base and SYN policies pass', async () => {
  await withFixture(async ({ env }) => {
    assert.equal(run('base', env).status, 0)
    assert.equal(run('syn', env).status, 0)
  })
})

for (const [label, mutate] of [
  ['no-new-privileges', (value) => { delete value.security_opt }],
  ['/tmp tmpfs', (value) => { delete value.tmpfs }],
  ['host networking', (value) => { value.network_mode = 'bridge' }],
]) {
  test(`the policy gate rejects missing ${label}`, async () => {
    await withFixture(async ({ directory, env }) => {
      const value = JSON.parse(await readFile(join(directory, 'base.json'), 'utf8'))
      mutate(value.services.edgewatch)
      await writeFile(join(directory, 'base.json'), JSON.stringify(value))
      assert.notEqual(run('base', env).status, 0)
    })
  })
}
