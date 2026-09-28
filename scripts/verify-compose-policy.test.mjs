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

// Each case names the render it mutates and the guard that must reject it, so
// a case cannot pass because an unrelated check happened to fail first.
for (const [mode, label, mutate, expected] of [
  ['base', 'missing no-new-privileges', (value) => { delete value.security_opt }, /no-new-privileges must be enabled/],
  ['base', 'missing /tmp tmpfs', (value) => { delete value.tmpfs }, /\/tmp must be backed by a bounded tmpfs/],
  ['base', 'missing host networking', (value) => { value.network_mode = 'bridge' }, /host networking is required/],
  ['base', 'missing NET_RAW', (value) => { value.cap_add = [] }, /NET_RAW is required/],
  ['base', 'NET_ADMIN', (value) => { value.cap_add = ['NET_RAW', 'NET_ADMIN'] }, /base Compose must not grant NET_ADMIN/],
  ['base', 'cap_add ALL', (value) => { value.cap_add = ['NET_RAW', 'ALL'] }, /base Compose must add only NET_RAW; unexpected cap_add: ALL/],
  ['base', 'cap_add SYS_ADMIN', (value) => { value.cap_add = ['NET_RAW', 'SYS_ADMIN'] }, /unexpected cap_add: SYS_ADMIN/],
  ['base', 'cap_add SYS_ADMIN and SYS_PTRACE', (value) => { value.cap_add = ['NET_RAW', 'SYS_ADMIN', 'SYS_PTRACE'] }, /unexpected cap_add: SYS_ADMIN, SYS_PTRACE/],
  ['base', 'privileged mode', (value) => { value.privileged = true }, /privileged mode is not allowed/],
  ['base', 'seccomp=unconfined', (value) => { value.security_opt.push('seccomp=unconfined') }, /security_opt seccomp=unconfined is not allowed/],
  ['base', 'apparmor:unconfined', (value) => { value.security_opt.push('apparmor:unconfined') }, /security_opt apparmor:unconfined is not allowed/],
  ['base', 'pid: host', (value) => { value.pid = 'host' }, /pid: host is not allowed/],
  ['base', 'ipc: host', (value) => { value.ipc = 'host' }, /ipc: host is not allowed/],
  ['base', 'userns_mode: host', (value) => { value.userns_mode = 'host' }, /userns_mode: host is not allowed/],
  ['syn', 'missing NET_ADMIN', (value) => { value.cap_add = ['NET_RAW'] }, /SYN override must grant NET_ADMIN/],
  ['syn', 'cap_add SYS_ADMIN', (value) => { value.cap_add = ['NET_RAW', 'NET_ADMIN', 'SYS_ADMIN'] }, /syn Compose must add only NET_ADMIN, NET_RAW; unexpected cap_add: SYS_ADMIN/],
  ['syn', 'cap_add ALL', (value) => { value.cap_add = ['NET_RAW', 'NET_ADMIN', 'ALL'] }, /unexpected cap_add: ALL/],
  ['syn', 'privileged mode', (value) => { value.privileged = true }, /privileged mode is not allowed/],
  ['syn', 'seccomp=unconfined', (value) => { value.security_opt.push('seccomp=unconfined') }, /security_opt seccomp=unconfined is not allowed/],
]) {
  test(`the ${mode} policy gate rejects ${label}`, async () => {
    await withFixture(async ({ directory, env }) => {
      const path = join(directory, `${mode}.json`)
      const value = JSON.parse(await readFile(path, 'utf8'))
      mutate(value.services.edgewatch)
      await writeFile(path, JSON.stringify(value))
      const result = run(mode, env)
      assert.notEqual(result.status, 0, result.output)
      assert.match(result.output, expected)
    })
  })
}
