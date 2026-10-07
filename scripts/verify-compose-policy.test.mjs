import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

const repoRoot = new URL('..', import.meta.url).pathname
const policyScript = join(repoRoot, 'scripts', 'verify-compose-policy.sh')

// The bind shape follows `docker compose config --format json`, which renders
// the short volume syntax of compose.yaml with absolute host sources.
const bind = (source, target, readOnly = false) => ({
  type: 'bind',
  source,
  target,
  ...(readOnly ? { read_only: true } : {}),
  bind: {},
})

const service = ({ syn = false } = {}) => ({
  image: 'ghcr.io/crypt0rr/edgewatch:latest',
  network_mode: 'host',
  cap_drop: ['ALL'],
  cap_add: ['NET_RAW', 'SETUID', 'SETGID', 'KILL', ...(syn ? ['NET_ADMIN'] : [])],
  security_opt: ['no-new-privileges:true'],
  read_only: true,
  tmpfs: ['/tmp:size=128m,mode=1777'],
  volumes: [
    bind('/opt/edgewatch/config.yaml', '/etc/edgewatch/config.yaml', true),
    bind('/opt/edgewatch/data', '/var/lib/edgewatch'),
  ],
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

async function runMutated(mode, mutate) {
  return withFixture(async ({ directory, env }) => {
    const path = join(directory, `${mode}.json`)
    const value = JSON.parse(await readFile(path, 'utf8'))
    mutate(value.services.edgewatch)
    await writeFile(path, JSON.stringify(value))
    return run(mode, env)
  })
}

test('the unmodified base and SYN policies pass', async () => {
  await withFixture(async ({ env }) => {
    assert.equal(run('base', env).status, 0)
    assert.equal(run('syn', env).status, 0)
  })
})

// The documented optional mounts and other bounded /tmp sizes stay accepted,
// so the stricter mount and tmpfs checks cannot reject a valid deployment.
for (const mode of ['base', 'syn']) {
  for (const [label, mutate] of [
    ['a read-only notification key under /run/secrets', (value) => {
      value.volumes.push(bind('/opt/edgewatch/notification-encryption.key', '/run/secrets/edgewatch-notification-key', true))
    }],
    ['read-only authentication key and notification URL files under /run/secrets', (value) => {
      value.volumes.push(bind('/etc/edgewatch/auth.key', '/run/secrets/edgewatch-auth-key', true))
      value.volumes.push(bind('/opt/edgewatch/notification-urls.txt', '/run/secrets/edgewatch-notification-urls', true))
    }],
    ['a /tmp tmpfs bounded in gigabytes', (value) => { value.tmpfs = ['/tmp:size=1g,mode=1777'] }],
    ['a /tmp tmpfs bounded in bytes', (value) => { value.tmpfs = ['/tmp:mode=1777,size=65536'] }],
    ['a /tmp tmpfs bounded by a share of memory', (value) => { value.tmpfs = ['/tmp:size=10%'] }],
  ]) {
    test(`the ${mode} policy gate accepts ${label}`, async () => {
      const result = await runMutated(mode, mutate)
      assert.equal(result.status, 0, result.output)
      assert.match(result.output, new RegExp(`${mode} Compose policy verified`))
    })
  }
}

// Each case names the render it mutates and the guard that must reject it, so
// a case cannot pass because an unrelated check happened to fail first.
for (const [mode, label, mutate, expected] of [
  ['base', 'missing no-new-privileges', (value) => { delete value.security_opt }, /no-new-privileges must be enabled/],
  ['base', 'missing /tmp tmpfs', (value) => { delete value.tmpfs }, /\/tmp must be backed by a bounded tmpfs/],
  ['base', 'missing host networking', (value) => { value.network_mode = 'bridge' }, /host networking is required/],
  ['base', 'missing NET_RAW', (value) => { value.cap_add = ['SETUID', 'SETGID', 'KILL'] }, /NET_RAW is required/],
  ['base', 'missing KILL', (value) => { value.cap_add = ['NET_RAW', 'SETUID', 'SETGID'] }, /the scanner sandbox requires cap_add: KILL/],
  ['base', 'missing SETUID and SETGID', (value) => { value.cap_add = ['NET_RAW', 'KILL'] }, /the scanner sandbox requires cap_add: SETGID, SETUID/],
  ['base', 'NET_ADMIN', (value) => { value.cap_add = ['NET_RAW', 'SETUID', 'SETGID', 'KILL', 'NET_ADMIN'] }, /base Compose must not grant NET_ADMIN/],
  ['base', 'cap_add ALL', (value) => { value.cap_add = ['NET_RAW', 'SETUID', 'SETGID', 'KILL', 'ALL'] }, /base Compose must add only KILL, NET_RAW, SETGID, SETUID; unexpected cap_add: ALL/],
  ['base', 'cap_add SYS_ADMIN', (value) => { value.cap_add = ['NET_RAW', 'SETUID', 'SETGID', 'KILL', 'SYS_ADMIN'] }, /unexpected cap_add: SYS_ADMIN/],
  ['base', 'cap_add SYS_ADMIN and SYS_PTRACE', (value) => { value.cap_add = ['NET_RAW', 'SETUID', 'SETGID', 'KILL', 'SYS_ADMIN', 'SYS_PTRACE'] }, /unexpected cap_add: SYS_ADMIN, SYS_PTRACE/],
  ['base', 'privileged mode', (value) => { value.privileged = true }, /privileged mode is not allowed/],
  ['base', 'seccomp=unconfined', (value) => { value.security_opt.push('seccomp=unconfined') }, /security_opt seccomp=unconfined is not allowed/],
  ['base', 'apparmor:unconfined', (value) => { value.security_opt.push('apparmor:unconfined') }, /security_opt apparmor:unconfined is not allowed/],
  ['base', 'pid: host', (value) => { value.pid = 'host' }, /pid: host is not allowed/],
  ['base', 'ipc: host', (value) => { value.ipc = 'host' }, /ipc: host is not allowed/],
  ['base', 'userns_mode: host', (value) => { value.userns_mode = 'host' }, /userns_mode: host is not allowed/],
  ['syn', 'missing NET_ADMIN', (value) => { value.cap_add = ['NET_RAW', 'SETUID', 'SETGID', 'KILL'] }, /SYN override must grant NET_ADMIN/],
  ['syn', 'cap_add SYS_ADMIN', (value) => { value.cap_add = ['NET_RAW', 'SETUID', 'SETGID', 'KILL', 'NET_ADMIN', 'SYS_ADMIN'] }, /syn Compose must add only KILL, NET_ADMIN, NET_RAW, SETGID, SETUID; unexpected cap_add: SYS_ADMIN/],
  ['syn', 'cap_add ALL', (value) => { value.cap_add = ['NET_RAW', 'SETUID', 'SETGID', 'KILL', 'NET_ADMIN', 'ALL'] }, /unexpected cap_add: ALL/],
  ['syn', 'privileged mode', (value) => { value.privileged = true }, /privileged mode is not allowed/],
  ['syn', 'seccomp=unconfined', (value) => { value.security_opt.push('seccomp=unconfined') }, /security_opt seccomp=unconfined is not allowed/],
]) {
  test(`the ${mode} policy gate rejects ${label}`, async () => {
    const result = await runMutated(mode, mutate)
    assert.notEqual(result.status, 0, result.output)
    assert.match(result.output, expected)
  })
}

// Host mounts, devices, the host cgroup and UTS namespaces, and an unbounded
// /tmp give the UID 0 container process a way around the capability controls,
// so both the base render and the SYN override must reject each of them.
for (const [label, mutate, expected] of [
  ['a Docker socket bind', (value) => {
    value.volumes.push(bind('/var/run/docker.sock', '/var/run/docker.sock'))
  }, /volume source \/var\/run\/docker\.sock is a socket; the Docker or another runtime socket gives the container control of the host/],
  ['a read-only Docker socket bind under /run/secrets', (value) => {
    value.volumes.push(bind('/run/docker.sock', '/run/secrets/docker.sock', true))
  }, /volume source \/run\/docker\.sock is a socket; the Docker or another runtime socket gives the container control of the host/],
  ['a rootless Docker socket bind', (value) => {
    value.volumes.push(bind('/home/operator/.docker/run/docker.sock', '/run/secrets/edgewatch-auth-key', true))
  }, /volume source \/home\/operator\/\.docker\/run\/docker\.sock is a socket; the Docker or another runtime socket gives the container control of the host/],
  ['a writable bind of the host root', (value) => {
    value.volumes.push(bind('/', '/host'))
  }, /volume source \/ is the host root or a host system directory/],
  ['a read-only bind of the host root', (value) => {
    value.volumes.push(bind('/', '/run/secrets/host', true))
  }, /volume source \/ is the host root or a host system directory/],
  ['the host root as the data directory', (value) => {
    value.volumes[1] = bind('/', '/var/lib/edgewatch')
  }, /volume source \/ is the host root or a host system directory/],
  ['a host root spelled with extra slashes and dots', (value) => {
    value.volumes[1] = bind('//opt/..', '/var/lib/edgewatch')
  }, /volume source \/\/opt\/\.\. is the host root or a host system directory/],
  ['a writable bind of /etc', (value) => {
    value.volumes.push(bind('/etc', '/host-etc'))
  }, /volume source \/etc is the host root or a host system directory/],
  ['a system directory as the data directory', (value) => {
    value.volumes[1] = bind('/etc/cron.d', '/var/lib/edgewatch')
  }, /writable volume source \/etc\/cron\.d is under the host system directory \/etc/],
  ['a bind of the host /proc', (value) => {
    value.volumes.push(bind('/proc/sysrq-trigger', '/run/secrets/sysrq', true))
  }, /volume source \/proc\/sysrq-trigger is under \/proc, a host kernel or container runtime path/],
  ['a bind of the container runtime state', (value) => {
    value.volumes[1] = bind('/var/lib/docker/volumes/edgewatch', '/var/lib/edgewatch')
  }, /volume source \/var\/lib\/docker\/volumes\/edgewatch is under \/var\/lib\/docker/],
  ['a bind of the host D-Bus socket', (value) => {
    value.volumes.push(bind('/run/dbus/system_bus_socket', '/run/secrets/bus', true))
  }, /volume source \/run\/dbus\/system_bus_socket is under \/run, a host kernel or container runtime path/],
  ['an extra host directory mount', (value) => {
    value.volumes.push(bind('/opt/edgewatch/scripts', '/usr/local/bin/extra'))
  }, /volume \/opt\/edgewatch\/scripts:\/usr\/local\/bin\/extra is not allowed; only \/etc\/edgewatch\/config\.yaml, \/var\/lib\/edgewatch and read-only files under \/run\/secrets\/ may be mounted/],
  ['a mount that escapes /run/secrets', (value) => {
    value.volumes.push(bind('/opt/edgewatch/secret', '/run/secrets/..', true))
  }, /volume \/opt\/edgewatch\/secret:\/run\/secrets\/\.\. is not allowed/],
  ['a writable secret file', (value) => {
    value.volumes.push(bind('/opt/edgewatch/notification-encryption.key', '/run/secrets/edgewatch-notification-key'))
  }, /volume \/opt\/edgewatch\/notification-encryption\.key:\/run\/secrets\/edgewatch-notification-key must be read-only/],
  ['a writable configuration file', (value) => {
    value.volumes[0] = bind('/opt/edgewatch/config.yaml', '/etc/edgewatch/config.yaml')
  }, /volume \/opt\/edgewatch\/config\.yaml:\/etc\/edgewatch\/config\.yaml must be read-only/],
  ['a named volume for runtime data', (value) => {
    value.volumes[1] = { type: 'volume', source: 'edgewatch-data', target: '/var/lib/edgewatch', volume: {} }
  }, /volume edgewatch-data:\/var\/lib\/edgewatch of type volume is not allowed; mount only the documented host files and \.\/data as binds/],
  ['a missing data mount', (value) => { value.volumes.pop() }, /runtime data must be mounted at \/var\/lib\/edgewatch/],
  ['volumes_from', (value) => { value.volumes_from = ['service:other'] }, /volumes_from is not allowed/],
  ['Compose secrets', (value) => { value.secrets = [{ source: 'socket', target: '/run/secrets/socket' }] }, /secrets is not allowed/],
  ['Compose configs', (value) => { value.configs = [{ source: 'extra', target: '/etc/extra' }] }, /configs is not allowed/],
  ['a host device', (value) => {
    value.devices = [{ source: '/dev/sda', target: '/dev/sda', permissions: 'rwm' }]
  }, /devices are not allowed: \/dev\/sda/],
  ['device cgroup rules', (value) => { value.device_cgroup_rules = ['b 8:* rmw'] }, /device_cgroup_rules are not allowed/],
  ['cgroup: host', (value) => { value.cgroup = 'host' }, /cgroup: host is not allowed/],
  ['uts: host', (value) => { value.uts = 'host' }, /uts: host is not allowed/],
  ['a /tmp tmpfs with size=0', (value) => { value.tmpfs = ['/tmp:size=0,mode=1777'] }, /\/tmp must be backed by a bounded tmpfs; size=0 is not a positive size bound/],
  ['a /tmp tmpfs with size=0m', (value) => { value.tmpfs = ['/tmp:size=0m,mode=1777'] }, /size=0m is not a positive size bound/],
  ['a /tmp tmpfs with size=0%', (value) => { value.tmpfs = ['/tmp:size=0%'] }, /size=0% is not a positive size bound/],
  ['a /tmp tmpfs with a hexadecimal zero size', (value) => { value.tmpfs = ['/tmp:size=0x0'] }, /size=0x0 is not a positive size bound/],
  ['a /tmp tmpfs whose later size=0 overrides the bound', (value) => { value.tmpfs = ['/tmp:size=128m,mode=1777,size=0'] }, /size=0 is not a positive size bound/],
  ['a /tmp tmpfs with nr_blocks=0', (value) => { value.tmpfs = ['/tmp:size=128m,nr_blocks=0'] }, /nr_blocks=0 is not a positive size bound/],
  ['a /tmp tmpfs without a size', (value) => { value.tmpfs = ['/tmp:mode=1777'] }, /\/tmp must be backed by a bounded tmpfs/],
  ['an unbounded second /tmp tmpfs', (value) => { value.tmpfs.push('/tmp:mode=1777') }, /\/tmp must be backed by a bounded tmpfs; \/tmp:mode=1777 has no size= option/],
  ['a writable tmpfs outside /tmp', (value) => { value.tmpfs.push('/etc/edgewatch:size=1m') }, /tmpfs \/etc\/edgewatch is not allowed; only \/tmp may be writable through a tmpfs/],
]) {
  for (const mode of ['base', 'syn']) {
    test(`the ${mode} policy gate rejects ${label}`, async () => {
      const result = await runMutated(mode, mutate)
      assert.notEqual(result.status, 0, result.output)
      assert.match(result.output, expected)
    })
  }
}
