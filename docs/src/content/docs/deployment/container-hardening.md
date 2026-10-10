---
title: Container runtime hardening
description: Review scanner capability requirements, runtime controls, and data ownership.
---

The EdgeWatch daemon runs as UID 0 inside the container, and the scanner
processes it starts do not. Nmap, its NSE scripts, and Naabu parse responses
from the networks they scan, so EdgeWatch starts each of them in a
[sandbox](#scanner-sandbox): as the unprivileged UID 65532, with no
supplementary groups and only the raw-packet capabilities a scan needs. A
compromised scanner process cannot read the database or the encryption keys.
When the kernel provides [Landlock](#landlock), EdgeWatch also limits each
scanner process to the files a scan needs, and this holds even for a scanner
process that runs as UID 0. A [seccomp filter](#seccomp-filter) refuses the
system calls no scanner needs, and [no EdgeWatch process dumps
core](#core-dumps). The process that delivers notifications runs in a
[sandbox](#notification-sandbox) of its own, without capabilities.

The daemon itself keeps UID 0 for compatibility. Nmap UDP and SYN scans, and
Naabu SYN discovery, need raw-packet privileges. On the supported Docker
engines, `--cap-add NET_RAW` (and, for Naabu SYN, `NET_ADMIN`) is effective for
the root container process but is removed when Docker starts the process
directly as an unprivileged UID. The daemon therefore receives the
capabilities and hands only the raw-packet ones to each scanner process.

The image and Compose deployment still apply the following controls:

- all capabilities are dropped first;
- the base deployment adds `NET_RAW` for the scanners, and `SETUID`, `SETGID`
  and `KILL` so the daemon can start scanner and notification processes as
  their sandbox identities and stop them;
- `compose.syn.yaml` is an explicit administrator opt-in for `NET_ADMIN`;
- `no-new-privileges` is enabled;
- the container is not privileged, sets no `unconfined` seccomp or AppArmor
  profile, does not join the host PID, IPC, UTS or cgroup namespace, and does
  not opt out of daemon user-namespace remapping with `userns_mode: host`;
- the container receives no host devices: no `devices` entries and no
  `device_cgroup_rules`;
- the root filesystem is read-only and only `/tmp` is writable through a
  tmpfs with a positive `size=` bound (the kernel treats `size=0` as no
  limit);
- SQLite state is limited to the explicit `./data` bind mount;
- the only other mounts are the read-only `config.yaml` bind and optional
  read-only secret files under `/run/secrets/`; the container mounts no Docker
  or other runtime socket, no host root or system directory, and nothing from
  `/proc`, `/sys`, `/dev` or `/run` on the host;
- Compose grants a seven-minute stop grace period so the daemon can cancel
  scanner processes and persist large snapshots within its six-minute
  graceful-shutdown deadline;
- scanner executables and their argument surface are fixed by EdgeWatch, and
  the web listener remains loopback-only.

CI renders `compose.yaml`, and `compose.yaml` with `compose.syn.yaml`, and
`scripts/verify-compose-policy.sh` checks the capability, privilege,
namespace, device, filesystem and mount controls above on each render. A
change to either file that drops one of them fails CI. CI and the release
also start the image with `compose.yaml` itself, replacing only the image and
the container name, in `scripts/verify-compose-deployment.sh`: the container
must become healthy with the capabilities, `TMPDIR` and memory limit of the
file, and `edgewatch health` must report both sandboxes enforced.

## Compatibility matrix

The release workflow runs the following matrix against the image before it is
published, on AMD64 and on ARM64:

| Runtime | Capabilities | Supported work | Result |
| --- | --- | --- | --- |
| UID 0 daemon, base Compose | `NET_RAW`, `SETUID`, `SETGID`, `KILL` | Nmap TCP SYN/connect, Nmap UDP, Naabu connect, each in the sandbox as UID 65532 with `NET_RAW`, restricted with Landlock and the seccomp filter | supported |
| UID 0 daemon, `compose.syn.yaml` | the above and `NET_ADMIN` | Naabu SYN in addition to the base modes, in the sandbox with `NET_RAW` and `NET_ADMIN`, restricted with Landlock and the seccomp filter | supported |
| UID 0 daemon, `NET_RAW` only | `NET_RAW` | the base modes as UID 0, restricted only with Landlock and the seccomp filter | supported; the identity sandbox is unavailable and EdgeWatch warns |
| UID 65532, experimental probe | none effective (even when `NET_RAW` is requested) | Naabu connect and Nmap TCP connect only | supported for those modes; not a supported default |
| UID 65532, experimental probe | none effective | Nmap SYN or UDP, Naabu SYN | rejected by the scanner or unavailable |

The matrix also runs the image with a disposable read-only root filesystem and
a writable data bind mount owned by the identity mapped to container UID 0. It
verifies that the normal root deployment can create SQLite state without
world-writable permissions and that scanner capability checks fail closed
instead of guessing from the UID. It runs real Nmap SYN, Nmap UDP and Naabu
scans of local listeners through EdgeWatch with the sandbox enforced, with
only Landlock, and with the sandbox off, and requires the same results from
all three. It checks that the sandbox identity cannot read the data
directory, and that a process restricted with Landlock cannot read the
database, list the data directory, read `config.yaml`, write to the data
directory, or execute a file it wrote, even as UID 0. It requires that a
running Nmap and the notification process each have one seccomp filter more
than the daemon, and that neither they nor the daemon can dump core. With
`TMPDIR` unset, it requires that a running scan's XML output and Naabu's target
list lie in the [scanner files directory](#scanner-files), and that another
sandboxed process can open neither. It requires that a running Nmap has the
[resource limits](#resource-limits) below, and that cancelling a scan whose
stand-in scanner left a background process that ignores hangups stops that
process too, that such a process cannot leave its process group, and that a
sandboxed Nmap dies with the `edgewatch scan` command that started it. The
seccomp filter and the Landlock restriction depend on the architecture and
the kernel, so the release runs these checks on an ARM64 runner against the
ARM64 image it publishes, and runs the ARM64 archive there. CI runs the
sandbox tests and the same checks on an ARM64 runner for every change,
against an ARM64 image built there.

## Data ownership and upgrades

`./data` must be owned by the host identity mapped to container UID 0 and
should use mode `0750`; the container runs as UID 0 but drops filesystem
capabilities, so it cannot bypass directory ownership and permission checks.
For standard rootful Docker this is host UID 0. For rootless Docker it is the
invoking host user. With user-namespace remapping, it is the host-side UID
mapped to container UID 0. Confirm this mapping before creating or repairing
the bind mount.

Keep the directory and its SQLite sidecars together when backing up or
upgrading. The same container UID is retained across image versions, so data
owned by the mapped identity remains writable without an ownership migration.
Do not add a Compose `user:` setting to an existing installation unless
you have tested ownership and every configured scan mode with a copy of the
data directory. Never use mode `0777` as a workaround; it masks ownership
errors and weakens protection for databases and encryption keys.

## Scanner sandbox

`scanner.sandbox` in `config.yaml` selects how scanner processes start:

| Value | Behaviour |
| --- | --- |
| `auto` (default) | Starts Nmap and Naabu in the sandbox when the container allows it. Otherwise they start as UID 0, restricted only with [Landlock](#landlock) when the kernel provides it, and EdgeWatch logs a warning, adds it to `edgewatch health`, and shows it on the Overview for administrators. |
| `required` | Refuses to start the daemon, or `edgewatch scan`, when the sandbox is unavailable. |
| `off` | Starts scanner processes unconfined, as releases before the sandbox did, without Landlock. |

A sandboxed scanner process:

- runs as UID and GID 65532 (`edgewatch-scanner`) with no supplementary
  groups;
- keeps `NET_RAW`, and `NET_ADMIN` when the container grants it, as ambient
  capabilities and no other capability;
- cannot read or list `./data`, which belongs to UID 0 with mode `0750`, or
  read `config.yaml`; it reads its target list and writes its results through
  file descriptors that EdgeWatch passes to it, to [files](#scanner-files)
  that no scanner can open by name;
- inherits `no-new-privileges`, and the image contains no setuid or file-capability
  binary it could use to gain privileges.

Nmap is started with `--privileged`, because Nmap otherwise assumes that a
process other than UID 0 cannot send raw packets and falls back to connect
scans. Naabu detects its capabilities itself. Scan results are the same as
without the sandbox.

At startup EdgeWatch checks that the container grants `SETUID`, `SETGID` and
`KILL`, and starts a short test process as UID 65532 to confirm that the
runtime allows the change. Check the outcome with:

```sh
docker compose exec edgewatch edgewatch health --config /etc/edgewatch/config.yaml --output json
```

`scanner_sandbox.state` is `enforced`, `disabled` or `unavailable`, and
`reason` explains a sandbox that is not enforced. `scanner_sandbox.landlock`
reports [Landlock](#landlock) the same way.

Administrators see the same information on the Overview, in the deployment
footprint's **Process isolation** section. Each sandbox has a status:

- **Enforced:** every layer holds.
- **Partial:** some layers hold.
- **Unavailable:** no layer holds.
- **Off:** the setting turns the sandbox off.

The section marks each layer (the sandbox identity, Landlock, and the
[seccomp filter](#seccomp-filter)) as holding, unavailable, or off, and gives
the reason for each layer that does not hold.

The sandbox needs the user namespace of the container to map UID 65532. Standard
rootful Docker, rootless Docker, and user-namespace remapping with a full
subordinate range all do. A runtime that maps only a few UIDs reports the
sandbox as unavailable.

### Landlock

On a kernel with [Landlock](https://docs.kernel.org/userspace-api/landlock.html),
Linux 5.13 or later with `landlock` among its enabled security modules, each
scanner process also starts through EdgeWatch's hidden `sandbox-exec`
command. The command restricts its own process and then runs the scanner in
place. The restricted process:

- can read and execute files only below `/usr`, `/bin`, `/sbin` and `/lib`;
- can read only the files in `/etc` that name resolution, service and user
  names, time zones, the dynamic loader and TLS need, plus `/proc` and
  `/sys`; `config.yaml` and `/run/secrets` stay closed;
- can write only to `/dev/null`, its terminal, and the files EdgeWatch passes
  to it, and can reopen a passed file only with the access EdgeWatch gave it;
- creates no file when it is Nmap. Naabu, which keeps its own target list and
  address map in temporary files, can create, change and remove files only
  below `/tmp`, and can execute none of them;
- with Landlock ABI 6 (Linux 6.12) or later, cannot signal processes outside
  its restriction, such as the daemon, or connect to their abstract UNIX
  sockets.

The restriction applies whatever identity the process runs as. It therefore
also protects a deployment whose `compose.yaml` does not grant `SETUID`,
`SETGID` and `KILL`, where scanner processes still run as UID 0. A process
cannot lift the restriction, and every process it starts inherits it.

`scanner.landlock` in `config.yaml` selects it:

| Value | Behaviour |
| --- | --- |
| `auto` (default) | Restricts scanner processes when the kernel provides Landlock. Otherwise they start without it, and EdgeWatch logs why. |
| `required` | Refuses to start the daemon, or `edgewatch scan`, when scanner processes cannot be restricted. |
| `off` | Starts scanner processes without Landlock. |

`scanner.sandbox: off` turns off Landlock too. At startup EdgeWatch runs
`nmap --version` restricted, as scans would run it. When Nmap or a library it
loads lies outside the allowed paths, this is found before any scan: Landlock
is reported unavailable with the reason, and scans run without it.
`scanner_sandbox.landlock.state` in `edgewatch health` reports the outcome,
and `abi` the kernel's Landlock version.

Docker's default seccomp profile permits the Landlock system calls. A custom
profile must allow `landlock_create_ruleset`, `landlock_add_rule` and
`landlock_restrict_self`, or Landlock is reported unavailable.

### Seccomp filter

With Landlock, the `sandbox-exec` command also installs a seccomp filter on
top of the container's seccomp profile. The scanner keeps the filter, and so
does every process the scanner starts. The filter:

- refuses with `EPERM` the system calls no scanner or notification process
  needs. These trace another process or read its memory (`ptrace`,
  `process_vm_readv`, `process_vm_writev`, `kcmp`), or use io_uring,
  `userfaultfd`, `perf_event_open`, or `bpf`. Others reach the kernel
  keyring, load kernels or modules, change mounts, namespaces, or the root
  directory (`unshare`, `setns`, `chroot`), or control the host's swap,
  reboot, accounting, quotas, file handles, and kernel log. On x86-64 it also
  refuses port I/O and `uselib`;
- refuses a `clone` that creates a namespace, and makes `clone3`, whose flags
  a filter cannot read, fail with `ENOSYS`, so that C libraries use `clone`;
- refuses `setsid` and `setpgid`, so that every process a scanner starts stays
  in the process group that EdgeWatch [stops](#stopping-scanners);
- refuses the x32 ABI on x86-64, and kills a process that makes a system call
  of another architecture.

Docker's default profile already refuses most of these calls. The filter
keeps them refused under a runtime or profile that does not, and it refuses
`ptrace` and io_uring, which recent Docker profiles allow. The startup probe
runs Nmap with the filter. When Nmap cannot start that way, scanners run
with Landlock alone. `scanner_sandbox.seccomp` in `edgewatch health` reports
`enforced`, `unavailable` with the reason, or `disabled`. The filter applies
only with Landlock: `scanner.landlock: off` turns it off too.

### Scanner files

EdgeWatch passes Nmap a file for its XML output and Naabu a file with its
target list. It creates them in `tmp/scanner` beside the database,
`/var/lib/edgewatch/tmp/scanner` in the container, whatever `TMPDIR` names.
The directory has mode `0700` and belongs to the daemon: EdgeWatch restricts a
directory there that grants its group or others any access, and refuses to
start when the path is not a directory, such as a symbolic link, or belongs to
another user. Each EdgeWatch process keeps its files in a directory of its own
below it, which it locks while it runs. At startup the daemon, and
`edgewatch scan`, remove the directories of processes that no longer run, with
the files of scans they were stopped in.

A sandboxed scanner cannot list `./data` or reach a file below it by its name,
and Landlock never grants the data directory to a scanner, even one that runs
as UID 0, so a scanner reaches only the files of its own scan, through the
descriptors it inherits. The bundled `compose.yaml` sets `TMPDIR` to
`/var/lib/edgewatch/tmp` for the daemon's other temporary files, such as
SQLite's, so they share the data volume rather than the 128 MiB `/tmp`
tmpfs.

### Stopping scanners

Each Nmap and Naabu process leads a process group of its own; Nmap in the
session of its private pseudo-terminal. When a scan is cancelled, times out,
or a scanner exceeds an output bound, EdgeWatch kills the whole group, and
when a scanner exits, EdgeWatch kills what is left in its group before it
collects the scanner's exit status. A scanner can therefore leave no process
behind that keeps probing or holds the scan open, such as a background process
that ignores the hangup of the terminal. Once the scanner has exited,
EdgeWatch waits at most five seconds, one deadline for all of them, for the
scanner's output pipes and Nmap's terminal to close, and fails the scan when a
process outside the group still holds one. The
[seccomp filter](#seccomp-filter) refuses the calls that leave a process
group. On Linux the kernel also kills a scanner whose EdgeWatch process dies,
and `edgewatch scan` cancels its scan when its terminal hangs up, as it does on
an interrupt or a termination signal.

### Scan memory

The daemon keeps a scope and, at a scan's end, a result for every address a
job's targets expand to. The bundled `compose.yaml` limits the container to
512 MiB: a resumable scan of a /16 with every address unreachable peaked at
about 344 MB of it, and a /14 was killed for lack of memory. So
`scanner.max_job_hosts` in `config.yaml`, 65,536 by default, caps the
addresses one job may scan; see the
[configuration reference](/reference/configuration/). Raise the setting only
together with the memory limit, and keep several large scans from running at
once with `scheduler.max_concurrent_scans`.

### Resource limits

With Landlock, the `sandbox-exec` command also sets the following limits for
each scanner process before it restricts it. Every process the scanner starts
inherits them:

- `oom_score_adj` is `1000`, the highest value, so that when the container or
  host runs out of memory the kernel's out-of-memory killer stops a scanner
  before the daemon, which every business unit shares. The scan fails; the
  daemon keeps running.
- The soft and hard open file limits are at most 65,536 descriptors. Nmap
  raises its soft limit to the hard limit for connect scans, and Naabu holds
  about one socket for each of at most 1,024 workers.

`scanner_sandbox.limits` in `edgewatch health` reports them, as
`oom_score_adj` and `max_open_files`; it is absent when Landlock does not
apply. EdgeWatch sets no process count limit (`RLIMIT_NPROC`), which the
kernel counts for the scanner's UID across all of its scans, threads, and
other containers that use the same UID, and no address space or data limit,
which would fail large scans whose memory needs the release matrix does not
cover.

### Core dumps

Every EdgeWatch process sets its soft and hard core file size limits to zero
and clears its dumpable flag at startup. Its child processes inherit the
limit and cannot raise it. A crash of the daemon, the notification process,
or a scanner therefore leaves no core file. Such a file would hold the keys,
a destination URL, or scan data, and could reach a core handler on the host
outside the container. A non-dumpable process cannot be traced, and its
memory cannot be read, by another process of its identity without
`CAP_SYS_PTRACE`.

### Upgrading an existing deployment

A `compose.yaml` from an earlier release adds only `NET_RAW`. With it,
`auto` keeps scanning as UID 0, restricted only with Landlock where the kernel
provides it, and warns. Add the three capabilities to enable the sandbox:

```yaml
    cap_add:
      - NET_RAW
      - SETUID
      - SETGID
      - KILL
```

Then recreate the container with `docker compose up -d`. No data migration is
needed; `./data` keeps its UID 0 ownership.

### What the sandbox does not cover

- The daemon, which serves the console and holds the database and keys, still
  runs as UID 0 with the container's capabilities.
- All sandboxed scanner processes share UID 65532, and all Naabu processes
  share `/tmp`, so a compromised scanner process could observe other scans
  that run at the same time. It cannot reach their XML output or target
  lists, which lie in the [scanner files directory](#scanner-files).
- Where the seccomp filter does not apply, such as on a kernel without
  Landlock, a process that a compromised scanner starts can leave the
  scanner's process group with `setsid` and outlive the scan. Without
  Landlock, the [resource limits](#resource-limits) do not apply either.
- A scanner process keeps its network access; target exclusions and probe
  budgets are enforced by EdgeWatch before it starts.
- On a kernel without Landlock, a sandboxed process can read every file its
  identity may read.

## Notification sandbox

Each notification is delivered by a short-lived child process, so a fault in
a provider cannot stop the daemon. The child receives one destination URL and
the message, and needs no other private data. `notifications.sandbox` in
`config.yaml` selects how it starts:

| Value | Behaviour |
| --- | --- |
| `auto` (default) | Starts the notification process in the sandbox when the container allows it. Otherwise it starts unconfined, and EdgeWatch logs a warning and adds it to `edgewatch health` when it runs as UID 0. |
| `required` | Refuses to start the daemon, or `edgewatch notify test`, when the sandbox is unavailable. |
| `off` | Starts the notification process unconfined, as releases before the sandbox did, without Landlock. |

A sandboxed notification process:

- runs as UID and GID 65531 (`edgewatch-notify`) with no supplementary groups
  and no capabilities. It has an identity of its own, so a compromised
  scanner process can neither signal it nor read its memory;
- is restricted with [Landlock](#landlock), when the kernel provides it, to the
  same system files as a scanner process, without `/tmp`: it can write no file
  at all. The [seccomp filter](#seccomp-filter) applies as it does to
  scanners;
- is non-dumpable for its whole run, so another process of its identity can
  neither trace it nor read the destination URL from its memory;
- keeps its network access and the proxy, time zone, and certificate authority
  variables the daemon passes to it: `HTTP_PROXY`, `HTTPS_PROXY`,
  `ALL_PROXY`, `NO_PROXY`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, `TZ`, `LANG`, and
  `LC_ALL`.

At startup EdgeWatch runs a short check as the notification process would
run. The check reads the certificate authorities that `SSL_CERT_FILE` and
`SSL_CERT_DIR` name. When a private certificate authority is mounted with a
mode that UID 65531 cannot read, the notification process keeps UID 0,
restricted only with Landlock where the kernel provides it, and the reason
names the file. TLS destinations behind that authority keep working. Make
such files readable by others, as certificates usually are, to enable the
sandbox. `notification_sandbox` in `edgewatch health` and
on the Overview reports the outcome, in the same form as `scanner_sandbox`.

A non-root daemon remains unsupported until the supported Docker and
rootless or containerd combinations provide a documented way to grant it the
capabilities above, with read-only filesystems, bind-mounted ownership and
upgrade rollback covered.
