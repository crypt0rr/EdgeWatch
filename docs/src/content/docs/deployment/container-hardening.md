---
title: Container runtime hardening
description: Review scanner capability requirements, runtime controls, and data ownership.
---

The EdgeWatch daemon runs as UID 0 inside the container, and the scanner
processes it starts do not. Nmap, its NSE scripts, and Naabu parse responses
from the networks they scan, so EdgeWatch starts each invocation in a
[sandbox](#scanner-sandbox): with a distinct unprivileged UID and GID leased
from 60000–60063, no supplementary groups, and only the raw-packet
capabilities that scan needs. A compromised scanner process cannot read the
database or the encryption keys. When the kernel provides
[Landlock](#landlock), EdgeWatch also limits each scanner process to the files
that scan needs. A [seccomp filter](#seccomp-filter) refuses the
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
- container logs use the `json-file` driver with rotation bounded to 10 MB per
  file and three files, limiting log storage to about 30 MB per container;
- scanner executables and their argument surface are fixed by EdgeWatch, and
  the web listener remains loopback-only.

CI renders `compose.yaml`, and `compose.yaml` with `compose.syn.yaml`, and
`scripts/verify-compose-policy.sh` checks the capability, privilege,
namespace, device, filesystem, mount, shutdown grace-period and log-rotation
controls above on each render. It requires at least seven minutes of stop
grace and bounded `json-file` logs. A change to either file that drops one of
these controls fails CI. CI and the release
also start the image with `compose.yaml` itself, replacing only the image and
the container name, in `scripts/verify-compose-deployment.sh`: the container
must become healthy with the capabilities, `TMPDIR` and memory limit of the
file, and `edgewatch health` must report both sandboxes enforced.

## Compatibility matrix

The release workflow runs the following matrix against the image before it is
published, on AMD64 and on ARM64:

| Runtime | Capabilities | Supported work | Result |
| --- | --- | --- | --- |
| UID 0 daemon, base Compose | `NET_RAW`, `SETUID`, `SETGID`, `KILL` | Nmap TCP SYN/connect, Nmap UDP, and Naabu connect; each invocation uses its own leased UID/GID, `NET_RAW`, and the seccomp filter, with Landlock when available | supported |
| UID 0 daemon, `compose.syn.yaml` | the above and `NET_ADMIN` | Naabu SYN in addition to the base modes, with a separate leased UID/GID, `NET_RAW`, `NET_ADMIN`, and the seccomp filter, with Landlock when available | supported |
| UID 0 daemon, missing `SETUID`, `SETGID`, or `KILL` | `NET_RAW` and optional `NET_ADMIN` only | health reports the identity pool unavailable and scanner launches fail closed; no UID 0 scanner fallback | not supported for scanner launches |
| UID 0 daemon, `scanner.sandbox: off` | the capabilities needed by the selected scan | scanners run unconfined as the daemon identity; identity leases, Landlock, and the scanner seccomp filter are disabled | explicit unconfined mode |
| non-root daemon | any | cannot establish the required leased scanner identities | scanner launches unavailable |

The matrix also runs the image with a disposable read-only root filesystem and
a writable data bind mount owned by the identity mapped to container UID 0. It
verifies that the normal root deployment can create SQLite state without
world-writable permissions and that scanner capability checks fail closed
instead of guessing from the UID. It runs real Nmap SYN, Nmap UDP and Naabu
scans of local listeners through EdgeWatch with the identity pool, seccomp,
and Landlock when available; with the identity pool and seccomp but Landlock
disabled; and with the sandbox explicitly off. It requires matching results
from these supported modes. It also checks concurrent invocations use distinct
leased identities, that one invocation cannot read another's temporary files
or target-list descriptor, and that an unproven cleanup quarantines its
identity. It checks that a scanner identity cannot read the data
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

The scanner identity allocator also keeps a private lease journal under
`/var/lib/edgewatch/scanner-identities` and a boot marker beside it. These are
filesystem state, separate from the SQLite database: the `backup` and `restore`
commands do not include or reset them, while a raw snapshot of the full `./data`
directory includes them. Keep them with the same live data volume. Do not edit,
delete, or restore the journal separately from that volume. If restoring a raw
volume snapshot, stop the daemon and all scans first. The v3 allocator passes a
read-only kernel liveness reference through the supervisor and every scanner
and helper process. It may move a nonempty journal to a new private PID
namespace only after the kernel proves that no process holds that reference;
before reset it archives the previous journal. A host reboot similarly proves
that no process from the old boot remains, so prior-boot state is archived
before reset.

Releases through v0.40.0 used a v2 journal and did not pass a liveness
reference to scanner processes. A nonempty same-boot v2 journal cannot be
reclaimed automatically after that upgrade. Stop every EdgeWatch container and
host process using the volume, including direct `edgewatch scan` commands, and
make a complete backup of `./data`. Then run the explicit one-off migration:

```sh
docker compose stop edgewatch
docker compose run --rm --no-deps --entrypoint edgewatch edgewatch \
  scanner-identities recover --confirm-all-volume-users-stopped
docker compose up -d edgewatch
```

The command requires this operator assertion because it cannot see old
processes in another PID namespace. It also requires the private PID-1 runtime,
an exclusive kernel liveness lock, and valid owned state-file metadata. It
preserves hash-named copies of the old journal and marker before writing an
empty v3 scope. It refuses malformed or unsafe files and never overwrites a
live v3 lock. Do not delete or hand-edit state files to recover capacity. If
the command refuses, preserve the volume and investigate or restore a complete
matching snapshot. Run it from the Compose one-off container shown above, not
from a host shell. Native installations that cannot provide this same private
PID-1 runtime must keep the pool fail-closed and preserve the state volume
while arranging a compatible isolated recovery environment.

## Scanner sandbox

`scanner.sandbox` in `config.yaml` selects how scanner processes start:

| Value | Behaviour |
| --- | --- |
| `auto` (default) | Starts the daemon even when the identity pool or required seccomp filter is unavailable. Health reports that state, and each scanner launch fails closed; EdgeWatch logs the reason, shows it on the Overview, and records a [deployment alert](#deployment-alerts). It never starts a scanner as UID 0. |
| `required` | Refuses daemon startup and direct scan commands when the identity pool or required seccomp filter is unavailable. When `scanner.landlock: required` is also set, it also refuses startup or direct scan commands without Landlock. |
| `off` | Starts scanner processes unconfined as the daemon identity, without scanner identity leases, Landlock, or the scanner seccomp filter. |

A sandboxed scanner process:

- runs with a distinct UID and matching GID leased from 60000–60063 for that
  invocation, with no supplementary groups;
- gives Nmap only `NET_RAW`; gives Naabu SYN `NET_RAW` and `NET_ADMIN` when
  the container grants it; and gives Naabu connect neither capability;
- cannot read or list `./data`, which belongs to UID 0 with mode `0750`, or
  read `config.yaml`; it reads its target list and writes its results through
  file descriptors that EdgeWatch passes to it, to [files](#scanner-files)
  that no scanner can open by name;
- inherits `no-new-privileges`, and the image contains no setuid or file-capability
  binary it could use to gain privileges.

Nmap is started with `--privileged`, because Nmap otherwise assumes that a
process other than UID 0 cannot send raw packets and falls back to connect
scans. Naabu detects its capabilities itself, and falls back to a connect
scan without a warning EdgeWatch can see when its raw-packet setup fails, so
`scripts/verify-scanner-sandbox.sh` checks that a sandboxed SYN Naabu owns raw
or packet sockets and that a connect Naabu owns none. Scan results are the
same as without the sandbox.

When `scanner.sandbox` is `auto` or `required`, before the daemon or `scan`
command opens storage or initializes keys, the sandbox detector runs the
configured Nmap executable with the fixed `--version` argument through a
leased scanner identity. This checks the actual binary and its runtime
libraries with the identity, seccomp, and Landlock restrictions the scanner
will use; it does not contact a target. If the Landlock check fails but the
same command succeeds with identity isolation and seccomp, `auto` continues
without Landlock and reports the fallback in health and startup warnings.
`required` refuses startup. If the identity-and-seccomp control also fails,
scanner launches are unavailable even in `auto`; EdgeWatch never falls back to
UID 0 or drops seccomp. Probe errors are bounded and sanitized. With
`scanner.sandbox: off`, detection skips these checks and disables those
confinement layers.

The daemon and `scan` command separately capture the Nmap and Naabu version
strings once when the application starts; the console serves the daemon's
cached values instead of starting scanner processes for each capabilities
request. Host commands such as `notify test` and baseline review do not need
scanner binaries and skip these version checks when they create an application
without a scanner policy.

At startup EdgeWatch checks that every UID/GID in the fixed scanner range is
mapped, the container grants `SETUID`, `SETGID` and `KILL`, the durable lease
state is safe to use, and the required seccomp filter can be installed. In
`auto`, an unavailable pool or filter leaves the daemon running but prevents
scanner launches; in `required`, it prevents daemon startup. Neither mode
falls back to running a scanner as UID 0. Check the reported state with:

```sh
docker compose exec edgewatch edgewatch health --config /etc/edgewatch/config.yaml --output json
```

`scanner_sandbox.state` is `enforced`, `disabled` or `unavailable`, and
`reason` explains a sandbox that is not enforced. `scanner_sandbox.identity_pool`
reports the pool state, the `per_invocation` strategy, the UID range, its
maximum parallel capacity of 64, active and quarantined leases, identities in
use by unleased processes, and free identities. The health command inspects
the journal without leasing an identity and warns when the identities that
scans can reach fall below `max_concurrent_scans`. This health warning uses
shared capacity: it subtracts quarantined leases and identities in use by
unleased processes, while counting all active leases as reachable because the
journal does not identify their owners. The daemon's built-in low-capacity
alert also subtracts active leases held by other processes and excludes the
daemon's own running scans. A live host `edgewatch scan` can therefore cause a
temporary alert; a lease left active by a killed host scan continues to lower
alert capacity until a clean container restart after all EdgeWatch processes
using the data volume have exited. Since concurrent scans can use different
identities, the scanner status does not report one
`uid`, `gid`, or
`process_uid`. The independent `scanner_sandbox.landlock` and
`scanner_sandbox.seccomp` fields report those layers separately.
When required capabilities are missing, the reason lists their names; when a
UID/GID mapping is incomplete, it identifies the first unmapped scanner ID.

Administrators see the same information on the Overview, in the deployment
footprint's **Process isolation** section. Each sandbox has a status:

- **Enforced:** every layer holds.
- **Partial:** some layers hold.
- **Unavailable:** no layer holds.
- **Off:** the setting turns the sandbox off.

The section marks each layer (the scanner identity pool, Landlock, and the
[seccomp filter](#seccomp-filter)) as holding, unavailable, or off, and gives
the reason for each layer that does not hold. For an enforced pool it also
shows the identity counts, and it warns when the identities that scans can
reach, counted as `edgewatch health` counts them, fall below the unit's
concurrent scan limit. Running scans do not lower that count.

The scanner pool needs the container's user namespace to map every UID and GID
from 60000 through 60063. Standard rootful Docker, rootless Docker, and
user-namespace remapping with a full subordinate range provide the required
mapping. A runtime that maps only part of the pool reports it unavailable.
Reserve the corresponding host UIDs and GIDs for scanner use. With rootful
Docker they are 60000–60063; with rootless Docker or user-namespace remapping,
reserve the host IDs to which that container range maps. The allocator checks
for identities in the container's own process and account tables, not for host
processes. A host process with one of the same mapped identities can signal a
scanner and disrupt its scan.

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
- creates no file when it is Nmap. Naabu keeps its target list and address
  map in a per-invocation leaf below `/tmp`; Landlock grants file and directory
  access only to that leaf, and does not let Naabu execute files there;
- with Landlock ABI 6 (Linux 6.12) or later, cannot signal processes outside
  its restriction, such as the daemon, or connect to their abstract UNIX
  sockets.

The restriction applies whatever identity the process runs as. A process
cannot lift it, and every process it starts inherits it. Scanner launches do
not fall back to UID 0 when the container lacks the capabilities required for
the leased identity pool; they fail closed instead.

`scanner.landlock` in `config.yaml` selects it. When Landlock is unavailable
in `auto` mode, each invocation still uses its own leased UID/GID and seccomp
filter. The different UID prevents another scanner invocation from opening
that invocation's temporary leaf by path. Landlock adds a separate
per-process file boundary. `required` refuses daemon startup and direct scan
commands without Landlock.

| Value | Behaviour |
| --- | --- |
| `auto` (default) | Restricts scanner processes when the kernel provides Landlock. Otherwise they start without it, and EdgeWatch logs why. |
| `required` | Refuses daemon startup and direct scan commands when scanner processes cannot be restricted. |
| `off` | Starts scanner processes without Landlock. |

`scanner.sandbox: off` turns off Landlock too and skips the sandbox
compatibility checks. With sandboxing enabled, the startup check runs the
configured Nmap executable with only `--version`, without a target. When this
command fails under Landlock, `auto` verifies it again with the mandatory
identity and seccomp restrictions before continuing without Landlock. If that
control fails too, scanner launches are unavailable rather than running with a
weaker policy. `required` refuses daemon startup and direct scan commands when
Landlock is unavailable.
`scanner_sandbox.landlock.state` in `edgewatch health` reports the outcome,
and `abi` the kernel's Landlock version. When Landlock is `required`, an
unavailable result prevents daemon startup and direct scan commands.

Docker's default seccomp profile permits the Landlock system calls. A custom
profile must allow `landlock_create_ruleset`, `landlock_add_rule` and
`landlock_restrict_self`, or Landlock is reported unavailable.

### Seccomp filter

The `sandbox-exec` command installs a seccomp filter on top of the container's
seccomp profile whether or not Landlock is enabled. The scanner keeps the
filter, and so does every process the scanner starts. The filter:

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

Except for one brokered request shape, the filter refuses Unix sockets and
socket pairs. Nmap's interface-name lookup uses a specific Unix datagram socket
request, so the supervisor handles that request and gives Nmap a verified IPv4
datagram socket for the ioctl.
Scanners receive no Unix socket through their inherited descriptors. If the
broker cannot complete the reply, the supervisor kills and reaps the process
tree before it can prove cleanup and release the identity; an unproven cleanup
keeps the identity quarantined.

Docker's default profile already refuses most of these calls. The filter
keeps them refused under a runtime or profile that does not, and it refuses
`ptrace` and io_uring, which recent Docker profiles allow. With sandboxing
enabled, startup first checks the filter with a harmless command, then runs the
configured Nmap compatibility command with it. If Nmap fails under both
Landlock and the identity-and-seccomp control, scanner launches fail closed;
EdgeWatch does not run without seccomp. `scanner_sandbox.seccomp` in
`edgewatch health` reports whether the filter itself was verified as
`enforced`, `unavailable` with the reason, or `disabled`. The filter applies
independently of Landlock:
`scanner.landlock: off` leaves it enabled, while `scanner.sandbox: off`
disables it.

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

Naabu also creates temporary target and address-map files of its own. With
scanner identity isolation enabled, EdgeWatch creates a daemon-owned
invocation namespace below `/tmp` with mode `0731` while a helper creates the
mode `0700` leaf owned by that invocation's leased UID/GID. The namespace group
is the invocation's unique leased GID, and the helper has no supplementary
groups; the daemon verifies the namespace owner, group, and mode before use.
It creates this group-writable namespace only when the pinned `/tmp` directory
is root-owned, is not setgid, and either grants no group/other write access or
has the sticky bit set. These checks keep scanner peers from renaming another
namespace in a writable parent and ensure parent group inheritance cannot
grant a different group write access. The daemon sets the filesystem GID on a
locked OS thread for the namespace creation syscall and verifies restoration
before that thread can be reused. After the helper reports readiness, the
daemon changes the pinned namespace to mode `0711` before acknowledging
startup. The daemon remains its
owner and can remove the leaf; other identities can search the namespace but
cannot add sibling entries. With identity isolation enabled, concurrent
scanners use different identities and cannot open each other's randomly named
leaves by path. When Landlock is available, it also confines each scanner to
its own leaf. With the sandbox explicitly off, the daemon uses a normal
`0711` namespace and owns its `0700` leaf, with no scanner isolation boundary.

In sandboxed mode the scanner controls the permissions and contents of its own
leaf. After the supervisor proves the process tree exited and was reaped, the
trusted cleanup helper verifies the pinned leaf's identity, restores its mode
to `0700`, and removes nested entries without following symbolic links.
Cleanup is iterative and bounded to 100,000 entries and ten seconds. It then
removes the empty leaf and namespace. If identity checks, traversal, or cleanup
fail, the scan fails, its results do not become a successful observation or
advance the baseline, artifacts remain, and the UID is quarantined rather than
released for reuse.
If setup fails before a supervised scanner process starts, the unused lease is
released because no scanner process could have used it. For a started process,
the lease is released only when the supervisor proves that descendants were
reaped and invocation cleanup succeeds.

A sandboxed scanner cannot list `./data` or reach a file below it by its name,
and Landlock never grants the data directory to a scanner. With Landlock, a
scanner reaches only the files of its own scan through the descriptors it
inherits. Without Landlock, each concurrent invocation still has a distinct
UID/GID, so DAC and procfs access checks separate its temporary leaf and
inherited descriptors from peer scanner identities. Landlock remains the
stronger per-process file boundary. The bundled `compose.yaml` sets `TMPDIR` to
`/var/lib/edgewatch/tmp` for the daemon's other temporary files, such as
SQLite's, so they share the data volume rather than the 128 MiB `/tmp`
tmpfs.

### Stopping scanners

Each Nmap and Naabu invocation runs in its own process group under a supervisor;
Nmap also uses its private pseudo-terminal. When a scan is cancelled, times
out, or a scanner exceeds an output bound, EdgeWatch kills the whole group.
When the scanner exits, its supervisor kills what remains in the group and
reaps adopted descendants before returning a cleanup proof. EdgeWatch waits a
bounded time for that proof and for the scanner's output pipes and Nmap's
terminal to close. It fails the scan if the process tree cannot be proven gone,
retains its temporary artifacts, and quarantines the leased identity while any
process still holds its liveness reference. It only removes scan files and
releases the lease after the proof and cleanup succeed. The
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

When the Linux scanner helper is available, it sets the following limits
before it execs each scanner process. Every process the scanner starts
inherits them. With Landlock, `sandbox-exec` sets the limits before it
restricts the scanner:

- `oom_score_adj` is `1000`, the highest value, so that when the container or
  host runs out of memory the kernel's out-of-memory killer stops a scanner
  before the daemon, which every business unit shares. The scan fails; the
  daemon keeps running.
- The soft and hard open file limits are at most 65,536 descriptors. Nmap
  raises its soft limit to the hard limit for connect scans, and Naabu keeps
  at most 65,408 connect sockets in flight, the limit less 128, however high
  its rate.
- For Nmap only, the soft and hard per-file size limits are 16 MiB plus one
  byte. The parser accepts at most 16 MiB; the extra byte lets EdgeWatch
  recognize an oversized XML file after Nmap exits, including when it exits
  before the next 200 ms size poll. The limit is inherited by Nmap's children.

`scanner_sandbox.limits` in `edgewatch health` reports them, as
`oom_score_adj` and `max_open_files`; it is absent when Landlock does not
apply. When Landlock is disabled but the Linux helper is available, it still
sets the OOM, open-file, and Nmap file-size limits before exec. The Nmap
file-size limit is not included in `scanner_sandbox.limits`, which reports
only the OOM score and open-file limit. If no helper starts the scanner,
including with `scanner.sandbox: off`, or on non-Linux systems, EdgeWatch uses
its 200 ms output polling and final size check without an OS per-file limit; a
fast writer can exceed 16 MiB before it is stopped or exits. EdgeWatch sets no
process count limit (`RLIMIT_NPROC`), which the
kernel counts for the scanner's UID across all of its scans, threads, and
other containers that use the same UID, and no address space or data limit,
which would fail large scans whose memory needs the release matrix does not
cover.

### Core dumps

On Linux, EdgeWatch sets its soft and hard core file size limits to zero,
sets `/proc/self/coredump_filter` to zero and reads it back, then clears the
dumpable flag before starting any command or child. A re-executed EdgeWatch
child verifies an already-zero inherited filter when Landlock prevents
rewriting the proc control file; startup stops if the filter is nonzero or
cannot be read. Children inherit the core limit and filter across `fork` and
`exec`; the limit cannot be raised by them. The zero filter excludes normal
memory mappings from core data. Linux always includes the vDSO mapping, and
the filter does not prevent the kernel from invoking a configured piped core
handler or prevent that handler from receiving core metadata. The `RLIMIT_CORE`
limit is not enforced for piped handlers. A non-dumpable process cannot be
traced, and its memory cannot be read, by another process of its identity
without `CAP_SYS_PTRACE`.

### Upgrading an existing deployment

A `compose.yaml` from an earlier release adds only `NET_RAW`. With it,
the daemon can start, but `scanner.sandbox: auto` reports the identity pool
unavailable and refuses scanner launches; it does not run scanners as UID 0,
even when Landlock is available. Add the three capabilities to enable the
scanner identity pool:

```yaml
    cap_add:
      - NET_RAW
      - SETUID
      - SETGID
      - KILL
```

Then recreate the container with `docker compose up -d`. No database schema
migration is needed; `./data` keeps its UID 0 ownership. Keep the allocator
journal and boot marker with that data directory. A quarantined identity stays
unavailable while any process holds its liveness reference. A clean container
restart can archive and reset the old scope after every EdgeWatch process using
the volume has exited and the new private PID namespace is verified. Older v2
lease state has no liveness references and may require a host reboot or the
documented recovery command. If the marker or journal is unreadable or invalid,
the pool remains fail-closed and needs storage recovery. Do not delete journal
entries to recover capacity.

### What the sandbox does not cover

- The daemon, which serves the console and holds the database and keys, still
  runs as UID 0 with the container's capabilities.
- The identity pool has 64 scanner UIDs/GIDs. Concurrent invocations use
  different identities, so filesystem ownership and procfs access checks
  separate their temporary files and inherited descriptors even when
  Landlock is unavailable. Landlock adds a per-process file boundary. These
  file boundaries do not hide Nmap command lines: each invocation's arguments
  include its target addresses and port list, which another scanner can read
  from `/proc/<pid>/cmdline` without ptrace access. A compromised scanner can
  learn the scope of concurrent Nmap scans.
- Seccomp is independent of Landlock and remains required in sandboxed scanner
  modes. It prevents a scanner from creating namespaces or leaving its
  supervised process group. If seccomp cannot be installed, scanner launches
  fail closed. `scanner.sandbox: off` disables the pool, Landlock and seccomp.
- A scanner process keeps its network access; target exclusions and probe
  budgets are enforced by EdgeWatch before it starts. When the container uses
  host networking, scanners retain `NET_RAW`, so the sandbox does not isolate
  scan traffic; a compromised scanner may be able to observe packets from
  concurrent scans.
- On a kernel without Landlock, a sandboxed process can read every file its
  identity may read.

## Deployment alerts

A Compose edit that drops `SETUID`, `SETGID`, or `KILL` makes the scanner pool
unavailable and scanner launches fail closed. A kernel without Landlock
removes that file-restriction layer but leaves the leased identity and seccomp
filter in place. The daemon compares, when it starts and with each heartbeat,
the scanner pool, Landlock, seccomp, and notification sandbox with the state
that the last deployment alert reported. A scanner pool that becomes
unavailable, or a sandbox that loses Landlock, records one
`application.health_alert` in the platform audit and sends it to the platform
destinations selected for **Deployment alerts**; a sandbox that regains a
layer records one recovery. A restart with the same state
records nothing, and each sandbox raises at most one alert an hour, so a
restart loop cannot flood a destination. The first start of v0.36.0 records
the current state and reports it once when it is already degraded. A daemon
that does not run as root counts as confined by identity, and a sandbox set
to `off` as unconfined when the daemon runs as UID 0. See
[Notifications](/user-guide/notifications/#deployment-alerts), which also
describes the scheduled-backup, low-identity-capacity, rollback, and
failed-delivery alerts. A low-identity alert means quarantined identities,
active leases held by other processes, and identities in use by processes
without a lease leave the daemon's scans fewer than
`scheduler.max_concurrent_scans`; its own running scans are excluded. Restart
the container once no other EdgeWatch process uses the data volume, or lower
that limit until capacity recovers. The daemon inspects the pool with each
heartbeat only when startup enforced it: a pool that was unavailable at
startup, as for a daemon that does not run as root, is not inspected again,
and an inspection that starts to fail is logged once, not with each
heartbeat.
`scanner.sandbox: required` and `notifications.sandbox: required` remain the
way to refuse to run degraded.

## Notification sandbox

Each notification is delivered by a short-lived child process, so a fault in
a provider cannot stop the daemon. The child receives one destination URL and
the message, and needs no other private data. `notifications.sandbox` in
`config.yaml` selects how it starts:

| Value | Behaviour |
| --- | --- |
| `auto` (default) | Starts the notification process in the sandbox when the container allows it. Otherwise it starts unconfined, and EdgeWatch logs a warning and adds it to `edgewatch health` when it runs as UID 0, and, from v0.36.0, records a [deployment alert](#deployment-alerts). |
| `required` | Refuses to start the daemon, or `edgewatch notify test`, when the sandbox is unavailable. |
| `off` | Starts the notification process unconfined, as releases before the sandbox did, without Landlock. |

A sandboxed notification process:

- runs as UID and GID 65531 (`edgewatch-notify`) with no supplementary groups
  and no capabilities. It has an identity of its own, so a compromised
  scanner process can neither signal it nor read its memory;
- is restricted with [Landlock](#landlock), when the kernel provides it, to the
  same system files as a scanner process, without `/tmp`: it can write no file
  at all. The notifier's [seccomp filter](#seccomp-filter) is installed through
  this helper path too. Without Landlock, the notifier runs without that filter;
  `edgewatch health` reports the Landlock and seccomp states separately;
- calls `HardenProcess` before it reads the request from stdin, keeps the
  destination URL out of argv and the environment, and remains non-dumpable
  until it exits. Same-UID processes cannot trace it or read the URL from its
  memory;
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
