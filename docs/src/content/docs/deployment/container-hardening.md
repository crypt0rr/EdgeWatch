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

The daemon itself keeps UID 0 for compatibility. Nmap UDP and SYN scans, and
Naabu SYN discovery, need raw-packet privileges. On the supported Docker
engines, `--cap-add NET_RAW` (and, for Naabu SYN, `NET_ADMIN`) is effective for
the root container process but is removed when Docker starts the process
directly as an unprivileged UID. The daemon therefore receives the
capabilities and hands only the raw-packet ones to each scanner process.

The image and Compose deployment still apply the following controls:

- all capabilities are dropped first;
- the base deployment adds `NET_RAW` for the scanners, and `SETUID`, `SETGID`
  and `KILL` so the daemon can start scanner processes as the sandbox identity
  and stop them;
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
change to either file that drops one of them fails CI.

## Compatibility matrix

The release workflow runs the following matrix against the image before it is
published:

| Runtime | Capabilities | Supported work | Result |
| --- | --- | --- | --- |
| UID 0 daemon, base Compose | `NET_RAW`, `SETUID`, `SETGID`, `KILL` | Nmap TCP SYN/connect, Nmap UDP, Naabu connect, each in the sandbox as UID 65532 with `NET_RAW` | supported |
| UID 0 daemon, `compose.syn.yaml` | the above and `NET_ADMIN` | Naabu SYN in addition to the base modes, in the sandbox with `NET_RAW` and `NET_ADMIN` | supported |
| UID 0 daemon, `NET_RAW` only | `NET_RAW` | the base modes, unconfined as UID 0 | supported; the sandbox is unavailable and EdgeWatch warns |
| UID 65532, experimental probe | none effective (even when `NET_RAW` is requested) | Naabu connect and Nmap TCP connect only | supported for those modes; not a supported default |
| UID 65532, experimental probe | none effective | Nmap SYN or UDP, Naabu SYN | rejected by the scanner or unavailable |

The matrix also runs the image with a disposable read-only root filesystem and
a writable data bind mount owned by the identity mapped to container UID 0. It
verifies that the normal root deployment can create SQLite state without
world-writable permissions and that scanner capability checks fail closed
instead of guessing from the UID. It runs real Nmap SYN, Nmap UDP and Naabu
scans of local listeners through EdgeWatch with the sandbox enforced and with
it off, requires the same results from both, and checks that the sandbox
identity cannot read the data directory.

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
| `auto` (default) | Starts Nmap and Naabu in the sandbox when the container allows it. Otherwise they start unconfined as UID 0, and EdgeWatch logs a warning, adds it to `edgewatch health`, and shows it on the Overview for administrators. |
| `required` | Refuses to start the daemon, or `edgewatch scan`, when the sandbox is unavailable. |
| `off` | Starts scanner processes unconfined, as releases before the sandbox did. |

A sandboxed scanner process:

- runs as UID and GID 65532 (`edgewatch-scanner`) with no supplementary
  groups;
- keeps `NET_RAW`, and `NET_ADMIN` when the container grants it, as ambient
  capabilities and no other capability;
- cannot read or list `./data`, which belongs to UID 0 with mode `0750`, or
  read `config.yaml`; it reads its target list and writes its results through
  file descriptors that EdgeWatch passes to it;
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
`reason` explains a sandbox that is not enforced. The Overview's deployment
footprint shows the same state.

The sandbox needs the user namespace of the container to map UID 65532. Standard
rootful Docker, rootless Docker, and user-namespace remapping with a full
subordinate range all do. A runtime that maps only a few UIDs reports the
sandbox as unavailable.

### Upgrading an existing deployment

A `compose.yaml` from an earlier release adds only `NET_RAW`. With it,
`auto` keeps scanning unconfined as UID 0 and warns. Add the three
capabilities to enable the sandbox:

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
- All sandboxed scanner processes share UID 65532, so a compromised scanner
  process could observe other scans that run at the same time.
- A scanner process keeps its network access; target exclusions and probe
  budgets are enforced by EdgeWatch before it starts.
- Notification delivery runs in its own child process, which is not yet
  sandboxed.

A non-root daemon remains unsupported until the supported Docker and
rootless or containerd combinations provide a documented way to grant it the
capabilities above, with read-only filesystems, bind-mounted ownership and
upgrade rollback covered.
