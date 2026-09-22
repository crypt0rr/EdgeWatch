# Container runtime hardening

EdgeWatch deliberately keeps the final container process as UID 0 in the
current release. This is a compatibility decision, not a requirement for the
web application: Nmap UDP and SYN scans, and Naabu SYN discovery, require raw
packet privileges. On the supported Docker engines tested for EdgeWatch,
`--cap-add NET_RAW` (and, for Naabu SYN, `NET_ADMIN`) is effective for the
root container process but is removed when Docker starts the process directly
as an unprivileged UID. A non-root default would therefore make existing UDP
and TCP SYN jobs fail or require a job-dependent privilege transition.

The image and Compose deployment still apply the following controls:

- all capabilities are dropped first;
- the base deployment adds only `NET_RAW`;
- `compose.syn.yaml` is an explicit administrator opt-in for `NET_ADMIN`;
- `no-new-privileges` is enabled;
- the root filesystem is read-only and only `/tmp` is writable through a
  bounded tmpfs;
- SQLite state is limited to the explicit `./data` bind mount;
- Compose grants a seven-minute stop grace period so the daemon can cancel
  scanner processes and persist large snapshots within its six-minute
  graceful-shutdown deadline;
- scanner executables and their argument surface are fixed by EdgeWatch, and
  the web listener remains loopback-only.

## Compatibility matrix

The release workflow runs the following matrix against the image before it is
published:

| Runtime | Capabilities | Supported work | Result |
| --- | --- | --- | --- |
| UID 0, base Compose | `NET_RAW` | Nmap TCP SYN/connect, Nmap UDP, Naabu connect | supported |
| UID 0, `compose.syn.yaml` | `NET_RAW`, `NET_ADMIN` | Naabu SYN in addition to the base modes | supported |
| UID 65532, experimental probe | none effective (even when `NET_RAW` is requested) | Naabu connect and Nmap TCP connect only | supported for those modes; not a supported default |
| UID 65532, experimental probe | none effective | Nmap SYN or UDP, Naabu SYN | rejected by the scanner or unavailable |

The matrix also runs the image with a disposable read-only root filesystem and
a writable data bind mount owned by the identity mapped to container UID 0. It
verifies that the normal root deployment can create SQLite state without
world-writable permissions and that scanner capability checks fail closed
instead of guessing from the UID.

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
Do not change the Compose `user:` setting on an existing installation unless
you have tested ownership and every configured scan mode with a copy of the
data directory. Never use mode `0777` as a workaround; it masks ownership
errors and weakens protection for databases and encryption keys.

## Reconsidering a non-root default

A future hardening change can revisit this decision after all supported Docker
and rootless/containerd combinations provide a documented way to grant the
minimum raw-packet capabilities to a non-root scanner process. It must also
cover Nmap UDP, Naabu SYN, read-only filesystems, bind-mounted ownership, and
upgrade rollback before changing the default. Until then, retaining UID 0
with the controls above is safer than shipping a default that only works for
TCP connect scans.
