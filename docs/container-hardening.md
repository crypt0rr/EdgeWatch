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
a writable data bind mount. It verifies that the normal root deployment can
create SQLite state and that scanner capability checks fail closed instead of
guessing from the UID.

## Data ownership and upgrades

`./data` is intentionally written by the container's runtime UID. Keep the
directory and its SQLite sidecars together when backing up or upgrading. The
same UID is retained across image versions, so existing databases, WAL files,
authentication keys, and notification keys remain writable without an
ownership migration. Do not change the Compose `user:` setting on an existing
installation unless you have tested ownership and every configured scan mode
with a copy of the data directory.

Rootless Docker remains supported: in that mode container UID 0 is mapped to
the invoking host user. A normal rootful Docker host should not make `./data`
world-writable just to simulate rootless behavior.

## Reconsidering a non-root default

A future hardening change can revisit this decision after all supported Docker
and rootless/containerd combinations provide a documented way to grant the
minimum raw-packet capabilities to a non-root scanner process. It must also
cover Nmap UDP, Naabu SYN, read-only filesystems, bind-mounted ownership, and
upgrade rollback before changing the default. Until then, retaining UID 0
with the controls above is safer than shipping a default that only works for
TCP connect scans.
