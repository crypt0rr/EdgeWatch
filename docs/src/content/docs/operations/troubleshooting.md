---
title: Troubleshooting
description: Diagnose storage permissions, proxy rejection, incomplete scans, notification failures, RDAP behind a proxy, and upgrade progress.
---

Start with a bounded log summary and the host health report:

```sh
docker compose logs --tail 100 edgewatch
docker compose exec edgewatch edgewatch health \
  --config /etc/edgewatch/config.yaml --output json
```

Keep credentials, setup tokens, target information, and encryption keys out of
public issue reports. Health exits non-zero for unhealthy migrations or a
missing daemon heartbeat; its warnings also list actions that do not stop the
service. See [Host commands](/reference/cli/) for output and exit behavior.

## Permission denied on startup

The container runs as UID 0 with filesystem capabilities dropped. The data
mount must be owned by the host identity mapped to container UID 0, with mode
`0750`; separately mounted secrets must be readable by that identity and
private to their owner. Run the actual read/write preflight in
[Installation](/getting-started/installation/) and inspect the mapping for your
Docker mode. Stop the service before correcting an existing directory's
ownership. World-readable or world-writable permissions are not a remedy.

## Scanner processes run unconfined as UID 0

EdgeWatch logs this warning, adds it to `edgewatch health`, and shows it on the
Overview when `scanner.sandbox` is `auto` and Nmap and Naabu cannot run in the
[scanner sandbox](/deployment/container-hardening/#scanner-sandbox). The
reason names the cause:

- **The container does not grant SETUID, SETGID, KILL.** Your `compose.yaml`
  predates the sandbox. Add the three capabilities to `cap_add`, as in the
  bundled file, and recreate the container with `docker compose up -d`.
- **A test process could not start as UID 65532.** The container runtime does
  not map UID 65532 into the container's user namespace. Use a full
  subordinate UID range for rootless Docker or user-namespace remapping.

Scans keep working as UID 0 in either case. Where the kernel provides
[Landlock](/deployment/container-hardening/#landlock), the warning reads
"scanner processes run as UID 0, restricted only by Landlock": scanner
processes still cannot read the database, keys, or configuration. Set
`scanner.sandbox: required` to refuse to scan without the sandbox instead.

## The notification process runs unconfined as UID 0

EdgeWatch logs this warning and adds it to `edgewatch health` when
`notifications.sandbox` is `auto` and the process that delivers
notifications cannot run in the
[notification sandbox](/deployment/container-hardening/#notification-sandbox).
The reason names the cause:

- **The container does not grant SETUID, SETGID, KILL.** As for the scanner
  sandbox, add the three capabilities to `cap_add`.
- **A test notification process could not start as UID 65531**, with
  `read SSL_CERT_FILE` or `read SSL_CERT_DIR` and a file name. A private
  certificate authority is mounted with a mode that UID 65531 cannot read.
  Certificates are public: make the file readable by others, for example
  with mode `0644`, and its directory searchable, then recreate the
  container.

Notifications keep being delivered in either case. Where the kernel provides
Landlock, the warning reads "the notification process runs as UID 0,
restricted only by Landlock": the process still cannot read the database,
keys, or configuration. Set `notifications.sandbox: required` to refuse to
start without the sandbox instead.

## Scanner processes start without Landlock

EdgeWatch logs this at startup, with the reason, and `edgewatch health`
reports `scanner_sandbox.landlock.state` as `unavailable`, when
`scanner.landlock` is `auto` and Nmap and Naabu cannot be restricted with
[Landlock](/deployment/container-hardening/#landlock):

- **The kernel does not provide Landlock, or the container's seccomp profile
  blocks it.** The host kernel is older than Linux 5.13 or built without
  Landlock, or a custom seccomp profile denies the `landlock_*` system calls.
  Use Docker's default profile or allow those calls.
- **Landlock is built into the kernel but not enabled.** Add `landlock` to
  the host's `lsm=` boot parameter, or to `CONFIG_LSM`, and reboot.
- **nmap could not start with Landlock.** Nmap, or a library it loads, lies
  outside the paths the restriction allows, as in a modified image. The
  reason ends with Nmap's last diagnostic line.

Scans keep working without Landlock, in the identity sandbox when it is
enforced.

`scanner_sandbox.seccomp.state` is `unavailable` when the kernel offers no
seccomp filters, or the container's seccomp profile blocks them, or when
Nmap could not start with the [seccomp filter](/deployment/container-hardening/#seccomp-filter).
In that case Landlock still applies alone, and the reason names the cause. Set `scanner.landlock: required` to refuse to scan without it
instead, or `scanner.landlock: off` to stop trying.

## Proxy hostname rejected

A `421 Misdirected Request` when loopback requests succeed usually means the
public hostname is missing from `web.allowed_hosts`. Use the bare hostname,
then recreate the container after editing configuration. Follow
[Reverse proxies](/deployment/reverse-proxies/) for the two-request diagnostic,
forwarded HTTPS handling, and trusted client attribution.

## Scans appear stuck or incomplete

Open the run's live details first. Broad scans report scanner phase, process
heartbeat, completed probes, and resumable work. A zero-progress display alone
does not mean that the scanner is idle. A timeout preserves work for the resume
window; partial or failed observations cannot change the baseline.

A stalled cycle holds scheduled runs until it is retried, discarded, or its
resume window ends. The first scheduled run after expiry records the expiry;
the next starts a fresh cycle. Read [Scanning and profiles](/user-guide/scanning/)
and [Host commands](/reference/cli/) before changing scan scope or retrying.

## Destinations are locked or delivery fails

Inspect the destination's health on **Notifications**. After restoring a key,
run `notify test` from [Host commands](/reference/cli/): it checks enabled
web-managed destinations across the deployment and reports `deployment_locked`
without printing URLs. Console tests cover only the current unit's destinations.

Restore the original database and notification key together. A missing key
cannot be recovered from the database alone. The restore refuses a backup
that the configured keys cannot open and reports the locked counts in
`key_check`; `verify --from` reports them for a backup file without a
restore. Paused destinations retain their
queue without consuming retries; URL replacement discards queued alerts unless
you select **Keep queued alerts**. After an outage, an administrator can
redeliver a destination's alerts that ran out of retries from its **Failed
alerts**. The error code `destination_excluded` means the destination's host
resolves to an address that `scanner.target_exclusions` or the loopback and
link-local rules refuse, and `provider_timeout` that the provider did not
answer within 15 seconds. See [Notifications](/user-guide/notifications/) for
retries, terminal failures, destination addresses, and legacy-import warnings.

## RDAP is unavailable behind a proxy

RDAP lookups ignore `HTTPS_PROXY` and the other proxy variables and need
direct HTTPS egress to IANA and the regional registries. When only a proxy
reaches the internet, host pages show RDAP as unavailable and the daemon logs
"RDAP lookups ignore the proxy environment" at startup. Set
`enrichment.rdap.enabled: false` in
[deployment configuration](/reference/configuration/).

## Upgrade or restore needs migration

Only the daemon upgrades the database. Some migrations rebuild projections or
finish deletion cleanup in restartable background batches. `health` reports
maintenance progress and `verify` lists checkpoints. Host commands that need
the upgraded schema refuse an older restored schema until the daemon starts.

An older binary refuses a database upgraded beyond its supported version.
Rollback requires a matching pre-upgrade backup; do not replace a live database.
Follow [Database compatibility](/reference/database-compatibility/) and
[Backup and recovery](/operations/backup-recovery/).
