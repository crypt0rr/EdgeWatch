---
title: Troubleshooting
description: Monitor the daemon from outside, and diagnose storage permissions, proxy rejection, incomplete scans, notification failures, RDAP behind a proxy, and upgrade progress.
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

## Monitor the monitor

The job silence alert and the deployment alerts are raised by the daemon
itself, so they cannot report a daemon that stopped or hangs. From v0.36.0,
an uptime checker can poll `GET /healthz` on the console's listener:

```sh
curl -fsS http://127.0.0.1:8080/healthz
```

It needs no session and no approved host name, and answers only
`{"status":"ready"}` with `200`, or with `503` `{"status":"starting"}` while
the daemon starts and migrates the database, or `{"status":"unhealthy"}`: for
a stalled migration, a daemon heartbeat older than two minutes or missing, or
a database that cannot be read. The daemon opens its listener before it
migrates the database, so a long upgrade answers `starting` instead of
refusing the connection, and every other path answers `503` until the
console is up. A migration that fails ends the daemon, and its listener with
it, so count a check that gets no answer as unhealthy; `edgewatch health`
and the daemon log report the error. The answer names no reason and no
unit; run `edgewatch health` for the details. Each client may send 120 requests a
minute, as for the public status pages, and gets `{"status":"rate_limited"}`
with `429` beyond that. The answer is reused for one second.

For Prometheus, turn on the opt-in `GET /metrics` with `web.metrics.enabled`
and a bearer token in `web.metrics.token_file`; see
[the configuration reference](/reference/configuration/#metrics). It reports
deployment aggregates only, such as heartbeat age, migration state, scan
slots, notification backlog, locked destinations, database size, sandbox
states, scheduled-backup outcomes, scanner identity counts, skipped scheduled
runs, overdue jobs, and stalled cycles. It never includes a unit name, job, or
target, and caches operational values for up to 30 seconds. Alert on
`edgewatch_backup_status_known` equal to zero as well as on consecutive backup
failures. Once the daemon has opened its database, the status-known metric is
present whenever scheduled backups are enabled; it is zero when the status
file is missing, unreadable, belongs to another configured directory, or has
no recorded outcome. This keeps an unavailable status visible while the
failure and last-success metrics are omitted. For example:

```yaml
groups:
  - name: edgewatch
    rules:
      - alert: EdgeWatchBackupStatusUnknown
        expr: edgewatch_backup_status_known == 0
        annotations:
          summary: EdgeWatch scheduled backup status is unknown
          description: The configured backup status has no readable recorded outcome.
      - alert: EdgeWatchBackupFailures
        expr: edgewatch_backup_status_known == 1 and edgewatch_backup_consecutive_failures > 0
        annotations:
          summary: EdgeWatch scheduled backups are failing
          description: The scheduled backup failure count is {{ $value }}.
```

The unknown-status alert clears when status becomes readable with a recorded
outcome. A failure alert remains active when that outcome still reports
failures. Both clear after a successful backup is recorded for the configured
directory; a directory change, a timestamp without a backup filename, or a
missing status file does not count as recovery. The daemon's durable
deployment alert follows the same recovery rule. Also alert on
`edgewatch_scanner_identities{state="free"}` below your
`scheduler.max_concurrent_scans`; deployment alerts also report a new failure
transition to platform destinations. The metric names are listed in
[the API reference](/reference/api-compatibility/#health-and-metrics). Keep
`/metrics` off a public reverse proxy; see
[Reverse proxies](/deployment/reverse-proxies/).

A lost or replaced notification key locks every web-managed destination, the
platform's too, so no alert can report it, and `/healthz` stays `ready`
because the daemon keeps running. Alert on
`edgewatch_notification_destinations_locked` above zero, or run
`edgewatch notify test` after a restore; see
[Destinations are locked or delivery fails](#destinations-are-locked-or-delivery-fails).

## Permission denied on startup

The container runs as UID 0 with filesystem capabilities dropped. The data
mount must be owned by the host identity mapped to container UID 0, with mode
`0750`; separately mounted secrets must be readable by that identity and
private to their owner. Run the actual read/write preflight in
[Installation](/getting-started/installation/) and inspect the mapping for your
Docker mode. Stop the service before correcting an existing directory's
ownership. World-readable or world-writable permissions are not a remedy.

## Scanner launches are unavailable

When `scanner.sandbox` is `auto`, EdgeWatch keeps the daemon running but fails
scanner launches closed if the [scanner identity pool](/deployment/container-hardening/#scanner-sandbox)
or required seccomp filter cannot be enforced. The reason appears in
`edgewatch health`, the Overview, and the deployment footprint. Follow the
action it names:

- **The container does not grant SETUID, SETGID, KILL.** Your `compose.yaml`
  predates the scanner identity pool. Add the three capabilities to `cap_add`,
  as in the bundled file, and recreate the container with
  `docker compose up -d`.
- **Scanner UID/GID 60000 is not mapped.** The user namespace does not map the
  complete scanner range, 60000–60063. Configure the full subordinate UID and
  GID ranges for rootless Docker or user-namespace remapping, then recreate
  the container.
- **The scanner identity allocator could not prove the previous private scope
  safe after a PID namespace change.** When using the v3 allocator, ensure the
  supported private scanner runtime is active. Stop every other EdgeWatch
  process or container using the data volume, including direct host commands,
  so inherited liveness references close, then retry. Once it has exclusive
  proof, the allocator can archive and reset the prior scope without a host
  reboot. Preserve the journal and boot marker; do not delete or edit them.

  A nonempty v2 journal from v0.40.0 or earlier has no liveness references and
  cannot be reclaimed automatically. Follow the [v2-to-v3 recovery steps](/deployment/container-hardening/#upgrading-an-existing-deployment),
  including `scanner-identities recover --confirm-all-volume-users-stopped`.

EdgeWatch does not run scanners as UID 0 when the pool is unavailable. Set
`scanner.sandbox: required` if the daemon should also refuse startup until the
identity pool and required seccomp filter are available.

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
  outside the paths the restriction allows, as in a modified image. In
  `scanner.sandbox: auto`, EdgeWatch retries the configured Nmap version
  command with the mandatory identity and seccomp controls. If that succeeds,
  scans continue without Landlock and startup/health report the fallback. If
  that fails too, scanner launches are unavailable; they do not continue with
  a weaker identity or without seccomp. The reported reason is sanitized and
  does not include Nmap's raw diagnostic output. `scanner.landlock: required`
  refuses startup instead.

When health reports Landlock unavailable but the scanner state is enforced,
scans keep working with the leased identity and seccomp. When the scanner state
is unavailable, the daemon can remain running in `auto`, but scans fail closed
until the configured Nmap binary works with the mandatory controls.

`scanner_sandbox.seccomp.state` is `unavailable` when the kernel offers no
seccomp filters or the container's seccomp profile blocks the filter probe.
The configured Nmap compatibility command is also checked with seccomp. If
that command cannot start even with identity isolation and seccomp, the overall
scanner state becomes unavailable while the seccomp field continues to report
the filter's independently verified status. In `scanner.sandbox: auto` and
`required`, scanner launches fail closed; Landlock alone is never a fallback.
`scanner.landlock: required` controls Landlock only. Setting
`scanner.landlock: off` does not disable seccomp. Restore seccomp support, or
set `scanner.sandbox: off` only when you intend to run scanners without the
identity, Landlock, and seccomp layers.

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
the next starts a fresh cycle. When the window ends while a run is working on
the cycle, that run records the expiry as timed out, once, and the next run
starts a fresh cycle. Read [Scanning and profiles](/user-guide/scanning/)
and [Host commands](/reference/cli/) before changing scan scope or retrying.

If a completed cycle's result cannot be finalized, EdgeWatch retries promotion
from the saved work once. After the second persisted finalization failure, the
cycle remains available until its next trigger. That trigger discards the saved
work and plans a fresh scan; the server log records a WARN with the discarded
cycle ID. Repeated warnings mean the merged result still cannot be finalized;
reduce the job's scan scope or address the reported storage problem.
Notification-destination lookup failures do not count toward this limit; after
correcting the destination configuration, the next trigger can still promote
the completed result. A process restart between cycle completion and
scan-history insertion also keeps the existing recovery path.

A scan that fails with `expanded targets exceed scanner.max_job_hosts=65536`
covers more addresses than one job may scan; split its targets into several
jobs, or raise `scanner.max_job_hosts` together with the container's memory.
A scan that fails because a scanner `left a process holding its output open`
or `holding its terminal open` ran a scanner that started a process outside
its process group; check that `/usr/bin/nmap` and `/usr/local/bin/naabu` are
the image's own.

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
resolves to an address that `scanner.target_exclusions` or the loopback,
link-local, or interface-local multicast rules refuse. A DNS failure is refused before sending but remains
retryable; it does not receive `destination_excluded`. `provider_timeout`
means the provider did not answer within 15 seconds. See
[Notifications](/user-guide/notifications/) for retries, proxy behavior,
terminal failures, destination addresses, and legacy-import warnings.

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

A database older than schema 54, written by a release before v0.20.0, is
refused with `upgrade through v0.35.0 first` and left unchanged; update
through v0.35.0 as described under
[Upgrade from a release before v0.20.0](/deployment/updates/#upgrade-from-a-release-before-v0200).
A daemon that exits with `another EdgeWatch process is migrating or restoring
the database in this directory` found another daemon migrating the database
on the same data volume, or a restore replacing it. Let the restore finish,
or make sure that only one daemon uses the volume, and start the service
again. Once the other daemon has completed startup and holds its lease, the
second daemon instead exits with `another EdgeWatch daemon holds the database
lease`; stop one daemon before starting another on the same database.

An older binary refuses a database upgraded beyond its supported version.
Rollback requires a matching pre-upgrade backup; do not replace a live database.
Follow [Database compatibility](/reference/database-compatibility/) and
[Backup and recovery](/operations/backup-recovery/).

If a write-capable host command was interrupted during a transaction on a
rollback-journal database, SQLite may leave a hot `-journal` file. The next
daemon start rolls back that incomplete transaction before checking the daemon
lease; it still refuses startup if the lease is live or malformed. The
read-only `edgewatch verify` command does not recover the live database.
