---
title: Backup and recovery
description: Back up data and keys together, verify backups while EdgeWatch runs, schedule rotated backups, and restore safely.
---

All runtime state lives in `./data`, including:

- `edgewatch.db` and SQLite sidecars;
- `notification.key`, which encrypts the notification destination URLs stored
  in the database, including URLs imported from `config.yaml`;
- `auth.key` for TOTP encryption when the default key location is used;
- optional backups and exported baselines.

Back up the complete `./data` directory together with `config.yaml` and any
separately mounted secret files. Notification credentials live encrypted in
the database, so a database backup is only usable with its
`notification.key`. The backup command does not create missing directories,
so create the backup directory first with the same owner as `./data`. For
standard rootful Docker:

```console
sudo install -d -m 0750 -o 0 -g 0 ./data/backups
```

For rootless Docker:

```console
install -d -m 0750 ./data/backups
```

Then take a live, consistent database snapshot. The backup command refuses an
output file that already exists, so give each backup its own name, for example
with a timestamp:

```console
docker compose exec edgewatch edgewatch backup \
  --config /etc/edgewatch/config.yaml \
  --out "/var/lib/edgewatch/backups/edgewatch-$(date -u +%Y%m%dT%H%M%SZ).db" \
  --output json
```

The `$(date …)` part is expanded by the host shell, so the same command works
unchanged from a scheduled job. Remove the backups you take this way with your
own retention policy, or let the daemon take and rotate backups itself; see
[Scheduled backups](#scheduled-backups).

The backup command checks the file it wrote before it publishes it under
`--out`, as a restore would check it: SQLite's `quick_check`, the
foreign-key check, and the detection of a supported EdgeWatch schema. Add
`--full-check` to run SQLite's full `integrity_check` instead of
`quick_check`; it also compares every index with its table and takes longer on
a large database. The output reports the backup's `path`, `bytes`, and
`schema_version`, the `check` it passed with its `integrity_check` result, and
`foreign_key_violations`. A database that fails a check, for example because a
row breaks a foreign key, fails the backup and leaves nothing at `--out`. A
supported schema is one from schema 54, of v0.20.0, to the current one. From
v0.36.0, `backup` refuses a database with an older schema before it copies it
or records the attempt in its audit log, so back up a database of an older
release with v0.35.0; see
[Restore a backup of an older release](#restore-a-backup-of-an-older-release). The
backup sets its private file mode on its temporary file before it is
published, and never changes another file in the output directory, such as a
file that happens to be named like a SQLite companion of the backup.

## Verify a backup

`edgewatch verify` checks the configured live database. Add `--from` to check
a backup file instead:

```console
docker compose exec edgewatch edgewatch verify \
  --config /etc/edgewatch/config.yaml \
  --from /var/lib/edgewatch/backups/BACKUP_FILE.db --output json
```

`verify --from` never opens the configured database or reads its daemon lease,
so it works while EdgeWatch runs. It reads the backup once, into a private
directory below the temporary directory (`TMPDIR`, which the bundled
`compose.yaml` sets to `/var/lib/edgewatch/tmp`), checks that copy, and
removes it, so the backup file stays byte for byte as it was and no SQLite
companion appears next to it. The private copy needs as much free space as
the backup. It runs the checks that a restore runs on its source: the SQLite
header, no `-wal`, `-shm`, or `-journal` companions next to the file, SQLite's
full `integrity_check`, the foreign-key check, and a supported EdgeWatch
schema. It then opens the copy with the configured keys and reports, in
`key_check`, how many web-managed notification destinations of every unit and
of the platform, paused or not, and how many TOTP seeds the keys cannot open,
as counts only. The report is one JSON document with `valid` and, when a check
fails, the reason in `error`; the command exits non-zero when the file is not
valid, for example when it is truncated, has a newer schema than this release
supports or one older than schema 54, or holds secrets that the configured
keys cannot open. Add
`--allow-key-mismatch` to report locked secrets without failing, for example
when you check a backup on a host without its keys. `verify --from` writes
nothing to the database and no audit record.

A restore, and its dry run, still validate a staged copy of the backup before
anything is replaced, so a backup that `verify --from` accepted is checked
again when it is restored.

`edgewatch verify` also reports the database's `auto_vacuum` mode. A
database created by v0.18.31 or later has `incremental` and returns the pages
it frees to the filesystem; an older one has `none` and keeps them in the
file, with the rows they held, until SQLite reuses them. A backup made with
the backup command holds no free pages, but a raw copy of `./data` holds the
entire database file. Deleting a business unit leaves no free page with the
unit's rows in either mode.

## Scheduled backups

The daemon can take backups on a schedule and keep a fixed number of them. Set
`backup.directory` in `config.yaml` to turn this on:

```yaml
backup:
  directory: /var/lib/edgewatch/backups
  schedule: "0 3 * * *"
  keep: 7
```

`schedule` is a five-field cron expression in the deployment `timezone`, or
UTC when none is set; it defaults to `0 3 * * *`, daily at 03:00. As for a
job's schedule, a `TZ=` or `CRON_TZ=` prefix and a schedule that never fires,
such as February 30, are refused. `keep`
defaults to 7 and accepts 1 to 1000. The directory must exist; create it as
shown above. The bundled Compose file mounts `./data` at `/var/lib/edgewatch`,
so `/var/lib/edgewatch/backups` is `./data/backups` on the host and needs no
further volume. The [hardened Compose policy](/deployment/container-hardening/)
allows no other writable mount, so keep the directory below
`/var/lib/edgewatch` and copy the backups off the host from `./data/backups`
with the host's own tools.

Each scheduled backup is written as `edgewatch-scheduled-YYYYMMDDTHHMMSSZ.db`,
with the UTC time it started, through the same code as the backup command, and
checked in the same way before it is published. After a backup succeeds, the
daemon removes the oldest of its scheduled backups beyond `keep`. It considers
only regular files with exactly that name and mode `0600`, so it never removes
another file in the directory, such as a backup taken with the backup command
under another name; do not give your own files that name. A failed backup
removes nothing, so the older good backups stay.

The daemon records the outcome in `backup-status.json` next to the database,
outside the backup directory, so a directory that cannot be written is still
reported. `edgewatch health` prints it in `backups`: the `directory`,
`schedule`, `keep`, `next_run_at`, the newest good backup as `last_backup`
with `last_success_at`, `last_success_age_seconds`, its size, and its schema
version, and the latest failure as `last_failure_at` and `last_error`, with
`consecutive_failures` since the newest good backup. While the latest backup
has failed, health adds a warning; it stays healthy, because monitoring still
runs. The console shows the same failure as a banner on the platform status
page and, in a deployment with one business unit, on the Overview of its
administrators. Scheduled backups are logged, not recorded in the security
audit. A scheduled backup holds every unit's data and is only usable with its
`notification.key` and `auth.key`: keep the directory as private as `./data`,
and copy the backups and the keys off the host.

## Restore a backup

The backup command uses SQLite's online snapshot support. A raw directory copy
must be made while EdgeWatch is stopped so the database and WAL sidecars stay
consistent. Never replace a live database. Restore with the host-safe command,
verify it, and only then start the service again. The image entrypoint is
already `edgewatch`, so `docker compose run` takes the subcommand directly,
while `docker compose exec` needs the `edgewatch` executable name:

```console
docker compose stop edgewatch
docker compose run --rm --no-deps -T edgewatch restore \
  --config /etc/edgewatch/config.yaml \
  --from /var/lib/edgewatch/backups/BACKUP_FILE.db \
  --output json
docker compose run --rm --no-deps -T edgewatch verify \
  --config /etc/edgewatch/config.yaml --output json
docker compose up -d edgewatch
```

To check a restore first, add `--dry-run` to the restore command. The dry run
runs the same checks as the restore: SQLite sidecars, an active daemon
heartbeat, validation of a staged copy of the backup, which is made in a
private directory next to the database and then removed, and the key check
below. The destination is never changed. The report includes `safe`, a
`refusal` reason when the restore would be refused, the backup's
`source_schema_version`, the number of claimable pending deliveries the chosen
`--pending-deliveries` policy would affect, and `key_check`. Terminal failures stay in the outbox; restore policies do not quarantine
or discard them. Quarantined payloads are removed in bounded batches after they
fall outside the configured history retention; the purge removes them for units
whose deletion is pending. The command exits non-zero when the restore would be
refused, so scripts can act on its exit status.

Restore and dry-run commands stop their staging work on `SIGINT` or `SIGTERM`
and remove the temporary copy. If a process is killed outright or the host
crashes, the next restore or dry run removes abandoned `.edgewatch-restore-*`
copies before starting. Concurrent restore commands are serialized with an
advisory lock on Linux using the database directory itself, so no extra lock
file is created. The daemon holds the same lock while it migrates the database
at startup, so a restore waits until the migration has finished, and a daemon
that starts while a restore runs exits instead of migrating the database that
is being replaced. Other platforms retain signal cleanup but skip automatic
orphan removal when cross-process locking is unavailable.

Before the staged copy can replace the database, the restore and its dry run
open it with the configured keys: `notifications.encryption_key_file`, or
`notification.key` next to the database, and `web.auth_key_file`, or
`auth.key` next to the database. `key_check` reports the number of web-managed
notification destinations of every unit and of the platform, paused or not,
in `destinations`, and how many of them the notification key cannot open in
`destinations_locked`; and the accounts with a TOTP seed in `totp_secrets`, and
how many seeds the authentication key cannot open in `totp_unreadable`. It
holds counts only, never a URL or an account. When either count of locked
secrets is not zero, the restore and the dry run refuse, because restoring the
wrong keys would lock those destinations, whose alerts are dropped once their
delivery deferrals run out, and lock those accounts out of TOTP. Put the
`notification.key` and `auth.key` that belong to the backup in place and run
the command again. The restore therefore needs the configured key files to be
readable.

A backup taken while the daemon runs contains that daemon's lease and the
leases of its running scans. No process runs on a restored copy, so restore
clears these copied leases, and the dry run does the same in its private copy.
The service therefore starts at once after a restore, and a repeated restore
onto the stopped service is not refused. The active-daemon check reads only
the lease in the database that is being replaced.

### Restore a backup of an older release

A restore accepts a backup of schema 54, the schema of v0.20.0, or of a later
schema up to the current one. The daemon upgrades it at its next start; see
[Migration ownership](/reference/database-compatibility/#migration-ownership).
From v0.36.0, a backup of an older release is refused by the restore, its dry
run, and `verify --from` with `database schema version N is older than schema
54, the oldest that this release upgrades; upgrade through v0.35.0 first`, and
the database is not changed. To use such a backup, upgrade it with v0.35.0,
which still upgrades every older schema:

1. Pin `ghcr.io/crypt0rr/edgewatch:0.35.0` in a `compose.override.yaml`, as
   under [Upgrade from a release before v0.20.0](/deployment/updates/#upgrade-from-a-release-before-v0200).
   v0.35.0 refuses the settings that v0.36.0 introduced,
   `scanner.max_job_hosts` and `web.metrics`, so comment them out of
   `config.yaml` until the last step; see
   [Settings and older releases](/reference/configuration/#settings-and-older-releases).
2. Restore the backup with that image as shown above, start the service, and
   wait until `edgewatch health` reports `ready`.
3. Take a new backup, remove the override, set again any settings you
   commented out, and update to the current release. Its daemon then upgrades
   the database from schema 65.

## Emergency restore overrides

A restore refuses SQLite sidecars, an active daemon heartbeat, a destination
it cannot inspect, and a backup whose secrets the configured keys cannot open,
because each of these usually means that the database is still in use or that
the files do not belong together. Only when you have confirmed the cause, and
with EdgeWatch stopped, add one of these options to the restore command:

| Option | Use it when | Risk |
| --- | --- | --- |
| `--allow-sidecar-replay` | The backup is a raw copy of a stopped or crashed database whose `-wal`, `-shm`, or `-journal` companions sit next to it, or the destination still has companions after a crash. The companions are copied with the backup so that transactions only in the WAL are kept. | Companions from another database, or from a database that was still open, can corrupt the restored copy. Not available with `--dry-run`. |
| `--allow-active-daemon` | The daemon is stopped or isolated, but its heartbeat in the database being replaced is less than two minutes old, or was renewed ahead by a scan that was saving its result when the daemon stopped. | If a daemon is still running against the destination, it keeps writing to the replaced file. |
| `--allow-unreadable-destination` | The destination is damaged and cannot be opened to read its daemon lease. The backup and its staged copy are still validated. | The active-daemon check is skipped for that destination. |
| `--allow-key-mismatch` | The keys that belong to the backup are lost, and you accept that its web-managed destinations and TOTP seeds stay locked. `key_check` still reports the counts. | Locked destinations deliver nothing until they are deleted and recreated with their credentials, and accounts with a locked TOTP seed need `admin disable-totp`. |

Stop the service first in every case:

```console
docker compose stop edgewatch
docker compose run --rm --no-deps -T edgewatch restore \
  --config /etc/edgewatch/config.yaml \
  --from /var/lib/edgewatch/backups/BACKUP_FILE.db \
  --allow-active-daemon --output json
```

A backup can also hold sign-in sessions, activation and password-reset links,
and a setup token that were ended, redeemed, or replaced after it was taken.
Restore therefore clears the copied sessions and marks every unused link and
setup token in the copy as used, and the dry run does the same in its private
copy. After a restore everyone signs in again, and administrators issue a new
link from **Users**, or the platform console, for each account that still
needs one. Print a new platform setup token with `edgewatch admin
platform-setup-token`; while no administrator exists, the daemon prints a new
setup token when it starts.

## Account recovery

An administrator who is locked out can be recovered from the host. The new
password is read from a file inside the container, whose root filesystem is
read-only, so write it below the mounted data directory, keep it private, and
delete it afterwards. A trailing newline is ignored, and the password must
meet the normal password requirements.

```console
install -m 0600 /dev/null ./data/new-password
printf '%s' 'NEW-PASSWORD' > ./data/new-password
docker compose exec edgewatch edgewatch admin reset-password \
  --config /etc/edgewatch/config.yaml \
  --username USERNAME --password-file /var/lib/edgewatch/new-password
rm ./data/new-password
```

To remove a lost second factor, so the account can sign in with its password
and enroll TOTP again:

```console
docker compose exec edgewatch edgewatch admin disable-totp \
  --config /etc/edgewatch/config.yaml --username USERNAME
```

`--username` defaults to `admin`. Both commands print the account's unit and
role before they act, and `--tenant UNIT_SLUG` makes them stop without a change
unless the account belongs to that unit. With rootful Docker, `./data` is
owned by root, so run the `install`, `printf`, and `rm` steps with `sudo`, for
example `sudo sh -c "printf '%s' 'NEW-PASSWORD' > ./data/new-password"`.

## Database compatibility

Read [Database compatibility](/reference/database-compatibility/) before upgrading or restoring a backup from another release.

## Pending notification deliveries

Single-file restores quarantine pending deliveries by default so alerts from the backup cannot be replayed. Explicitly choose `--pending-deliveries discard` or `--pending-deliveries preserve` only when that policy is appropriate. Terminal failures remain in the outbox. Keep the database and its original encryption keys together; the restore refuses a backup that the configured keys cannot open unless `--allow-key-mismatch` is given.
