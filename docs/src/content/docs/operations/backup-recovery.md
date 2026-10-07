---
title: Backup and recovery
description: Back up data and keys together, validate restores, and recover sessions safely.
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
unchanged from a scheduled job. Remove old backups with your own retention
policy; EdgeWatch does not prune the backup directory.

`edgewatch verify` checks the configured live database, not a backup file:

```console
docker compose exec edgewatch edgewatch verify \
  --config /etc/edgewatch/config.yaml --output json
```

A backup file is validated when it is restored: the restore, and its dry run,
validate a staged copy of the backup before anything is replaced. A dry run
refuses while the daemon heartbeat is active, so stop the service before
checking a backup that way.

`edgewatch verify` also reports the database's `auto_vacuum` mode. A
database created by v0.18.31 or later has `incremental` and returns the pages
it frees to the filesystem; an older one has `none` and keeps them in the
file, with the rows they held, until SQLite reuses them. A backup made with
the backup command holds no free pages, but a raw copy of `./data` holds the
entire database file. Deleting a business unit leaves no free page with the
unit's rows in either mode.

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
heartbeat, and validation of a staged copy of the backup, which is made in a
private directory next to the database and then removed. The destination is
never changed. The report includes `safe`, a `refusal` reason when the restore
would be refused, the backup's `source_schema_version`, and the number of
claimable pending deliveries the chosen `--pending-deliveries` policy would
affect. Terminal failures stay in the outbox; restore policies do not quarantine
or discard them. Quarantined payloads are removed in bounded batches after they
fall outside the configured history retention; the purge removes them for units
whose deletion is pending. The command exits non-zero when the restore would be
refused, so scripts can act on its exit status.

Restore and dry-run commands stop their staging work on `SIGINT` or `SIGTERM`
and remove the temporary copy. If a process is killed outright or the host
crashes, the next restore or dry run removes abandoned `.edgewatch-restore-*`
copies before starting. Concurrent restore commands are serialized with an
advisory lock on Linux using the database directory itself, so no extra lock
file is created. Other platforms retain signal cleanup but skip automatic
orphan removal when cross-process locking is unavailable.

A backup taken while the daemon runs contains that daemon's lease and the
leases of its running scans. No process runs on a restored copy, so restore
clears these copied leases, and the dry run does the same in its private copy.
The service therefore starts at once after a restore, and a repeated restore
onto the stopped service is not refused. The active-daemon check reads only
the lease in the database that is being replaced.

## Emergency restore overrides

A restore refuses SQLite sidecars, an active daemon heartbeat, and a
destination it cannot inspect, because each of these usually means that the
database is still in use or that the files do not belong together. Only when
you have confirmed the cause, and with EdgeWatch stopped, add one of these
options to the restore command:

| Option | Use it when | Risk |
| --- | --- | --- |
| `--allow-sidecar-replay` | The backup is a raw copy of a stopped or crashed database whose `-wal`, `-shm`, or `-journal` companions sit next to it, or the destination still has companions after a crash. The companions are copied with the backup so that transactions only in the WAL are kept. | Companions from another database, or from a database that was still open, can corrupt the restored copy. Not available with `--dry-run`. |
| `--allow-active-daemon` | The daemon is stopped or isolated, but its heartbeat in the database being replaced is less than two minutes old. | If a daemon is still running against the destination, it keeps writing to the replaced file. |
| `--allow-unreadable-destination` | The destination is damaged and cannot be opened to read its daemon lease. The backup and its staged copy are still validated. | The active-daemon check is skipped for that destination. |

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

Single-file restores quarantine pending deliveries by default so alerts from the backup cannot be replayed. Explicitly choose `--pending-deliveries discard` or `--pending-deliveries preserve` only when that policy is appropriate. Terminal failures remain in the outbox. Keep the database and its original encryption keys together.
