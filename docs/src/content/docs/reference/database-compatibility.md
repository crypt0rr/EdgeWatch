---
title: Database compatibility
description: Understand the current SQLite schema, the oldest schema that upgrades, forward-only migrations, and historical upgrade steps.
---

## Current schema and rollback

The current schema is version 66. Schema 31 records terminal notification
deliveries and marks rows that had already exhausted the original eight
attempts. Schema 63 repairs databases that had already passed schema 31 by
marking still-unsent rows with at least eight attempts and a scheduled retry
before v0.22.1, when the retry budget increased to fifteen. Retries scheduled
on or after that release remain eligible, so upgrading does not replay
deliveries that were still retrying. Schema 64 adds an index for pruning old
restore-quarantine records; it does not rewrite delivery history. Schema 65
records how each new scan was compared with its job's baseline; it does not
change existing scans. Schema 66 replaces scan history indexes; it does not
change scans either. Database migrations are forward-only. An older image
must not be pointed at a database already upgraded by a newer image; restore
the matching pre-upgrade `./data` backup if a rollback is required. The daemon
and the commands that write to the database (admin, scan, notify test,
baseline approve and reset, and backup) refuse versions above their supported
schema version with the error
`database schema version N is newer than supported version M`. Back up such a
database with the release that upgraded it, or copy `./data` while
EdgeWatch is stopped. A daemon that finds another daemon's live lease exits
before it migrates the database, and so does a daemon whose configured key
file or notification URL is unusable (see `config validate` under
[Host commands](/reference/cli/)). Keep encryption keys with the database or
encrypted web-managed destinations and never commit them.

## Upgrade floor

From v0.36.0, EdgeWatch upgrades a database from schema 54, the schema of
v0.20.0, the first release with business units, or from any later schema.
The daemon refuses an older database before it changes anything, so its
schema version and its startup state stay as they were, and exits with:

```text
database schema version N is older than schema 54, the oldest that this release upgrades; upgrade through v0.35.0 first
```

`edgewatch health` and `edgewatch verify` report the same error, and the host
commands refuse with it instead of advising you to start the daemon. A
database without a schema version that already holds tables, such as one of
the releases before the web console, is refused as schema version 0.

v0.35.0 still upgrades every schema back to schema 1. To upgrade such a
database, back up `./data`, run v0.35.0 on it, as described under
[Upgrade from a release before v0.20.0](/deployment/updates/#upgrade-from-a-release-before-v0200),
until `edgewatch health` reports `ready`, then back up again and update to the
current release. A restore refuses a backup older than schema 54 with the same
error and leaves the database unchanged; see
[Restore a backup of an older release](/operations/backup-recovery/#restore-a-backup-of-an-older-release).

A new database starts from a frozen copy of schema 54, the schema that the
retired migrations from schema 1 created, and then runs the later migrations
and startup phases as an upgraded database does.

## Schema 58

Schema 58 rebuilds the bounded host-search indexes from retained scan and
baseline evidence in restartable batches. Service names and products are
prioritized so services on late ports remain searchable even when a host has
many positive ports. The rebuild does not change scan results or baselines.
From v0.36.0 it starts by dropping the scan and latest-host search indexes and
creating them empty, in one short transaction; earlier releases deleted every
entry in one transaction, which held the database's writer and grew the
write-ahead log with the retained history. Search results stay empty until
the batches have indexed the hosts again, as before. On every start, the
daemon truncates the write-ahead log once its startup work has finished, so a
large migration step does not leave a log of its size beside the database.
That includes a start that finds the schema current and finishes the rebuild
of a start that was stopped before it was ready.

## Schema 66

Schema 66, introduced in v0.36.0, replaces four indexes of the scan history
with indexes that also hold each scan's business unit, job, outcome, and cycle
outcome: `scans_job_id_history`, `scans_tenant_history`, `scans_identity`, and
`scans_cycle_outcome` take the place of `scans_job_id_time`,
`scans_tenant_id_time`, `scans_job_time`, and `scans_cycle_id`. A scan's row
stores those values after its result, so reading them from the row read the
whole result too. With the new indexes, a job's scan history, the scan list,
the Hosts view, saving a successful scan, deleting a job, and the retention
pass no longer read the stored results of the scans they skip or count, so
their cost no longer grows with the size of the retained results. Saving a
successful scan no longer grows with the square of its host count. The
upgrade changes no scan or result. It builds the four indexes in one
transaction at startup, which reads every stored scan once for each index, so
on a large history it can take a while. Back up `./data` before upgrading.

Schema 66 also records the completion of the backfill that indexes the hosts
of scans saved before the host index existed. The daemon completes it at the
first start after the upgrade, once it finds no such scan; until then
`edgewatch verify` lists its `legacy_scan_host_index` checkpoint as not
complete. Later starts and Hosts requests then skip the search for such scans
over the whole history. An older release refuses the upgraded database, so a
rollback means restoring the pre-upgrade `./data` backup.

## Schema 65

Schema 65, introduced in v0.26.0, adds a `comparison` column to the scans
table. When a scan of a job finishes, it records whether the scan was compared
with the baseline, was a baseline sample, established the baseline, or was not
compared. The scan detail reports that outcome, so a successful baseline sample
is no longer described as a scan that did not complete, and its result no
longer changes after the baseline is established, an incident is accepted, or
the baseline is reset; see
[Scan comparison](/user-guide/jobs-baselines-incidents/#scan-comparison).
Existing scans keep an empty value, because the migration cannot tell an
earlier baseline sample from a scan recorded before scan-time comparisons. They
behave as before: a scan without changes recorded at scan time is compared with
the current baseline. It is a quick in-place change with no background phase.
An older release refuses the upgraded database, so a rollback means restoring
the pre-upgrade `./data` backup.

## Schema 62

Schema 62, introduced in v0.25.14, adds the work queues that erase a
permanently deleted job's history in bounded transactions, and indexes that
find the job's pending and restore-quarantined deliveries. A deletion that is
interrupted resumes after a restart. The migration creates empty tables and
indexes and does not change existing data.

## Schema 61

Schema 61, introduced in v0.23.3, changes the incident reminder cadence that a
business unit inherited from the default, every successful scan, to hourly. A
unit keeps its cadence when an administrator chose another value, or when its
audit log records an earlier change of the reminder settings, because older
releases did not record which setting changed. Check **Incident reminders** on
the **Notifications** page after upgrading from an earlier release if you want
a reminder on every successful scan.

## Schema 60

Schema 60, introduced in v0.22.0, adds each business unit's incident reminder
cadence, with every successful scan as the initial value. It is a quick
in-place change with no background phase.

## Schema 59

Schema 59, introduced in v0.21.1, adds the switch that turns incident reminders
on or off for each business unit, on by default. It is a quick in-place change
with no background phase.

## Migration ownership

Only the daemon migrates the database, when it starts. A restored backup of an
older release, back to schema 54, keeps its schema until then. On such a
database, `restore`, `verify`, `health`, and `backup` work as usual, so the
restored copy can be checked and backed up first, and `verify --from` checks
a backup file of an older release in the same way. The commands that act on business units or
accounts need the upgraded schema, whether they only read (`status`,
`history`, and `baseline export`) or also write (`admin`, `scan`, `baseline
approve` and `reset`, and `notify test`). They change nothing and stop with
`database schema version N has not been upgraded to version M yet; start the
daemon once to upgrade it, then run this command again`. Start the service,
for example with `docker compose up -d edgewatch`, and run the command
again; it can run while the daemon is running.

One process migrates a database at a time. From v0.36.0, the daemon holds an
advisory lock on the database directory from before it opens the database
until its migration and startup phases have finished, the lock with which
restores of that directory are serialized. A second daemon on the same data
volume exits with `another EdgeWatch process is migrating or restoring the
database in this directory` and changes nothing, and a restore waits until
the migration has finished. Each migration step also
checks, in its own transaction, that the schema version is still the one it
upgrades from, so no step runs twice even where the directory cannot be
locked. The startup phases that read their progress before they write, such
as the backfills, take the database's write lock first, so a host command
that writes while they run, such as `scan` or `admin`, makes them wait, up
to the five-second busy timeout, instead of failing the daemon's start.

## Schemas 48 to 54

From v0.36.0, EdgeWatch no longer runs the migrations to schema 54 or
earlier: v0.35.0 runs them when it upgrades an older database, as described under
[Upgrade floor](#upgrade-floor), and the sections below describe what those
upgrades do. The startup copy of schema 54 still runs when an earlier release
upgraded a database to schema 54 but the copy has not finished.

## Schema 48

Schema 48 rebuilds the baseline host search index at startup in bounded,
resumable batches. While it runs, `edgewatch health` reports the
`host-search:baseline_hosts` phase, and a restart resumes after the last
committed batch.

## Schema 49

Schema 49 records which revision of each web-managed destination last changed
its credentials, so an alert raised during a rename is still queued. It is a
quick in-place change with no background phase.

## Schema 50

Schema 50 records which notification URLs from `config.yaml` were imported as
web-managed destinations, and the outcome of the import at each daemon start.
It is a quick in-place change; the import itself runs once after the
migration, as described in [Notifications](/user-guide/notifications/#notification-urls-in-configyaml-deprecated).

## Schema 51

Schema 51 adds a default tenant to the database. The update alert routing and
the public status page settings move to it unchanged, setup tokens record their
purpose, and each security audit record gains a tenant and a category. It is a
quick in-place change with no background phase, and the console, API, CLI,
public status page, and notifications behave as before.

## Schema 52

Schema 52 rebuilds the users, jobs, scanner profiles, and notification
destinations tables so that each row records the tenant that owns it; every
existing row moves to the default tenant. It also removes the legacy
administrator row, which the original administrator's user account already
replaces. The rebuild runs once at startup in one transaction, and on a large
database its foreign key check can take a while. Back up `./data` before
upgrading. Sign-in, setup, and the host recovery commands behave as before.

## Schema 53

Schema 53 records the tenant of each scan, event, and notification delivery;
every existing row belongs to the default tenant. Adding the column does not
rewrite the stored scan results or event payloads, but the migration builds
two new indexes on the scan and event history in one transaction at startup,
which can take a while on a large history. The console, API, CLI, public
status page, and notifications behave as before.

## Schema 54

Schema 54 keys the latest-host projection behind the Hosts view by tenant and
address, so each tenant keeps its own newest observation of an address. The
migration only swaps the table; the daemon then rebuilds the projection at
startup by copying it in resumable batches of 500 hosts. Each host keeps its
host search entry, so the search index is not rebuilt. While the copy runs, `edgewatch
health` reports the `tenant-latest-hosts` phase with its progress, `edgewatch
verify` lists its `latest_scan_hosts_tenant_rekey` checkpoint, and a restart
resumes after the last committed batch. Until the copy completes, a host
command that saves a successful scan is refused; start the daemon to finish
the upgrade. The console, API, CLI, public status page, and notifications
behave as before.

## Schema 55

Schema 55 finishes the deletion of business units that earlier releases
deleted. Those releases marked a unit deleted once its rows were erased and
only then tried to compact the search indexes and truncate the write-ahead
log, so the index files, and after an unclean shutdown the log, may still
hold copies of its erased rows, which backups then copy. When the database
holds a deleted unit, the migration records a one-time cleanup; a database
without one gets none. The daemon runs it in the background with the unit
deletion's steps and limits: each pass, at startup and every minute,
compacts the search indexes for at most 30 seconds and resumes where the
previous pass or a restart stopped, and the cleanup ends with a checkpoint
that truncates the log. A running backup delays that checkpoint until the
backup ends, which the daemon logs as a warning. While a unit is being
deleted, the cleanup waits, and that unit's deletion completes it; a
deletion that was already compacting the indexes at the upgrade starts its
compaction over, so that it covers the earlier units too. While the cleanup
is pending, `edgewatch health` reports it under `maintenance` with its
`legacy-tenant-purge` phase and progress, and `edgewatch verify` lists its
`legacy_tenant_purge_maintenance` checkpoint, which is complete once it has
finished; the daemon logs its start and its end. It never runs again.
Backups taken before it has finished may still hold the erased rows of
those units. An older release refuses the upgraded database, so a rollback
means restoring the pre-upgrade `./data` backup.

## Schema 56

Schema 56 finishes the deletion of business units in a database whose
`auto_vacuum` mode is `none`, one created before v0.18.31. Earlier releases
left the free pages of such a database as they were, and those may still hold
rows of a deleted unit that retention removed while the unit existed. When
such a database holds a deleted unit, the migration records the cleanup of
schema 55 as pending again, from its overwrite of free pages: the daemon
overwrites every free page with zeros in the same bounded, resumable passes
and then truncates the write-ahead log, without compacting the search indexes
again. While it is pending, `edgewatch health` reports the
`legacy-tenant-purge:free-pages` phase, and `edgewatch verify` lists the
`legacy_tenant_purge_maintenance` checkpoint as not complete. A deletion that
was in progress at the upgrade and had reached its log truncation goes back
to the overwrite. A database with `auto_vacuum` mode `incremental` is not
changed. Raw copies of `./data` made before the cleanup has finished may still
hold those rows. An older release refuses the upgraded database, so a
rollback means restoring the pre-upgrade `./data` backup.

## Schema 57

Schema 57 records whether a business unit has a high-cost grant. Earlier
releases gave each new unit a high-cost ceiling equal to the lower of the
deployment's two probe budgets when it was created. Once `config.yaml` lowered
those budgets, that ceiling let an approval of high-cost work raise the
unit's budgets up to it, although no platform administrator had granted it.
The upgrade marks the ceiling of every unit other than the default one as
**Not granted** when no platform administrator has ever saved that unit's
capacity. A unit whose capacity a platform administrator saved keeps its
ceiling as a grant, because the earlier **Capacity** tab sent the initial
ceiling back with every save, so the database cannot tell it from a ceiling
that was typed. After the upgrade, review the high-cost ceiling on the
**Capacity** tab of each such unit and choose **Not granted** where no
grant was intended. The default unit keeps its ceiling. It is a quick
in-place change with no background phase. An older release refuses the
upgraded database, so a rollback means restoring the pre-upgrade `./data`
backup.
