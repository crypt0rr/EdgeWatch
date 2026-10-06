---
title: Database compatibility
description: Understand the current SQLite schema, forward-only migrations, and historical upgrade steps.
---

## Current schema and rollback

The current schema is version 64. Schema 31 records terminal notification
deliveries and marks rows that had already exhausted the original eight
attempts. Schema 63 repairs databases that had already passed schema 31 by
marking still-unsent rows with at least eight attempts and a scheduled retry
before v0.22.1, when the retry budget increased to fifteen. Retries scheduled
on or after that release remain eligible, so upgrading does not replay
deliveries that were still retrying. Schema 64 adds an index for pruning old
restore-quarantine records; it does not rewrite delivery history. Database
migrations are forward-only. An older image must not be pointed at a database
already upgraded by a newer image; restore the matching pre-upgrade ./data
backup if a rollback is required. The daemon and the commands that write to the
database (admin, scan, notify test, baseline approve and reset, and backup)
refuse versions above their supported schema version with the error
`database schema version N is newer than supported version M`. Back up such a
database with the release that upgraded it, or copy ./data while
EdgeWatch is stopped. A daemon that finds another daemon's live lease exits
before it migrates the database, and so does a daemon whose configured key
file or notification URL is unusable (see `config validate` under
[Useful commands](/reference/cli/)). Keep encryption keys with the database or
encrypted web-managed destinations and never commit them.

## Schema 58

Schema 58 rebuilds the bounded host-search indexes from retained scan and
baseline evidence in restartable batches. Service names and products are
prioritized so services on late ports remain searchable even when a host has
many positive ports. The rebuild does not change scan results or baselines.

## Migration ownership

Only the daemon migrates the database, when it starts. A restored backup of an
older release keeps its schema until then. On such a database, `restore`,
`verify`, `health`, and `backup` work as usual, so the restored copy can be
checked and backed up first. The commands that act on business units or
accounts need the upgraded schema, whether they only read (`status`,
`history`, and `baseline export`) or also write (`admin`, `scan`, `baseline
approve` and `reset`, and `notify test`). They change nothing and stop with
`database schema version N has not been upgraded to version M yet; start the
daemon once to upgrade it, then run this command again`. Start the service,
for example with `docker compose up -d edgewatch`, and run the command
again; it can run while the daemon is running.

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

Schema 50 records which notification URLs from config.yaml were imported as
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
database its foreign key check can take a while. Back up ./data before
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
means restoring the pre-upgrade ./data backup.

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
changed. Raw copies of ./data made before the cleanup has finished may still
hold those rows. An older release refuses the upgraded database, so a
rollback means restoring the pre-upgrade ./data backup.

## Schema 57

Schema 57 records whether a business unit has a high-cost grant. Earlier
releases gave each new unit a high-cost ceiling equal to the lower of the
deployment's two probe budgets when it was created. Once config.yaml lowered
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
upgraded database, so a rollback means restoring the pre-upgrade ./data
backup.
