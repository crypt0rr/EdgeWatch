---
title: Database compatibility
description: Understand the current SQLite schema, the oldest schema that upgrades, forward-only migrations, and historical upgrade steps.
---

## Current schema and rollback

The current schema is version 79. Schema 31 records terminal notification
deliveries and marks rows that had already exhausted the original eight
attempts. Schema 63 repairs databases that had already passed schema 31 by
marking still-unsent rows with at least eight attempts and a scheduled retry
before v0.22.1, when the retry budget increased to fifteen. Retries scheduled
on or after that release remain eligible, so upgrading does not replay
deliveries that were still retrying. Schema 64 adds an index for pruning old
restore-quarantine records; it does not rewrite delivery history. Schema 65
records how each new scan was compared with its job's baseline; it does not
change existing scans. Schema 66 replaces scan history indexes; it does not
change scans either. Schema 67 adds the routing and state of the security
and deployment alerts; no existing row changes and every routing starts
empty. Schema 68 adds durable incident review records and an indexed inbox
projection. Its startup backfill populates the projection from active runtime
incidents in restartable batches of 250 rows; it does not rewrite scan results
or baselines. Database migrations are forward-only. An older image
must not be pointed at a database already upgraded by a newer image; restore
the matching pre-upgrade `./data` backup if a rollback is required. The daemon
and the commands that write to the database (admin, scan, notify test,
baseline approve and reset, and backup) refuse versions above their supported
schema version with the error
`database schema version N is newer than supported version M`. Back up such a
database with the release that upgraded it, or copy `./data` while
EdgeWatch is stopped. A daemon that finds another daemon's live lease exits
before it migrates the database, and so does a daemon whose configured key
file, notification URL, or metrics token file is unusable (see
`config validate` under [Host commands](/reference/cli/)). Keep encryption
keys with the database or encrypted web-managed destinations and never
commit them.

When `backup.directory` is configured, the daemon creates and verifies a
pre-migration backup before it starts schema writes. Separately from scheduled
backups, it keeps the copy just written, the latest three other automatic
copies, and, from each schema below the database's current schema, the newest
copy for an upgrade beyond it, so retrying a failed upgrade never removes the
copy the previous release can open. A failure to create or verify that backup
stops the migration. If no directory is configured, the daemon warns and
continues without an automatic pre-migration copy. Keep a separate off-host
backup and the matching keys for recovery from storage loss.

## Schema 69

Schema 69 adds tenant-scoped `change_windows`, compact per-window event and
change references, and delivery metadata for planned quiet windows. The
For an outbox row that is still unsent, the migration reads a valid JSON
payload to fill its event type and job ID; malformed payloads keep empty
metadata and do not block the upgrade. Sent rows are left unchanged. A direct
upgrade from schema 68 therefore leaves sent-history metadata empty, while a
database previously upgraded by a v0.39 release may already have metadata on
those rows. This difference is only in optional metadata: it does not resend,
rewrite, or remove notifications. The migration builds two pending-delivery
indexes over all outbox rows, so its duration and temporary WAL depend on total
outbox size even though the payload update targets only unsent rows.
New window references are captured before the existing event-payload size
bound, so later event pruning does not erase a retained closing review.

Closing an active or expired window stores a bounded summary and exact
aggregate counts in the same transaction that queues its optional summary
notification. A review-due window stays available until an authorized
operator reviews it. Open and scheduled windows are retained; closed windows
without a pending review, their compact evidence, and old linked delivery rows
expire with the configured history retention in bounded batches. Pending
delivery attempts keep their window association until the provider outcome is
resolved, so retention cannot orphan an active handoff. Permanent job deletion
and business-unit deletion erase window records and evidence through the
existing resumable purge paths. The new tables inherit tenant ownership from
their job and are not exposed through public status.

An older release refuses the upgraded database, so a rollback means restoring
the pre-upgrade `./data` backup.

## Schema 70

Schema 70 rebuilds `scans_identity` with the scan comparison outcome in the
index. The Investigation Inbox can read a newer scan's status, completion
time, and comparison without reading its snapshot. It loads a snapshot only
when a strictly newer successful, compared scan needs target and protocol
coverage evidence, and does so once per distinct scan for each request.

Inbox commits the page metadata read before loading those blobs. Finished scan
rows are immutable, and each selected snapshot is read by its fixed tenant,
job, and scan ID; this releases the shared read connection before JSON
decoding. If retention deletes a selected scan between those reads, the Inbox
reports that item's evidence as unclassifiable.

The Inbox classifies all matching incidents and discards a scan's raw and
decoded data before loading the next one, keeping memory proportional to the
largest individual snapshot needed by the page instead of the sum of all
distinct snapshots. The migration does not change scan results or baselines.

It rebuilds one index by reading retained scans, so it can take time on a
large history. An older release refuses the upgraded database; restore the
matching pre-upgrade `./data` backup to roll back.

## Schema 71

Schema 71 adds an all-row index on outbox tenant and row ID. Tenant deletion
uses it to select bounded batches of every delivery, including sent history
and rows without event metadata. Sent rows may have empty or populated event
metadata depending on the upgrade path described under schema 69. The
migration does not read or rewrite payloads or change delivery state. It builds
the index over existing outbox rows, so its duration depends on outbox size.
An older release refuses the upgraded database; restore the matching
pre-upgrade `./data` backup to roll back.

## Schema 72

Schema 72 replaces the tenant event-order index and adds tenant-qualified
indexes for legacy job-name and stable job-ID history lookups. Counts can use
the indexes without reading event payloads, and ordered pages apply purge
filtering and pagination before fetching only the selected payloads. The
migration builds the indexes over existing event rows without rewriting or
removing history, so its duration and temporary WAL depend on event history
size. An older release refuses the upgraded database; restore the matching
pre-upgrade `./data` backup to roll back.

## Schema 73

Schema 73 adds partial indexes for active, expired, scheduled, due-review, and
closed-history change windows. The job details page selects at most 100
candidates from each priority group, then merges those bounded candidates in
the documented order. Due-review and open-window rows remain retained until
they are resolved, so their indexes make the priority lookup avoid sorting
unrelated retained window history. The migration builds indexes over existing
window rows without changing their state, summaries, or evidence. Its duration
and temporary WAL depend on the retained change-window history size. An older
release refuses the upgraded database; restore the matching pre-upgrade
`./data` backup to roll back.

## Schema 74

Schema 74 adds a bounded scalar copy of a scheduled probe-budget skip to the
job runtime metadata used by the Jobs list. A partial index identifies rows
that still need the copy. The daemon backfills those rows in restartable
batches of 250, validates legacy JSON, and records progress in startup status;
malformed or oversized values become empty markers. The migration does not
rewrite scan history, runtime snapshots, or baselines. Its duration and
temporary WAL depend on the number of runtime metadata rows. An older release
refuses the upgraded database; restore the matching pre-upgrade `./data`
backup to roll back.

## Schema 75

Schema 75 adds three scan-history projections: the unit results and their
count, plus a compact coverage summary with target scopes, failures, host
states, and host/protocol status. The summary omits port inventories and
service evidence; the immutable full snapshot remains available for detailed
history. The daemon backfills one scan per restartable transaction. A malformed
legacy snapshot stays unchanged and receives empty projections, so it cannot
block startup or make inbox recovery classification parse the full document.
The migration's duration and temporary WAL depend on retained scan history. An
older release refuses the upgraded database; restore the matching pre-upgrade
`./data` backup to roll back.

## Schema 76

Schema 76 adds the `perimeter_seeds` table, which holds the address ranges a
business unit declares: space it owns, of kind `prefix`, and third-party space
it may scan, of kind `authorized`. Each row stores its unit, its kind, its
canonical IPv4 or IPv6 CIDR value of 1 to 64 characters, an optional label,
its source, its creation time, and the username that declared it. A unit holds
a value at most once per kind, and a trigger refuses any change of a row's
`tenant_id`. The kind check also accepts `asn`, and the source check accepts
`declared` and `adopted` with an `adopted_from` column, so a later release can
watch an ASN's announced space without rebuilding the table; this release
writes only `prefix` and `authorized` ranges with the source `declared`. The
index of the unique constraint serves the lookups by unit and kind, so the
table has no other index. The table backs the
[perimeter coverage API](/reference/api-compatibility/#perimeter-coverage)
and the console's [Perimeter](/user-guide/perimeter/) page.

The ranges are unit data: deleting the unit erases them through the resumable
purge, and public status never shows them. A declared range records ownership
or permission and does not authorize scanning it. The migration creates an
empty table and changes no existing row, so its duration does not depend on
the database size. An older release refuses the upgraded database; restore
the matching pre-upgrade `./data` backup to roll back.

## Schema 77

Schema 77 adds four columns to the platform's existing deployment-alert
state: the last reported scheduled-backup failure condition and its alert
time, plus the last reported scanner identity-capacity condition and its alert
time. The daemon uses them to report a new failure transition at most once an
hour, even across restarts. A successful backup or a pool whose scans can
reach enough identities again clears the condition without sending a recovery
alert. The columns default to healthy and empty; the migration changes no
existing alert or delivery. An older release refuses the upgraded database;
restore the matching pre-upgrade `./data` backup to roll back.

## Schema 78

Schema 78 adds the latest attempt's start time to each scan cycle. The daemon
records it when an attempt starts, allowing capacity history to preserve the
actual final attempt if the process stops after cycle completion but before
scan finalization. Existing cycles are not backfilled; their recorded attempt
rows remain usable, and a legacy single-attempt cycle may use its cycle start
as the available duration evidence. The migration changes no scan or
baseline rows. An older release must not open the upgraded database; rollback
requires the complete pre-upgrade backup.

## Schema 79

Schema 79 adds a partial index of completed scan cycles by job, execution
hash, and completion time. The scan-slot demand estimate reads each job's
newest completed cycles through it instead of reading and sorting the job's
whole cycle history. Building the index reads each scan cycle once; the
migration changes no cycle, scan, or baseline rows. An older release must not
open the upgraded database; rollback requires the complete pre-upgrade backup.

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

## Schema 67

Schema 67, introduced in v0.36.0, adds what the
[security and deployment alerts](/user-guide/notifications/#security-alerts)
need:

- `tenants.security_destinations_json`, each business unit's security alert
  routing, the IDs of its web-managed destinations. It defaults to an empty
  selection, so every existing and new unit gets no security alerts until its
  administrators turn them on.
- `platform_alert_state`, one platform row with the platform's security alert
  and deployment alert routing, both empty, the sandbox states and times that
  the last deployment alerts reported, the time of the last rollback alert,
  and the count of alerts that failed for good since the last report. It
  holds no business unit's data.
- `security_alert_windows`, the open alert window of each business unit, or
  of the platform, and alert kind, with the number of alerts it held back. A
  unit's rows carry its `tenant_id`, and deleting the unit erases them with
  its other rows.

The migration adds a column with a default, the platform's alert row with
empty routings, and an empty `security_alert_windows` table, so it is quick
and has no background phase. It runs in one transaction that first
checks that the database is still at schema 66, like every step described
under [Migration ownership](#migration-ownership), and it rebuilds no table.
An older release refuses the upgraded database, so a rollback means
restoring the pre-upgrade `./data` backup.

## Schema 68

Schema 68, introduced in v0.37.0, adds `incident_reviews` and its bounded
`incident_review_history` for review status, reviewer label, review time,
plain-text note, optional follow-up time, and revision of one incident
occurrence. Reviews reference jobs rather than `runtime_incidents` or scans:
active incidents are a replaceable projection, and scan history can be pruned
while a review remains useful. A versioned occurrence token binds the review
to the tenant, job, incident key, opening scan and time when known, and the
exact change. Legacy incidents without opening metadata keep an explicit
unknown opening time.

The migration adds indexed occurrence and sort columns to the replaceable
runtime projection. The daemon backfills active rows after applying migrations,
in batches of 250 under a writer transaction; each committed batch can be
resumed after shutdown or restart. New scans refresh the projection in the
same transaction as runtime state, so review updates serialize with scan
finalization. Review history keeps at most 20 edits per occurrence. The regular
retention pass removes closed reviews older than the configured history
retention in batches of 25; active reviews remain. Permanent job deletion and
business-unit deletion erase reviews and their history through restartable
purge steps. Backups contain these records, including notes. An older release
refuses the upgraded database, so a rollback means restoring the pre-upgrade
`./data` backup.

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
over the whole history. The backfill leaves the scans of a business unit that
is being deleted to its purge, which erases their host rows before the scans,
so a start while such a purge is unfinished does not index them again. An
older release refuses the upgraded database, so a
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
until its migration and startup phases have finished and it has acquired its
daemon lease. Restores of that directory use the same lock. The daemon runs
only on Linux because this directory-lock implementation is Linux-only; an
attempt to start it on a non-Linux system fails closed before migration, even
on a filesystem that supports `flock`. On Linux, a second daemon on the same
data volume exits with
`another EdgeWatch process is migrating or restoring the database in this directory`
while the first daemon is migrating or completing startup. Once its lease is
live, a later daemon exits with
`another EdgeWatch daemon holds the database lease`. A restore waits until
startup has finished. Each migration step also checks, in its own
transaction, that the schema version is still the one it upgrades from, so no
step runs twice. The Linux database filesystem must support advisory
directory locking; if the directory cannot be locked, startup exits with
`daemon startup requires a lockable database directory` before migrating or
changing startup state. The daemon also requires a persistent, file-backed
SQLite database; in-memory SQLite paths have no directory to lock and are
refused before startup work.

The startup phases that read their progress before they write, such as the
backfills, take the database's write lock first, so a host command that writes
while they run, such as `scan` or `admin`, makes them wait, up to the
five-second busy timeout, instead of failing the daemon's start. Daemon and
scheduled-job lease acquisition also reserves the write lock before reading
lease ownership or job revision, so a concurrent writer delays the claim
through SQLite's busy timeout instead of causing a failed read-to-write
upgrade. A host command's write that reads the current state first takes the
write lock first too: `admin setup-token`, `admin reissue-setup-token`,
`admin platform-setup-token`, `admin reset-password`, `admin disable-totp`,
`baseline approve`, `baseline reset`, `perimeter declare`, and the scan cycle
progress of `scan` wait for the running daemon's write, up to the same busy
timeout, instead of failing with `database is locked`. During service, a
heartbeat that receives `SQLITE_BUSY` retries on the next heartbeat tick
without counting it as a missed heartbeat; lease loss, `SQLITE_LOCKED`, and other database errors
keep their existing failure behavior. A host process holding SQLite's writer
lock for more than two minutes can still prevent a successful heartbeat long
enough for the daemon lease to become stale. If a second daemon acquires the
database after that
writer releases the lock, it can take over and reclaim the first daemon's job
leases while the first process is still alive. The first daemon detects lease
loss at its next heartbeat and stops its scans. Avoid suspending or otherwise
leaving a host write open for this long; check `health` before starting a
replacement daemon. A daemon shutdown signal cancels context-aware startup work;
completed migration steps and backfill batches remain committed, and the next
start resumes the remaining work.
The daemon also opens its listener before it migrates, so `GET /healthz`
answers `starting` during a long upgrade; see
[Monitor the monitor](/operations/troubleshooting/#monitor-the-monitor).

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
