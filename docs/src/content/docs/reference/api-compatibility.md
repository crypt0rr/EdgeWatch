---
title: API compatibility
description: Review scan response shapes, business-unit routes, health and metrics endpoints, and compatibility changes.
---

## Job scan work estimates

`scan_estimate` probe, host, and process counts are preflight scope figures,
not predictions of elapsed scan time. `estimated_seconds` is omitted when no
defensible duration estimate is available. Clients should treat this field as
optional and must not infer that a scan will finish within any fixed time from
the probe count alone.

## Scheduled scan-slot demand

`GET /api/v1/jobs/slot-demand` requires `jobs.read` and returns the current
business unit's scheduled scan demand compared with its effective scan-slot
capacity. It reads only that unit's enabled jobs and bounded recent
scan-duration history. The response is tenant-scoped; it contains no job names
or IDs.

```json
{
  "enabled_jobs": 2,
  "history_jobs": 1,
  "lower_bound_jobs": 1,
  "unestimated_jobs": 1,
  "cadence_unattainable_jobs": 0,
  "slots": 1,
  "estimated_slot_seconds_per_day": 21600,
  "capacity_slot_seconds_per_day": 86400,
  "utilization_percent": 25,
  "over_capacity": false
}
```

`history_jobs` use the median duration from each job's 11 most recent
completed scan samples with its current scan settings. Each completed cycle is
one sample that sums its recorded scan-attempt durations, excluding idle time
between attempts; it counts while it recorded the job's current execution
hash, which covers the monitored scope, the timeout, resume window and timing,
and the scanner profile revisions and arguments. A successful or incomplete
scan without a cycle is its own sample; it counts while it recorded the job's
current scope hash and TCP scanner profile revision, and only when it is one
of the job's 44 most recent successful or incomplete scans, so the estimate
never reads further back in a job's history. If the newest runs with the
current key all timed out, the configured timeout supplies the expected run
duration. For a cycle attempt, the key is its cycle's execution hash; for a
scan without a cycle, it is the recorded scope hash and TCP scanner profile
revision. A rename, a schedule or notification edit, or a pause and resume
therefore keeps a job's samples. Other history remains available but is
excluded from this estimate; a job without samples uses its known-work lower
bound until a scan with its current settings completes. For a job without such
history, `lower_bound_jobs` count estimates that include only known probe work
divided by configured maximum scanner rates. A configured scope contributes
only when it is known to fit both the job's
`max_expanded_hosts` and deployment's `scanner.max_job_hosts`; over-limit or
unresolved DNS scopes add no lower bound because the scanner may reject them
before sending probes. These values are lower bounds, because DNS, target
responses, retries, and data-dependent Nmap confirmation can add time.
`unestimated_jobs` counts jobs with additional work that has no configured rate
ceiling, or whose schedule cannot be estimated. The job's timeout ends each
run, so each run counts at most the timeout, whether its duration comes from
samples or from the lower bound: a resumable cycle whose attempts add up to
more continues in later runs. The estimate follows the job's cron ticks over a
representative four-year calendar cycle in its timezone, which averages
leap-day schedules over the longer cycle, and skips a tick when the previous
estimated run is still active.
It counts only the runs the scheduler can start. A job runs at most once at a
time, so it adds at most one slot-day, 86,400 slot-seconds, to
`estimated_slot_seconds_per_day`. The additive `cadence_unattainable_jobs`
field counts jobs for which at least one tick is skipped; it does not depend on
whether the job's demand exceeds a slot-day. The console shows a warning at
80% utilization and above, and names the count of jobs with skipped ticks.
`lower_bound_jobs` and `unestimated_jobs` are not disjoint counts: a job with a
known-rate lower bound may also have additional work that cannot be fully
estimated. The platform panel labels this possible overlap explicitly. The
Tenant and deployment estimates bound schedule work per request, including
pattern expansion and duration projection. The deployment estimate also shares
equivalent schedule-duration projections across active units. A job whose
pattern or projection cannot finish within that budget is counted as
unestimated and its slot-seconds are left out of the total.

A unit's capacity is a limit, not a reservation: every unit's scans share the
deployment's `scheduler.max_concurrent_scans` slots, so units that each stay
within their own capacity can still oversubscribe those slots together. From
v0.44.0, `GET /api/v1/platform/status`, which requires
`platform_status.read`, adds `scan_demand`: the scheduled demand of every
active unit together, compared with the slots of the whole deployment.

```json
{
  "scan_demand": {
    "units": 3,
    "enabled_jobs": 3,
    "history_jobs": 3,
    "lower_bound_jobs": 0,
    "unestimated_jobs": 0,
    "cadence_unattainable_jobs": 0,
    "slots": 1,
    "estimated_slot_seconds_per_day": 155520,
    "capacity_slot_seconds_per_day": 86400,
    "utilization_percent": 180,
    "over_capacity": true
  }
}
```

`units` counts the active units included; disabled units and units being
deleted schedule no scans and are left out. Each unit contributes its own
estimate capped at its effective slot limit × 86,400 slot-seconds per day.
The daemon calculates each contribution from that unit's enabled jobs,
bounded recent scan-duration history, and effective capacity through its
tenant-scoped store.
The job counts are sums of the units' counts, while
`estimated_slot_seconds_per_day` is the sum of these capped contributions.
`slots` is the deployment's `scheduler.max_concurrent_scans`, and
`capacity_slot_seconds_per_day` is `slots` × 86,400. `utilization_percent`
and `over_capacity` compare the capped sum with that deployment capacity.
The object holds sums and counts only: no unit or job ID or name, and no
per-unit figure. With one active unit, this aggregate can be lower than its
Jobs page estimate when that estimate exceeds the unit's effective capacity.
The daemon starts at most one estimate a
minute, however often the status is requested, and reuses its outcome for that
minute: when an estimate fails or takes longer than 10 seconds, the status
leaves `scan_demand` out until the next estimate, and the daemon logs one
warning for it.
The platform console's **Status** page shows it with a warning at 80%
utilization and above.

## Job creation preview

v0.32.0 adds `POST /api/v1/jobs/preview`. Send the same new-job JSON payload
accepted by `POST /api/v1/jobs`; the response returns the normalized public
job form, the existing `WorkEstimate`, the existing `ScanBudget` outcome, and
at most five stable warnings:

```json
{
  "job": {
    "name": "edge inventory",
    "schedule": "0 * * * *",
    "timezone": "UTC",
    "run_on_start": false,
    "assume_alive": true,
    "targets": ["198.51.100.10"],
    "dns_comparison_mode": "address_sensitive",
    "max_expanded_hosts": 256,
    "tcp": {
      "ports": "22,443",
      "mode": "connect",
      "service_detection": false,
      "engine": "nmap"
    },
    "udp": null,
    "timing": "balanced",
    "timeout": "1m0s",
    "resume_window": "192h0m0s",
    "baseline_samples": 2,
    "change_confirmations": 2,
    "enabled": true,
    "allow_high_cost": false
  },
  "scan_estimate": {
    "hosts": 1,
    "tcp_ports": 2,
    "udp_ports": 0,
    "probes": 2,
    "naabu_probes": 0,
    "nmap_probes": 2,
    "nmap_invocations": 1,
    "naabu_invocations": 0,
    "unknown_dns": 0
  },
  "scan_budget": {"exceeded": false},
  "warnings": [
    {
      "code": "elapsed_time_unknown",
      "message": "Probe and process counts are preflight estimates; elapsed scan time depends on DNS, scanner behavior, target responses, retries, and discovered ports."
    },
    {
      "code": "tcp_partial_coverage",
      "field": "tcp.ports",
      "message": "This Nmap TCP selection covers only the configured ports, not the full TCP port range."
    }
  ]
}
```

The preview applies the same new-job defaults, selected scanner-profile
resolution, destination routing, deployment target exclusions, and permission
rules as creation. It then compares the prepared estimate with the current
unit probe budget. When TCP engine/profile is omitted, the existing default
Naabu-to-Nmap profile and its full TCP discovery range are returned in `job`;
clients that deliberately select only some TCP ports must send
`engine: "nmap"`. Optional UDP work is included in the estimate.

`scan_estimate` is a bounded preflight, not a duration promise. Each DNS name
is counted as one logical address and increments `unknown_dns`; preview does
not resolve names. Naabu's known discovery pass covers ports 1–65535, while
the subsequent Nmap confirmation work depends on discovered ports and is not
included before discovery. Warnings have stable `code` values, an optional
field path, and user-facing text. Clients should handle unknown warning codes
as generic advisories.

A valid estimate above the unit budget still returns `200`. Its
`scan_budget.exceeded` is `true`, with `estimated_probes`, `limit`, and
`approval_would_fit`; the latter says whether the unit's high-cost ceiling
would admit the estimate if the caller is authorized to enable that approval.
A job over the absolute probe ceiling cannot fit even with that approval.
Creating a job remains compatible with existing behavior, but preview does
not reserve budget and a later run checks the current limits again. Do not
promise that an over-budget job will start.
If the unit budget cannot be read, preview returns `503 preview_unavailable`
with `details.reason: "scan_budget_unavailable"` and does not claim a fit.

Preview is advisory and read-only: it creates no job or revision, baseline,
scan, audit entry, outbox item, or schedule change; it does not resolve DNS,
start scanner or notification processes, reserve capacity, or publish an SSE
event. Creation and run remain authoritative and revalidate current policy and
resources. Invalid input and stale profile selections keep creation's
validation/conflict semantics. A foreign unit's profile or destination ID is
indistinguishable from an unknown ID.

The route requires `jobs.write`, so unit administrators and operators may
preview; viewers, platform administrators, and anonymous callers may not. It
uses the existing authenticated POST session and CSRF checks. It has no
additional route-specific Origin check; sending an Origin does not replace
CSRF validation. `allow_high_cost` remains administrator-only.

## Scan history

The authenticated scan-history endpoints provide metadata, full results, and
paginated host summaries:

| Endpoint | Response | Use |
| --- | --- | --- |
| `GET /api/v1/scans/{scanID}/summary` | Scan metadata only | Scan history/detail headers and status displays. Does not read or return stored results. |
| `GET /api/v1/scans/{scanID}` | Full scan, including `snapshot` and `changes` | Existing API clients that need the complete historical result. |
| `GET /api/v1/scans/{scanID}/hosts` | Paginated effective-host summaries | Host inventory and per-address navigation. |

The original full-response endpoint is retained for compatibility. New clients
that only need scan metadata should use `/summary`, then request paginated
results or host evidence separately when needed. This avoids loading large
snapshots just to show scan status and timestamps.

Since v0.35.0, the full-response endpoint writes the
`snapshot` and `changes` that EdgeWatch stored for the scan as they are,
rather than decoding and encoding them again, so a broad scan is held in the
daemon's memory once. For a scan that this release recorded, the response is
the same, byte for byte. A scan recorded by an older release can lack keys
that a newer release adds to its stored results; the response then lacks them
too, where it used to show them with empty values. A stored value that is not
a JSON object (`snapshot`) or array (`changes`) is still decoded as before.
The daemon serves at most two full responses at once across the deployment and
at most one for each business unit. A bounded number of requests can wait
briefly for admission. If the queue is full or capacity remains unavailable,
the endpoint returns `503 scan_slots_busy` with `Retry-After: 1` while there is
time left to write that refusal. Admission waits at most two seconds and never
extends the listener's response-write budget. If the admission budget is spent,
the handler does not load the scan result and attempts the same bounded `503`
refusal while the request and listener still allow a write. If the listener's
write deadline has already expired, it may close the connection without a
response.

## Job baseline pages

`GET /api/v1/jobs/{jobID}/baseline` returns the job's baseline summary and
one page of its logical units in `snapshot.units`, with the baseline's
`scopes`, `dns`, and `target_failures` on every page. A page carries neither
the host observations (`hosts`) nor, since v0.35.0, the
per-address `host_states`: both grow with every address in the scope, so a
page of a broad baseline would otherwise grow without bound. Request host
evidence from `GET /api/v1/jobs/{jobID}/baseline/hosts`, which is paginated
and filtered.

The `baseline` object of `GET /api/v1/jobs/{jobID}`, of the job create and
update responses, and of `GET /api/v1/jobs` is built from the same compact
runtime summary, so its `host_count` is the same in all of them.

## Per-address port changes

A change in scan `changes`, an incident, a pending change, or an event can
have the kind `port-address`: a port of a DNS target opened or closed on one of
the target's resolved addresses while another address exposed it. `target` is
the DNS name and the new `address` key is the resolved address. `old` and `new`
are a positive port state or `not-open`, and `key` has the form
`port-address|<target>|<protocol>|<port>|<address>`. Other change kinds have no
`address`. Clients that handle change kinds individually should treat an
unknown kind as a generic change.

## Scan comparison states

`GET /api/v1/jobs/{jobID}/scans/{scanID}` and
`GET /api/v1/jobs/{jobID}/scans/{scanID}/changes` describe how the scan was
compared with the job's baseline:

| `comparison_state` | `comparison_source` | Meaning |
| --- | --- | --- |
| `compared` | `scan_time` | Compared with the baseline that existed when the scan finished. `changes` is the diff stored with the scan, and `baseline_scan_id` names that baseline. |
| `compared` | `current_baseline_legacy` | A scan recorded before v0.26.0 without a scan-time comparison, compared with the current baseline on each request. |
| `baseline_sample` | `none` | The job had no baseline when the scan finished, so nothing was compared. |
| `baseline_established` | `none` | The scan was the sample that completed the baseline; `baseline_scan_id` is the scan's own ID. |
| `not_compared` | `none` | The scan failed, timed out, or was canceled, or its result was kept without a comparison. |

v0.26.0 adds `baseline_sample` and `baseline_established`. Earlier releases
reported those scans as `not_compared` while the job had no baseline, and
compared them with the current baseline once it had one. The scan objects of
the scan and job scan endpoints also carry the recorded `comparison`; it is
omitted for scans recorded before v0.26.0.

## Notification destination provider configuration

v0.31.0 adds structured provider configuration to notification destination
create and update routes. They accept the existing `url` field or a structured
`config` object. A structured configuration has the
shape `{provider, fields}`; supported providers are `smtp`, `discord`, and
`ntfy`. For example, an ntfy destination can be created with:

```json
{
  "name": "Operations",
  "config": {
    "provider": "ntfy",
    "fields": { "topic": "edgewatch-alerts" }
  },
  "password": "account password"
}
```

Unit destinations use `POST /api/v1/notifications/destinations` and
`PUT /api/v1/notifications/destinations/{id}`. Platform destinations use
`POST /api/v1/platform/notifications` and
`PATCH /api/v1/platform/notifications/{id}`. The update routes require the
current `revision`; omitting both `url` and `config` preserves credentials.
Providing either replaces them. Responses remain write-only and contain
provider metadata, never the URL or fields. Existing clients can continue to
send `url` unchanged.

## Job and scanner profile limits

`GET /api/v1/scanner/capabilities` includes `max_job_hosts` from v0.36.0: the
deployment's `scanner.max_job_hosts`, the most addresses the targets of one
job may expand to when it scans. The console warns while editing targets that
expand to more. A job's `max_expanded_hosts` keeps its range of 1 to
1,000,000; a scan of a job whose targets expand beyond `max_job_hosts` fails;
see [Scanning](/user-guide/scanning/#nmap-or-naabu-to-nmap).

The response reports Nmap and Naabu versions captured when the daemon starts
with its scanner policy. An unavailable or unrecognized version is `unknown`;
reading the endpoint does not start scanner processes. Host commands that build
an application without a scanner policy leave both cached versions `unknown`
and do not start probes.

From v0.36.0, creating, updating, or validating a scanner profile refuses
`nse_args` keys other than the selected script's own and values with a comma
or a quote, with an `nse_args` field error; see
[NSE scripts](/user-guide/scanning/#nse-scripts). Reading a profile, its
revisions, or a job pinned to an existing revision is unchanged.

## Session capabilities

`POST /api/v1/auth/login` and `GET /api/v1/auth/session` include
`high_cost_override: true` when the session may approve high-cost scans on a
job (`allow_high_cost`); the key is absent otherwise. Today that is an
administrator of a unit. The console shows the approval control only to such a
session, and the job API still enforces the rule.

## Request paths

From v0.36.0, one route table serves the console API under `/api/v1` and
the public API under `/api/public/v1`: each route's method, path, and
permission are listed once, in `apiRoutes` in `internal/web/permissions.go`,
with the handler that serves it. A request that no route serves gets the
answer it always got: `401 unauthorized` without a session, `403 csrf` for a
state-changing request without the CSRF token, and otherwise `403 forbidden`
with `details.permission` set to `route`. The public API answers such a
request with `404 not_found`. Neither API redirects a request or answers
`405`.

From v0.39.1, the server passes the original request path to the API route
table whenever it belongs to an API namespace or the outer ServeMux would
clean it into one. A request such as `GET /api/v1/jobs//{id}` is checked as
written and gets the route gate's fail-closed response, without `Location` or
`Allow`. A path that starts in an API namespace but would clean out of it,
such as `/api/v1/../../healthz`, also stays behind that API's gate and cannot
reach `/healthz` or the console shell. The public API follows the same
boundary rule and returns `404 not_found` for an unmatched path. Paths outside
the APIs keep the outer ServeMux behavior.

A path segment is percent-decoded before it is matched, and an escaped slash
(`%2F`) separates segments, as before. The routes that always accepted one
trailing slash still do: the scanner profile and user routes, the
notification destination routes from `/api/v1/notifications/destinations/{id}`
down, the job routes from `/api/v1/jobs/{id}` down, the platform console's
routes, and the public pages. These requests now get `403 route`, like any
other path that no route serves:

| Request | Before v0.36.0 |
| --- | --- |
| A scan route with a trailing slash, such as `GET /api/v1/scans/{id}/` or `GET /api/v1/scans/active/` | `404 not_found`: the slash became part of the ID or address |
| `GET /api/v1/jobs/schedule-suggestion/` | `404 not_found`, as a job with the ID `schedule-suggestion` |
| A path with an empty segment behind an escaped slash, such as `/api/v1/users/%2F{id}` or `/api/v1/platform/%2Funits` | Answered as if the empty segment were not there |

On the public API, a slug with an empty segment, such as
`/api/public/v1/dashboard/%2F{slug}`, gets `404 not_found` instead of
`404 public_disabled`. No unit can have such a slug.

## Notification delivery outcomes

v0.35.0 changes these notification destination responses and adds two
routes for a unit's destinations:

| Endpoint | Change |
| --- | --- |
| `POST /api/v1/notifications/destinations/{id}/test` | A provider that does not answer within 15 seconds gets `504 notification_timeout`, "the destination did not answer in time; the message may still arrive", instead of `500 notification_failed`. Nothing was saved. |
| `POST /api/v1/notifications/destinations`, `PUT /api/v1/notifications/destinations/{id}`, and the destination test | A destination whose host is, or resolves to, an address in `scanner.target_exclusions` or an unspecified, loopback, or link-local address gets `400 validation_failed` with `details.url`. The message is fixed and repeats neither the URL nor the address. Platform destinations and a destination imported from `config.yaml`, until its URL is replaced, are not checked. |
| `POST /api/v1/notifications/destinations`, `PUT /api/v1/notifications/destinations/{id}` | With the destination policy active, a hostname that returns an error, no addresses, or times out during save gets a fixed `400 validation_failed`; no destination is saved or updated, and the response omits the hostname and resolver details. This save-time validation error is separate from retryable delivery DNS failures and provider test failures. |
| `PUT /api/v1/notifications/destinations/{id}` | Accepts `keep_pending: true`. When the update replaces the credentials, the destination's queued alerts move to the new credentials instead of being discarded. It is ignored when the update keeps the credentials. |
| `last_error_code` in destination responses | Can be `provider_timeout`, for a provider that did not answer in time, and `destination_excluded`. |
| `last_error_fingerprint` in destination responses | Identifies the kind of failure: its error code and class only, the same for every destination. A fingerprint stored by an earlier release, which the destination URL determined, is left out. |

`GET /api/v1/notifications/destinations/{id}/deliveries` and
`POST /api/v1/notifications/destinations/{id}/deliveries/redeliver` need
`notifications.manage`, so only a unit's administrators can use them; an
operator or viewer gets `403`. Another unit's destination, a platform or
deployment destination, and an unknown ID get the same `404`.

The list returns `{deliveries, next_before}`, newest first: the alerts that
the destination dropped after their retries ran out and that a redelivery
would send. Each has `id`, `event_type`, `job` when the alert has one,
`event_at`, `terminal_at`, `attempts`, `deferrals`, and `error_code`, never
the alert's message, the URL, or provider text. `state` may only be
`terminal`, the default; `limit` is 1 to 100, default 50; pass `next_before`
as `before` for the next page, and it is `null` on the last page.

The redelivery takes `{}` to queue every listed alert again or
`{"delivery_ids": [...]}`, with 1 to 100 IDs, to queue those of them, and
returns `{redelivered}`. The alerts are due at once with fresh retries and
are sent to the destination's current URL. A redelivery that queues any is
recorded in the unit's audit as `notifications.redelivered`, and a kept
replacement as `notifications.pending_kept`.

## Generated response types

From v0.36.0, the TypeScript types of these responses are generated from the
Go structs that write them, in
[`src/generated/api-types.ts`](https://github.com/crypt0rr/EdgeWatch/blob/main/src/generated/api-types.ts):
the console status (`GET /api/v1/status`), the platform status
(`GET /api/v1/platform/status`), the notification `status` of the destination
lists, and scans with their summaries, changes, and snapshots. The status
responses were built as maps before; their JSON matches the prior map
representations for the same fields, except that tenant status now replaces a
non-empty raw update-check diagnostic with the fixed category described above.
An optional property (`?`) is a key that
the response can leave out, such as the operational keys that a viewer's
status lacks, and a property typed `| null` can be `null`. The full scan
response of a scan that an older release recorded can still lack keys, as
[Scan history](#scan-history) describes.

## Health and metrics

v0.36.0 adds two endpoints outside the versioned APIs, on the console's
listener. Neither is in `apiRoutes`: `Server.Handler` registers each
beside the two API bases, and the route drift test lists them among the
patterns that it may register.

`GET /healthz` (and `HEAD`) needs no session and accepts any `Host`, as the
public status pages do. Its body is always one key, `status`:

| Status | Code | Meaning |
| --- | --- | --- |
| `ready` | `200` | The daemon's heartbeat is less than two minutes old. |
| `starting` | `503` | The daemon starts: it migrates the database with a recent heartbeat, or has not served the console yet. |
| `unhealthy` | `503` | A migration stalled or an earlier start left a failed one, the daemon heartbeat is stale or missing, or the database cannot be read. |
| `rate_limited` | `429` | The client sent more than 120 requests in a minute; `Retry-After: 60`. |

Other methods get `405` with `{"status":"method_not_allowed"}`. The answer
carries no reason, phase, version, or unit, and is reused for one second.

The daemon opens the listener before it opens and migrates the database.
Until it serves the console, the listener answers `/healthz` and `/metrics`
from the database's startup state, which it reads through a read-only handle
that never migrates or writes, and every other path, the console and both
APIs, with `503` and the error code `starting`. A migration that fails ends
the daemon and closes the listener, as before, so `edgewatch health` and the
log report the failure, and a check that gets no answer should count as
unhealthy. When the address cannot be opened before the migration, the
daemon opens it after the migration, as earlier releases did, and fails its
start there if the address is still taken.

`GET /metrics` (and `HEAD`) answers `404` unless `web.metrics.enabled` is
true. Then it needs `Authorization: Bearer <token>` with the token of
`web.metrics.token_file`: a request without it, or with another token, gets
`401` with `WWW-Authenticate: Bearer realm="edgewatch-metrics"`, and a token
file that cannot be read keeps the endpoint at `503 metrics_unavailable`.
Each client may send 120 requests a minute (`429 rate_limited`). The answer
is `text/plain; version=0.0.4` and holds gauges plus the scheduled-run skip
counter; their names and labels are stable, and a label never names a
business unit, an account, a job, a target, or a destination. The database
and operational metrics are each cached for up to 30 seconds. Until the daemon serves the console, it
holds only `edgewatch_build_info`, `edgewatch_health_status`, and the
`edgewatch_migration_*` gauges:

| Metric | Labels | Value |
| --- | --- | --- |
| `edgewatch_build_info` | `version` | `1` for the running build. |
| `edgewatch_health_status` | `status`: `ready`, `starting`, `unhealthy` | `1` for the answer of `/healthz`, `0` for the others. |
| `edgewatch_daemon_heartbeat_age_seconds` | | Seconds since the daemon renewed its lease; only while it is ready. |
| `edgewatch_migration_state` | `state`: `migrating`, `ready`, `failed`, `unknown` | `1` for the startup migration's state. |
| `edgewatch_migration_phase_info` | `phase` | `1` for the running migration phase, such as `host-search:scan_hosts`; only while migrating. |
| `edgewatch_migration_progress_ratio` | | The running phase's progress from 0 to 1, when it reports one. |
| `edgewatch_scan_slots_capacity` | | The deployment's scan slots. |
| `edgewatch_scan_slots_in_use` | | Slots that running scans hold. |
| `edgewatch_scans_queued` | | Accepted scans that wait for a slot. |
| `edgewatch_database_bytes` | | The size SQLite has allocated for the database. |
| `edgewatch_backup_status_known` | | `1` when the enabled backup status has a recorded outcome for the configured directory, `0` when it is missing, unreadable, for another directory, or has no outcome. Once the daemon opens its database, present whenever scheduled backups are enabled. |
| `edgewatch_backup_last_success_timestamp_seconds` | | When a scheduled backup last succeeded, as a Unix time; zero means none has succeeded. Present when backup status is known. |
| `edgewatch_backup_consecutive_failures` | | Consecutive scheduled backup failures since the last success. Present when backup status is known. |
| `edgewatch_scanner_identities` | `state`: `active`, `quarantined`, `in_use_by_other_processes`, `free` | Number of scanner identities in each allocation state. Present when startup enforced the pool and the bounded pool inspection succeeds. `active` plus `free` is shared capacity and counts every active lease as reachable; the metric does not identify lease owners. The daemon's built-in low-capacity alert separately subtracts active leases its own allocator did not acquire. |
| `edgewatch_scheduled_runs_skipped_total` | `reason`: `job_active`, `cycle_stalled` | Counter since this daemon started for scheduled runs skipped because their job was already active or their resumable cycle was stalled. |
| `edgewatch_jobs_overdue` | | Enabled schedules currently due for the job-silence watchdog; live scans and alert retry windows are excluded. |
| `edgewatch_scan_cycles_stalled` | | Stalled cycles for visible jobs in active business units. |
| `edgewatch_notification_outbox_pending` | | Alerts still to be delivered, including those retrying. |
| `edgewatch_notification_outbox_retrying` | | Alerts whose delivery failed at least once and is retried. |
| `edgewatch_notification_outbox_terminal` | | Alerts that failed for good and are kept in the outbox. |
| `edgewatch_notification_destinations_locked` | | Enabled web-managed destinations, of every unit and the platform, that alerts cannot reach: the notification key cannot open them, or their URL is no longer valid. It follows a lost or replaced key from the next delivery pass, normally within 30 seconds. |
| `edgewatch_telemetry_collected_timestamp_seconds` | | When the database and outbox counts were read; they are read at most every 30 seconds. |
| `edgewatch_scanner_sandbox_state` | `state`: `sandboxed`, `identity_only`, `landlock_only`, `unconfined`, `launches_refused` | `1` for how scanner processes are confined; `launches_refused` means the scanner identity or required sandbox could not be established and scans fail closed. |
| `edgewatch_notification_sandbox_state` | `state`, as above | `1` for how the notification process is confined. |
| `edgewatch_update_check_status` | `status`: `up_to_date`, `update_available`, `ahead`, `check_failed`, `disabled`, `development_build` | `1` for the release check's status. |
| `edgewatch_update_available` | | `1` when a newer release is available. |
| `edgewatch_update_last_successful_check_timestamp_seconds` | | When the release check last succeeded. |

`GET /api/v1/platform/status` also gains `telemetry`: the deployment's
counts of jobs, scans, host observations, effective hosts, events, and scan
cycles, `database_bytes`, `outbox_pending`, `outbox_retrying`,
`outbox_failed`, and `collected_at`, read at most every 30 seconds and left
out when they cannot be read.

## Security and deployment alert routing

v0.36.0 adds opt-in routings for the security and deployment alerts; see
[Notifications](/user-guide/notifications/#security-alerts). Each routing
starts empty. A `PUT` takes `{destinations, password}` and replaces it, an
empty array selecting none; a `PATCH` takes `{destination_id, enabled,
password}` and turns one destination on or off against the saved routing.
Both confirm the caller's password and answer `{configured: true,
destinations}`. A destination that is not the owner's, an unknown ID, and a
deployment destination from `config.yaml` get `400 validation_failed` naming
the ID, and nothing changes.

| Endpoint | Permission | Routing |
| --- | --- | --- |
| `PUT`, `PATCH /api/v1/notifications/security-routing` | `notifications.manage` | The unit's security alerts, to the unit's web-managed destinations. Recorded in the unit's audit as `notifications.security_routing`. |
| `PUT`, `PATCH /api/v1/platform/notifications/security-routing` | `platform_notifications.manage` | The platform's security alerts, to platform destinations. Recorded as `platform_notifications.security_routing`. |
| `PUT`, `PATCH /api/v1/platform/notifications/health-routing` | `platform_notifications.manage` | The deployment alerts, to platform destinations. Recorded as `platform_notifications.health_routing`. |

`GET /api/v1/notifications/destinations` and `/notifications/options` add
`security_routing`, and `GET /api/v1/platform/notifications` adds
`security_routing` and `health_routing`, each as `{configured, destinations}`.
The alerts are delivered as events of the types `security.alert` and
`application.health_alert`, which a destination's failed alerts can list;
they do not appear in the activity history.

## Perimeter coverage

Four new routes serve a business unit's perimeter: the address ranges that
its administrators declare, either as space the unit owns
(`kind: "prefix"`) or as third-party space it may scan
(`kind: "authorized"`), and a report that compares them with what the unit's
monitors will scan. A declared range states ownership or permission; it does
not authorize a scan. No route scans, resolves a DNS name, opens an outbound
connection, or creates, changes, or starts a job. Existing routes and
responses are unchanged, apart from the two new entries in `permissions`.
The console's **Perimeter** page uses these routes; see
[Perimeter coverage](/user-guide/perimeter/).

| Endpoint | Permission | Request and response |
| --- | --- | --- |
| `GET /api/v1/perimeter` | `perimeter.read` | `200` with a `PerimeterOverview`. |
| `POST /api/v1/perimeter/seeds` | `perimeter.manage` | `{entries: [{kind, value, label}]}`, with 1 to 256 entries. `200` with a `PerimeterDeclareResult`, `{created, skipped}`. |
| `GET /api/v1/perimeter/seeds/{id}` | `perimeter.read` | `200` with a `PerimeterRangeDetail`. |
| `DELETE /api/v1/perimeter/seeds/{id}` | `perimeter.manage` | No body and no password. `204`. |

A unit's administrators hold both permissions and its operators hold
`perimeter.read`, so `permissions` in the login, session, and status responses
lists them for those roles. Viewers, platform administrators, and anonymous
callers reach none of the routes and get the route gate's answers. The `POST`
and `DELETE` need the session's CSRF token, like every state-changing route.
None of the routes accepts a trailing slash.

### Declaring ranges

```json
{
  "entries": [
    { "kind": "prefix", "value": "203.0.113.0/24", "label": "DC1 edge" },
    { "kind": "authorized", "value": "198.51.100.7" }
  ]
}
```

`value` is an IPv4 or IPv6 address or CIDR prefix. The server masks the host
bits and stores a bare address as a `/32` or `/128`; every range in a
response carries that canonical value, while a refused entry echoes the value
as submitted (see the table below). `label` is optional, at most 200
characters, and holds no control characters. Ranges may overlap. An entry
whose value the unit already holds under the same kind, or that repeats an
earlier entry of the same kind, is not refused: the range is created once and
each repeat counts as `skipped`. The server is authoritative for these rules
and refuses an entry, with its own reason, when:

- `kind` is not `prefix` or `authorized`; `asn` is refused as well;
- the value is not an address or CIDR prefix, such as a DNS name, a range such
  as `10.0.0.1-10`, or an ASN, or it carries an IPv6 zone;
- the value overlaps IPv4-mapped IPv6 space (`::ffff:0:0/96`), which takes
  the IPv4 form instead, or unspecified, loopback, multicast, or link-local
  space;
- an IPv4 prefix is shorter than `/8`, or an IPv6 prefix shorter than `/16`;
- the value is already declared under the other kind, stored or earlier in the
  same request.

A declaration is all or nothing: when any entry is refused, or the unit would
hold more than 1,024 ranges, nothing is written. Each accepted declaration,
including one whose entries were all skipped, and each removal is recorded in
the unit's audit, as `perimeter.seeds_added` with the counts by kind and as
`perimeter.seed_removed` with the kind and value. The platform audit does not
show them.

| Case | Response |
| --- | --- |
| A `POST` body with another content type | `415 unsupported_media_type` |
| A `POST` body that is not JSON, has an unknown field or trailing data, or is over 1 MiB | `400 invalid_json` |
| No entries, or more than 256 | `400 validation_failed`, "Declare between 1 and 256 entries.", with `details: {"limit": 256}` |
| A refused entry | `400 validation_failed` with `details.entries`: every refused entry as a `PerimeterLineError`, `{index, value, reason}`, in request order. `index` is the entry's position in `entries`, `value` is the submitted value cut to 64 bytes, and `reason` is a fixed text. |
| More than 1,024 ranges after the declaration | `400 perimeter_limit` with `details: {"limit": 1024, "held": …, "new": …}`: the ranges the unit held before the request and those the request would have created. |
| `GET` or `DELETE /api/v1/perimeter/seeds/{id}` with an unknown ID or another unit's | `404 not_found`, byte-identical for both and without the ID. |
| A declaration or removal whose audit record cannot be written | `503 audit_unavailable`, like the job routes; nothing is stored or removed, and no live update is sent. |
| A report whose data or unit probe budget cannot be read | `500`; never a partial report. |

### The coverage report

`GET /api/v1/perimeter` computes the report on each request from the unit's
ranges, the configuration of its unarchived jobs, the status of their scans,
the unit's probe budgets, and the deployment's `scanner.max_job_hosts` and
`scanner.target_exclusions`. Coverage comes from job configuration only,
never from observed hosts or DNS answers.

Each monitor in the report is a `PerimeterMonitorRef`. Its `state` is the
first check that fails, in the order a scheduled run meets them, or
`covering`; `reasons` lists every failing check. Only `covering` monitors
count as coverage.

| `state` | Meaning |
| --- | --- |
| `paused` | The job is disabled. |
| `invalid_config` | The stored job no longer passes the work estimator. |
| `over_budget` | The scheduler's preflight refuses the job's estimate: it exceeds the unit's probe budget, or, for a job with `allow_high_cost`, the high-cost ceiling. |
| `over_expansion` | The targets expand past the lower of the job's `max_expanded_hosts` and `scanner.max_job_hosts`, counted as the scanner counts them: every IP and CIDR target in full, overlaps included, and each DNS name as one address. |
| `excluded_target` | An IP or CIDR target contains an address in `scanner.target_exclusions`. |
| `covering` | No check fails. |

A `covering` monitor's coverage stays unproven until a successful scan
establishes its current security scope, including before the first
successful scan when recent resumable progress is shown. A latest failed,
timed-out, or incomplete attempt also leaves coverage unproven unless recent
resumable progress exists. Such progress preserves an existing same-scope
success, while a success from an older scope does not prove the current one.
Other flags that leave coverage unproven are `stale`, with the `stale_reason`
`overdue` once the `job-silent` watchdog's deadline has passed or
`schedule never fires` when its schedule gives that rule no deadline;
`stalled_cycle` when its active scan cycle is stalled; and `scope_changed`
when the latest successful scan's security hash does not match the current job
scope. The hash covers settings such as targets, protocol settings,
`max_expanded_hosts`, and `assume_alive`. Unlike
the `job-silent` alert, which waits while a scan holds the job's lease,
staleness does not wait for a scan that is still running. `cycle_in_progress`
reports a resumable cycle with recent completed work; `cycle_completed_units`
and `cycle_total_units` report that cycle's progress. Every monitor has
`last_attempt_status`, the status of its latest scan attempt or an empty
string, and `last_success_at`, when its latest successful scan finished or
`null`. `host_discovery` is true for a job with `assume_alive: false`, which
scans only hosts that answer host discovery. `dns_targets` counts the
DNS-name targets, which never count as coverage. `protocols` names the
buckets that the job's protocol settings fill, whatever its state:

- `full_tcp`: TCP with the engine `naabu_nmap`, or `nmap` with ports that
  cover 1–65535;
- `any_tcp`: TCP with any engine and ports, so it includes `full_tcp`;
- `udp`: UDP with any ports.

`PerimeterOverview` has these keys:

| Key | Content |
| --- | --- |
| `ranges` | One `PerimeterRange` per declared range: `id`, `kind`, `value`, `label`, `family` (`4` or `6`), `created_at`, `created_by`, and the `monitor_ids` of the monitors whose targets touch it. An IPv4 range has its `addresses`, the `excluded` addresses that `scanner.target_exclusions` holds, and `coverage`, a `PerimeterCoverage` of `full_tcp`, `any_tcp`, and `udp` with the addresses that `covering` monitors of each bucket scan, excluded addresses left out. A percentage uses `addresses` minus `excluded` as its denominator, and when that is 0 every address is excluded. An IPv6 range has these at 0 and its covered counts in `ipv6_monitored` instead, which saturate like every address count. It has no percentage: one job scans at most `limits.max_job_hosts` addresses, so no monitor sweeps an IPv6 prefix. |
| `monitors` | Once the unit declares a range, the monitors with an IP or CIDR target that overlaps a declared range or lies at least partly outside them, in name order; empty while the unit declares none. |
| `outside` | Once the unit declares a range, each IP or CIDR target of a monitor in any state that lies fully or partly outside the union of the declared ranges, as a `PerimeterOutsideTarget`: `job_id`, `job_name`, `state`, `target`, `partial` when only part of it is outside, and `outside_addresses`, the count of its addresses outside them, which saturates. At most 200; DNS names are not listed. |
| `outside_truncated` | `true` when `outside` was cut at 200. |
| `totals` | A `PerimeterTotals`: `declared_ipv4`, `excluded_ipv4`, and `covered_full_tcp`, `covered_any_tcp`, and `covered_udp` over the union of the IPv4 ranges, so overlapping ranges count once; `ranges`, every declared range, and `ipv6_ranges`, the IPv6 ones among them; `cannot_scan_monitors`, the monitors that touch the perimeter and are not `covering`; `unproven_monitors`, the `covering` ones that touch it without a successful scan for the current scope, that are stale, have a stalled cycle or changed scope, or whose latest attempt failed, timed out, or was incomplete without recent resumable progress; and `outside_targets`. Each count is taken before any list is cut. |
| `limits` | A `PerimeterLimits`: `max_job_hosts`; `max_probe_count` and `max_naabu_probe_count`, the unit's normal probe budgets that the states and suggestions use, not its high-cost ceiling; `max_ranges` (1,024); and `max_entries_per_request` (256). |
| `generated_at` | When the report was computed. |

Every address count in the perimeter responses saturates at
9,007,199,254,740,991, JavaScript's `Number.MAX_SAFE_INTEGER`, so a client
that parses the JSON into JavaScript numbers reads each one exactly. The
limit applies to `addresses`, `excluded`, `coverage`, `ipv6_monitored`, the
address counts of `totals`, and `outside_addresses`; a suggestion's
`addresses` and `addresses_per_monitor` never exceed
`limits.max_job_hosts`. Only an IPv6 count reaches it, such as that of a
`/64` target outside the declared ranges, and a count at the limit means at
least that many.

### Range detail and suggested monitors

`GET /api/v1/perimeter/seeds/{id}` returns a `PerimeterRangeDetail` with the
`range`, the `monitors` that touch it, and:

| Key | Content |
| --- | --- |
| `uncovered` | A `PerimeterUncovered` with a `PerimeterBlocks` for each of `full_tcp`, `any_tcp`, and `udp`: the range's addresses outside `scanner.target_exclusions` that no `covering` monitor of the bucket scans, as `cidrs`, the fewest aligned CIDR blocks, at most 256; `truncated`; and `total`, the number of blocks before the cap. An IPv6 range lists its blocks too. |
| `addresses_per_monitor`, `monitors_needed` | `PerimeterModeCounts` with a count for each suggestion mode: `full_tcp`, `selected_tcp`, and `udp`. |
| `suggestions` | Up to 64 gaps-only `PerimeterSuggestion` objects per mode: `mode`, `targets`, `addresses`, `already_covered_addresses` (0), `estimated_probes`, and `protocol`. Full TCP suggestions may also include `minimum_duration_seconds`. |
| `suggestions_truncated`, `budget_too_low` | `PerimeterModeFlags` with a flag for each mode. |
| `coalesced_monitors_needed` | `PerimeterModeCounts` for the bounded coalesced alternative. When `coalesced_suggestions_truncated` is true, `17` means 17 or more monitors. It is 0 when the mode has no alternative: none bridges covered space, or the complete one does not improve on the mode's gaps-only plan. |
| `coalesced_suggestions` | A complete alternative plan per mode, when one can bridge already-covered space within the limits below and improves on the mode's gaps-only plan, as described below. Each `PerimeterSuggestion` gives the repeated address count in `already_covered_addresses`. |
| `coalesced_suggestions_truncated` | `PerimeterModeFlags`; true when the complete coalesced plan needs more than 16 monitors and is withheld without being compared with the gaps-only plan. |

Suggestions fill uncovered IPv4 space, of owned and authorized ranges alike.
An IPv6 range gets none, and its `monitors_needed` are 0, while its
`addresses_per_monitor` and `budget_too_low` still describe the unit's modes.
Each mode fills one bucket's gaps with a fixed preset, which `protocol`, a
`PerimeterProtocol`, returns with `protocol` (`tcp` or `udp`), `engine`,
`ports`, `service_detection`, `mode` for the TCP modes only, and
`profile_id` for `full_tcp` only:

| Mode | Fills the gaps of | Preset |
| --- | --- | --- |
| `full_tcp` | `full_tcp` | TCP, engine `naabu_nmap`, ports `1-65535`, mode `connect`, no service detection, the built-in Naabu profile |
| `selected_tcp` | `any_tcp` | TCP, engine `nmap`, ports `22,443`, mode `connect`, no service detection |
| `udp` | `udp` | UDP, engine `nmap`, ports `53,123,161,500,1194,4500`, service detection |

`addresses_per_monitor` is the number of addresses one monitor of the mode
fits: the lowest of `scanner.max_job_hosts`, each of the unit's Naabu and
Nmap probe budgets divided by the probes that one address needs, rounded
down, and a cap of 4,096 addresses for `selected_tcp` and 1,024 for `udp`.
At the default budgets that is 305, 4,096, and 1,024. When one address does
not fit the budget, it is 0, `budget_too_low` is `true`, and the mode has no
suggestions.

Packing is deterministic. Each uncovered block at least as large as the
largest power of two that fits one monitor is split into monitors of that
size, and the smaller blocks, in address order, join the first monitor with
room. `monitors_needed` counts every monitor; `suggestions_truncated` is
`true` when more than 64 were needed. No suggestion contains an excluded
address. A Full TCP suggestion may include `minimum_duration_seconds`, a
lower-bound estimate based on the built-in Naabu probe rate; it excludes host
response time, retries, and Nmap confirmation. Other suggestion modes omit
this field, and the estimate is not a scan-duration promise.

`coalesced_suggestions` can give each mode a second, complete plan that may
also scan already-covered addresses. A mode has one only when it improves on
that mode's gaps-only plan: its monitors hold fewer targets in total than the
gaps-only monitors do, or it needs fewer monitors than the mode's
`monitors_needed`. Otherwise the mode has no coalesced suggestions and its
`coalesced_monitors_needed` is 0. Each coalesced target is no larger than a
`/24` (256 IPv4 addresses), further limited by the mode's probe budget; each
monitor has at most 16 target CIDRs; and the complete plan has at most 16
monitors per mode. If it needs more, it is not compared with the gaps-only
plan: the array is empty, the truncation flag is true, and
`coalesced_monitors_needed` is 17 to mean 17 or more. Thus a
target may repeat up to 255 already-covered addresses when only one address
in its `/24` is uncovered, but probe budgets still limit the whole monitor.
`already_covered_addresses` and `estimated_probes` include that repeated
space. Coalesced targets remain inside scannable declared space and never
include `scanner.target_exclusions`. Full TCP duration estimates apply to
either plan and are lower bounds, not promises. A suggestion creates nothing:
a client that wants the monitor sends it to
`POST /api/v1/jobs`, which checks it like any other new job.

### Live updates and generated types

A declaration that created at least one range, and each removal, sends
`{"type": "perimeter.updated"}` to the unit's own live-update streams, and to
no other audience. A declaration whose entries were all skipped sends none.
The report also changes when the unit's jobs and scans change, which send
their own updates, and when the unit's capacity or the deployment's scanner
settings change, which send the unit none.

The TypeScript types of these responses, and of the refused entries in
`details.entries`, are generated in
[`src/generated/api-types.ts`](https://github.com/crypt0rr/EdgeWatch/blob/main/src/generated/api-types.ts):
`PerimeterOverview`, `PerimeterRange`, `PerimeterCoverage`, `PerimeterTotals`,
`PerimeterLimits`, `PerimeterMonitorRef`, `PerimeterOutsideTarget`,
`PerimeterRangeDetail`, `PerimeterUncovered`, `PerimeterBlocks`,
`PerimeterModeCounts`, `PerimeterModeFlags`, `PerimeterSuggestion`,
`PerimeterProtocol`, `PerimeterDeclareResult`, and `PerimeterLineError`.
The generated types declare each list as `T[] | null`, but these responses
always send an array, which is empty when there is nothing to list.

## Business units

v0.20.0 adds business units to every installation. The routes and response
keys below are new or changed in that release; a single-unit installation
gets them too, with its accounts in the default unit. Every route is in the
route inventory, `apiRoutes` in `internal/web/permissions.go`.

### Changed responses

| Endpoint | Change |
| --- | --- |
| `GET /api/v1/setup/status` | `platform_setup_available` is true while the token from `edgewatch admin platform-setup-token` is unused and unexpired. Present once the first administrator exists. |
| `GET /api/v1/auth/session` | `scope` is `platform` for a platform administrator and `unit` otherwise; `unit` is the account's unit as `{id, name, slug}`, or `null` for a platform administrator; `multi_unit` reports whether more than one unit that is not deleted exists. `role` can be `platform_admin`. |
| `POST /api/v1/auth/login`, `GET /api/v1/auth/session` | `totp_enrollment_required: true` when an administrator or platform administrator without TOTP must enroll first; `permissions` then lists only `account.self`. The key is absent otherwise. It depends on the number of units. |
| `GET /api/v1/status` | `live_updates` is left out while more than one unit exists or the units cannot be counted; `telemetry` counts the unit's own rows, and only the default unit's status includes `telemetry.database_bytes`; and `max_concurrent_scans`, `max_probe_count`, and `max_naabu_probe_count` are the unit's own limits, which the scheduler enforces: the unit's cap where it has one and it is lower, otherwise the deployment's setting. A unit without caps reports the deployment's settings as before. The three keys are left out when the unit's capacity cannot be read. |
| `updates.error` | In `GET /api/v1/status`, a release-check diagnostic is replaced with the fixed `update_check_failed` category. The raw diagnostic remains available on `/api/v1/platform/status` to platform administrators. |
| `permissions` in the login, session, and status responses | Administrators also hold `audit.read`. A platform administrator holds `units.manage`, `unit_accounts.manage`, `platform_audit.read`, `platform_notifications.manage`, `platform_status.read`, and `account.self`. |

### New routes

`POST /api/v1/setup/platform` needs no session. It takes `{token, username,
password}` and returns `201` with `{configured, username}`. It checks the
browser origin (`403 origin`), answers a wrong, used, or expired token with
the generic `400 setup_failed`, and answers a client over the failure budget
with `429 rate_limited` and `Retry-After`.

`GET /api/public/v1/dashboard/{slug}` needs no session and returns the same
projection as `GET /api/public/v1/dashboard`, for the unit with that slug.
An unknown slug, a page that is not enabled, and a unit that is disabled or
being deleted get `404 public_disabled`. Each
slug has its own rate limit and cache. A client's requests for all public
pages together, on either URL, also share a budget of 600 a minute, past
which every page answers `429 rate_limited` with `Retry-After: 60`.

The audit views are read-only and return `{entries, next_before}`, newest
first. Pass `next_before` as `before` for the next page; it is `null` on the
last page. Both accept `limit` (1 to 200, default 50), `action` (an action
prefix), `since` and `until` (RFC 3339), and `actor` (an account ID).

| Endpoint | Permission | Use |
| --- | --- | --- |
| `GET /api/v1/audit` | `audit.read` | The unit's audit, for its administrators. `source_ip` is left out of a platform administrator's actions. |
| `GET /api/v1/platform/audit` | `platform_audit.read` | The platform audit: records without a unit and every unit's account and platform records, each with its `unit`. `unit` limits it to one unit's records. |

The platform console's routes serve only platform administrators; every other
role gets `403`. A body `password` is the caller's password, which the route
confirms before it changes anything. An unknown or deleted unit, an account
that is not the unit's, and a destination that is not the platform's get
`404`, except that `GET /api/v1/platform/units/{id}` returns a deleted unit's
tombstone. `DELETE /api/v1/platform/admins/{id}/activation` was added after
v0.20.3, when `PATCH /api/v1/platform/admins/{id}` began to answer a request
to disable a pending platform administrator with `403 not_permitted` instead
of `200`. `POST /api/v1/platform/admins/{id}/activation` and
`DELETE /api/v1/platform/admins/{id}` were added after v0.20.5.

| Endpoint | Permission | Request and response |
| --- | --- | --- |
| `GET /api/v1/platform/units` | `units.manage` | Units that are not deleted, with their counts (`accounts`, `administrators`, `jobs`, and `stored_scans`) and slot use, and the deployment's `limits`. `stored_scans` counts every scan in the unit's history, including scans for archived jobs. |
| `POST /api/v1/platform/units` | `units.manage` | `{name, slug}`; the slug is derived from the name when empty. `201` with the unit. |
| `GET /api/v1/platform/units/{id}` | `units.manage` | One unit with the same counts, including a deleted unit's tombstone and a deleting unit's `purge` progress; a deleting unit's `stored_scans` counts the scans that are left to erase. |
| `PATCH /api/v1/platform/units/{id}` | `units.manage` | `{revision, name, slug}`, name and slug optional. A stale revision gets `409` with `details.current`. |
| `DELETE /api/v1/platform/units/{id}` | `units.manage` | `{confirm_name, password}` for a disabled unit that is not the default. The unit in the `deleting` state. |
| `POST /api/v1/platform/units/{id}/disable` | `units.manage` | `{password, revision}`, revision optional. |
| `POST /api/v1/platform/units/{id}/enable` | `units.manage` | `{password, revision}`, revision optional. |
| `GET /api/v1/platform/units/{id}/capacity` | `units.manage` | The unit's `capacity`, the deployment's `limits`, its `slots`, and the unit's `revision` when the capacity was read. The `capacity.high_cost_ceiling` is `null` when the unit inherits the deployment's (`limits.max_probe_count_limit`), `0` when no ceiling is granted, so a job approved for high-cost work keeps the unit's budgets, and otherwise the granted ceiling. A new unit starts at `0`; up to v0.20.7 it started at the lower of the deployment's two probe budgets. |
| `PATCH /api/v1/platform/units/{id}/capacity` | `units.manage` | `max_concurrent_scans`, `max_probe_count`, `max_naabu_probe_count`, and `high_cost_ceiling`: an absent key keeps the setting, `null` inherits the deployment's, and a number sets it. A `high_cost_ceiling` of `0` takes the grant away; releases up to v0.20.7 refused it. `revision`, optional, is the one from the capacity the change is based on; once another change moved the unit on, the change gets `409 conflict` and nothing is saved. Without it, the change applies to the settings current at the request. |
| `GET /api/v1/platform/units/{id}/accounts` | `unit_accounts.manage` | The unit's accounts as summaries without credentials. |
| `POST /api/v1/platform/units/{id}/accounts` | `unit_accounts.manage` | `{username, display_name, role, password}`; `role` may only be `administrator`. `201` with the one-time `activation_token` and `activation_path`. |
| `POST /api/v1/platform/units/{id}/accounts/{uid}/password-reset` | `unit_accounts.manage` | `{password}`, for an administrator of the unit. The one-time link, `expires_at`, and `totp_enrolled`. |
| `DELETE /api/v1/platform/units/{id}/accounts/{uid}/sessions` | `unit_accounts.manage` | `{password}`, for any account of the unit. `204`. |
| `GET /api/v1/platform/admins` | `unit_accounts.manage` | The platform administrators. |
| `POST /api/v1/platform/admins` | `unit_accounts.manage` | `{username, display_name, password}`. `201` with the one-time link. |
| `PATCH /api/v1/platform/admins/{id}` | `unit_accounts.manage` | `{enabled, revision, password}`; never the caller's own account or the last enabled platform administrator. A pending platform administrator, which has not redeemed its invitation, is neither enabled nor disabled: both get `403 not_permitted`. |
| `DELETE /api/v1/platform/admins/{id}` | `unit_accounts.manage` | `{password}`, for a pending platform administrator: the account and its activation links are removed, so its username can be invited again. `204`. Any other platform administrator, enabled or disabled, the caller's own account included, gets `403 not_permitted`. |
| `POST /api/v1/platform/admins/{id}/activation` | `unit_accounts.manage` | `{password}`, for a pending platform administrator, including one whose link expired or was revoked: a new one-time link, and every older link stops working. `200` with `user`, `activation_token`, `activation_path`, and `expires_at`. Any other platform administrator, the caller's own account included, gets `403 not_permitted`. |
| `DELETE /api/v1/platform/admins/{id}/activation` | `unit_accounts.manage` | `{password}`, for a pending platform administrator: its unused activation link stops working, and the account stays pending. `204`, or `404 no_active_activation` when no usable link is left. Any other platform administrator, the caller's own account included, gets `403 not_permitted`. |
| `GET /api/v1/platform/notifications` | `platform_notifications.manage` | The platform's destinations without URLs, each with its delivery health as a unit's destinations have it; their `status`, with the `delivery_*` totals of the platform's destinations only; and the platform's `update_routing`. |
| `POST /api/v1/platform/notifications` | `platform_notifications.manage` | `{name, url, enabled, password}`. `201` with the destination. |
| `PATCH /api/v1/platform/notifications/{id}` | `platform_notifications.manage` | `{revision, name, url, enabled, password}`; an absent `url` or `enabled`, or an empty `name`, keeps its value. |
| `DELETE /api/v1/platform/notifications/{id}` | `platform_notifications.manage` | `{revision, password}`. `204`. |
| `PUT /api/v1/platform/notifications/update-routing` | `platform_notifications.manage` | `{destinations, password}`; platform destination IDs only, and an empty array selects none. |
| `GET /api/v1/platform/status` | `platform_status.read` | Units by state, account, job, and stored scan totals (`accounts`, `jobs`, `stored_scans`), platform administrator counts, the deployment's scan limits and slot use, the version and update status, from v0.36.0 the deployment's `telemetry`, and from v0.44.0 the active units' scheduled `scan_demand` together; see [Scheduled scan-slot demand](#scheduled-scan-slot-demand). |
