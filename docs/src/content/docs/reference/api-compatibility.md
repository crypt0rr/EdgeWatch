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
The daemon answers two such requests at a time; further requests wait for
one of them to finish.

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
`405`; the server's path cleaning still redirects a path such as
`/api/v1/jobs//{id}` before any route is looked up, as before.

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
responses were built as maps before; their JSON is unchanged, byte for byte,
for every role and number of units. An optional property (`?`) is a key that
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
| `starting` | `503` | A startup migration runs and its heartbeat is recent. |
| `unhealthy` | `503` | A migration failed or stalled, the daemon heartbeat is stale or missing, or the database cannot be read. |
| `rate_limited` | `429` | The client sent more than 120 requests in a minute; `Retry-After: 60`. |

Other methods get `405` with `{"status":"method_not_allowed"}`. The answer
carries no reason, phase, version, or unit, and is reused for one second.

`GET /metrics` (and `HEAD`) answers `404` unless `web.metrics.enabled` is
true. Then it needs `Authorization: Bearer <token>` with the token of
`web.metrics.token_file`: a request without it, or with another token, gets
`401` with `WWW-Authenticate: Bearer realm="edgewatch-metrics"`, and a token
file that cannot be read keeps the endpoint at `503 metrics_unavailable`.
Each client may send 120 requests a minute (`429 rate_limited`). The answer
is `text/plain; version=0.0.4` and holds only these gauges; their names and
labels are stable, and a label never names a business unit, an account, a
job, a target, or a destination:

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
| `edgewatch_notification_outbox_pending` | | Alerts still to be delivered, including those retrying. |
| `edgewatch_notification_outbox_retrying` | | Alerts whose delivery failed at least once and is retried. |
| `edgewatch_notification_outbox_terminal` | | Alerts that failed for good and are kept in the outbox. |
| `edgewatch_telemetry_collected_timestamp_seconds` | | When the database and outbox counts were read; they are read at most every 30 seconds. |
| `edgewatch_scanner_sandbox_state` | `state`: `sandboxed`, `identity_only`, `landlock_only`, `unconfined` | `1` for how scanner processes are confined. |
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
| `GET /api/v1/platform/status` | `platform_status.read` | Units by state, account, job, and stored scan totals (`accounts`, `jobs`, `stored_scans`), platform administrator counts, the deployment's scan limits and slot use, the version and update status, and, from v0.36.0, the deployment's `telemetry`. |
