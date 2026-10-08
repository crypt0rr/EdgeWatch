---
title: API compatibility
description: Review scan response shapes, business-unit routes, and compatibility changes.
---

## Job scan work estimates

`scan_estimate` probe, host, and process counts are preflight scope figures,
not predictions of elapsed scan time. `estimated_seconds` is omitted when no
defensible duration estimate is available. Clients should treat this field as
optional and must not infer that a scan will finish within any fixed time from
the probe count alone.

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
slug has its own rate limit and cache.

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
| `GET /api/v1/platform/status` | `platform_status.read` | Units by state, account, job, and stored scan totals (`accounts`, `jobs`, `stored_scans`), platform administrator counts, the deployment's scan limits and slot use, and the version and update status. |
