# API compatibility

## Scan history

The authenticated historical scan endpoints have two response shapes:

| Endpoint | Response | Use |
| --- | --- | --- |
| `GET /api/v1/scans/{scanID}/summary` | Scan metadata only | Scan history/detail headers and status displays. Does not read or return stored results. |
| `GET /api/v1/scans/{scanID}` | Full scan, including `snapshot` and `changes` | Existing API clients that need the complete historical result. |
| `GET /api/v1/scans/{scanID}/hosts` | Paginated effective-host summaries | Host inventory and per-address navigation. |

The original full-response endpoint is retained for compatibility. New clients
that only need scan metadata should use `/summary`, then request paginated
results or host evidence separately when needed. This avoids loading large
snapshots just to show scan status and timestamps.

## Business units (experimental)

The routes and response keys below exist only while
`experimental.business_units` is `true`, except where noted. While it is off,
the keys are absent, the public slug endpoint answers `404 public_disabled`,
and a request to any other of these routes is refused like a route that does
not exist: `401 unauthorized` without a session, which includes
`POST /api/v1/setup/platform`, and `403 forbidden` with `details.permission`
set to `route` with one. A single-unit client therefore sees the API as
before. The route inventory, `apiRoutes` in `internal/web/permissions.go`,
marks these routes, apart from the public slug endpoint, with
`BusinessUnits`.

### Changed responses

| Endpoint | Change |
| --- | --- |
| `GET /api/v1/setup/status` | `platform_setup_available` is true while the token from `edgewatch admin platform-setup-token` is unused and unexpired. Present once the first administrator exists. |
| `GET /api/v1/auth/session` | `scope` is `platform` for a platform administrator and `unit` otherwise; `unit` is the account's unit as `{id, name, slug}`, or `null` for a platform administrator; `multi_unit` reports whether more than one unit that is not deleted exists. `role` can be `platform_admin`. |
| `POST /api/v1/auth/login`, `GET /api/v1/auth/session` | `totp_enrollment_required: true` when an administrator or platform administrator without TOTP must enrol first; `permissions` then lists only `account.self`. The key is absent otherwise. It depends on the number of units, not on the flag. |
| `GET /api/v1/status` | `live_updates` is left out while more than one unit exists or the units cannot be counted. Whatever the flag says, `telemetry` counts the unit's own rows, and only the default unit's status includes `telemetry.database_bytes`. |
| `permissions` in the login, session, and status responses | Administrators also hold `audit.read`. A platform administrator holds `units.manage`, `unit_accounts.manage`, `platform_audit.read`, `platform_notifications.manage`, `platform_status.read`, and `account.self`. |

### New routes

`POST /api/v1/setup/platform` needs no session. It takes `{token, username,
password}` and returns `201` with `{configured, username}`. It checks the
browser origin (`403 origin`), answers a wrong, used, or expired token with
the generic `400 setup_failed`, and answers a client over the failure budget
with `429 rate_limited` and `Retry-After`.

`GET /api/public/v1/dashboard/{slug}` needs no session and returns the same
projection as `GET /api/public/v1/dashboard`, for the unit with that slug.
An unknown slug, a page that is not enabled, a unit that is disabled or being
deleted, and every slug while the flag is off get `404 public_disabled`. Each
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
tombstone.

| Endpoint | Permission | Request and response |
| --- | --- | --- |
| `GET /api/v1/platform/units` | `units.manage` | Units that are not deleted, with their counts and slot use, and the deployment's `limits`. |
| `POST /api/v1/platform/units` | `units.manage` | `{name, slug}`; the slug is derived from the name when empty. `201` with the unit. |
| `GET /api/v1/platform/units/{id}` | `units.manage` | One unit, including a deleted unit's tombstone and a deleting unit's `purge` progress. |
| `PATCH /api/v1/platform/units/{id}` | `units.manage` | `{revision, name, slug}`, name and slug optional. A stale revision gets `409` with `details.current`. |
| `DELETE /api/v1/platform/units/{id}` | `units.manage` | `{confirm_name, password}` for a disabled unit that is not the default. The unit in the `deleting` state. |
| `POST /api/v1/platform/units/{id}/disable` | `units.manage` | `{password, revision}`, revision optional. |
| `POST /api/v1/platform/units/{id}/enable` | `units.manage` | `{password, revision}`, revision optional. |
| `GET /api/v1/platform/units/{id}/capacity` | `units.manage` | The unit's `capacity`, the deployment's `limits`, and its `slots`. |
| `PATCH /api/v1/platform/units/{id}/capacity` | `units.manage` | `max_concurrent_scans`, `max_probe_count`, `max_naabu_probe_count`, and `high_cost_ceiling`: an absent key keeps the setting, `null` inherits the deployment's, and a number sets it. |
| `GET /api/v1/platform/units/{id}/accounts` | `unit_accounts.manage` | The unit's accounts as summaries without credentials. |
| `POST /api/v1/platform/units/{id}/accounts` | `unit_accounts.manage` | `{username, display_name, role, password}`; `role` may only be `administrator`. `201` with the one-time `activation_token` and `activation_path`. |
| `POST /api/v1/platform/units/{id}/accounts/{uid}/password-reset` | `unit_accounts.manage` | `{password}`, for an administrator of the unit. The one-time link, `expires_at`, and `totp_enrolled`. |
| `DELETE /api/v1/platform/units/{id}/accounts/{uid}/sessions` | `unit_accounts.manage` | `{password}`, for any account of the unit. `204`. |
| `GET /api/v1/platform/admins` | `unit_accounts.manage` | The platform administrators. |
| `POST /api/v1/platform/admins` | `unit_accounts.manage` | `{username, display_name, password}`. `201` with the one-time link. |
| `PATCH /api/v1/platform/admins/{id}` | `unit_accounts.manage` | `{enabled, revision, password}`; never the caller's own account or the last enabled platform administrator. |
| `GET /api/v1/platform/notifications` | `platform_notifications.manage` | The platform's destinations without URLs, their `status`, and the platform's `update_routing`. |
| `POST /api/v1/platform/notifications` | `platform_notifications.manage` | `{name, url, enabled, password}`. `201` with the destination. |
| `PATCH /api/v1/platform/notifications/{id}` | `platform_notifications.manage` | `{revision, name, url, enabled, password}`; an absent `url` or `enabled`, or an empty `name`, keeps its value. |
| `DELETE /api/v1/platform/notifications/{id}` | `platform_notifications.manage` | `{revision, password}`. `204`. |
| `PUT /api/v1/platform/notifications/update-routing` | `platform_notifications.manage` | `{destinations, password}`; platform destination IDs only, and an empty array selects none. |
| `GET /api/v1/platform/status` | `platform_status.read` | Units by state, account and job totals, platform administrator counts, the deployment's scan limits and slot use, and the version and update status. |
