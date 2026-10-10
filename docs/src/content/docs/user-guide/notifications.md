---
title: Notifications
description: Manage destinations, reminders, update, security, and deployment alerts, delivery retries, and legacy imports.
---

EdgeWatch uses [Shoutrrr](https://github.com/containrrr/shoutrrr) for delivery.
Destinations are named and managed on the **Notifications** page. Their URLs
are write-only and encrypted at rest with `notification.key`; their
credentials are never returned by the API or written to logs.

## Add a destination

Choose a built-in provider to enter connection details in separate fields:

- **Email (SMTP):** server, sender address, recipients, and optional login.
  Recipients can be comma-separated. The port defaults to 25; StartTLS is
  enabled when the server advertises support.
- **Discord webhook:** paste the HTTPS webhook URL for a Discord channel.
- **ntfy:** enter a topic and, when needed, a server and login. A blank server
  uses `https://ntfy.sh`.
- **Advanced Shoutrrr URL:** use this for any other provider Shoutrrr supports
  or when you already have a URL.

The form never reads a saved credential back. To rotate a saved destination,
edit it and enter all fields for its new provider configuration; leaving the
Advanced URL blank keeps its existing credentials. Replacing credentials
discards alerts queued for the old credentials unless you choose to keep them;
see [Changing destinations](#changing-destinations). A successful test means
the provider accepted the test send; check the recipient to confirm the
message arrived. A test that the provider does not answer within 15 seconds
reports that the destination did not answer in time: nothing was saved, and
the message may still arrive. Destinations added after existing job routing
is frozen remain opt-in. Select a destination in each job that should use it.

## Destination addresses

A unit's destinations cannot point the daemon at the addresses that the
scanner refuses to scan. EdgeWatch refuses a destination whose host is, or
resolves to, an address in `scanner.target_exclusions` or an unspecified,
loopback, or link-local address, such as `127.0.0.1`, `::1`, or the
`169.254.169.254` cloud metadata endpoint. It checks the host when a
destination is created or its URL is replaced, and again before each delivery
and test, so a name whose DNS answer changes to such an address afterwards is
not contacted either. The error says only that the deployment does not allow
the address; it never repeats the URL or the address. A delivery that is
refused fails with the error code `destination_excluded` and is retried like
any other failed delivery.

The check uses the host that the provider connects to: the host of the URL
for providers such as the generic webhook, ntfy, Gotify, Matrix, Mattermost,
and SMTP, and the `host` parameter for Teams. Providers that always connect
to their public service, such as Discord, Slack, and Telegram, need no check.

The rule follows `scanner.target_exclusions`, with the same override: set it
to an explicitly empty list, `[]`, to allow every address, which also lets the
scanner scan the host itself. A receiver on the Docker host, such as a local
ntfy server, otherwise needs an address that is not loopback. Destinations
that the host operator or a platform administrator configured are not
checked: platform destinations, URLs that `config.yaml` still lists, and a
destination imported from `config.yaml` until its URL is replaced in the
console. A destination that a unit's administrator added on a loopback or
link-local address before this check existed is refused from the upgrade on;
its deliveries fail with `destination_excluded` until you move the receiver
or set the override.

The check resolves names with the daemon's resolver. It cannot see a
redirect that the provider follows, or a name whose answer changes between
the check and the notification process's own lookup.

You can also add and test a destination while creating a monitor. This uses the
same provider fields and account-password confirmation as this page. The
destination is saved independently from the monitor: if you cancel the monitor
or its creation fails, the destination remains here. Credentials and the
account password stay in the temporary form and are cleared after saving.
Operators can select available destinations but cannot add or test them. They
can explicitly create a monitor without alerts.

## Routing and update alerts

Each job can select its own destinations. On the **Notifications** page,
**Update alerts** is an independent toggle on each configured destination:

- pausing a destination does not erase its update-alert selection;
- when legacy routing is first frozen, existing paused destinations remain
  selected and resume delivery if they are enabled again; destinations added
  afterward remain opt-in for existing jobs;
- saving an empty selection keeps update alerts silent while checks and the
  in-console indicator continue to work;
- password confirmation is required for every destination, credential,
  update-alert routing, and reminder change on the **Notifications** page.
  Selecting a job's destinations in the job editor needs only permission to
  edit jobs, which operators have.

## Security alerts

From v0.36.0, a business unit can send its security events to its own
destinations as they happen, instead of leaving them for a later review of
its audit. **Security alerts** is a toggle on each web-managed destination on
the unit's **Notifications** page. It is off for every destination until an
administrator turns it on, and turning it on or off needs the account
password, as every change on the page does. A deployment destination from
`config.yaml` cannot receive security alerts.

These audit records send a security alert:

| Event | Audit action | The alert names |
| --- | --- | --- |
| A client became rate limited on sign-in, password or TOTP confirmation, activation, or setup | `auth.rate_limited` | the operation, the client's address, and, for a sign-in, the unit's account |
| An account's one-time and recovery codes were locked after ten wrong codes | `auth.second_factor_locked` | the account and the address of the code that started the lockout |
| An account signed in with a recovery code | `auth.recovery_code_used` | the account and the client's address |
| A platform administrator invited a unit administrator | `user.created` with the `platform` actor | the invited account and the platform administrator |
| A platform administrator issued a password-reset link for a unit administrator | `user.password_reset_issued` with the `platform` actor | the account and the platform administrator |
| A platform administrator ended the sessions of a unit's account | `user.sessions_revoked` with the `platform` actor | the account and the platform administrator |

Each alert goes to the destinations of the unit that the record belongs to,
the unit of the account it names, and never to another unit's or the
platform's. It is queued in the same database change as its audit record, so
it is sent only when the record is kept, and it is delivered and retried like
any other alert. The alerts of a unit that is disabled or being deleted are
not sent; its audit keeps the records. An alert carries only the fixed
wording of its event, the unit's name, usernames, a client address, counts,
and times. It never contains a password, a code, a token or link, a URL, or a
file path, and an alert about a platform administrator's action leaves out
the administrator's address, as the unit's audit does.

Alerts are coalesced so that an attack cannot flood a destination. A rate
limit already records one `auth.rate_limited` per client, operation, and unit
in five minutes. On top of that, each unit gets at most one alert of each kind
every 15 minutes: the first event of a kind sends its alert at once and opens
a 15-minute window, and the events of that kind within the window are counted
instead of sent. When the window ends, the daemon sends one summary, such as
`3 more rate-limit episodes since 12:30 UTC`, which opens the next window; a
window that ends without further events sends nothing. The three platform
administrator actions share one window. The summary names no account; the
unit's audit holds every record. A failure to queue an alert never fails the
action or its audit record; the daemon logs a warning instead.

The platform has security alerts of its own, for the records in platform
scope: the rate limits, lockouts, and recovery-code sign-ins of platform
administrators, and the rate limits of sign-ins with a username that no
account has, whose alert leaves the username out. Platform administrators turn
them on per platform destination with the **Security alerts** toggle on the
platform console's **Notifications** page.

## Deployment alerts

From v0.36.0, the daemon reports problems with the deployment itself to the
platform's destinations. **Deployment alerts** is a toggle on each platform
destination on the platform console's **Notifications** page, off until a
platform administrator turns it on. A unit's destinations never receive them.
Each deployment alert is also recorded in the platform audit as
`application.health_alert`, whether or not a destination is selected.

| Alert | When |
| --- | --- |
| A sandbox lost confinement | The scanner or notification processes start with less confinement than the last alert reported: they lost the sandbox identity and run as UID 0, or they lost Landlock. See [the container hardening guide](/deployment/container-hardening/). |
| A sandbox regained confinement | They start with more confinement than the last alert reported, and lost none. |
| A version rollback | The daemon starts a version older than the installed one. |
| Alerts failed for good | Alerts of any unit or the platform dropped after their retries ran out since the previous report. The alert gives their number and how many of them were the platform's, never a destination, a URL, or a provider's answer. |

The daemon compares the sandboxes when it starts and with each heartbeat,
against the state that the last alert reported, so a restart with the same
state sends nothing. The first start of v0.36.0 records the current state;
when it is already degraded, it is reported once. A sandbox alert and a
rollback alert are sent at most once an hour each, so a daemon that restarts
in a loop, or whose sandbox comes and goes, cannot flood a destination; a
change within the hour is reported when the hour ends, if it still holds. A
rollback within the hour is recorded in the platform audit without being sent
again. Failed alerts are reported at most once every six hours, and the
failure of a deployment alert itself is not counted, so it cannot start a
loop. A lost or replaced `notification.key` locks every destination, the
platform's too, so it cannot be reported this way; watch for it with
[`/healthz` and the metrics](/operations/troubleshooting/#monitor-the-monitor)
or `edgewatch notify test`.

## Incident reminders

**Incident reminders** is a separate business-unit setting on the same page,
enabled by default. After a fully successful scan that still confirms an open
incident, EdgeWatch sends a grouped reminder to that job's selected
destinations. New incidents continue to get their initial alert; suppressed
incidents and incomplete, failed, canceled, or timed-out scans do not generate
reminders. The first successful follow-up may send a reminder immediately;
the selected cadence limits later reminders. Administrators can turn reminders
off or choose one minimum cadence for the business unit: hourly (the default),
every six hours, daily, or every successful scan. EdgeWatch applies the cadence
to each job separately. Existing saved cadence choices are retained
during upgrades; legacy every-scan values with no reminder-setting audit
history are treated as inherited defaults and changed to hourly. If an older
version recorded any reminder-setting action, EdgeWatch keeps the stored
cadence because that action may have saved an explicit every-scan choice. The
cadence survives restarts and does not change incident detection or job
routing.

## Changing destinations

Deleting a destination removes it from every job and from the update-alert
and security-alert routing, and a platform destination also from the
deployment-alert routing, in the same change. Each affected job gets a new revision and an
audit record. Its delivery health goes with it, so its failures no longer
count in the notification totals.

Renaming a destination keeps its queued alerts, including an alert that is
raised while the rename is saved. Replacing its URL or provider configuration
discards its queued alerts instead of sending them to the new credentials, and
deleting it discards them too.

When you repair a broken URL, such as a revoked webhook token, select
**Keep queued alerts** in the edit form. The replacement then keeps the alerts
queued for the old credentials and sends them with the new ones: alerts that
are waiting or retrying become due at once with their retries reset, and
alerts that failed for good stay in the destination's
[failed alerts](#failed-alerts), where you can redeliver them. The security
audit log records the counts as `notifications.pending_kept`. Do not keep
them when the new URL belongs to another recipient, who would receive alerts
meant for the old one. An alert that a delivery is sending at that moment may
also reach the old URL, and an alert raised while the replacement is saved is
still discarded.
This includes an alert that a delivery pass has picked up but not yet sent. An
alert raised while either change is saved is also discarded, and the security
audit log records it as `notifications.pending_discarded`. An alert raised
after the replacement is saved goes only to the new URL. To rotate a
credential, such as a webhook token, replace the destination's URL in the
console.

Pausing a destination keeps its queued alerts until it is enabled again,
including an alert that a delivery pass has picked up but not yet sent. A
pause uses none of their retries and is not reported as a delivery failure.

## Delivery retries and health

Scan changes, scan failures, cancellations, timeouts, stalled cycles,
scheduled runs skipped because they exceed the probe budget, and recovery
events can all generate notifications. A scan that stops because
EdgeWatch stopped, for example during an upgrade or restart, is recorded as
canceled with the reason "scan interrupted because EdgeWatch stopped" and
appears in Activity as **Scan interrupted**, but sends no notification. A
daemon that keeps stopping is still reported by the job's silence alert, which
the daemon itself raises; to detect a daemon that stopped or hangs from
outside, poll [`GET /healthz`](/operations/troubleshooting/#monitor-the-monitor).
Definitive provider failures
are retried durably for up to 15 attempts over roughly 77 hours; the delay
doubles from two minutes and caps at 12 hours. A restart preserves each
delivery's retry schedule. A provider that does not answer within 15 seconds
counts as a failed attempt too, so an outage that shows up as hanging
requests keeps alerts for the same retry schedule. Because such a provider may
have accepted the message, the alert is not sent again sooner than 30
minutes later. A delivery that EdgeWatch itself interrupts, for example when
the daemon stops, gets two seconds to finish; one that does not is deferred
for 30 minutes, at most eight times, without using an attempt. An alert that
is delivered more than ten minutes after it was raised names the time it was
raised.

Delivery is at least once. After a provider accepts an alert, EdgeWatch
retries recording the delivery for up to a minute if the database is busy.
If it still cannot record it, the daemon logs `notification sent but its
delivery could not be recorded; it may be sent again`, and the alert is sent
again when its 30-minute claim ends or at the next start. A provider that
accepts an alert without answering in time can also receive it twice.

Terminal failures are visible in the console without exposing provider errors
or destination secrets. Each destination shows its pending and retrying
alerts, terminal failures, and last success or failure with its error code on
its unit's **Notifications** page, or on the platform console for
platform-owned destinations. The API also returns an error fingerprint that
identifies the kind of the last failure, such as a name that did not resolve,
a refused connection, a certificate that is not trusted, or a provider that
did not answer in time. It is the same for every destination that fails the
same way and is derived from nothing that identifies the destination.

### Failed alerts

An administrator can review the alerts that a destination dropped after its
retries ran out: open **Failed alerts** on a destination with terminal
failures. The list shows each alert's event, job, the time it was raised and
dropped, its attempts and deferrals, and its error code, never its message or
the destination's URL. **Redeliver** queues one alert again and **Redeliver
all** queues all of the destination's failed alerts; the next delivery pass
sends them to the destination's current URL with fresh retries, and each
message names when the alert was raised. Redelivered alerts no longer count
as terminal failures. The security
audit log records each redelivery as `notifications.redelivered` with a count.
Only alerts queued for the destination's current credentials are listed, and
alerts held in restore quarantine are never redelivered. A paused or locked
destination holds redelivered alerts like any other alert. A provider that
accepted an alert but reported a failure receives it again.

### Proxies

Notifications to providers that use HTTPS or HTTP go through the proxy that
the daemon's `HTTPS_PROXY`, `HTTP_PROXY`, and `NO_PROXY` variables name, as
update checks do; SMTP connects directly. RDAP lookups ignore these variables;
see [the configuration reference](/reference/configuration/).

## Notification URLs in `config.yaml` (deprecated)

Earlier releases also read Shoutrrr URLs from `notifications.urls` and
`notifications.urls_file` in `config.yaml`. These keys are deprecated, and a later
release will refuse to start while either is set. `notifications.encryption_key_file`
stays supported.

An entry in `notifications.urls` may also be a complete environment reference
such as `${MATTERMOST_URL}`, which is read from the daemon's environment when
the URL is imported. The reference must be the whole value: a partly expanded
URL, or a variable that is unset, empty, or itself contains `${`, is refused.
The URL file must be a regular file, not a symbolic link, with mode `0400` or
`0600` and at most 1 MiB.

On the first daemon start of this release, after the database migration and
before any alert is sent, EdgeWatch imports each configured URL once as an
encrypted destination on the **Notifications** page:

- it is named after its console label, `Deployment destination`, with a number
  added when that name is taken, and can then be renamed, paused, tested,
  rotated, or deleted like any other destination;
- the same database change moves every reference to it: job selections,
  update-alert routing, alerts that are still queued (including alerts queued
  under the URL's older digest-based ID), and its delivery health. Queued
  alerts are still delivered, and jobs that use all enabled destinations keep
  receiving alerts from the imported destinations;
- the default `notification.key` is created next to the database if it does
  not exist yet, as for the first destination added in the console. A
  configured `notifications.encryption_key_file` is used instead.

After the import, EdgeWatch no longer delivers to the URLs in `config.yaml`. Each
start logs a warning while `config.yaml` still lists them, and `edgewatch health`
reports `notification URLs in config.yaml were imported; remove them from
config.yaml`. Remove `notifications.urls` and `notifications.urls_file` from
`config.yaml`, and the URL file mount from `compose.yaml`. A URL that is added to
or changed in `config.yaml` later is imported as an additional destination at
the next start. An imported destination that you delete in the console is not
recreated.

The import is all or nothing. If it cannot complete, for example because the
notification key is missing while encrypted destinations exist, or is
unreadable or cannot decrypt them, nothing is imported and EdgeWatch keeps
delivering to the configured URLs as before. The daemon still starts, logs the
error without the URL, and `edgewatch health` reports `notification URLs in
config.yaml could not be imported (<reason>); they are still delivered from
config.yaml`. Fix the cause and restart to retry. The security audit log
records a successful import as `notifications.config_imported`, with counts and
destination IDs only.

Only the daemon imports. Host commands such as `notify test` keep using the
configured URLs until the daemon has imported them, and use the imported
destinations afterward. A backup taken before the import is imported again
after it is restored.

Until its import succeeds, a URL in `config.yaml` is a read-only deployment
destination. Its ID follows its exact URL, so changing any part of the URL
creates a new destination at the next restart, and alerts still queued for the
old URL are not delivered. Jobs do not follow that change: EdgeWatch logs a
warning that names the jobs whose routing selects a destination that no longer
exists, each affected job shows a notice in the console, and saving the job
editor removes the missing selection. After the import, change a URL by
replacing it on the **Notifications** page instead; a changed URL in
`config.yaml` only adds another destination.
