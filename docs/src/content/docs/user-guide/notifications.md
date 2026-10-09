---
title: Notifications
description: Manage destinations, reminders, update alerts, delivery retries, and legacy imports.
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
discards alerts queued for the old credentials. A successful test means the
provider accepted the test send; check the recipient to confirm the message
arrived. Destinations added after existing job routing is frozen remain
opt-in. Select a destination in each job that should use it.

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
routing in the same change. Each affected job gets a new revision and an
audit record. Its delivery health goes with it, so its failures no longer
count in the notification totals.

Renaming a destination keeps its queued alerts, including an alert that is
raised while the rename is saved. Replacing its URL or provider configuration
discards its queued alerts instead of sending them to the new credentials, and
deleting it discards them too.
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
daemon that keeps stopping is still reported by the job's silence alert.
Definitive provider failures
are retried durably for up to 15 attempts over roughly 77 hours; the delay
doubles from two minutes and caps at 12 hours. A restart preserves each
delivery's retry schedule. Terminal failures are visible in the console
without exposing provider errors or destination secrets. Each destination
shows its pending and retrying alerts, terminal failures, and last success or
failure on its unit's **Notifications** page, or on the platform console for
platform-owned destinations.

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
