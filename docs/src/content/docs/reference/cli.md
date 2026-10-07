---
title: Host commands
description: Validate configuration, check health, inspect scans, and recover accounts from the host.
---

## Command examples

Run these commands from the host with `docker compose exec`:

```console
# Validate deployment configuration
docker compose exec edgewatch edgewatch config validate \
  --config /etc/edgewatch/config.yaml

# Check migrations, leases, and runtime health
docker compose exec edgewatch edgewatch health \
  --config /etc/edgewatch/config.yaml --output json

# Inspect jobs and their latest scan state
docker compose exec edgewatch edgewatch status \
  --config /etc/edgewatch/config.yaml --output json

# Run or inspect a managed job from the CLI
docker compose exec edgewatch edgewatch scan \
  --config /etc/edgewatch/config.yaml --job JOB_NAME
docker compose exec edgewatch edgewatch history \
  --config /etc/edgewatch/config.yaml --job JOB_NAME --limit 20

# Test configured notification delivery
docker compose exec edgewatch edgewatch notify test \
  --config /etc/edgewatch/config.yaml

# Act on one business unit by its slug
docker compose exec edgewatch edgewatch status \
  --config /etc/edgewatch/config.yaml --tenant UNIT_SLUG --output json
```

## Configuration validation

`config validate` runs every check of the daemon's startup that needs no
database: the deployment settings, the notification URLs file, the key in
`web.auth_key_file` and in `notifications.encryption_key_file` when they are
set (present, private to its owner, and well formed), and the syntax of each
notification URL in `notifications.urls` and `notifications.urls_file`. It
prints the normalized configuration with `"valid": true`, or `"valid": false`
with the reason and exits non-zero. An invalid URL is named by a digest
prefix, never by the URL. The daemon runs the same checks before it opens the
database, so a start that they refuse leaves the database as it was.

## Business-unit selection and recovery

`scan`, `status`, `history`, `baseline approve|reset|export`, and `notify test`
act on the default business unit. `--tenant UNIT_SLUG` makes them act on that
unit's jobs, scans, baselines, and destinations instead, and record their
audit entries in that unit; the key check of `notify test` still covers every
unit and the platform. A disabled unit can still be read with `status`,
`history`, and `baseline export`; the other commands refuse it until it is
enabled, and every command refuses a unit that is being deleted. These rules
apply to the default unit with or without `--tenant`, even after it is
renamed. A `scan` that is still running when its unit is disabled records its
scan as canceled when it finishes, without changing the unit's baseline,
incidents, or alerts, and exits non-zero with a message that the unit was
disabled.
`admin reset-password` and `admin disable-totp` find the account by
`--username` in any unit; they print the account's unit and role before they
act, and `--tenant UNIT_SLUG` makes them stop without a change unless the
account belongs to that unit. Their security audit record names the account
by username and ID, with its unit or the platform. Every other command
refuses `--tenant`.

## Health checks

`health` exits non-zero when migrations or the daemon heartbeat are unhealthy.
Its `warnings` list actions that do not stop EdgeWatch, such as removing
imported notification URLs from `config.yaml`.

## Notification tests

`notify test` sends one test message to each enabled destination of the unit
and prints the number of the unit's destinations `tested`, `failed`, and
`locked`. The notification key is one for the whole deployment, so it also
opens every enabled web-managed destination of every unit and of the platform
with the key, and prints how many it cannot open as `deployment_locked`. It
exits non-zero when a send fails or when any enabled web-managed destination
in the deployment is locked because the notification key is missing,
replaced, or unreadable, whichever unit `--tenant` selects, so it can confirm
a restored key for the whole deployment. Paused destinations are neither
tested nor counted.

## Status and structured output

Each `status` row has a `state`: `scheduled`, `paused`, `archived`,
`unit_disabled` for an enabled job of a disabled unit, which is off the
schedule until the unit is enabled, or `legacy` for an inactive YAML job.
Only scheduled jobs have a `next_run`. For a unit without jobs, `status
--output json` prints `[]`, and `history --output json` prints empty `scans`
and `events` lists for a unit without history. Commands print
their result on stdout and write log lines to stderr, so `--output json` output
can be piped straight into a JSON parser. Only the daemon logs to stdout.

## Audit records

Commands that change state, such as `scan`, `baseline approve` and
`baseline reset`, record a `host-cli` entry in the security audit log. A CLI
scan is recorded as `scan.run_requested`, like a run started from the console,
with the job ID and the scan outcome.

## Stalled and resumable scans

For a scan that appears stuck, open its live details in the dashboard first.
Broad jobs report scanner phase, process heartbeat, completed probes, and
resumable work. If a cycle has timed out, it will resume on the next scheduled
or manual run until its resume window expires. A stalled cycle holds scheduled
runs until an operator retries or discards it, or until its resume window
ends; the first scheduled run after that records the expiry, and the next one
starts a fresh cycle. Check `docker compose logs --tail 100 edgewatch` for a
bounded error summary; do not assume a zero-progress display means the process
is idle.
