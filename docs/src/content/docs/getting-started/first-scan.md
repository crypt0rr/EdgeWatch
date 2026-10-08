---
title: Your first scan
description: Create a monitoring job, establish a baseline, and review changes to your network surface.
---

After [installing EdgeWatch](/getting-started/installation/), sign in as the
administrator you created during setup.

## Set up notifications

Open **Notifications** and choose Email (SMTP), Discord webhook, ntfy, or
**Advanced Shoutrrr URL**. Add a name, connection details, and confirm your
account password. Credentials are write-only and encrypted; the console does
not return them after you save them. Use **Test** and check that the message
arrives. When you create a job, select the destination in its notification
routing.

The [notification guide](/user-guide/notifications/)
covers routing, delivery health, and destinations imported from older deployments.

## Choose a scanner profile

Open **Scanner profiles**. Keep the built-in profile to begin with, or create
an administrator-managed profile suited to your network.

New TCP jobs default to Naabu connect discovery followed by Nmap confirmation.
UDP always uses Nmap. Read [Scanning and profiles](/user-guide/scanning/)
before selecting SYN discovery or expanding the probe scope.

## Create a monitoring job

Create a job with:

- **Targets:** authorized IP addresses, CIDRs, or DNS names.
- **Protocols and ports:** the TCP and UDP surface you want to monitor.
- **Schedule:** five-field cron syntax with the selected IANA timezone.
- **Baseline samples:** how many successful samples establish the expected surface.
- **Change confirmation:** how many matching changes confirm an incident.

Start with a small, known scope. Deployment probe budgets and target exclusions
still apply to the job.

## Establish the baseline

Run the job and inspect its results. Approve a successful scan as the baseline
once you have verified that it represents the surface you expect. Until the
job has collected its baseline samples, the scan detail describes each scan as
a baseline sample instead of a comparison; see
[Scan comparison](/user-guide/jobs-baselines-incidents/#scan-comparison).

:::note[Incomplete observations do not change expectations]
Failed, canceled, timed-out, or incomplete scans remain available for
troubleshooting. They cannot establish or advance the baseline or turn a
missing port into an expected state.
:::

## Review changes

Use **Hosts** to inspect effective addresses, ports, services, and scan evidence.
Use **Incidents** to review confirmed changes.

- **Accept change** makes the observed change expected and preserves scan history.
  Accepting a service on a newly opened port also accepts the port. Accepting
  only the port leaves its service for a separate decision.
- **Suppress 1 scan** defers the alert for the next successful scan. If the
  change remains, it is reported again afterward.

Administrators and operators can take these incident actions. The
[jobs, baselines, and incidents guide](/user-guide/jobs-baselines-incidents/)
also explains rebaselining, DNS aggregation, archival, and deletion.
