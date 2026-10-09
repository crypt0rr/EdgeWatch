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
arrives. You can also create a destination while setting up a monitor. An
operator can select destinations but cannot create or test them. A monitor can
also be created with the explicit **Continue without alerts** choice.

The [notification guide](/user-guide/notifications/)
covers routing, delivery health, and destinations imported from older deployments.

## Choose a scanner profile

Open **Scanner profiles** only if you need an administrator-managed profile
suited to your network. The guided setup uses the built-in profile by default;
profile tuning is available in the full editor.

New TCP jobs default to Naabu connect discovery followed by Nmap confirmation.
UDP always uses Nmap. Read [Scanning and profiles](/user-guide/scanning/)
before selecting SYN discovery or expanding the probe scope.

## Create a monitoring job

Open **Jobs → New job** and follow **Targets → Coverage → Schedule and
alerts → Review**. Use only systems you are authorized to scan. The guided form
starts with full-range TCP discovery: Naabu checks ports 1–65535 and Nmap
confirms discoveries. Choosing specific TCP ports switches to Nmap-only
partial coverage. UDP is optional and always uses Nmap. The full editor remains
available for advanced scanner and baseline settings.

Review the five-field cron schedule, its timezone, selected alert destinations,
baseline sample count, confirmation threshold, and the server's probe estimate
and unit budget before creating the monitor. The preview does not resolve DNS
or send probes; actual work can differ after DNS resolution and exclusions are
applied.

Choose **Create without starting** to save the monitor without requesting an
immediate scan, or **Create and start first scan** to request one immediately.
An enabled schedule still requests scans at its scheduled times. The full
editor's separate **Run at daemon startup** option can also request a scan when
EdgeWatch starts. A destination created during setup is saved separately and
remains in **Notifications** if you cancel the monitor.

The full editor lets you review or change:

- **Targets:** authorized IP addresses, CIDRs, or DNS names.
- **Protocols and ports:** full-range or selected TCP coverage, plus optional
  UDP ports.
- **Schedule:** five-field cron syntax with the selected IANA timezone, or a
  paused schedule.
- **Baseline samples:** how many successful samples establish the expected surface.
- **Change confirmation:** how many matching changes confirm an incident.
- **Run at daemon startup:** an independent option to request a scan when
  EdgeWatch starts.

Start with a small, known scope. Deployment probe budgets and target exclusions
still apply to the monitor. If the estimate exceeds the budget, you can save
without starting; narrow the scope or ask an administrator to approve a
high-cost scan before requesting a fresh preview.

## Establish the baseline

The job page's **Next steps** card shows baseline learning progress and the
next available action. EdgeWatch establishes the baseline automatically after
the configured number of successful scans with complete, consistent coverage;
new jobs require two samples by default. The schedule supplies future samples
when it is enabled. Use **Run another sample** in Next steps when you want to
request one sooner. Until learning finishes, scans appear as baseline samples
rather than comparisons; see
[Scan comparison](/user-guide/jobs-baselines-incidents/#scan-comparison).

A complete baseline with zero positive ports in the configured TCP and UDP
coverage is valid. **Use as baseline** is an optional, explicit override after
you review the scan evidence; ordinary learning does not require approval.
If learning stalls or a run is rejected or incomplete, review the scan result,
correct the target or scanner configuration, and follow the
[baseline and scan lifecycle guide](/user-guide/jobs-baselines-incidents/#first-scan-and-baseline-learning).

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
