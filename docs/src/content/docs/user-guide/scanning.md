---
title: Scanning and profiles
description: Understand Nmap and Naabu confirmation, scanner profiles, probe budgets, and resumable scans.
---

EdgeWatch observes authorized targets using fixed scanner executables and
validated argument arrays. Choose the engine and profile that match your
network and runtime capabilities.

The guided monitor setup starts with full-range TCP discovery: Naabu checks
ports 1–65535 and Nmap confirms discoveries. Choosing specific TCP ports
switches that job to Nmap-only partial coverage. UDP is optional and uses Nmap
for the selected ports. Switching between full-range and selected TCP coverage
preserves the prior settings for each mode; the full editor also keeps a pinned
profile revision and its tuning when you return to that mode. Review the actual
engine, port scope, profile revision, and estimate before creating the job.

## Nmap or Naabu to Nmap

Each TCP job chooses a scanner engine:

| Engine | Behavior |
| --- | --- |
| **Naabu discovery to Nmap** | Naabu discovers TCP ports 1-65535, then Nmap confirms discovered ports and can identify services. Only Nmap-confirmed positive states affect baselines and incidents. |
| **Nmap only** | Nmap scans the configured TCP port expression directly. |

Naabu connect discovery is the built-in default for new TCP jobs. Naabu SYN
discovery requires both `NET_RAW` and `NET_ADMIN`, which the `compose.syn.yaml`
override adds. Nmap-only SYN scans need only `NET_RAW`, which the default
Compose file grants. UDP is always Nmap-only. Naabu evidence and disagreements are retained as diagnostic
data, but they do not independently create incidents.

Naabu reports open ports only, so Nmap also confirms every TCP port the job
still tracks: baseline ports and the ports of open incidents, pending changes,
and suppressed changes. It checks them on every address the target resolves
to in that scan, also after a DNS name has moved to a new address. A single
Naabu miss cannot close them. An address with no Naabu result counts as
complete coverage only when host discovery is skipped (`assume_alive`, the
default). With SYN host discovery, Naabu cannot tell a down address from one
without open ports, so that address stays incomplete. With **Nmap only** and
host discovery enabled (`assume_alive: false`), EdgeWatch adds Nmap verbosity
level 1 (`-v`) so explicit down hosts appear in Nmap's XML output. Those results
are tracked as host-state changes, not as sets of closed ports, and the
incidents of a down host's ports do not recover while it is down. During Naabu
enrichment, each address has already been discovered, so Nmap uses `-Pn` to
confirm discovered ports without a second host-discovery pass or a verbose
down-host signal. Omitted Nmap hosts and timed-out probes remain incomplete.
Naabu connect discovery cannot use host discovery: a job that uses it must
keep `assume_alive` enabled, and EdgeWatch rejects the job when it is saved
otherwise. For host-state tracking, use **Nmap only**, or a Naabu SYN profile
when the runtime grants `NET_RAW` and `NET_ADMIN`.

Repeated Naabu results are
counted once. One Naabu invocation keeps at most 131,070 distinct open ports,
the equivalent of two addresses with every port open. Beyond that, the
addresses with the most results are recorded as incomplete with the reason
`naabu-too-many-open-ports`.

Nmap folds more than 25 `open|filtered` UDP ports into a summary line (the
threshold rises with `-v` and `-vv`). EdgeWatch records the ports listed in
that summary, so the baseline does not depend on the port count or on profile
verbosity. If a result lacks that list, the host's UDP coverage is marked
incomplete (`open-filtered-ports-unlisted`) rather than treating the ports as
closed.

Jobs can configure TCP and UDP independently, service detection, timing,
timeouts, host discovery (`assume_alive`), and approved scanner-profile
overrides. EdgeWatch executes fixed Nmap and Naabu binaries with validated
argument arrays; it never runs browser-supplied shell commands or arbitrary
executables.

Full-range scans are deliberately bounded by scheduler probe budgets. A scan
that runs as a single invocation resolves DNS again when it starts, and the
budget is checked against that resolution before any scanner runs.

A job's targets expand to at most its **Maximum expanded hosts**, and to at
most the deployment's `scanner.max_job_hosts`, 65,536 addresses, a /16, by
default. The daemon, which every business unit shares, keeps a scope and a
result for every address of a running scan in its memory, and a scan of a /16
was tested within the 512 MiB limit of the bundled `compose.yaml`. A job whose
targets expand to more fails to scan with
`expanded targets exceed scanner.max_job_hosts=65536`; split its targets into
several jobs. The editor and the guided setup warn while targets expand to
more, the daemon logs such jobs at startup, and `edgewatch health` lists
them. See the [configuration reference](/reference/configuration/) before
raising the setting.

A job whose estimated work exceeds its unit's budget needs an administrator's
high-cost approval. **Scan now** on such a job is refused with an error. A
scheduled run is skipped before it starts and is reported in Activity as
**Scheduled scan skipped**, with a notification to the job's destinations. It
is reported once for each scope and budget, and again after a scan of the job
has run. The job page shows when a job exceeds its budget and whether an
approval would let it run. An operator's change to a job's targets, ports, or
scanner clears its high-cost approval; the scope-change confirmation says so. A broad
scan may be split into resumable address, discovery, enrichment, and UDP work
units. A timeout or restart preserves completed work for the configured resume
window; partial work cannot change a baseline. When a cycle completes but
EdgeWatch cannot read the job's notification destinations, the cycle's result
is kept and compared on the next run instead of being scanned again. Once a
cycle expires or is discarded, its saved progress is deleted, at the latest by
the next daily retention pass. The dashboard shows scanner
phase, heartbeat, completed probes, ports found, and the last sanitized output.
A resumed cycle keeps the scanner-profile arguments it started with, and its
scans record that job and profile revision; a profile change applies from the
next cycle. Accepting an incident, approving or resetting the baseline, or
changing the monitored scope discards paused progress, and the next run starts
a fresh cycle.

**Cancel scan** stops the scanner and every process it started, and the job
page and Overview show **Cancellation requested** until the scan ends; see
[stopping scanners](/deployment/container-hardening/#stopping-scanners). Once EdgeWatch is saving a
scan's result, the scan can no longer be canceled. A scan that stops because
EdgeWatch itself stopped is recorded as interrupted rather than canceled; see
[notifications](/user-guide/notifications/#delivery-retries-and-health).

## Runtime capabilities

The default Compose configuration grants `NET_RAW`. Naabu SYN additionally
requires the explicit `compose.syn.yaml` override with `NET_ADMIN`:

```sh
docker compose -f compose.yaml -f compose.syn.yaml up -d
```

Review the [container capability matrix](/deployment/container-hardening/)
before enabling SYN discovery. Preserve target exclusions and deployment probe
budgets when editing profiles or increasing scan scope.

## Profile revisions

Scheduled jobs retain scanner-profile revisions. Editing a profile does not
silently change the profile revision of existing jobs. A resumable cycle uses
the arguments with which it started; updated settings apply to a new cycle.

A Naabu profile decides which discovery settings a job may tune and within
which range. The job editor enables only those fields, shows each range, and
keeps every field disabled until the profiles have loaded. The built-in Naabu
profile fixes every discovery setting; an administrator can create a profile
that allows tuning on the **Scanner profiles** page.

## NSE scripts

A scanner profile can run one approved NSE script with Nmap, and pass it
arguments of its own:

| Script | Arguments |
| --- | --- |
| `banner` | `banner.ports`, `banner.timeout` |
| `http-headers` | `http-headers.path`, `http-headers.useget` |
| `http-title` | `http-title.url` |
| `ssh-hostkey` | `ssh_hostkey` |
| `ssl-cert` | none |
| `dns-recursion` | none |

A script also reads the arguments of the NSE libraries and of other scripts,
such as `newtargets`, which would let a script add scan targets that the
target exclusions and probe budgets never see, so saving a profile refuses
any other argument. Values cannot contain a comma or a quote, which would
start another argument, nor paths, wildcards, or `@file` references. A
profile revision saved before v0.36.0 with other arguments keeps
working for the jobs that use it, and the daemon logs a warning naming those
arguments each time such a job scans. Saving the profile again requires
removing them; then update the jobs to the new revision.

## Scanner output

Nmap's terminal status stream is only a progress hint while Nmap writes its
XML result to a file, so a long scan is never stopped for the amount of status
it prints. The XML result is limited to 16 MiB and Nmap's diagnostic output to
8 MiB; a scanner that exceeds either is stopped and the error names the
limit.

See the [configuration reference](/reference/configuration/) for deployment
budgets and exclusions, and [Your first scan](/getting-started/first-scan/)
for the baseline workflow.
