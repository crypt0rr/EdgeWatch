---
title: Jobs, baselines, and incidents
description: Schedule jobs, choose DNS aggregation, review hosts, and act on confirmed changes.
---

Job names can have at most 200 characters and cannot contain control
characters. Existing jobs with longer names are not changed, but saving an edit
to one requires a shorter name.

Jobs accept individual IP addresses, CIDRs, and DNS names. DNS names remain
logical targets while each resolved effective address is shown separately in
host evidence. If a DNS target cannot be resolved, EdgeWatch still scans other
targets it could resolve, marks the overall scan incomplete, and protects the
unresolved target's baseline from false removals until a complete scan succeeds.
By default, DNS answer membership and each resolved host's reachability are
part of the monitored baseline. Jobs can opt into **Aggregate port and service
surface** in the job editor when DNS answers rotate routinely. Aggregate mode
continues comparing the logical DNS target's positive ports and service
fingerprints, but intentionally ignores answer additions/removals and individual
backend reachability; IP and CIDR targets remain address-sensitive. Per-IP scan
evidence is retained for investigation. This is a security-relevant change and
requires an explicit new baseline.
Schedules use five-field cron syntax in the selected IANA timezone. New jobs
default to the deployment `timezone` from `config.yaml`, or to the browser's
timezone when it is omitted. New jobs receive an optional 30-minute
schedule-offset suggestion when another active job is nearby; the administrator
can keep concurrent times.

Choose how many successful samples establish a baseline and how many matching
changes confirm an incident. When a security-impacting job setting changes,
EdgeWatch shows the affected scope and asks for explicit rebaselining. Schedule
and execution-tuning changes do not reset the baseline. A run that waits for a
free scan slot uses the job's settings when it starts; if the job is paused or
archived while a scheduled run waits, that run is skipped.

Archiving stops a job while keeping its results and incidents available. An
administrator can permanently delete an archived job by typing its exact name;
this also removes that job's scan results, incidents, saved scan progress, and
notification delivery records. The job and its evidence disappear from the
interface immediately; retained data is erased in bounded, restart-safe
background batches. The security audit record is retained. This action is
irreversible and does not delete history belonging to other jobs, even when
they monitor the same IP address.

From **Incidents**, administrators and operators can:

- **Accept change** to make the current observation expected while preserving
  the original scan history. Accepting a service on a newly opened port also
  accepts that port; accepting the port alone leaves its service for a
  separate decision. Until you accept a service for that port, its
  fingerprint is reported as a change, also after a suppression or a scan
  without a fingerprint, and never enters the baseline on its own.
- **Suppress 1 scan** to defer the alert for the next successful scan. If the
  change remains, it is reported again afterward.

The **Hosts** page aggregates the latest successful result for each effective
IP. A host detail page shows configured-target relationships, TCP/UDP coverage,
positive ports, services, scanner provenance, and summarized closed/filtered
results. Opening a public host may load normalized RDAP information from the
authoritative registry; raw responses and contact records are not retained.
Host searches cover partial IP addresses, DNS names, targets, job names, and
service names or products. Enter at least 3 and no more than 256 characters;
searches stay on the indexed path and service names/products are prioritized
within the bounded search document.
