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
By default, in **Address-sensitive** mode, DNS answer membership, each resolved
host's reachability, and the resolved addresses that expose each port are part
of the monitored baseline. A port that opens on one address while another
address of the name already exposes it, or that closes on one address while
another keeps it open, is reported as a change on that address, for example
`edge.example tcp/22 on 2001:db8::10: not-open -> open`. A port that no
address exposed before, or that no address exposes any more, is a port change,
and an address that joins or leaves the DNS answer is a DNS change; the ports
of an address that joined the answer are compared after you accept that DNS
change. A port missing from an address
whose host is down is reported as that host's state change. While an address's
scan coverage is incomplete, a port that opened on another, complete address
is still reported, and closures wait for a complete scan. Baseline samples
converge only when they agree on which addresses expose each port. A baseline
port without recorded addresses, such as one accepted from an incident, takes
its addresses from the next complete scan without a report.

Jobs can opt into **Aggregate port and service surface** in the job editor when
DNS answers rotate routinely. Aggregate mode continues comparing the logical DNS
target's positive ports and service fingerprints, but intentionally ignores
answer additions/removals, individual backend reachability, and which address
exposes a port. IP and CIDR targets remain address-sensitive, so list addresses
as IP targets when they need per-address monitoring under a name whose answers
rotate. Per-IP scan evidence is retained for investigation. This is a
security-relevant change and requires an explicit new baseline.

Releases before per-address port comparison merged a DNS target's ports
across its addresses. After an upgrade, the first scans of an
address-sensitive job can report per-address changes that built up before the
upgrade; review them and accept the ones that are expected. A DNS target's
baseline that is still being learned during the upgrade may need one more
sample.

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

**Pause schedule** on the job page stops a job's scheduled runs without
editing the job, and **Resume schedule** starts them again; **Scan now** keeps
working while a job is paused. Pausing and resuming are unavailable while the
job's scan is running.

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
  without a fingerprint, and never enters the baseline on its own. Accepting
  a change on one address of a DNS target updates which addresses the
  baseline expects to expose the port. Accepting a closure also recomputes
  the port's expected service from the remaining addresses and accepts a
  reported service change that matches it.
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
