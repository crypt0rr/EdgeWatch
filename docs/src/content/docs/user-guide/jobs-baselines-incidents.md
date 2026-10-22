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
change. The host state and per-address port changes of an address that left
the answer are no longer compared, so their incidents close without a
recovery. A port missing from an address
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

The **Jobs** and **Perimeter** pages show the business unit's scheduled
scan-slot demand against its effective slot capacity. Jobs with completed scan
history from the current job revision use the median duration of their 11 most
recent samples, multiplied by their scheduled runs per day. Each completed
resumable cycle sums the recorded durations of its scan attempts, excluding
idle time between scheduled attempts. A successful or incomplete scan without
a cycle is one sample. Samples from earlier revisions remain in scan history
but do not determine the current estimate; after any job revision change,
EdgeWatch uses the known-work lower bound until a scan of the current revision
completes. That lower bound divides only known probe work by a configured
maximum scanner rate, and is counted only when the configured scope is known to
fit both the job's **Maximum expanded hosts** and the deployment's
`scanner.max_job_hosts`. An over-limit or unresolved DNS scope adds no lower
bound because the scanner may reject it before sending probes. DNS, target
responses, retries, and data-dependent Nmap confirmation can make a scan take
longer, and work without a configured rate ceiling is called out as
unestimated. A warning appears at 80% utilization and when estimated demand
exceeds capacity.

## Planned change windows

On a job page, an operator or administrator can schedule one finite change
window, or start it immediately. Enter a reason and an end time; a scheduled
window also needs a start time. A window lasts no more than 24 hours, and
windows for the same job cannot overlap. Times use that job's IANA timezone,
with the numeric UTC offset shown before saving. Choose another wall time when
the local time is skipped by a daylight-saving change. When a local time is
repeated, select the matching UTC offset so the window has one exact instant.
The window is saved durably and continues across an EdgeWatch restart.

A window holds only that job's **change detected**, **change reminder**, and
**change recovered** notifications. Scans, baseline learning and comparison,
incident tracking, scan-health alerts, operator alerts, security alerts,
deployment alerts, and delivery-failure alerts continue normally. Pending
change alerts raised before the window are held too. When the window ends or an
operator cancels an active window, EdgeWatch coalesces those alerts rather than
replaying an old backlog afterward. A provider handoff that began before the
window cannot be recalled and may still finish while the window is active. If
its claim is still live at close, the review records it separately as in
flight. If its claim was released or recovered without a recorded result, the
review records an unknown prior outcome instead; this does not claim that a
provider is still running. Neither category counts as an alert held during the
window. When a summary is queued, a later provider failure does not replay that
stale individual alert or change the closing snapshot.

When there was change activity, closing the window creates one summary
notification for the job's configured destinations and a durable review task.
The review remains due if the notification cannot be delivered; normal
notification retries and delivery-health reporting continue. The closing
review shows unique new or recovered changes from held event records, the
incidents still open at close, the number of held change events, a separate
count of change events whose provider handoff was still in flight at close, and
a count of earlier provider attempts with unknown outcomes after recovery or
lease release. It can include a pending alert raised before the window if that
alert had not been delivered before the window started. Some event payloads are truncated or do
not contain enough change identity to count unique changes; EdgeWatch reports
those events as incomplete instead of guessing. When an incomplete event
reports a number of entries, that is shown as a reported count, not a unique
change count. The totals remain exact for identities EdgeWatch could retain.
Job readers can see the summary counts.
Incident details and evidence links require `incidents.read`; marking the
review complete requires `incidents.manage`. Canceling before a scheduled
window starts produces no closing review. Canceling an active window closes it
early and produces the same durable review as an expiry.
If EdgeWatch cannot read the job's notification destinations when an expired
window is due, it keeps the window open and its alerts held while retrying the
lookup for up to one hour after the window ends. If destinations become
available during that period, expiry creates the normal summary notification
and review. If they remain unavailable at the one-hour bound, EdgeWatch closes
the window with a durable review but does not queue a summary notification.
The summary includes `summary_notification_status` set to
`not_queued_destinations_unavailable`. Eligible held alerts are released for
individual delivery, or linked to a later open window when one applies. A
provider attempt already in flight keeps its claim; a later failure remains
retryable. The closing review remains available even though no summary was
sent.

If EdgeWatch cannot load the job's notification destinations, it can still
cancel a window that is strictly before its scheduled start because that path
creates no closing summary. If the window has started or expired, cancellation
fails and leaves it unchanged; retry when destinations are available.
Creation errors remain by the form, cancellation errors stay in the open
confirmation dialog so the operator can retry, and review errors remain beside
the affected window.

The **Jobs** list shows each job's latest scan attempt separately from its
latest successful scan, along with its next scheduled run and current queued,
running, resumable, or progressing work. A paused cycle with a recent completed
work-unit checkpoint inside its resume window is shown as **Scan cycle in
progress** with its completed and total units; its timed-out attempt is not
listed under **Needs attention** while that checkpoint remains recent. The
cycle's last completed-work checkpoint, not its lifecycle update time, controls
freshness, so starting or pausing an attempt without completing another unit
does not refresh it. A cycle with no recent progress remains resumable until
three consecutive timed-out attempts without a completed unit stall it, after
which it stays marked for a manual retry. A job
with no scan history is distinct
from one whose monitoring summary could not be read. Missing schedule, paused,
manual-only, and archived states do not create attention by themselves.
The list shows an active change window first, then an expired but unclosed
window, then the nearest scheduled window. Unclosed windows remain ahead of a
due review in the Jobs list. In job details, due reviews remain visible even
when many windows are still open or scheduled. The next scheduled run is shown
in the job's scheduler timezone displayed beside it. Job details list up to
500 windows: at most 100 active, expired-unclosed, scheduled, due-review, and
reviewed-history rows each, in that order.

Choose **Needs attention** to filter the full tenant job list to jobs whose
latest attempt failed, timed out, or was incomplete without current progressing
resumable work, whose saved scan cycle stalled, or whose last scheduled run was
skipped because it exceeded the probe budget.
That saved marker reports the last skip rather than predicting the next run:
DNS answers, job settings, or the unit's budget can change. The job keeps its
next scheduled time, and a later scan clears the marker when its result is
finalized. Queued or running work supersedes an older failed or incomplete
attempt or budget-skip marker; a later successful attempt clears that older
failure. A progressing resumable cycle is also current work and does not add
failure attention for its latest timed-out attempt. A stalled cycle remains
actionable while a retry waits or runs. The
filter does not infer problems from elapsed time or the absence of a schedule.
Unavailable summaries remain visible in **All jobs** and are reported as
unavailable rather than treated as healthy or as having no scan history. When
a summary is unavailable, known attention reasons remain eligible for **Needs
attention**; jobs without a known attention reason are not included. Readers
with `jobs.read` can see the summary; opening scan details from it requires
`scans.read`.

Choose how many successful samples establish a baseline and how many matching
changes confirm an incident. The same number of scans in a row must observe
the expected state again before an open incident recovers.

A host-state incident recovers only when a scan observes the host in its
expected state again. A host that host discovery reports down shows none of
its ports, so its state change is reported instead. The incidents, pending changes, and one-scan
suppressions of its ports and services stay as they are until a scan observes
the host up again. A port that is still changed when its host returns keeps
its target-level incident, without a recovery or a new alert. For a DNS name
in **Address-sensitive** mode, a target-level port finding that opened
outside the baseline waits while any of the name's addresses is down. A
per-address port finding for an address whose host discovery completes down
cannot be compared, so that complete scan retires the finding without a
recovery even if the address remains in the DNS answer. If the same exposure
is present when the address returns, it opens as a new per-address incident.
An address that leaves the DNS answer also retires its per-address findings
without a recovery.

When a security-impacting job setting changes,
EdgeWatch shows the affected scope and asks for explicit rebaselining. Schedule
and execution-tuning changes do not reset the baseline. A run that waits for a
free scan slot uses the job's settings when it starts; if the job is paused or
archived while a scheduled run waits, that run is skipped. **Cancel queued
scan** on the job page or the Overview withdraws a run that is still waiting
for a slot, so it never starts; a scan that has started is stopped with
**Cancel scan** instead.

**Pause schedule** on the job page stops a job's scheduled runs without
editing the job, and **Resume schedule** starts them again; **Scan now** keeps
working while a job is paused. Pausing and resuming are unavailable while the
job's scan is running.

## Find coverage gaps

The **Perimeter** page compares the address ranges that the unit declares
with what its monitors will scan per protocol. It lists the declared space
that no monitor scans, the monitors that cannot scan or have not proven their
coverage, such as paused, over-budget, or stale ones, and the monitored IP and
CIDR targets outside the declared ranges. For uncovered IPv4 space it suggests
monitors sized to the unit's probe budget. See
[Perimeter coverage](/user-guide/perimeter/).

## First scan and baseline learning

On the final review, choose **Create and start first scan** to save and open the
job page, then request one scan, or choose **Create without starting** to save
the job without requesting an immediate scan. Creating the job and starting its
scan are separate actions.
If the scan request fails, the job remains saved on its page; retrying starts a
scan for that job and does not create another copy. Refreshing the page or
returning to it later does not replay the one-time create-and-start action.
Existing schedule settings and the configured `run_on_start` behavior remain
authoritative, including when EdgeWatch restarts.

The job page's **Next steps** card reads the saved job, scan, and baseline
state. It shows successful samples collected against the configured sample
count and, while the schedule is enabled, the next scheduled sample in the
job's timezone. A paused schedule has no automatic next sample. A job with no
schedule can still be sampled manually by a permitted operator or
administrator. If the unit's scan slots are full, an explicit manual request
waits in the queue and can be canceled before it starts.

Only successful scans with complete coverage count toward learning. Failed,
canceled, timed-out, and incomplete scans stay in history but do not count as
samples or remove expected results. If learning stalls after incomplete
coverage, open the scan evidence and correct target reachability or the saved
scanner profile, then retry. The scan uses the job's current saved settings;
the next scheduled run also uses the current revision. Once the configured
number of complete successful samples has been recorded, EdgeWatch establishes
the baseline automatically. It never lowers that sample count or performs the
explicit **Use as baseline** override on your behalf. Incident acceptance
remains an explicit decision.

An incomplete scan also does not recover a service incident just because its
port is closed. The incident stays open until a complete scan can verify the
closure; if the port is still closed then, EdgeWatch retires the service finding
without reporting that its previous fingerprint returned.

An active baseline applies to the targets and TCP/UDP ports configured for that
job. It can be complete even when no positive ports were found; the job page
states this as a valid empty baseline. When the card says **Ready (updating
scope)**, the existing baseline remains active while its stored scope is
re-keyed by the next finalized scan or a saved job change.

Archiving stops a job while keeping its results and incidents available. An
administrator can permanently delete an archived job by typing its exact name;
this also removes that job's scan results, incidents, saved scan progress,
change-window history, and notification delivery records. The job and its
evidence disappear from the interface immediately; retained data is erased in
bounded, restart-safe background batches, with deliveries removed before their
window history. The security audit record is retained. This action is
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

The **Investigation inbox** adds shared review metadata for active incidents;
it does not change scan comparisons, notifications, or reminders. Reviewers
with `incidents.read` can inspect the inbox, while saving review status, a note,
or a follow-up time requires `incidents.manage`. **Needs review** includes
incidents with no saved review and incidents explicitly returned for review.
**Investigating** includes an investigation with no follow-up time or one due in
the future. **Follow-up due** includes investigations whose follow-up instant
has arrived or passed. **All active** shows every active incident. Returning an
incident to **Needs review** clears its follow-up time but keeps its note.

When an investigation's follow-up becomes due, the inbox API supplies the next
upcoming instant and its server time, including when the **Follow-up due** view
is currently empty. The console schedules one refresh from that server-time
pair, so a browser clock that is ahead does not mark a follow-up due early. An
open, visible inbox refreshes when the instant arrives; if the page is hidden
then or a refresh fails, it retries when you return to the page. The console
does not poll while waiting, including for follow-ups scheduled up to 30 days
away.

The inbox can filter by job, severity, and change kind. It orders matching
incidents by severity (critical, warning, then info), oldest opening time,
and stable tie-breakers before paging, so pages preserve the same priority
order. The displayed total follows the selected view and filters; the global
active-incident count remains unfiltered. Opening an incident keeps these
filters and its page in the URL. Its evidence panel shows the observed change,
scan provenance, reviewer metadata, and any known observation uncertainty.
When scan or host evidence is available, its link is labelled as opening in a
new tab so the inbox context stays open.

A plain-text review note is shared with other reviewers and can contain up to
4096 UTF-8 bytes. A follow-up is an exact instant entered in the console's
displayed timezone; that timezone is shown beside the field and the resulting
instant is shown before saving. A time already past is allowed and appears
immediately in **Follow-up due**. Times more than 30 days ahead are not
accepted. During a daylight-saving clock change, a local time that does not exist must be changed;
if a local time occurs twice, select which displayed UTC offset to use. These
review fields record operator context only; they do not silence or alter
existing alerts and reminders.

The editor keeps the review revision from when you first change a field in a
draft. If a refresh or another review update shows a newer revision, your
edited fields stay in the form and the latest status, note, and follow-up time
appear above it. Compare those values before choosing **Rebase my draft to
revision N**. Rebase keeps your edits and changes only the revision expected
when you save; it does not copy the shared fields into your draft or save it.
Until you rebase, saving still uses the revision your draft started from, so a
newer shared review cannot be silently replaced. After rebasing, choose **Save
review** to publish your edits.

The **Hosts** page aggregates the latest successful result for each effective
IP. A host detail page shows configured-target relationships, TCP/UDP coverage,
positive ports, services, scanner provenance, and summarized closed/filtered
results. Opening a public host may load normalized RDAP information from the
authoritative registry; raw responses and contact records are not retained.
Host searches cover partial IP addresses, DNS names, targets, job names, and
service names or products. Enter at least 3 and no more than 256 characters;
searches stay on the indexed path and service names/products are prioritized
within the bounded search document.

## Scan comparison

Each scan's detail says how the scan was compared with the job's baseline when
it finished. That description is recorded with the scan, so it stays the same
after the baseline is established, an incident is accepted, or the baseline is
reset.

- **Baseline sample:** the job was still learning its baseline, so there was
  nothing to compare the scan with. A successful scan counts as one of the
  job's baseline samples; an incomplete scan does not. Jobs created in the
  console learn from two samples by default, so their first scan is a baseline
  sample. Each scope change or baseline reset starts a new set of samples.
- **Established the baseline:** the scan was the sample that completed the
  baseline.
- **Changes recorded at scan time:** the scan was compared with the baseline
  that existed when it finished. Its changes are kept with it and are not
  recalculated later.
- **Not compared because it did not complete successfully:** the scan failed,
  timed out, or was canceled.
- **Not compared with the baseline:** the scan completed, but EdgeWatch kept
  its result without a comparison, for example because the job's security
  settings changed while it ran.

Scans recorded before v0.26.0 have no recorded comparison. When such a scan has
no changes recorded at scan time, its detail compares it with the current
baseline and reports the changes against the current baseline.
