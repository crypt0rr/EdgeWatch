---
title: Perimeter coverage
description: Declare the address space your unit owns or may scan, find what its monitors do not scan, and create monitors for the gaps.
---

The **Perimeter** page compares the address space that a business unit
declares with what the unit's monitors will actually scan, per protocol. It
answers three questions:

1. Which declared space is not scanned, and on which protocol?
2. Which monitors that touch the perimeter cannot scan, or have not proven
   their coverage?
3. Which monitored IP and CIDR targets lie outside the declared space?

For uncovered IPv4 space, the page suggests monitors sized to the unit's
probe budget, and **Create monitor** opens the guided monitor setup with the
suggestion filled in. You still review and save every monitor yourself.

Apart from declaring and removing ranges, the page only reads: it sends no
packets, opens no outbound connection, and never starts a scan or creates,
changes, pauses, or deletes a job.

:::caution[A declared range is not an authorization]
Declaring a range records that your unit owns it or may scan it, so that
EdgeWatch can report its coverage. It does not authorize scanning. Before you
create a monitor for a range, confirm that you may scan those addresses.
`scanner.target_exclusions`, the probe budgets, and high-cost approval apply
to every monitor, whether or not its targets are declared.
:::

## Declared ranges

A range has one of two kinds:

- **Owned** (`prefix` in the API): address space that the unit owns.
- **Authorized** (`authorized`): third-party space that the team may scan but
  does not own, such as cloud or partner ranges.

Neither kind authorizes a scan. Both count the same way for coverage,
suggestions, and the outside list.

A range is an IPv4 or IPv6 address or CIDR prefix. EdgeWatch masks the host
bits, so `203.0.113.17/24` is stored as `203.0.113.0/24`, and stores a bare
address as a `/32` or `/128`. It refuses an entry, with a reason for that
entry, when the value:

- is not an address or CIDR prefix, such as a DNS name, a range such as
  `10.0.0.1-10`, or an ASN;
- overlaps unspecified, loopback, multicast, or link-local space;
- is an IPv4 prefix shorter than `/8`, or an IPv6 prefix shorter than `/16`;
- overlaps IPv4-mapped IPv6 space (`::ffff:0:0/96`), such as
  `::ffff:192.0.2.1`: write the IPv4 form instead;
- has an IPv6 zone, such as `fe80::1%eth0`;
- is already declared under the other kind, either stored or earlier in the
  same declaration.

A value that the unit already holds under the same kind, or that repeats
earlier in the same declaration, is not refused: the range is created once,
and each repeat counts as skipped. Ranges may overlap, such as a `/16` and a
labelled `/24` inside it. Each range shows its own coverage, and the totals
count every address once.

A label is optional, has at most 200 characters, and cannot contain control
characters.

### Declare and remove ranges

Administrators declare ranges with the form on **Perimeter**. Choose the
kind, then paste one entry per line:

```text
203.0.113.0/24 DC1 edge
198.51.100.0/25
2001:db8:10::/48 Amsterdam office
```

The value is the text before the first whitespace character, and the rest of
the line is its label. Ordinary leading and trailing whitespace is trimmed.
Runs of spaces, tabs, and Unicode space, line, and paragraph separators in the
label are collapsed to one space, so tab-separated label columns such as
`DC1<TAB>edge` become `DC1 edge`. Vertical tabs (`U+000B`), form feeds
(`U+000C`), U+0085 NEXT LINE, and other control characters that are not
normalized as whitespace stay in the label for server validation, which
refuses them. Blank lines are ignored, and a declaration has at most 256
entries. A declaration is all or nothing: when any line is refused, EdgeWatch
saves nothing and the form lists each refused line by its line number, with
its value and the reason. Correct or remove those lines and declare again.
After a declaration, the form reports how many ranges were created and how
many entries were skipped.

Administrators remove a range from the page after a confirmation. Removing
a range changes no monitor: its monitors keep scanning, and their targets may
then appear under **Outside the perimeter**.

Every declaration and removal is recorded in the unit's audit, as
`perimeter.seeds_added` with the number of ranges by kind and as
`perimeter.seed_removed` with the kind and value. The platform audit does not
show them.

### Host commands

Host scripts can list or declare ranges for a specific unit. Both commands
require its slug:

```sh
docker compose exec edgewatch edgewatch perimeter list \
  --tenant UNIT_SLUG --output json

docker compose exec -T edgewatch edgewatch perimeter declare \
  --tenant UNIT_SLUG --kind prefix --from - < ./perimeter-ranges.txt
```

`perimeter list` reads only that unit's declarations. `--output json` prints
the ranges as a JSON array; text output prints one range per line.
`perimeter declare` reads an IP address or CIDR prefix and an optional label
per line from standard input with `--from -`, or from a file inside the
container with `--from FILE`. Blank lines are ignored, and at most 256
entries can be declared at once. It applies the same validation as the page,
skips ranges already declared under the selected kind, and saves nothing if
any entry is refused. Each successful declaration writes one
`perimeter.seeds_added` audit record with actor `host-cli`; range values,
labels, and input paths are not included in that audit record or refusal
messages. Host command changes send no live update, so reload an open
Perimeter page to see them. These commands do not scan ranges or change
monitors.

## How coverage is computed

Coverage comes from the configuration of the unit's unarchived jobs, not from
scan results: observed hosts and DNS answers never count. EdgeWatch computes
the report each time the page loads it.

### Monitor states

Every unarchived job of the unit gets a state: the first check that fails, in
the order a scheduled run meets them. The page lists every failing check as a
reason, so a monitor that is both over its budget and over its expansion limit
shows both.

| State | Meaning | Counts as coverage |
| --- | --- | --- |
| `paused` | The job's schedule is paused. A monitor saved with **Schedule enabled** off is paused too. | No |
| `invalid_config` | The stored job no longer passes the scan work estimate. | No |
| `over_budget` | The scheduler's preflight check refuses the job: its estimate exceeds the unit's probe budget, or, for a job approved for high-cost scans, the unit's high-cost ceiling. | No |
| `over_expansion` | The targets expand past the lower of the job's **Maximum expanded hosts** and the deployment's `scanner.max_job_hosts`. | No |
| `excluded_target` | An IP or CIDR target contains an address in `scanner.target_exclusions`. EdgeWatch refuses to save such a job, so this happens when the exclusions change after the job was saved. | No |
| `covering` | No check fails. | Yes |

The expansion is counted as the scanner counts it: every IP and CIDR target
in full, so overlapping targets count twice, and each DNS name as one address.
For a monitor with DNS targets this is a lower bound, because a name with
several answers can still exceed the limit when it scans, and an answer in
`scanner.target_exclusions` fails the scan. The budget check is the
scheduler's preflight answer; checks at scan time can still refuse a
`covering` monitor. Such failures appear in the monitor's latest attempt, not
in its state.

### Coverage not proven

A `covering` monitor still counts as coverage, but **Coverage not proven**
lists it when it:

- is stale: the job silence alert would call it overdue. Counted from the
  latest of the monitor's creation, its last resume or restore, and its last
  successful scan, it is overdue once its next scheduled run and one more
  schedule interval have passed without a successful scan. A new monitor is
  not stale until its first scheduled run is overdue, and a monitor whose
  schedule never fires is stale;
- has a stalled scan cycle, which scheduled runs skip until someone retries it
  or its resume window ends;
- has a successful scan whose security hash does not match its current scan
  security scope. That scope includes settings such as its targets, protocol
  settings, `max_expanded_hosts`, and `assume_alive`. Renaming a monitor or
  changing its schedule does not invalidate this proof; a successful scan
  with the current scope does;
- has a latest attempt that failed, timed out, or was incomplete.

The list says **Not scanned yet**, **No successful scan since** a date,
**Schedule never fires**, **Scan cycle stalled**, **Last attempt failed**,
**Last attempt timed out**, or **Last attempt incomplete**, plus
**Not scanned since its security scope changed** when the last success belongs
to an older security scope. A current resumable cycle with completed
work inside its resume window and a recent completed-work checkpoint is shown
separately as **Scan cycles in progress** and does not turn its recent timed-out
attempt into a failed result. The cycle's last completed-work checkpoint, not
its lifecycle update time, controls progress freshness, so starting or pausing
an attempt without completing another work unit does not refresh it. The report
marks the monitor's coverage unproven until a successful scan matches its
current security scope. Stalled or expired cycles and saved work whose
last checkpoint is no longer recent do not get this in-progress status. Three
consecutive timed-out attempts without a completed unit still stall the cycle.
Unlike the job silence alert, which waits while a scan holds the job, a scan
that is still running does not stop a monitor from being stale.

### Coverage buckets

Each `covering` monitor adds its IP and CIDR targets to the buckets that its
protocols fill:

| Bucket | Filled by |
| --- | --- |
| Full TCP | TCP with Naabu discovery and Nmap confirmation, or Nmap only with ports that cover 1–65535. |
| Any TCP | TCP with any engine and any ports. It includes full TCP. |
| UDP | UDP with any ports. |

For each declared IPv4 range, the page shows the covered addresses and a
percentage per bucket. Addresses in `scanner.target_exclusions` are left out
of the range first: a percentage is the covered share of the range's
addresses that are not excluded. When every address of a range is excluded,
the page shows **All addresses excluded**, with no percentage and no
suggestions. The summary computes the same percentages over all declared IPv4
ranges together, so overlapping ranges count once.

A monitor counts only for the protocols it scans and only for the addresses
its targets list:

- **DNS names** never cover addresses, whatever they resolve to. The page
  shows how many DNS targets a monitor has. List addresses as IP or CIDR
  targets when you want them counted.
- **Host discovery:** a monitor with host discovery enabled
  (`assume_alive: false`) port-scans only the hosts that answer host
  discovery, so perimeter addresses that drop discovery probes are not
  scanned. It still counts as coverage, and the page marks it with
  **Scans only hosts that answer host discovery**.

### IPv6 ranges

An IPv6 range shows the number of addresses that monitors scan in each bucket,
with no percentage, and gets no suggestions. One job scans at most
`scanner.max_job_hosts` addresses, 65,536 by default, the size of a `/112`,
so EdgeWatch cannot sweep an IPv6 prefix. List the IPv6 addresses you serve
from as targets instead.

Address counts saturate at 9,007,199,254,740,991. A count at that value, which
only IPv6 space reaches, means at least that many.

## The Perimeter page

Administrators and operators open **Perimeter** from the navigation. A unit
without declared ranges sees an explanation and, for administrators, the
declare form. The page also shows the business unit's scheduled scan-slot
demand and effective capacity. The estimate uses the median duration of recent
completed scan samples. A completed cycle sums the recorded durations of its
attempts, excluding idle time between scheduled attempts, and a successful or
incomplete scan without a cycle is one sample. Without history, known work at
configured maximum scanner rates is shown as a lower bound only when the
configured scope is known to fit both the job's **Maximum expanded hosts** and
the deployment's `scanner.max_job_hosts`. An over-limit or unresolved DNS
scope adds no lower bound because the scanner may reject it before sending
probes. The warning starts at 80% utilization. When the unit has declared
ranges, the page also shows:

- **Summary:** the declared IPv4 addresses; the covered percentage for full
  TCP, any TCP, and UDP; and the numbers of monitors that cannot scan, of
  monitors whose coverage is not proven, and of targets outside the
  perimeter.
- **Ranges:** one row per declared range, with its kind, value, and label, a
  coverage bar with counts and percentages per bucket, or the monitored
  counts of an IPv6 range, and the states of the monitors that touch it.
  A legend above the ranges says what fills each bucket, as the
  [coverage buckets](#coverage-buckets) table does. Select a row to open the
  range's detail.
- **Monitors that cannot scan:** each monitor that touches the perimeter and
  is not `covering`, with all its reasons and a link to the job.
- **Coverage not proven:** each `covering` monitor that touches the perimeter
  and is stale, has a stalled cycle, or has a latest attempt that failed,
  timed out, or was incomplete.
- **Outside the perimeter:** each IP or CIDR target of an unarchived monitor
  that lies fully or partly outside the declared ranges, with the monitor,
  its state, and the number of addresses outside. Monitors in every state are
  listed, because a paused monitor can still be run by hand. DNS names are
  not listed. A target outside may be a mistake, or space that you may scan
  but have not declared: correct the monitor, or declare the space if you own
  it or are authorized to scan it. The list shows at most 200 targets and says
  how many there are in total.

A monitor touches the perimeter, or a range, when one of its IP or CIDR
targets shares an address with a declared range.

### Range detail

A range's detail shows:

- the monitors that touch the range, with their states, reasons, and flags;
- the uncovered blocks of each bucket, as the fewest aligned CIDR blocks of
  addresses that no `covering` monitor of the bucket scans, excluded
  addresses left out: at most 256 blocks per bucket, with their total;
- how many addresses one suggested monitor of each mode holds, and the
  suggested monitors for the range's uncovered IPv4 space.

## Suggested monitors

Each suggestion mode fills the gaps of one bucket with fixed settings:

| Mode | Fills the gaps of | Settings |
| --- | --- | --- |
| Full TCP | Full TCP | TCP, Naabu discovery of ports 1–65535 with Nmap confirmation, connect mode, no service detection, the built-in Naabu profile. These are the guided setup's defaults. |
| Selected TCP | Any TCP | TCP, Nmap only, ports `22,443`, connect mode, no service detection, like the guided setup's **Selected TCP ports**. |
| UDP | UDP | UDP, Nmap, ports `53,123,161,500,1194,4500` (DNS, NTP, SNMP, IKE, OpenVPN, and IKE NAT traversal), with service detection. |

Suggestions apply to owned and authorized ranges alike, and never include an
excluded address.

### Addresses per monitor

A suggested monitor holds at most the lowest of:

- `scanner.max_job_hosts`;
- the unit's Naabu probe budget divided by the Naabu probes that one address
  needs in the mode, rounded down;
- the unit's Nmap probe budget divided by the Nmap probes that one address
  needs, rounded down;
- the mode's cap: 4,096 addresses for selected TCP and 1,024 for UDP. Full
  TCP has no cap.

At the default budgets, that is 305 addresses for full TCP, because one
address costs 65,535 Naabu probes of the 20,000,000 budget, and 4,096 and
1,024 for the other modes. The budgets are the unit's normal probe budgets,
which a platform administrator can lower on the unit's
[capacity](/administration/business-units/#what-belongs-to-each-unit), never
its high-cost ceiling. When one address does not fit the budget, the mode
has no suggestions and the page says that the unit's probe budget is too
small for one address in that mode.

Each suggestion shows its estimated probe count. Full TCP also shows a
lower-bound duration at the built-in Naabu rate of 1,000 probes per second.
This estimate excludes host response time, retries, and Nmap confirmation, so
an actual scan can take longer. It does not impose a scan timeout or change
runtime timeout semantics. When the lower bound exceeds the guided setup's
current timeout but fits its existing resume window, setup raises the timeout
draft to that lower bound rounded up to a whole minute. It does not extend the
resume window; if the estimate does not fit, the timeout draft is left as is.

### Packing

Suggestions are packed the same way every time:

1. The uncovered space is split into the fewest aligned CIDR blocks, in
   address order.
2. The block size of a monitor is the largest power of two that fits the
   addresses per monitor: 256 for 305 addresses.
3. Each block larger than that is split into blocks of that size, and each of
   them gets its own monitor.
4. Each smaller block, in address order, joins the first monitor with room,
   and a new monitor starts only when none has room.

At 305 addresses per monitor, an uncovered `/20` needs 16 full TCP monitors of
one `/24` each, and an uncovered `/24` with separate uncovered `/27` and `/28`
blocks fits one monitor of 304 addresses.

The report returns at most 64 suggestions per range and mode. The page lists
them, each with a **Create monitor** button, only when a mode needs 16
monitors or fewer; above that it shows how many monitors the mode needs.
Declare smaller ranges inside it, which get their own suggestions, or plan the
monitors in the job editor.

### Create a monitor from a suggestion

**Create monitor** needs permission to create jobs, which administrators and
operators have. Without it, a suggestion is shown as text. The button opens
**Jobs → New job** with a new draft filled in once:

- **Name:** `Perimeter`, the first target, the number of further targets, and
  the mode, such as `Perimeter 203.0.113.0/24 · full TCP` or
  `Perimeter 198.51.100.0/24 +2 more · UDP`. Job names are unique in the unit,
  archived jobs included; if the name is taken, creating the monitor fails
  with "job name is already in use" and keeps the draft, so rename it.
- **Targets:** the suggestion's CIDR blocks.
- **Coverage:** the mode's settings exactly as the suggestion lists them. A
  TCP suggestion turns UDP off, and a UDP suggestion turns TCP off; you can
  turn either on again.
- **Maximum expanded hosts:** raised to the suggestion's address count when
  it is lower.

The draft never requests high-cost approval, and the schedule, alerts, and
baseline settings keep the guided setup's defaults. The targets step, and the
full editor while you edit the same draft, show which range the draft came
from and remind you that a declared range is not an authorization. Review the estimate, the unit's budget, the schedule, and
the alerts as for any new monitor, then choose **Create without starting** or
**Create and start first scan**. Each click creates at most one monitor, and
EdgeWatch never creates monitors in bulk. The draft counts as edited, so
leaving the setup asks you to discard it, and going back or reloading does
not fill it in again. A draft that already holds your edits is never
overwritten.

A monitor saved with **Schedule enabled** off is `paused`, so it does not
count as coverage until you resume its schedule.

## Limits and permissions

| Limit | Value |
| --- | --- |
| Entries in one declaration | 1 to 256 |
| Ranges per unit, owned and authorized together | 1,024; skipped entries do not count |
| Label length | 200 characters |
| Shortest prefix | IPv4 `/8`, IPv6 `/16` |
| Targets in **Outside the perimeter** | 200, with the total |
| Uncovered blocks per bucket in a range's detail | 256, with the total |
| Suggestions per range and mode | 64, with the number of monitors needed |
| **Create monitor** buttons per range and mode | Up to 16 monitors |

A declaration that would leave the unit with more than 1,024 ranges is
refused, and nothing is saved.

| Role | Perimeter |
| --- | --- |
| Administrator | Views the page and range details, declares and removes ranges, and creates monitors from suggestions. |
| Operator | Views the page and range details, and creates monitors from suggestions. Cannot declare or remove ranges. |
| Viewer | No access; the navigation does not show **Perimeter**. |

Platform administrators never see a unit's perimeter, and it never appears
on public status. The declared ranges are unit data; see
[Business units](/administration/business-units/#what-belongs-to-each-unit).
In the API, reading needs `perimeter.read` and declaring or removing needs
`perimeter.manage`; see
[API compatibility](/reference/api-compatibility/#perimeter-coverage).

## Live updates

An open Perimeter page updates when a range is declared or removed in the
console, when the unit's monitors are created, edited, paused, resumed,
archived, restored, or deleted, when their scans start or end, including
failed, canceled, and skipped runs, and when a job silence alert is raised. A platform
administrator's change to the unit's probe budgets, and a change to
`scanner.max_job_hosts` or `scanner.target_exclusions` in `config.yaml`, send
no update: they appear the next time the page loads its data, for example
after you reload it.

## Seed the perimeter from an ASN

EdgeWatch does not look up ASNs. It never queries RIPEstat or any other
source, and an ASN entered as a range is refused. To declare the space that
an ASN announces, look up its prefixes yourself and paste them:

1. On [RIPEstat](https://stat.ripe.net), search for the ASN, such as
   `AS64496`, and open its announced-prefixes view, which lists the IPv4 and
   IPv6 prefixes that the ASN announces in BGP. From your own workstation,
   RIPEstat's data API returns the same list:

   ```sh
   curl -s 'https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS64496' \
     | jq -r '.data.prefixes[].prefix'
   ```

2. Review the list before you declare it. It covers a recent period, so it
   can hold a prefix that is no longer announced. An ASN can announce space
   that a customer owns, and your unit can own space that the ASN does not
   announce or that another ASN announces. Keep the prefixes that your unit
   owns, declare third-party space as authorized only when you may scan it,
   and add unannounced space by hand.
3. Keep a prefix only when your unit owns it or is authorized to scan it. If
   you want to recognize the ranges later, append the ASN as a label, such as
   `203.0.113.0/24 AS64496`. Save the resulting prefixes one per line.
4. Declare the ranges on **Perimeter**, or import the reviewed host file:

   ```sh
   docker compose exec -T edgewatch edgewatch perimeter declare \
     --tenant UNIT_SLUG --kind prefix --from - < ./as64496-prefixes.txt
   ```

   A declaration takes up to 256 lines, so split a longer list into parts; a
   unit holds at most 1,024 ranges. An announced prefix that is more specific
   than another one is accepted, and the totals count its addresses once.
   IPv6 prefixes show their monitored counts but get no suggestions.

Announcements change, and the declared ranges do not follow them. Repeat the
lookup from time to time: pasting the current list again creates only the new
prefixes and skips the ranges you already declared. A prefix that the ASN no
longer announces stays declared until you remove it.
