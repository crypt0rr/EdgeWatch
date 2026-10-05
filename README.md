# EdgeWatch

[![CI](https://github.com/crypt0rr/EdgeWatch/actions/workflows/ci.yml/badge.svg)](https://github.com/crypt0rr/EdgeWatch/actions/workflows/ci.yml)
[![CodeQL](https://github.com/crypt0rr/EdgeWatch/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/crypt0rr/EdgeWatch/actions/workflows/github-code-scanning/codeql)
[![Latest release](https://img.shields.io/github/v/release/crypt0rr/EdgeWatch?sort=semver)](https://github.com/crypt0rr/EdgeWatch/releases)
[![Container](https://img.shields.io/badge/container-GHCR-2496ED?logo=docker&logoColor=white)](https://github.com/crypt0rr/EdgeWatch/pkgs/container/edgewatch)
[![Go version](https://img.shields.io/github/go-mod/go-version/crypt0rr/EdgeWatch)](go.mod)
[![License](https://img.shields.io/github/license/crypt0rr/EdgeWatch)](LICENSE)

EdgeWatch is a self-hosted network-surface monitor. It schedules TCP and UDP
scans, learns what is expected, and notifies you when the observed surface
changes. It ships as one Docker image with an embedded web console and SQLite
storage.

https://github.com/user-attachments/assets/ddff32e8-617a-477f-b9b7-8681dbc25b82

> Only scan systems you own or are authorized to assess. Full-range UDP scans
> can take many hours and generate significant traffic.

## What you get

| Capability | What it does |
| --- | --- |
| Scheduled jobs | Monitor individual IPs, CIDRs, and DNS names on cron schedules. |
| TCP and UDP coverage | Use Nmap for both protocols, or Naabu full-range TCP discovery followed by Nmap confirmation. |
| Baselines and incidents | Establish an expected surface and receive alerts for confirmed port, service, or DNS changes. |
| Host evidence | Inspect effective IPs, positive ports, services, scan provenance, Nmap reasons, and summarized non-open results. |
| Notifications | Deliver Shoutrrr alerts to named, encrypted destinations managed in the console. |
| Safe administration | Use administrator, operator, and viewer roles, optional TOTP, and an optional limited public-status page. |
| Resumable broad scans | Continue large scans after timeouts or restarts without changing the monitored scope. |
| Update monitoring | See and optionally notify on new stable EdgeWatch releases. |

## Quick start

Requirements: Docker Engine and Docker Compose v2 on a host where Docker host
networking and the required scanner capabilities are available.

From a checkout of this repository:

```console
cp config.example.yaml config.yaml
```

Choose the data-directory owner for your Docker mode. The container runs as
UID 0 with filesystem capabilities dropped, so mode `0750` must be owned by the
host identity mapped to container UID 0.

For standard rootful Docker:

```console
sudo install -d -m 0750 -o 0 -g 0 ./data
```

For rootless Docker:

```console
install -d -m 0750 ./data
```

Start EdgeWatch:

```console
docker compose pull
docker compose up -d
```

The container uses host networking so scanners can reach the same networks as
the Docker host. Runtime state, the SQLite database, and generated encryption
keys are stored in ./data.

The container runs as UID 0 with filesystem capabilities dropped. The `0750`
data directory must be owned by the host identity mapped to container UID 0:
host root for standard rootful Docker, the invoking host user for rootless
Docker, or the mapped host UID when user-namespace remapping is enabled.

For an existing rootful deployment whose data directory was created by another
user, stop EdgeWatch before correcting ownership:

```console
docker compose down
sudo chown -R 0:0 ./data
sudo chmod 0750 ./data
docker compose up -d
```

Notification destinations are added in the web console, so a new deployment
needs no notification URL file. For a rootful installation, create any
separately mounted secret file, such as the key for
`notifications.encryption_key_file` or `web.auth_key_file`, as host root with
mode `0600`. For rootless Docker, create it as the invoking user instead.

Before starting, this preflight performs real reads and writes; `test -r` or
`test -w` alone can be misleading for UID 0:

```console
docker compose run --rm --no-deps --entrypoint /bin/sh edgewatch \
  -c 'cat /etc/edgewatch/config.yaml >/dev/null && touch /var/lib/edgewatch/.edgewatch-permission-check && rm /var/lib/edgewatch/.edgewatch-permission-check'
```

If this check fails with `Permission denied`, inspect `docker compose logs edgewatch` and correct the host ownership described above. Do not make the data directory or secret files world-readable or world-writable.

If you enabled a secret mount, verify the mounted file itself is readable using
its path, for example:

```console
docker compose run --rm --no-deps --entrypoint /bin/sh edgewatch \
  -c 'cat /run/secrets/edgewatch-notification-key >/dev/null'
```

If you are upgrading from a deployment that used the old named
edgewatch-data volume, the bind mount starts with fresh state. That volume is
left untouched and is not read or migrated automatically; restore or copy its
data only through a deliberate, stopped-database recovery procedure.

Open http://127.0.0.1:8080. On the first start, EdgeWatch prints a one-time
setup token to the container log:

```console
docker compose logs edgewatch | grep setup_token
```

The token expires after 15 minutes and creates the first admin account. The web
listener is loopback-only. For a remote Docker host, create an SSH tunnel from
your workstation:

```console
ssh -L 8080:127.0.0.1:8080 user@docker-host
```

Then open http://127.0.0.1:8080 locally. If the initial token was lost before
setup completed, a host operator can issue one replacement token:

```console
docker compose exec edgewatch edgewatch admin setup-token \
  --config /etc/edgewatch/config.yaml --force
```

This recovery action is refused after an administrator has been created.

A platform administrator, who manages business units, is created the same
way once the first administrator exists; see
[Business units](#business-units).

### Tailscale Serve and reverse proxies

Keep EdgeWatch bound to loopback when exposing it through Tailscale Serve or a
reverse proxy. Serve the public hostname over HTTPS and add the hostname that
users open to `web.allowed_hosts`:

```yaml
web:
  listen: 127.0.0.1:8080
  allowed_hosts:
    - edgewatch.example.ts.net
  forwarded_header: x-forwarded-for
  trusted_proxies:
    - 127.0.0.1/32
    - ::1/128
```

Replace `edgewatch.example.ts.net` with your tailnet or proxy hostname. Use the
bare hostname only; do not include `https://`, a path, or a port. EdgeWatch
checks the forwarded `Host` value before authentication, so an unlisted proxy
hostname is rejected with `421 Misdirected Request` even when the loopback
listener is healthy. Approved non-loopback hostnames receive Secure session
cookies; direct loopback HTTP remains available for local administration and
SSH tunnels. The example trusts a local proxy and its sanitized
`X-Forwarded-For` client address; replace these networks with the addresses that
actually connect to EdgeWatch when the proxy runs elsewhere. If a
TLS-terminating proxy rewrites the upstream `Host` to a loopback address, list
the proxy address or network in `web.trusted_proxies` so EdgeWatch can trust its
`X-Forwarded-Proto: https` (or RFC 7239 `Forwarded: ...;proto=https`) signal
and keep the session cookie Secure. Do not trust untrusted peers: the configured
proxy must sanitize the forwarding headers.

After changing the bind-mounted configuration, recreate the container:

```console
docker compose up -d --force-recreate edgewatch
```

You can verify both paths from the Docker host (replace the example hostname
with the one configured above):

```console
curl -i http://127.0.0.1:8080/api/v1/setup/status
curl -i -H 'Host: edgewatch.example.ts.net:8443' \
  http://127.0.0.1:8080/api/v1/setup/status
```

Both requests should return a successful response. If the direct request works
but the request with the proxy `Host` returns `421`, correct
`web.allowed_hosts`. The listener remains loopback-only; this setting approves
the public name, not a new network bind address.

## The first five minutes

1. Create the administrator with the setup token.
2. Open **Notifications** and add Shoutrrr destinations. URLs from an older
   config.yaml appear there as imported destinations.
3. Open **Scanner profiles** and keep the built-in profile or create an
   administrator-managed profile.
4. Create a job with its targets, TCP/UDP options, schedule, and baseline
   sample count.
5. Run the job, approve a successful scan as the baseline, and use **Hosts**
   and **Incidents** to inspect what changes over time.

Only completed, valid scans can establish or advance a baseline. Failed,
cancelled, timed-out, or incomplete scans remain visible for troubleshooting
but never turn a missing port into an expected state.

## Deploy and update safely

The supplied compose.yaml pulls ghcr.io/crypt0rr/edgewatch:latest; it does not
build locally. Pull explicitly whenever you choose to update:

```console
docker compose pull
docker compose up -d
```

Before upgrading from v0.19.0 to v0.20.0, back up ./data as described in
[Data, backup, and recovery](#data-backup-and-recovery). The first start of
v0.20.0 runs the schema 51 to 54 migrations, which move all existing data
into the default business unit. A v0.19.0 binary cannot open the upgraded
database, so a rollback means restoring that backup. What a single-unit
installation notices afterwards is listed under
[Business units](#business-units).

The image uses a read-only root filesystem, drops all capabilities, and adds
NET_RAW for the default scanner modes. Host networking is intentional, and the
administration listener accepts only loopback addresses. Keep the service on
the Docker host or reach it through an authenticated SSH tunnel.

Naabu SYN discovery additionally needs NET_ADMIN. The normal Compose setup uses
connect discovery and does not grant that capability. If you have reviewed the
extra privilege and need SYN discovery, use the explicit override:

```console
docker compose -f compose.yaml -f compose.syn.yaml pull
docker compose -f compose.yaml -f compose.syn.yaml up -d
```

Adding the override does not change existing jobs or profiles to SYN. See
[docs/container-hardening.md](docs/container-hardening.md) for the capability
matrix and hardening rationale.

## Configuration at a glance

config.yaml contains deployment settings. Create monitoring jobs and manage
users, destinations, scanner profiles, baselines, and public status in the web
console. See [config.example.yaml](config.example.yaml) for the complete
validated schema.

| Configuration | Managed in | Purpose |
| --- | --- | --- |
| database, retention | YAML | SQLite location and history retention. |
| timezone | YAML | Optional IANA timezone for log, CLI, notification, and console times, and the default for new jobs. |
| web.listen, web.allowed_hosts, web.trusted_proxies, web.forwarded_header | YAML | Loopback listener, approved proxy host names, trusted proxy networks, and the single forwarding header used for client IPs. |
| scheduler.* | YAML | Concurrent scans and probe budgets. |
| scanner.target_exclusions | YAML | Addresses that may never be scanned. |
| enrichment.rdap.enabled | YAML | Enable or disable on-demand public network-registration lookups. |
| updates.enabled | YAML | Enable or disable the three-hour stable-release check. |
| notifications.encryption_key_file | YAML/secrets | Optional separate key for the encrypted notification destinations. |
| notifications.urls, urls_file | YAML/secrets | Deprecated. Imported once as web-managed destinations; see [Notifications](#notifications). |
| Jobs, users, profiles, notification destinations | Web console | Runtime administration stored in SQLite. |

The YAML jobs section from older deployments is not imported into the scheduler.
Such jobs remain inactive and EdgeWatch shows a startup warning so they can be
recreated and reviewed explicitly in the console.

Important defaults:

- `timezone` is omitted by default: the daemon and CLI keep the process
  timezone (UTC in the container image), and each signed-in console shows its
  browser's timezone. Set it to an IANA name such as `Europe/Amsterdam` to use
  one timezone everywhere. The public status page keeps the visitor's browser
  timezone and never receives the configured value. Invalid names stop
  startup; host recovery commands ignore them.
- The web listener defaults to 127.0.0.1:8080; non-loopback listeners are
  rejected.
- Requests using a proxy or tunnel host must match `web.allowed_hosts`; foreign
  Host headers are rejected before authentication. Keep this list limited to
  names you control.
- Forwarding headers are ignored unless the connecting proxy addresses are
  explicitly listed in web.trusted_proxies. By default, EdgeWatch reads only
  web.forwarded_header: x-forwarded-for; set it to forwarded only when your
  trusted proxy controls that header, or none to ignore forwarded client IPs.
  EdgeWatch never combines the two conventions, so configure the header that
  your proxy sanitizes or constructs for the trusted proxy chain.
- Session cookies use the same trusted-proxy boundary for forwarded HTTPS
  protocol headers. A trusted TLS-terminating proxy must send
  X-Forwarded-Proto: https or Forwarded: ...;proto=https when it forwards a
  loopback Host; otherwise EdgeWatch keeps the direct-loopback HTTP behavior.
- If a tunnel or reverse proxy is not listed in web.trusted_proxies, every
  client may appear as the same loopback peer. After five failed login or TOTP
  attempts within five minutes, all logins through that shared peer receive a
  short two-second cooldown instead of a five-minute lockout. A successful
  sign-in through the peer, with any account, does not reset the count; each
  failure expires five minutes after it happened. Applying the same
  cooldown to known and unknown usernames avoids revealing account existence.
  The first-run setup, the platform setup, and account activation through that
  peer get the same cooldown after five wrong tokens, so wrong tokens cannot
  block them for five minutes. Password and TOTP confirmations through that
  peer are limited per account: an account that fails five confirmations
  within five minutes is refused for five minutes, and other accounts, in any
  unit or on the platform, are not affected. Configure the proxy network and
  forwarding header when you need per-client rate limits and audit
  identities. EdgeWatch logs a startup warning when approved proxy hosts lack
  trusted client-IP forwarding.
- A client identified by its own address may fail five sign-ins within five
  minutes. Every failed sign-in counts the same: an unknown username, a
  disabled account, an account whose unit is not active, and a wrong
  password, one-time code, or recovery code. After that, every sign-in from
  that client, with any username, receives the same 429 rate_limited answer
  for five minutes, so neither the answer nor the number of attempts left
  reveals which accounts exist. A successful sign-in does not reset the
  count; each failure expires five minutes after it happened. Clients that
  share one address, such as the clients of an untrusted proxy on another
  host, share this budget, and a hundred wrong setup or activation tokens from
  that address block setup and activation for all of them for five minutes.
  When requests come through a proxy that EdgeWatch does not trust, EdgeWatch
  logs a warning at most once an hour and shows the proxy's address on the
  dashboard of a single unit's administrators and on the platform status
  page. Such a proxy is a peer that is not listed in web.trusted_proxies and
  sends X-Forwarded-For or Forwarded, such as an unlisted proxy on the host,
  or, behind the listed proxies, the first unlisted address in the forwarding
  chain when the chain names another client before it, such as an unlisted
  proxy on another host in front of the proxy on the host. A client can send
  these headers itself and have its own address shown, so add the address to
  web.trusted_proxies only when it is a proxy that you run.
- Sessions end after 24 hours without activity and 30 days after sign-in; the
  daemon removes ended sessions at startup and once a day. An account keeps
  at most 20 sessions: a new sign-in beyond that ends the account's least
  recently used session. A TOTP code or recovery code counts as used only
  when its sign-in creates a session.
- By default, scanner.target_exclusions covers the loopback and link-local
  ranges 127.0.0.0/8, ::1/128, 169.254.0.0/16, and fe80::/10. The IPv4
  link-local range includes the 169.254.169.254 cloud metadata endpoint. Other
  metadata endpoints are not excluded by default; add the ones your provider
  uses, such as fd00:ec2::254/128 on AWS with the IPv6 instance metadata
  endpoint enabled or 100.100.100.200/32 on Alibaba Cloud. An explicit list
  replaces the defaults, so keep the default ranges when you add entries.
  Change scanner.target_exclusions only when you understand the host-network
  exposure.
- RDAP is enabled by default and is requested only when an authenticated user
  opens a public host. Private and special-use addresses are never queried.
  Set enrichment.rdap.enabled: false for isolated or privacy-sensitive
  deployments.
- Update checks are enabled by default, run at startup and every three hours,
  and consider stable GitHub releases only. Set updates.enabled: false for
  offline deployments. Checks reveal the host's public IP and EdgeWatch user
  agent to GitHub; EdgeWatch reports updates but never upgrades itself.

## Scanning

### Nmap or Naabu to Nmap

Each TCP job chooses a scanner engine:

| Engine | Behavior |
| --- | --- |
| **Naabu discovery to Nmap** | Naabu discovers TCP ports 1-65535, then Nmap confirms discovered ports and can identify services. Only Nmap-confirmed positive states affect baselines and incidents. |
| **Nmap only** | Nmap scans the configured TCP port expression directly. |

Naabu connect discovery is the built-in default for new TCP jobs. SYN profiles
are available only when the runtime has both NET_RAW and NET_ADMIN. UDP is
always Nmap-only. Naabu evidence and disagreements are retained as diagnostic
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
are tracked as host-state changes, not as sets of closed ports. Omitted Nmap
hosts and timed-out probes remain incomplete. Repeated Naabu results are
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
timeouts, host discovery (assume_alive), and approved scanner-profile
overrides. EdgeWatch executes fixed Nmap and Naabu binaries with validated
argument arrays; it never runs browser-supplied shell commands or arbitrary
executables.

Full-range scans are deliberately bounded by scheduler probe budgets. A scan
that runs as a single invocation resolves DNS again when it starts, and the
budget is checked against that resolution before any scanner runs. A broad
scan may be split into resumable address, discovery, enrichment, and UDP work
units. A timeout or restart preserves completed work for the configured resume
window; partial work cannot change a baseline. The dashboard shows scanner
phase, heartbeat, completed probes, ports found, and the last sanitized output.
A resumed cycle keeps the scanner-profile arguments it started with, and its
scans record that job and profile revision; a profile change applies from the
next cycle. Accepting an incident, approving or resetting the baseline, or
changing the monitored scope discards paused progress, and the next run starts
a fresh cycle.

## Jobs, baselines, and incidents

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
default to the deployment `timezone` from config.yaml, or to the browser's
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

## Notifications

EdgeWatch uses [Shoutrrr](https://github.com/containrrr/shoutrrr) for delivery.
Destinations are named and managed on the **Notifications** page. Their URLs
are write-only and encrypted at rest with `notification.key`; their
credentials are never returned by the API or written to logs.

Each job can select its own destinations. On the **Notifications** page,
**Update alerts** is an independent toggle on each configured destination:

- pausing a destination does not erase its update-alert selection;
- when legacy routing is first frozen, existing paused destinations remain
  selected and resume delivery if they are enabled again; destinations added
  afterward remain opt-in for existing jobs;
- saving an empty selection keeps update alerts silent while checks and the
  in-console indicator continue to work;
- password confirmation is required for every routing or credential change.

**Incident reminders** is a separate business-unit setting on the same page,
enabled by default. After a fully successful scan that still confirms an open
incident, EdgeWatch sends a grouped reminder to that job's selected
destinations. New incidents continue to get their initial alert; suppressed
incidents and incomplete, failed, cancelled, or timed-out scans do not generate
reminders. The first successful follow-up may send a reminder immediately;
the selected cadence limits later reminders. Administrators can turn reminders
off or choose a minimum cadence per job: hourly (the default), every six hours,
daily, or every successful scan. Existing saved cadence choices are retained
during upgrades; legacy every-scan values with no reminder-setting audit
history are treated as inherited defaults and changed to hourly. If an older
version recorded any reminder-setting action, EdgeWatch keeps the stored
cadence because that action may have saved an explicit every-scan choice. The
cadence survives restarts and does not change incident detection or job
routing.

Deleting a destination removes it from every job and from the update-alert
routing in the same change. Each affected job gets a new revision and an
audit record. Its delivery health goes with it, so its failures no longer
count in the notification totals.

Renaming a destination keeps its queued alerts, including an alert that is
raised while the rename is saved. Replacing its URL discards its queued alerts
instead of sending them to the new URL, and deleting it discards them too.
This includes an alert that a delivery pass has picked up but not yet sent. An
alert raised while either change is saved is also discarded, and the security
audit log records it as `notifications.pending_discarded`. An alert raised
after the replacement is saved goes only to the new URL. To rotate a
credential, such as a webhook token, replace the destination's URL in the
console.

Pausing a destination keeps its queued alerts until it is enabled again,
including an alert that a delivery pass has picked up but not yet sent. A
pause uses none of their retries and is not reported as a delivery failure.

Scan changes, scan failures, cancellations, timeouts, stalled cycles, and
recovery events can all generate notifications. Definitive provider failures
are retried durably for up to 15 attempts over roughly 77 hours; the delay
doubles from two minutes and caps at 12 hours. A restart preserves each
delivery's retry schedule. Terminal failures are visible in the console
without exposing provider errors or destination secrets. Each destination
shows its pending and retrying alerts, terminal failures, and last success or
failure on its unit's **Notifications** page, or on the platform console for
platform-owned destinations.

### Notification URLs in config.yaml (deprecated)

Earlier releases also read Shoutrrr URLs from `notifications.urls` and
`notifications.urls_file` in config.yaml. These keys are deprecated, and a later
release will refuse to start while either is set. `notifications.encryption_key_file`
stays supported.

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

After the import, EdgeWatch no longer delivers to the URLs in config.yaml. Each
start logs a warning while config.yaml still lists them, and `edgewatch health`
reports `notification URLs in config.yaml were imported; remove them from
config.yaml`. Remove `notifications.urls` and `notifications.urls_file` from
config.yaml, and the URL file mount from compose.yaml. A URL that is added to
or changed in config.yaml later is imported as an additional destination at
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
destinations afterwards. A backup taken before the import is imported again
after it is restored.

Until its import succeeds, a URL in config.yaml is a read-only deployment
destination. Its ID follows its exact URL, so changing any part of the URL
creates a new destination at the next restart, and alerts still queued for the
old URL are not delivered. Jobs do not follow that change: EdgeWatch logs a
warning that names the jobs whose routing selects a destination that no longer
exists, each affected job shows a notice in the console, and saving the job
editor removes the missing selection. After the import, change a URL by
replacing it on the **Notifications** page instead; a changed URL in
config.yaml only adds another destination.

## Users and public status

The first account is an administrator. Administrators can invite additional
accounts with single-use activation links. Every user can manage their own
display name, password, and optional TOTP protection. Usernames can use at most
80 bytes of UTF-8 text, so accented and non-Latin characters count as 2 to 4
bytes each, and cannot contain control characters, `/`, `\`, or `:`.

New activation and password-reset links keep their one-time token in the URL
fragment, which is not sent in the HTTP request to EdgeWatch or a reverse proxy.
EdgeWatch removes it from the browser address bar as soon as the activation page
opens. Previously issued query-string links remain usable only until their
existing 30-minute expiry and are also removed from browser history on arrival.
A browser that is already signed in never uses a link with its session: the
console names the signed-in account and offers to sign out, and then opens the
activation page with the link's token, which stays in the address bar until
then. **Return to the console** keeps the session and leaves the link unused.

The console shows the data of one account at a time. When its session ends, or
when a session read finds that the browser is now signed in as another account,
for example after a sign-in in another tab, the console drops the data that it
loaded before it shows the sign-in page or the other account. A request that
fails without ending the session, as while EdgeWatch restarts, keeps the open
console and what was typed in it: the console says that it is reconnecting and
reads its session again every few seconds until EdgeWatch answers.

An account has one usable link at a time: a new link stops the older ones. A
link also stops working when the account's password changes in any other way
(the account's own change, `edgewatch admin reset-password` on the host, or
redeeming another link), when the account's role changes, and when the account
is disabled. A role change stops a pending account's activation link too, so
issue a new link after changing the role of an account that has not activated
yet. Each stopped link that could still have been used is recorded in the
security audit as `user.activation_revoked`, with the account's name.

| Role | Access |
| --- | --- |
| Administrator | Full administration, users, destinations, profiles, jobs, baselines, incidents, and public status. |
| Operator | Configure and run jobs; approve or reset baselines; accept or suppress incidents; review evidence; and select existing destinations for jobs. Cannot manage destinations, users, or scanner profiles, permanently delete archived jobs, or approve high-cost scans; an operator's scope change clears an existing high-cost approval. |
| Viewer | Read-only jobs and baseline information. |

An administrator can enable **Public status** and explicitly publish selected
effective hosts. The unauthenticated /public page contains only the chosen job
names, latest successful scan time, positive ports, service names, and cached
normalized network-registration data. It does not expose raw Nmap evidence,
product fingerprints, credentials, or an arbitrary RDAP proxy.

Each business unit publishes its own page; see
[Business units](#business-units).

A public-status save applies only to the configuration the editor loaded. If
another administrator saved in the meantime, EdgeWatch rejects the save with a
conflict and the editor reloads the current settings, so an outdated editor
cannot re-publish a withdrawn page. API clients send the `updated_at` value from
`GET /api/v1/public-dashboard` with each `PUT`.

## Business units

Business units let several internal teams share one deployment and its
database. Each unit has its own accounts, jobs, scans, baselines, incidents,
notification destinations, custom scanner profiles, and public status page.
EdgeWatch enforces the separation in the application, not in the host or the
database; see [Limits](#limits).

Every installation starts with one unit, the default unit, named `Default`
with the slug `default`. The upgrade to schema 54 moves everything that
existed into it, and every account keeps its role there, so existing
administrators administer the default unit. There is nothing to configure.
While the default unit is the only one, jobs, schedules, notifications,
public status, and optional TOTP work as before. After upgrading, an
administrator notices only this:

- administrators get a read-only **Audit** page with the unit's security
  audit;
- the public status page is also served at /public/default;
- host commands accept `--tenant`, and `admin reset-password` and
  `admin disable-totp` print the account's unit and role before they act
  (see [Useful commands](#useful-commands));
- the host can create a platform administrator, who creates further units
  (see [The platform administrator](#the-platform-administrator)).

A config.yaml written for the preview of business units may still contain
`experimental.business_units`. EdgeWatch ignores that setting and logs a
warning at startup; remove the `experimental` section.

### The platform administrator

A platform administrator is a separate account that belongs to no unit. It
creates, renames, disables, and deletes units, sets their capacity, invites
and resets their administrators, can sign out any of their accounts, manages
the other platform administrators and the platform's own notification
destinations, and reads the platform audit and status. It never sees a
unit's jobs, scans, hosts, baselines, incidents, destinations, or public
status settings: the platform console shows each unit with its name, slug,
state, and counts of accounts, administrators, jobs, stored scans, and scan
slots in use, and lists the unit's accounts without credentials. Stored
scans counts every scan the unit's history holds, those of archived jobs
included; retention lowers it, and while a unit is being deleted it shows
the scans that are left to erase.

The host creates the first platform administrator, after the first
administrator exists. Print a one-time platform setup token:

```console
docker compose exec edgewatch edgewatch admin platform-setup-token \
  --config /etc/edgewatch/config.yaml
```

The token is valid for 15 minutes. While it is valid, the sign-in page links
to the setup page, where the token, a username, and a password create the
account. Without a valid token, the setup page says that EdgeWatch is already
set up and links to sign-in; print a token and reload the page. When the token
expires, or someone else uses it, while the page is open, the page says so and
keeps what was typed; print a new token and paste it. The command is refused
once an enabled platform administrator exists, and it replaces an unused token
only with `--force`. An
existing platform administrator invites the others from **Platform admins**.
An invited account stays pending until its one-time link is redeemed, and
the link expires after 30 minutes. For a pending account, **Renew
invitation** shows a new link once and stops every earlier one, which
recovers an invitation that expired or was revoked. **Revoke invitation**
stops the link, and **Remove** deletes the pending account so its username
can be invited again. Each needs your password.

### Units and their accounts

Create a unit on the **Units** page of the platform console. Its name has at
most 80 characters and is unique without regard to case. Its slug, derived
from the name when left empty, has 2 to 40 lowercase letters, digits, or
hyphens and cannot be a reserved word such as `api`, `platform`, or `public`.
Then invite the unit's first administrator from the unit's **Accounts** tab.

The platform administrator invites and resets only unit administrators, and
receives each one-time link to pass on. It does both only while the unit is
active: the **Accounts** tab of a disabled unit offers only to sign an
account out. The unit's administrators invite and
manage every account of their unit on **Users**, including further
administrators, operators, and viewers, and cannot reach another unit's
accounts or a platform administrator. Each unit keeps at least one enabled
administrator. Usernames are unique across every unit and the platform.

Once more than one unit exists, counting disabled units and units being
deleted, every unit administrator and platform administrator must use TOTP.
Operators and viewers are not affected. An administrator without TOTP gets a
forced enrolment screen after signing in, which offers only the authenticator
setup, a password change, and sign-out; until TOTP is on, the session can
manage only its own account. A console that is already open switches to that
screen as soon as the server refuses one of its requests, and the platform
administrator's console does so right after it creates the second unit.
After enabling TOTP and saving the recovery codes, sign out and sign in
again with the authenticator's next code; the code that enabled TOTP counts
as used. Enrol the existing administrators before you create the second unit.
The host command `admin disable-totp` stays the recovery path, and the
account then enrols again.

### What belongs to each unit

- **Notifications:** each unit adds and routes its own destinations; jobs can
  select only their unit's destinations. URLs from `notifications.urls` and
  `urls_file` in config.yaml are imported into the default unit only. The
  platform has its own destinations on the platform console's
  **Notifications** page.
- **Update alerts:** each active unit gets its own copy of an update alert,
  routed by its own **Update alerts** selection, and an empty selection
  silences it. A new unit starts with update alerts off: its copy goes to
  none of its destinations until its administrators select some on
  **Notifications**. The default unit keeps its behavior from before
  business units: until its administrators save a selection, it sends update
  alerts to all of its enabled destinations. The platform's copy goes only to
  the platform destinations selected there; none are selected until a
  platform administrator chooses them. When an update check cannot read the
  list of units, it records no copy, and a later check records every copy.
- **Scanner profiles:** the built-in profiles are shared and read-only. Custom
  profiles belong to the unit that created them.
- **YAML jobs:** the inactive jobs in config.yaml belong to the default unit.
  Only its administrators and operators see them listed on **Overview**, and
  `edgewatch status` lists them for the default unit only.
- **Public status:** each unit's administrators publish its page at
  /public/<slug>; /public keeps serving the default unit's page. An unknown
  slug, a page that is not enabled, and a unit that is disabled or being
  deleted get the same answer as a page that is not enabled. Each page has
  its own anonymous rate limit and cache. Changing a unit's slug changes its
  public address.
- **Capacity:** the `scheduler` settings in config.yaml stay the deployment's
  limits. On a unit's **Capacity** tab, a platform administrator can cap the
  unit's scan slots and its Nmap and Naabu probe budgets below those limits,
  or keep the deployment's setting. A save changes only the settings that
  were edited on the tab, and EdgeWatch rejects it with a conflict when
  another change to the unit was saved after the tab read its capacity; the
  tab then shows the current values with the edits, to review before saving
  again. API clients send the `revision` from the capacity they read. A slot
  cap is a limit, not a reservation: free slots go in turn to the units that
  have queued scans, up to each unit's cap. A unit's **Overview** shows its
  own limit, the cap where it has one and the deployment's setting
  otherwise, as "N scans at a time", and
  the API's status reports the unit's own slots and probe budgets the same
  way. The high-cost ceiling is the most probes that a job approved
  for high-cost work may send. A new unit has none: its **Capacity** tab
  shows the ceiling as **Not granted**, and such an approval raises neither
  probe budget, whatever config.yaml sets now or later, until a platform
  administrator chooses **Grant a ceiling** and enters one. A granted
  ceiling stays in force when config.yaml later lowers the deployment's
  budgets below it; choose **Not granted** to take it away. Saving the tab
  keeps a ceiling that was not granted as it is. The default unit keeps the
  high-cost behavior from before business units.
- **Audit:** a unit's administrators read its security audit on **Audit**,
  including a platform administrator's actions on the unit's accounts and
  capacity, without the platform administrator's source address. The platform
  audit shows the records that belong to no unit, such as each unit's
  creation, rename, disabling, enabling, and deletion, and every unit's
  account records, never its data records. A failed redemption of an
  activation or password-reset link, and its rate-limit record, are in the
  audit of the link's unit, or in the platform audit for a platform
  administrator's invitation; a token that matches no link is recorded in
  the default unit's audit. Both views are read-only. The
  platform audit filters by unit, by the start of the action, which is
  lower-case, and by day; a day is a calendar day in the configured
  `timezone`, in which the entries are shown, or in the browser's timezone
  when it is omitted.

### Disabling and deleting a unit

Disabling a unit, from its **Danger zone** tab with the platform
administrator's password, pauses it and keeps its data:

- its sessions end, its open invitations are revoked, and sign-in fails as it
  does with a wrong password, without using up the one-time or recovery code
  it presents;
- its running scans are cancelled without changing baselines, its queued runs
  fail, and its jobs leave the schedule;
- a scan that finishes after the disable, including a host `edgewatch scan`
  that the daemon cannot cancel, is recorded as canceled and changes no
  baseline, incident, or alert; a resumable cycle that such a scan completed
  is discarded, so enabling the unit again does not apply it;
- its undelivered alerts are held, including one that a delivery pass has
  picked up but not yet sent, and it gets no copy of new update alerts;
- its public page answers as a page that is not enabled;
- retention keeps removing its expired history.

Enabling it again restores sign-in and the schedule and delivers the held
alerts; revoked invitations stay revoked. The default unit can be disabled
but never deleted.

Deleting a unit needs a disabled unit, its exact name typed, and the platform
administrator's password. Its jobs are archived at once, and the daemon then
erases its data in small batches, compacts the search indexes, and truncates
the database's write-ahead log, so neither keeps copies of the erased data.
Before it truncates the log, it also clears the database's free pages, which
can still hold the unit's history that retention removed while the unit
existed: a database created by v0.18.31 or later returns them to the file
system, and in an older one, which keeps them in the file and whose
`auto_vacuum` mode `edgewatch verify` reports as `none`, the deletion
overwrites every one of them with zeros. The deletion continues in the
background, resumes after a restart, and waits for a running scan to finish;
a running backup delays its last step until the backup ends. The unit's page
shows its progress. The records of platform administrators' actions and of
the deletion stay in the platform audit; the unit's other audit records are
erased. Afterwards the unit's name and slug can be used again. Backups taken
before the deletion still contain the unit. Releases before schema 55 could
finish a deletion before the compaction and the log truncation had, and
releases before schema 56 did not overwrite free pages; the upgrades to
schema 55 and 56 finish that work once, as described in
[Data, backup, and recovery](#data-backup-and-recovery).

### Limits

The separation of units is enforced by the console, the API, live updates,
and the public pages. Units share the process, the database, and the
`notification.key` and `auth.key`, so anyone with access to the Docker host,
the container, the host commands, the database, or a backup can read and
change every unit's data. A backup and a restore always cover every unit
together. Use business units for teams that trust the deployment's operators,
and separate deployments for parties that must not share them.
[SECURITY.md](SECURITY.md) describes the trust boundary, the platform
administrator's reach, and the signals that units can still observe about
each other.

## Data, backup, and recovery

All runtime state lives in ./data, including:

- edgewatch.db and SQLite sidecars;
- notification.key, which encrypts the notification destination URLs stored
  in the database, including URLs imported from config.yaml;
- auth.key for TOTP encryption when the default key location is used;
- optional backups and exported baselines.

Back up the complete ./data directory together with config.yaml and any
separately mounted secret files. Notification credentials live encrypted in
the database, so a database backup is only usable with its
`notification.key`. The backup command does not create missing directories,
so create the backup directory first with the same owner as ./data. For
standard rootful Docker:

```console
sudo install -d -m 0750 -o 0 -g 0 ./data/backups
```

For rootless Docker:

```console
install -d -m 0750 ./data/backups
```

Then take a live, consistent database snapshot:

```console
docker compose exec edgewatch edgewatch backup \
  --config /etc/edgewatch/config.yaml \
  --out /var/lib/edgewatch/backups/edgewatch-backup.db \
  --output json
docker compose exec edgewatch edgewatch verify \
  --config /etc/edgewatch/config.yaml --output json
```

`edgewatch verify` also reports the database's `auto_vacuum` mode. A
database created by v0.18.31 or later has `incremental` and returns the pages
it frees to the file system; an older one has `none` and keeps them in the
file, with the rows they held, until SQLite reuses them. A backup made with
the backup command holds no free pages, but a raw copy of ./data holds the
database file whole. Deleting a business unit leaves no free page with the
unit's rows in either mode.

The backup command uses SQLite's online snapshot support. A raw directory copy
must be made while EdgeWatch is stopped so the database and WAL sidecars stay
consistent. Never replace a live database. Restore with the host-safe command,
verify it, and only then start the service again. The image entrypoint is
already `edgewatch`, so `docker compose run` takes the subcommand directly,
while `docker compose exec` needs the `edgewatch` executable name:

```console
docker compose stop edgewatch
docker compose run --rm --no-deps -T edgewatch restore \
  --config /etc/edgewatch/config.yaml \
  --from /var/lib/edgewatch/backups/edgewatch-backup.db \
  --output json
docker compose run --rm --no-deps -T edgewatch verify \
  --config /etc/edgewatch/config.yaml --output json
docker compose up -d edgewatch
```

To check a restore first, add `--dry-run` to the restore command. The dry run
runs the same checks as the restore: SQLite sidecars, an active daemon
heartbeat, and validation of a staged copy of the backup, which is made in a
private directory next to the database and then removed. The destination is
never changed. The report includes `safe`, a `refusal` reason when the restore
would be refused, the backup's `source_schema_version`, and the number of
pending deliveries the chosen `--pending-deliveries` policy would affect. The
command exits non-zero when the restore would be refused, so scripts can act on
its exit status.

Restore and dry-run commands stop their staging work on `SIGINT` or `SIGTERM`
and remove the temporary copy. If a process is killed outright or the host
crashes, the next restore or dry run removes abandoned `.edgewatch-restore-*`
copies before starting. Concurrent restore commands are serialized with an
advisory lock on Linux using the database directory itself, so no extra lock
file is created. Other platforms retain signal cleanup but skip automatic
orphan removal when cross-process locking is unavailable.

A backup taken while the daemon runs contains that daemon's lease and the
leases of its running scans. No process runs on a restored copy, so restore
clears these copied leases, and the dry run does the same in its private copy.
The service therefore starts at once after a restore, and a repeated restore
onto the stopped service is not refused. The active-daemon check reads only
the lease in the database that is being replaced.

A backup can also hold sign-in sessions, activation and password-reset links,
and a setup token that were ended, redeemed, or replaced after it was taken.
Restore therefore clears the copied sessions and marks every unused link and
setup token in the copy as used, and the dry run does the same in its private
copy. After a restore everyone signs in again, and administrators issue a new
link from **Users**, or the platform console, for each account that still
needs one. Print a new platform setup token with `edgewatch admin
platform-setup-token`; while no administrator exists, the daemon prints a new
setup token when it starts.

The current schema is version 63. Schema 31 records terminal notification
deliveries and marks rows that had already exhausted the original eight
attempts. Schema 63 repairs databases that had already passed schema 31 by
marking still-unsent rows with at least eight attempts and a scheduled retry
before v0.22.1, when the retry budget increased to fifteen. Retries scheduled
on or after that release remain eligible, so upgrading does not replay
deliveries that were still retrying. Database migrations are forward-only. An
older image must not be pointed at a database already upgraded by a newer
image; restore the matching pre-upgrade ./data backup if a rollback is
required. The daemon and the commands that write to the database (admin, scan,
notify test, baseline approve and reset, and backup) refuse a newer schema
with `database schema version N is newer than supported version M`. Back up
such a database with the release that upgraded it, or copy ./data while
EdgeWatch is stopped. A daemon that finds another daemon's live lease exits
before it migrates the database, and so does a daemon whose configured key
file or notification URL is unusable (see `config validate` under
[Useful commands](#useful-commands)). Keep encryption keys with the database or
encrypted web-managed destinations and never commit them.

Schema 58 rebuilds the bounded host-search indexes from retained scan and
baseline evidence in restartable batches. Service names and products are
prioritized so services on late ports remain searchable even when a host has
many positive ports. The rebuild does not change scan results or baselines.

Only the daemon migrates the database, when it starts. A restored backup of an
older release keeps its schema until then. On such a database, `restore`,
`verify`, `health`, and `backup` work as usual, so the restored copy can be
checked and backed up first. The commands that act on business units or
accounts need the upgraded schema, whether they only read (`status`,
`history`, and `baseline export`) or also write (`admin`, `scan`, `baseline
approve` and `reset`, and `notify test`). They change nothing and stop with
`database schema version N has not been upgraded to version M yet; start the
daemon once to upgrade it, then run this command again`. Start the service,
for example with `docker compose up -d edgewatch`, and run the command
again; it can run while the daemon is running.

Schema 48 rebuilds the baseline host search index at startup in bounded,
resumable batches. While it runs, `edgewatch health` reports the
`host-search:baseline_hosts` phase, and a restart resumes after the last
committed batch.

Schema 49 records which revision of each web-managed destination last changed
its credentials, so an alert raised during a rename is still queued. It is a
quick in-place change with no background phase.

Schema 50 records which notification URLs from config.yaml were imported as
web-managed destinations, and the outcome of the import at each daemon start.
It is a quick in-place change; the import itself runs once after the
migration, as described in [Notifications](#notification-urls-in-configyaml-deprecated).

Schema 51 adds a default tenant to the database. The update alert routing and
the public status page settings move to it unchanged, setup tokens record their
purpose, and each security audit record gains a tenant and a category. It is a
quick in-place change with no background phase, and the console, API, CLI,
public status page, and notifications behave as before.

Schema 52 rebuilds the users, jobs, scanner profiles, and notification
destinations tables so that each row records the tenant that owns it; every
existing row moves to the default tenant. It also removes the legacy
administrator row, which the original administrator's user account already
replaces. The rebuild runs once at startup in one transaction, and on a large
database its foreign key check can take a while. Back up ./data before
upgrading. Sign-in, setup, and the host recovery commands behave as before.

Schema 53 records the tenant of each scan, event, and notification delivery;
every existing row belongs to the default tenant. Adding the column does not
rewrite the stored scan results or event payloads, but the migration builds
two new indexes on the scan and event history in one transaction at startup,
which can take a while on a large history. The console, API, CLI, public
status page, and notifications behave as before.

Schema 54 keys the latest-host projection behind the Hosts view by tenant and
address, so each tenant keeps its own newest observation of an address. The
migration only swaps the table; the daemon then rebuilds the projection at
startup by copying it in resumable batches of 500 hosts. Each host keeps its
host search entry, so the search index is not rebuilt. While the copy runs, `edgewatch
health` reports the `tenant-latest-hosts` phase with its progress, `edgewatch
verify` lists its `latest_scan_hosts_tenant_rekey` checkpoint, and a restart
resumes after the last committed batch. Until the copy completes, a host
command that saves a successful scan is refused; start the daemon to finish
the upgrade. The console, API, CLI, public status page, and notifications
behave as before.

Schema 55 finishes the deletion of business units that earlier releases
deleted. Those releases marked a unit deleted once its rows were erased and
only then tried to compact the search indexes and truncate the write-ahead
log, so the index files, and after an unclean shutdown the log, may still
hold copies of its erased rows, which backups then copy. When the database
holds a deleted unit, the migration records a one-time cleanup; a database
without one gets none. The daemon runs it in the background with the unit
deletion's steps and limits: each pass, at startup and every minute,
compacts the search indexes for at most 30 seconds and resumes where the
previous pass or a restart stopped, and the cleanup ends with a checkpoint
that truncates the log. A running backup delays that checkpoint until the
backup ends, which the daemon logs as a warning. While a unit is being
deleted, the cleanup waits, and that unit's deletion completes it; a
deletion that was already compacting the indexes at the upgrade starts its
compaction over, so that it covers the earlier units too. While the cleanup
is pending, `edgewatch health` reports it under `maintenance` with its
`legacy-tenant-purge` phase and progress, and `edgewatch verify` lists its
`legacy_tenant_purge_maintenance` checkpoint, which is complete once it has
finished; the daemon logs its start and its end. It never runs again.
Backups taken before it has finished may still hold the erased rows of
those units. An older release refuses the upgraded database, so a rollback
means restoring the pre-upgrade ./data backup.

Schema 56 finishes the deletion of business units in a database whose
`auto_vacuum` mode is `none`, one created before v0.18.31. Earlier releases
left the free pages of such a database as they were, and those may still hold
rows of a deleted unit that retention removed while the unit existed. When
such a database holds a deleted unit, the migration records the cleanup of
schema 55 as pending again, from its overwrite of free pages: the daemon
overwrites every free page with zeros in the same bounded, resumable passes
and then truncates the write-ahead log, without compacting the search indexes
again. While it is pending, `edgewatch health` reports the
`legacy-tenant-purge:free-pages` phase, and `edgewatch verify` lists the
`legacy_tenant_purge_maintenance` checkpoint as not complete. A deletion that
was in progress at the upgrade and had reached its log truncation goes back
to the overwrite. A database with `auto_vacuum` mode `incremental` is not
changed. Raw copies of ./data made before the cleanup has finished may still
hold those rows. An older release refuses the upgraded database, so a
rollback means restoring the pre-upgrade ./data backup.

Schema 57 records whether a business unit has a high-cost grant. Earlier
releases gave each new unit a high-cost ceiling equal to the lower of the
deployment's two probe budgets when it was created. Once config.yaml lowered
those budgets, that ceiling let an approval of high-cost work raise the
unit's budgets up to it, although no platform administrator had granted it.
The upgrade marks the ceiling of every unit other than the default one as
**Not granted** when no platform administrator has ever saved that unit's
capacity. A unit whose capacity a platform administrator saved keeps its
ceiling as a grant, because the earlier **Capacity** tab sent the initial
ceiling back with every save, so the database cannot tell it from a ceiling
that was typed. After the upgrade, review the high-cost ceiling on the
**Capacity** tab of each such unit and choose **Not granted** where no
grant was intended. The default unit keeps its ceiling. It is a quick
in-place change with no background phase. An older release refuses the
upgraded database, so a rollback means restoring the pre-upgrade ./data
backup.

## Useful commands

Run these from the host with docker compose exec:

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

`config validate` runs every check of the daemon's startup that needs no
database: the deployment settings, the notification URLs file, the key in
`web.auth_key_file` and in `notifications.encryption_key_file` when they are
set (present, private to its owner, and well formed), and the syntax of each
notification URL in `notifications.urls` and `notifications.urls_file`. It
prints the normalized configuration with `"valid": true`, or `"valid": false`
with the reason and exits non-zero. An invalid URL is named by a digest
prefix, never by the URL. The daemon runs the same checks before it opens the
database, so a start that they refuse leaves the database as it was.

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

`health` exits non-zero when migrations or the daemon heartbeat are unhealthy.
Its `warnings` list actions that do not stop EdgeWatch, such as removing
imported notification URLs from config.yaml.

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

Each `status` row has a `state`: `scheduled`, `paused`, `archived`,
`unit_disabled` for an enabled job of a disabled unit, which is off the
schedule until the unit is enabled, or `legacy` for an inactive YAML job.
Only scheduled jobs have a `next_run`. For a unit without jobs, `status
--output json` prints `[]`, and `history --output json` prints empty `scans`
and `events` lists for a unit without history. Commands print
their result on stdout and write log lines to stderr, so `--output json` output
can be piped straight into a JSON parser. Only the daemon logs to stdout.

Commands that change state, such as `scan`, `baseline approve` and
`baseline reset`, record a `host-cli` entry in the security audit log. A CLI
scan is recorded as `scan.run_requested`, like a run started from the console,
with the job ID and the scan outcome.

For a scan that appears stuck, open its live details in the dashboard first.
Broad jobs report scanner phase, process heartbeat, completed probes, and
resumable work. If a cycle has timed out, it will resume on the next scheduled
or manual run until its resume window expires. A stalled cycle holds scheduled
runs until an operator retries or discards it, or until its resume window
ends; the first scheduled run after that records the expiry, and the next one
starts a fresh cycle. Check docker compose logs
edgewatch for a bounded error summary; do not assume a zero-progress display
means the process is idle.

## Development

The project uses Go 1.27.1 or newer and Node.js 24.16.0 or newer within the
Node 24 release line. CI and the container build are pinned to 24.21.0; local
version managers can use [.node-version](.node-version). From the repository
root:

```console
npm ci
make check
npm run build
npm run test:coverage
npm run test:e2e
docker compose config --quiet
```

`npm run test:e2e` builds the console and serves it on 127.0.0.1:4173. Set
`PLAYWRIGHT_PORT` to use another port. If the port is already in use, the run
stops before any test instead of testing whatever server is listening there.
Set `PLAYWRIGHT_REUSE_SERVER=1` only to reuse a preview of the same checkout
that you started yourself.

The production image embeds the frontend and does not include Node.js. Use
controlled listeners for integration scans and never commit notification URLs,
passwords, setup tokens, database files, or encryption keys.

More security detail, including the live-update session-revocation and
isolation bounds, is in [SECURITY.md](SECURITY.md); container capability
guidance is in [docs/container-hardening.md](docs/container-hardening.md).
The historical scan API's metadata and full-result endpoints, and the API of
the business units, are documented in
[docs/api-compatibility.md](docs/api-compatibility.md).

## License

Copyright (c) 2026 Bart. EdgeWatch is released under
[AGPL-3.0-only](LICENSE). Bundled components keep their separate licenses;
see [third-party notices](THIRD_PARTY_LICENSES.md).
Releases before v0.25.0 retain their previously published MIT terms.

The console's **Source code** link is public, including on sign-in and public
status pages. An official release links to its exact Git tag. If you deploy a
modified or forked build, publish its complete corresponding source and build
instructions, then set `web.source_url` in `config.yaml` to that HTTPS location.
Without an override, a development build links to the upstream repository,
which does not represent local modifications. Changing the source link does
not change the obligations of the license.
