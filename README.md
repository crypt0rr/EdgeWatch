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

![EdgeWatch overview dashboard](EdgeWatch.png)

> Only scan systems you own or are authorized to assess. Full-range UDP scans
> can take many hours and generate significant traffic.

## What you get

| Capability | What it does |
| --- | --- |
| Scheduled jobs | Monitor individual IPs, CIDRs, and DNS names on cron schedules. |
| TCP and UDP coverage | Use Nmap for both protocols, or Naabu full-range TCP discovery followed by Nmap confirmation. |
| Baselines and incidents | Establish an expected surface and receive alerts for confirmed port, service, or DNS changes. |
| Host evidence | Inspect effective IPs, positive ports, services, scan provenance, Nmap reasons, and summarized non-open results. |
| Notifications | Deliver Shoutrrr alerts to deployment-managed or encrypted web-managed destinations. |
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

For a rootful installation, create notification and authentication secret files
as host root with mode `0600`:

```console
sudo install -m 0600 -o 0 -g 0 notification-urls.example.txt ./notification-urls.txt
```

For rootless Docker, run the install command without `sudo` or ownership flags
so the file belongs to the invoking user.

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
  -c 'cat /run/secrets/edgewatch-notification-urls >/dev/null'
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
2. Open **Notifications** and add Shoutrrr destinations, or confirm the
   deployment-managed destinations from config.yaml.
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
| notifications.urls, urls_file | YAML/secrets | Deployment-managed Shoutrrr destinations. |
| Jobs, users, profiles, web destinations | Web console | Runtime administration stored in SQLite. |

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
  short two-second cooldown instead of a five-minute lockout. Applying the same
  cooldown to known and unknown usernames avoids revealing account existence.
  Configure the proxy network and forwarding header when you need per-client
  rate limits and audit identities. EdgeWatch logs a startup warning when
  approved proxy hosts lack trusted client-IP forwarding.
- Loopback, link-local, and cloud metadata addresses are excluded by default.
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
and suppressed changes. A single Naabu miss cannot close them. An address with
no Naabu result counts as complete coverage only when host discovery is
skipped (assume_alive, the default). With SYN host discovery, Naabu cannot
tell a down address from one without open ports, so that address stays
incomplete, as a down host does with Nmap. Repeated Naabu results are counted
once. One Naabu invocation keeps at most 131,070 distinct open ports, the
equivalent of two addresses with every port open. Beyond that, the addresses
with the most results are recorded as incomplete with the reason
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
host evidence. Schedules use five-field cron syntax in the selected IANA
timezone. New jobs default to the deployment `timezone` from config.yaml, or to
the browser's timezone when it is omitted. New jobs receive an optional 30-minute schedule-offset suggestion
when another active job is nearby; the administrator can keep concurrent times.

Choose how many successful samples establish a baseline and how many matching
changes confirm an incident. When a security-impacting job setting changes,
EdgeWatch shows the affected scope and asks for explicit rebaselining. Schedule
and execution-tuning changes do not reset the baseline. A run that waits for a
free scan slot uses the job's settings when it starts; if the job is paused or
archived while a scheduled run waits, that run is skipped.

From **Incidents**, administrators and operators can:

- **Accept change** to make the current observation expected while preserving
  the original scan history. Accepting a service on a newly opened port also
  accepts that port; accepting the port alone leaves its service for a
  separate decision.
- **Suppress 1 scan** to defer the alert for the next successful scan. If the
  change remains, it is reported again afterward.

The **Hosts** page aggregates the latest successful result for each effective
IP. A host detail page shows configured-target relationships, TCP/UDP coverage,
positive ports, services, scanner provenance, and summarized closed/filtered
results. Opening a public host may load normalized RDAP information from the
authoritative registry; raw responses and contact records are not retained.

## Notifications

EdgeWatch uses [Shoutrrr](https://github.com/containrrr/shoutrrr) for delivery.
Destinations can be supplied in config.yaml or a protected URL file, or added as
named web-managed destinations. Web-managed URLs are write-only and encrypted
at rest; their credentials are never returned by the API or written to logs.

Each job can select its own destinations. On the **Notifications** page,
**Update alerts** is an independent toggle on each configured destination:

- pausing a destination does not erase its update-alert selection;
- deployment-managed destinations remain read-only for credentials but their
  update-alert routing can still be changed;
- saving an empty selection keeps update alerts silent while checks and the
  in-console indicator continue to work;
- password confirmation is required for every routing or credential change.

Routing stores destination IDs. A deployment destination's ID follows its exact
URL, so changing any part of a URL in config.yaml or the URL file, such as a
rotated webhook token, creates a new destination at the next restart. Jobs do
not follow that change: open each affected job and select the new destination.
Alerts still queued for the old URL are not delivered. After the restart,
EdgeWatch logs a warning that names the jobs whose routing selects a
destination that no longer exists, and each affected job shows a notice in the
console. The job editor lists the missing selection, and saving removes it.
If update alerts went to the old destination, turn on **Update alerts** for the
new one on the **Notifications** page.

Deleting a web-managed destination removes it from every job and from the
update-alert routing in the same change. Each affected job gets a new revision
and an audit record.

Scan changes, scan failures, cancellations, timeouts, stalled cycles, and
recovery events can all generate notifications. Delivery is retried durably;
terminal failures are visible in the console without exposing provider errors
or destination secrets.

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

| Role | Access |
| --- | --- |
| Administrator | Full administration, users, destinations, profiles, jobs, baselines, incidents, and public status. |
| Operator | Configure and run jobs; approve or reset baselines; accept or suppress incidents; review evidence; and select existing destinations for jobs. Cannot manage destinations, users, or scanner profiles. |
| Viewer | Read-only jobs and baseline information. |

An administrator can enable **Public status** and explicitly publish selected
effective hosts. The unauthenticated /public page contains only the chosen job
names, latest successful scan time, positive ports, service names, and cached
normalized network-registration data. It does not expose raw Nmap evidence,
product fingerprints, credentials, or an arbitrary RDAP proxy.

A public-status save applies only to the configuration the editor loaded. If
another administrator saved in the meantime, EdgeWatch rejects the save with a
conflict and the editor reloads the current settings, so an outdated editor
cannot re-publish a withdrawn page. API clients send the `updated_at` value from
`GET /api/v1/public-dashboard` with each `PUT`.

## Data, backup, and recovery

All runtime state lives in ./data, including:

- edgewatch.db and SQLite sidecars;
- notification.key for web-managed Shoutrrr URLs;
- auth.key for TOTP encryption when the default key location is used;
- optional backups and exported baselines.

Back up the complete ./data directory together with config.yaml and any
separately mounted secret files. The backup command does not create missing
directories, so create the backup directory first with the same owner as
./data. For standard rootful Docker:

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

The current schema is version 47. Database migrations are forward-only. An
older image must not be pointed at a database already upgraded by a newer
image; restore the matching pre-upgrade ./data backup if a rollback is
required. The daemon and the commands that write to the database (admin, scan,
notify test, baseline approve and reset, and backup) refuse a newer schema
with `database schema version N is newer than supported version M`. Back up
such a database with the release that upgraded it, or copy ./data while
EdgeWatch is stopped. A daemon that finds another daemon's live lease exits
before it migrates the database. Keep encryption keys with the database or
encrypted web-managed destinations and never commit them.

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
```

Each `status` row has a `state`: `scheduled`, `paused`, `archived`, or `legacy`
for an inactive YAML job. Only scheduled jobs have a `next_run`. Commands print
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
The historical scan API's metadata and full-result endpoints are documented in
[docs/api-compatibility.md](docs/api-compatibility.md).

## License

EdgeWatch is released under the [MIT License](LICENSE). Licenses for bundled
third-party components are listed in
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
