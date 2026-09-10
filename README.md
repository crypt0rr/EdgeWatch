# EdgeWatch

EdgeWatch is a Docker-deployed network-surface monitor. It schedules TCP and
UDP scans, records a baseline, and sends Shoutrrr notifications when the
observed network surface changes. TCP jobs can use Nmap directly or an optional
Naabu full-range discovery pass followed by Nmap confirmation.

Only scan systems you own or are authorized to assess. Full-range UDP scans can
take many hours and generate significant traffic.

## Deploy

Requirements: Docker Engine with Docker Compose v2.

From the repository directory:

```console
cp config.example.yaml config.yaml
mkdir -p data
docker compose pull
docker compose up -d
docker compose logs edgewatch
```

The Compose file pulls `ghcr.io/crypt0rr/edgewatch:latest`, uses host
networking for scan routing, and persists all runtime state in `./data`.
Run `docker compose pull` explicitly before starting when you want the latest
image.

The final image keeps the daemon at UID 0 for scanner compatibility. All
capabilities are dropped before adding only the raw-packet capability needed
by the default Nmap modes; an explicit `compose.syn.yaml` override adds
`NET_ADMIN` for Naabu SYN profiles. The compatibility matrix and the reasons a
non-root default is not enabled are documented in
[`docs/container-hardening.md`](docs/container-hardening.md).

Open [http://127.0.0.1:8080](http://127.0.0.1:8080). On the first start,
EdgeWatch prints a one-time setup token in the container log:

```console
docker compose logs edgewatch | grep setup_token
```

Create the `admin` account in the browser, then create and schedule jobs from
the Jobs page. The token expires after 15 minutes. The web listener is
loopback-only; use an SSH tunnel for a remote Docker host:

```console
ssh -L 8080:127.0.0.1:8080 user@docker-host
```

If the initial token was lost before the administrator was created, a host
operator can issue one replacement token. This command is deliberately
explicit and rate-limited, and prints the token only to the invoking terminal:

```console
docker compose exec edgewatch edgewatch admin setup-token --config /etc/edgewatch/config.yaml --force
```

It is refused after setup has completed. The existing token is invalidated when
the replacement is issued.

## Configuration

`config.yaml` contains deployment settings only. See
[`config.example.yaml`](config.example.yaml) for the complete schema.

- `database`, `retention`, `scheduler.max_concurrent_scans`,
  `scheduler.max_probe_count`, and `scheduler.max_naabu_probe_count` control
  local storage and scan capacity. Nmap-only jobs use the 5,000,000-probe
  default; Naabu pipeline jobs use a separate 20,000,000-probe default, which
  covers the editor's 256-host full-range (1–65535) discovery scope with
  headroom. A job's estimated probe count is shown in the console and runs
  over the applicable budget are rejected before scanning unless an
  administrator explicitly enables `allow_high_cost`. That override is still
  bounded by the 100,000,000-probe per-run safety ceiling.
- `log.level` controls structured JSON daemon logging and defaults to `info`.
  Use `debug` for additional request-start diagnostics; `warn` or `error`
  suppress routine request lines. Each completed HTTP request records a
  correlation ID, method, path, status, duration, and response size, and the
  same ID is returned in the `X-Request-ID` response header.
- `scanner.target_exclusions` is a deployment-wide CIDR/IP denylist applied
  before managed jobs are saved and again when targets are resolved. The safe
  default refuses IPv4/IPv6 loopback and link-local networks, including
  `169.254.169.254` on cloud hosts. Set it explicitly to `[]` only after
  accepting the host-networking implications and intentionally monitoring a
  local surface. DNS names are checked after resolution as well, so a name
  resolving to an excluded address fails the scan rather than silently
  scanning only the remaining addresses.
- `web.listen` must be a loopback address; the default is
  `127.0.0.1:8080`.
- Forwarding headers are ignored by default. If a local reverse proxy is used,
  set `web.trusted_proxies` to its exact IP address or CIDR. EdgeWatch then
  resolves the first untrusted address in the validated `X-Forwarded-For` or
  `Forwarded` chain for authentication throttling and security-audit records;
  do not trust a network that is not fully controlled by the operator.
- `enrichment.rdap.enabled` controls on-demand network-registration lookups
  from the host explorer. It defaults to `true`; set it to `false` for an
  isolated or privacy-sensitive deployment. Host detail pages query the
  authoritative RIR over HTTPS and cache only normalized network metadata for
  24 hours (stale data can be shown for up to seven days). The unauthenticated
  public page only shows data already present in that cache. Private and
  special-use addresses are never queried, and raw RDAP responses/contact
  details are not retained.
- `updates.enabled` controls the outbound GitHub release check. It defaults to
  `true`; EdgeWatch checks the latest stable release at startup and every three
  hours, notifying each globally enabled destination once per release when an
  update is available. After a newer image starts, it also sends a one-time
  previous/current version notification. Set it to `false` for offline or
  privacy-sensitive deployments. Checks reveal the host's public IP and the
  EdgeWatch user agent to GitHub. EdgeWatch reports releases only; Docker image
  updates and restarts remain operator-controlled.
- The authenticated administrator status response and Overview page include
  cached deployment telemetry: allocated database size, retained scans,
  effective hosts, host observations, events, resumable cycles, and pending or
  failed notification deliveries. Counts are sampled at most every 30 seconds
  so status polling does not repeatedly decode retained history.
- History-heavy host inventory and public-dashboard reads use a bounded
  read-only SQLite pool alongside the single writer connection. WAL keeps those
  reads available during scan commits and pruning; in-memory test databases
  intentionally continue to use their shared writer connection.
- TOTP is optional. Its seed is encrypted with a separate authentication key
  generated at `./data/auth.key` when TOTP is first enabled. Set
  `web.auth_key_file` to a mode-`0600` file containing 32 raw bytes or 64
  hexadecimal characters when the key must be supplied separately; an
  explicitly supplied path is never generated automatically.
- Notification URLs can be supplied with `notifications.urls`,
  `notifications.urls_file`, or a complete environment value such as
  `${SHOUTRRR_URL}`. Environment variables must be set and non-empty; partial
  or unresolved expressions are rejected. The URL file must be a regular
  owner-readable file with mode `0400` or `0600`, is limited to 1 MiB, and is
  validated before the daemon starts.
- The Notifications page shows per-destination pending and retrying counts,
  last successful delivery, and redacted terminal-failure status. A delivery
  that reaches the retry limit is recorded as a system event; provider
  responses and destination credentials are never retained.
- Create all monitoring jobs in the web console. The YAML `jobs` section is
  not used for scheduling.

Scanner profiles are managed by administrators in **Scanner profiles**. New
TCP jobs default to **Naabu discovery → Nmap**; existing and legacy jobs pinned
to Nmap remain unchanged. Users may select **Nmap only** or the Naabu pipeline.
Naabu always discovers TCP ports `1-65535`; only Nmap's
confirmed `open` and `open|filtered` results enter baselines and incidents.
Naabu discoveries and disagreements remain available as diagnostic host
evidence. UDP remains Nmap-only. Profiles pin a revision into each job, so
editing a profile never changes a scheduled job silently; applying a newer
revision is an explicit job edit and may require rebaselining. Built-in profile
definitions are checked at startup; when a release changes one, EdgeWatch
appends a new revision for future jobs while preserving every existing job's
pinned revision.

Profile command customization is an administrator-controlled, validated array
of arguments for the fixed `/usr/local/bin/naabu` and `/usr/bin/nmap`
executables. EdgeWatch uses `exec.CommandContext` directly and never executes
shell strings, pipelines, substitutions, arbitrary binaries, or arbitrary NSE
scripts. Operators can tune only fields that an administrator exposes within
bounded limits. Connect discovery is the built-in default. Naabu SYN discovery
requires both `NET_ADMIN` and `NET_RAW`; the default Compose file grants only
`NET_RAW` so it remains least-privilege. For a reviewed SYN profile, use the
opt-in `compose.syn.yaml` override, then select or create a profile with
`scan_type: syn` in the administration UI:

```sh
docker compose -f compose.yaml -f compose.syn.yaml pull
docker compose -f compose.yaml -f compose.syn.yaml up -d
```

Adding the override alone does not switch existing jobs or profiles to SYN.
The extra capability broadens the container's packet-access privileges, so
omit the override when connect discovery is sufficient.

## Users and public status

The first-run account is an `administrator`. Administrators can invite more
accounts from **Users**; the recipient receives a single-use activation token
and chooses an Argon2id password in the browser. Roles are deliberately small:

- **Administrator** can manage users, notification destinations, public-status
  publication, jobs, baselines, and incidents.
- **Operator** can configure and run jobs, review baselines and incidents, and
  select existing notification destinations for a job. Operators cannot read
  or change destination URLs or manage users.
- **Viewer** is read-only for the operational console and can inspect jobs and
  baseline information. Every account can change its own display name,
  password, and optional authenticator protection.

To publish a limited unauthenticated highlights page, an administrator enables
**Public status** and explicitly selects effective hosts. The page is available
at `/public` and contains only the selected job names, latest successful scan
time, positive ports (protocol, port, and service name), and cached normalized
network-registration data. Product/version fingerprints and raw Nmap evidence
remain private to the authenticated console. It does not provide a host
selector or proxy arbitrary RDAP requests. If you place it behind a reverse
proxy, allow only `/public`, `/assets/*`, `/favicon.svg`, and
`/api/public/v1/dashboard`; keep the authenticated `/api/v1/*` routes private.
Public responses use a short-lived
in-memory cache and a bounded legacy-history lookup; a request that exceeds the
five-second build budget receives a timeout response instead of running
unbounded database work. Keep the page disabled for isolated or
privacy-sensitive deployments.

Retention applies to completed scans, events, sent notification deliveries,
terminally failed deliveries, superseded job revisions, and terminal
resumable-cycle metadata that no retained scan still references. Active
baselines, the current revision of every job, pending/retryable deliveries,
active scan cycles, and the security audit log are retained; audit records are
intentionally indefinite. The daemon logs the row counts removed from each
retention class at startup and during its daily pruning pass.

Notification deliveries are attempted by four workers in bounded passes so a
large event burst does not delay scans. A failed delivery is retried up to
eight times with exponential delays starting at two minutes and capped at one
hour; after the eighth failure it is marked terminal and remains visible until
retention pruning. Claims expire after 30 minutes so an interrupted worker can
be recovered by the next pass.

The web job editor supports individual IP addresses, CIDRs, DNS names, target
expansion limits, independent TCP and UDP scans, ports `1-65535`, TCP SYN or
connect mode, service detection, timing, timeouts, cron schedules, timezones,
pause/resume controls, and a preflight scanner work estimate. Broad scans are
guarded by the scheduler probe budget; enable the explicit high-cost override
only when the additional load is understood. Active scans expose completed
probe/process counts in the dashboard and can be canceled without changing a
baseline or opening/recovering incidents. Every terminal non-success outcome
(including operator cancellation, scanner errors, and timeouts) is recorded and
sent to configured notification destinations; the message includes the scan
and failure reason.

For broad jobs (more than 4,096 configured ports or 65,536 estimated probes),
EdgeWatch automatically breaks the scan into deterministic work units. Nmap
units are split by addresses and then ports. Naabu discovery units checkpoint
one pinned full-range address batch. After all discovery units complete,
deterministic Nmap enrichment units are derived from the committed discoveries,
followed by any configured UDP units. A retry never changes that mandatory
scope into a partial port scan. Each successful unit is checkpointed in SQLite.
If the per-attempt timeout is reached, the
cycle is paused for the next scheduled or manual trigger; partial cycles never
affect the baseline. Paused progress is retained for eight days by default.
Configure the per-job `resume_window` between `1h` and `30d`, or use **Discard
saved progress** on the job page to force a fresh cycle. Three consecutive
attempts without any completed work mark a cycle stalled and generate a failure
notification. If the resume window expires, EdgeWatch records one terminal
failure notification before the next trigger starts from a fresh plan. A
completed cycle emits a recovery notification when it follows earlier timeout
pauses. Once a completed cycle's merged scan and host indexes are committed,
the per-unit snapshot payloads are reclaimed while unit status, timing, and
attempt metadata remain for operational history. The payloads are deliberately
kept between cycle completion and scan promotion so a restart can recover that
short transaction window safely.

When creating a job, the editor compares its next scheduled run with active
jobs and offers a non-blocking 30-minute offset when another run is too close.
The suggestion is optional: keep the chosen schedule when concurrent runs are
intentional.

Schedules use standard five-field cron semantics in the configured IANA
timezone. Daylight-saving transitions are not compensated for: a local time
that is skipped during the spring-forward transition does not run that day,
while a time in the repeated fall-back hour may run twice. When an exact
once-per-day cadence matters, choose a time outside the local transition hours
and keep the timezone's daylight-saving rules in mind.

The daemon also watches for jobs that go silent. For each enabled job, a
heartbeat compares the last successful scan (or the job creation time when it
has never run) with two of that job's own cron intervals. A running scan is not
considered silent, and at most one `job-silent` notification is emitted in each
interval window. This catches a scheduler or lease that has stopped producing
scans without repeatedly alerting for a legitimately slow weekly job. Silence
events are retained in the event history and use the job's normal notification
selection.

`assume_alive` defaults to `true` and passes host-discovery skip flags to the
selected scanner. Set it to `false` when host discovery is required. If Nmap
discovery reports an expected target as down or omits it, EdgeWatch records an
explicit `unreachable` host observation while committing the other addresses.
That partial result never treats the target as closed or changes a baseline;
the next complete scan can resume comparison. A completely empty Nmap result
still fails the scan as a scanner error.

For an already established baseline, a complete scan that suddenly reports no
positive ports is treated as a scan-level anomaly. EdgeWatch records one
warning and waits for a matching successful scan before opening the individual
port-change incidents. A genuine estate-wide loss is therefore still reported,
but a single degraded discovery pass cannot create an alert storm. A later
scan that finds any positive port clears the pending anomaly and is compared
normally.

When a baseline is ready, use **Explore baseline** on the job page to inspect
every effective address produced by the configured targets. Host detail pages
show the exact TCP/UDP scope, positive ports, service fingerprints, Nmap
reasons, and summarized closed/filtered outcomes. Scan history has the same
per-address view; older snapshots remain readable with a legacy-detail notice.
The **Hosts** page aggregates the latest successful historical result for each
effective IP across all jobs and links directly to that scan's detailed host
view.

## Baselines and incidents

Set the number of baseline samples and change confirmations per job. Only
successful scans can advance a baseline; failed, timed-out, partial, or
malformed scans never change comparison state. Confirmed port, service, or DNS
changes appear as incidents and can trigger notifications.

From the Incidents page, the administrator can **Accept change** to fold a
confirmed observation into the current baseline (scan history remains
unchanged), or **Suppress 1 scan** to hide it for the next successful scan.
Suppression is scan-based rather than time-based: if the same change is still
present after that scan, it is reported again and notifications resume.

Review and approve a successful current-scope scan, or reset the baseline,
from the job detail page. Security-relevant job edits require explicit
rebaseline confirmation and preserve scan history.

## Notifications

Deployment-managed Shoutrrr URLs remain active and read-only in the
Notifications page. The same page can add named web-managed destinations.

Web-managed URLs are write-only and encrypted with AES-256-GCM. The default key
is generated at `./data/notification.key`; ciphertext and metadata are stored
in `./data/edgewatch.db`. Adding, replacing, enabling, pausing, or removing a
destination requires administrator password confirmation and uses optimistic
revisions. URLs are never returned by the API or written to audit records.

Each web-managed job can select one or more named destinations in its editor.
Selections use stable destination IDs, so rotating a managed destination's
credentials does not require reconfiguring jobs. Deployment-managed URLs are
available as read-only destinations. Jobs created before per-job routing was
introduced are frozen to the destinations that exist when EdgeWatch starts (or
when the next destination is added), so a newly added endpoint is never silently
enabled for an existing job. An explicitly empty selection keeps a job silent.

Administrators can choose one or more destinations for EdgeWatch release and
upgrade alerts in the **Application update notifications** panel on the
Notifications page. Until a selection is saved, update alerts use all globally
enabled destinations; saving an empty selection keeps update alerts silent
without disabling the release check or its in-console indicator.

To supply the key separately, set `notifications.encryption_key_file` to a
`0600` file containing 32 raw bytes or 64 hexadecimal characters and mount it
into the container. An explicitly supplied key path is never generated
automatically and is validated before the daemon starts; a missing, invalid,
or unsafe key is a startup error. The default key is still generated lazily
beside the database when the first web-managed destination is created. Back
up the key with `./data/edgewatch.db`.

The TOTP authentication key is independent of the notification key. Back up
`./data/auth.key` together with `./data/edgewatch.db` (or the separately mounted
`web.auth_key_file`); losing it prevents TOTP verification until the key is
restored. TOTP ciphertext is authenticated to the owning stable user ID, so a
value copied between accounts fails closed. Existing plaintext or older
unbound encrypted seeds are re-encrypted in the owner-bound format on the
first read when the key is available.

## Operations

Useful commands run inside the container:

```console
docker compose exec edgewatch edgewatch health --config /etc/edgewatch/config.yaml
docker compose exec edgewatch edgewatch status --config /etc/edgewatch/config.yaml
docker compose exec edgewatch edgewatch scan --config /etc/edgewatch/config.yaml --job NAME
docker compose exec edgewatch edgewatch history --config /etc/edgewatch/config.yaml --job NAME --limit 20
docker compose exec edgewatch edgewatch notify test --config /etc/edgewatch/config.yaml
```

### Backup and restore

EdgeWatch can create a consistent SQLite snapshot while the daemon is running.
Create the destination directory first; existing files are never overwritten:

```console
mkdir -p ./data/backups
docker compose exec edgewatch edgewatch backup \
  --config /etc/edgewatch/config.yaml \
  --out /var/lib/edgewatch/backups/edgewatch-$(date -u +%Y%m%dT%H%M%SZ).db \
  --output json
docker compose exec edgewatch edgewatch verify \
  --config /etc/edgewatch/config.yaml --output json
docker compose exec edgewatch edgewatch baseline export \
  --config /etc/edgewatch/config.yaml \
  --out /var/lib/edgewatch/backups/baselines.json
```

`backup` uses SQLite's online `VACUUM INTO` snapshot, so WAL contents and
committed writes are captured consistently without stopping scans. `verify`
runs both `PRAGMA integrity_check` and `PRAGMA foreign_key_check`; it returns a
non-zero exit status when either check finds a problem. `baseline export` writes
a portable JSON document for every managed and legacy baseline, or one job when
`--job NAME` (or its managed ID) is supplied. Jobs without a ready baseline are
included with `status: "not_ready"`.

Keep the resulting database or JSON file together with `config.yaml`,
`notification.key` (when web-managed destinations are configured), and any
separately mounted notification URL or encryption-key files. Keep notification
secrets out of source control. The export intentionally contains baseline
observations and scan metadata only; it never contains notification URLs,
passwords, sessions, or encryption keys.

For a full deployment backup, retain the complete `./data` directory as well as
the deployment configuration and key files. SQLite uses WAL mode, so a raw
directory copy should be made while EdgeWatch is stopped; the `backup` command
is the supported live alternative. To restore a single database, stop the
service first, remove any existing `edgewatch.db-wal`, `edgewatch.db-shm`, and
`edgewatch.db-journal` sidecars, then replace the database and its companion key
files together. Alternatively restore the complete `./data` directory as one
consistent snapshot. Run `verify` against the restored database before starting
the matching EdgeWatch image; never replace a live database while the daemon is
running, because stale WAL frames can otherwise be replayed into the restored
file.

For an upgrade, stop the current service and make a complete backup before
starting the new image. SQLite uses WAL mode, so copy the database only while
EdgeWatch is stopped (or use SQLite's backup tooling). Keep the backup of
`./data` and any separately mounted encryption-key file together.

The schema migration from the v0.3 database is additive (the current schema is
version 26), but it is forward-only: an older binary refuses a newer schema.
To roll back, stop the new service, restore the entire pre-upgrade `./data`
directory and deployment configuration, then start the previous image. Do not
point an older image at the upgraded database. The previous named Docker
volume, if one exists, is not read or migrated automatically.

## Development

Go 1.27.1 or newer and Node.js 24.8.0 are required. The repository checks are:

```console
npm ci
make check
npm run build
npm test
npm run test:e2e
docker compose config --quiet
```

`make check` runs formatting, vetting, race-enabled tests, frontend type
checks, a pinned Go lint configuration, `govulncheck`, and `npm audit` at the
high-severity threshold. Go lint findings are limited to the change under
review so existing legacy findings can be addressed incrementally; dependency
vulnerability checks always cover the complete module and package trees. The
individual build, browser-test, and Compose commands can still be run when
iterating on a specific layer.

The browser acceptance tests use deterministic API fixtures; integration
scans should only target controlled listeners. The production image embeds the
frontend and does not include Node.js.

## License

MIT
