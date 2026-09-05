# EdgeWatch

EdgeWatch is a Docker-deployed Nmap monitor. It schedules TCP and UDP scans,
records a baseline, and sends Shoutrrr notifications when the observed network
surface changes.

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

- `database`, `retention`, `scheduler.max_concurrent_scans`, and
  `scheduler.max_probe_count` control local storage and scan capacity. A job's
  estimated probe count is shown in the console and runs over the budget are
  rejected before scanning unless `allow_high_cost` is explicitly enabled.
- `web.listen` must be a loopback address; the default is
  `127.0.0.1:8080`.
- `enrichment.rdap.enabled` controls on-demand network-registration lookups
  from the host explorer. It defaults to `true`; set it to `false` for an
  isolated or privacy-sensitive deployment. Public host pages query the
  authoritative RIR over HTTPS and cache only normalized network metadata for
  24 hours (stale data can be shown for up to seven days). Private and
  special-use addresses are never queried, and raw RDAP responses/contact
  details are not retained.
- TOTP is optional. Its seed is encrypted with a separate authentication key
  generated at `./data/auth.key` when TOTP is first enabled. Set
  `web.auth_key_file` to a mode-`0600` file containing 32 raw bytes or 64
  hexadecimal characters when the key must be supplied separately; an
  explicitly supplied path is never generated automatically.
- Notification URLs can be supplied with `notifications.urls`,
  `notifications.urls_file`, or an environment value such as
  `${SHOUTRRR_URL}`.
- Create all monitoring jobs in the web console. The YAML `jobs` section is
  not used for scheduling.

Retention applies to completed scans, events, sent notification deliveries,
terminally failed deliveries, superseded job revisions, and terminal
resumable-cycle metadata that no retained scan still references. Active
baselines, the current revision of every job, pending/retryable deliveries,
active scan cycles, and the security audit log are retained; audit records are
intentionally indefinite.
The daemon logs the row counts removed from each retention class at startup
and during its daily pruning pass.

The web job editor supports individual IP addresses, CIDRs, DNS names, target
expansion limits, independent TCP and UDP scans, ports `1-65535`, TCP SYN or
connect mode, service detection, timing, timeouts, cron schedules, timezones,
pause/resume controls, and a preflight Nmap work estimate. Broad scans are
guarded by the scheduler probe budget; enable the explicit high-cost override
only when the additional load is understood. Active scans expose completed
probe/process counts in the dashboard and can be canceled without changing a
baseline or opening/recovering incidents. Every terminal non-success outcome
(including operator cancellation, scanner errors, and timeouts) is recorded and
sent to configured notification destinations; the message includes the scan
and failure reason.

For broad jobs (more than 4,096 configured ports or 65,536 estimated probes),
EdgeWatch automatically breaks the scan into deterministic Nmap work units.
Each successful unit is checkpointed in SQLite. If the per-attempt timeout is
reached, the current unit is split (addresses first, then ports) and the cycle
is paused for the next scheduled or manual trigger; partial cycles never affect
the baseline. Paused progress is retained for eight days by default. Configure
the per-job `resume_window` between `1h` and `30d`, or use **Discard saved
progress** on the job page to force a fresh full-range cycle. Three consecutive
attempts without any completed work mark a cycle stalled and generate a failure
notification. If the resume window expires, EdgeWatch records one terminal
failure notification before the next trigger starts from a fresh plan. A
completed cycle emits a recovery notification when it follows earlier timeout
pauses.

When creating a job, the editor compares its next scheduled run with active
jobs and offers a non-blocking 30-minute offset when another run is too close.
The suggestion is optional: keep the chosen schedule when concurrent runs are
intentional.

`assume_alive` defaults to `true` and passes `-Pn` to Nmap. Set it to `false`
when host discovery is required. If discovery reports an expected target as
down or omits it, the scan fails safely instead of treating the target as
closed.

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

To supply the key separately, set `notifications.encryption_key_file` to a
`0600` file containing 32 raw bytes or 64 hexadecimal characters and mount it
into the container. An explicitly supplied key path is never generated
automatically. Back up the key with `./data/edgewatch.db`; a missing, invalid,
or unsafe key locks web-managed destinations while scans and deployment-managed
notifications continue.

The TOTP authentication key is independent of the notification key. Back up
`./data/auth.key` together with `./data/edgewatch.db` (or the separately mounted
`web.auth_key_file`); losing it prevents TOTP verification until the key is
restored. Existing plaintext TOTP seeds from older databases are re-encrypted
on the first administrator read when the key is available.

## Operations

Useful commands run inside the container:

```console
docker compose exec edgewatch edgewatch health --config /etc/edgewatch/config.yaml
docker compose exec edgewatch edgewatch status --config /etc/edgewatch/config.yaml
docker compose exec edgewatch edgewatch scan --config /etc/edgewatch/config.yaml --job NAME
docker compose exec edgewatch edgewatch history --config /etc/edgewatch/config.yaml --job NAME --limit 20
docker compose exec edgewatch edgewatch notify test --config /etc/edgewatch/config.yaml
```

Back up `./data` while EdgeWatch is stopped, together with `config.yaml` and
any notification URL or encryption-key files. Keep notification secrets out of
source control.

For an upgrade, stop the current service and make a complete backup before
starting the new image. SQLite uses WAL mode, so copy the database only while
EdgeWatch is stopped (or use SQLite's backup tooling). Keep the backup of
`./data` and any separately mounted encryption-key file together.

The schema migration from the v0.3 database is additive (the current schema is
version 10), but it is
forward-only: an older binary refuses a newer schema. To roll back, stop the
new service, restore the entire pre-upgrade `./data` directory and deployment
configuration, then start the previous image. Do not point an older image at
the upgraded database. The previous named Docker volume, if one exists, is
not read or migrated automatically.

## Development

Go 1.27.1 or newer and Node.js 24.8.0 are required. The repository checks are:

```console
go test -race ./...
go vet ./...
npm ci
npm run lint
npm run build
npm test
npm run test:e2e
docker compose config --quiet
```

The browser acceptance tests use deterministic API fixtures; integration
scans should only target controlled listeners. The production image embeds the
frontend and does not include Node.js.

## License

MIT
