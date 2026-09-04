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

## Configuration

`config.yaml` contains deployment settings only. See
[`config.example.yaml`](config.example.yaml) for the complete schema.

- `database`, `retention`, and `scheduler.max_concurrent_scans` control local
  storage and scan capacity.
- `web.listen` must be a loopback address; the default is
  `127.0.0.1:8080`.
- Notification URLs can be supplied with `notifications.urls`,
  `notifications.urls_file`, or an environment value such as
  `${SHOUTRRR_URL}`.
- Create all monitoring jobs in the web console. The YAML `jobs` section is
  not used for scheduling.

The web job editor supports individual IP addresses, CIDRs, DNS names, target
expansion limits, independent TCP and UDP scans, ports `1-65535`, TCP SYN or
connect mode, service detection, timing, timeouts, cron schedules, timezones,
and pause/resume controls.

`assume_alive` defaults to `true` and passes `-Pn` to Nmap. Set it to `false`
when host discovery is required. If discovery reports an expected target as
down or omits it, the scan fails safely instead of treating the target as
closed.

## Baselines and incidents

Set the number of baseline samples and change confirmations per job. Only
successful scans can advance a baseline; failed, timed-out, partial, or
malformed scans never change comparison state. Confirmed port, service, or DNS
changes appear as incidents and can trigger notifications.

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

The schema migration from the v0.3 database is additive, but it is
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

## Releases

Pull requests and pushes to `main` run the Go, frontend, browser, Compose, and
multi-architecture container checks. Releases are tag-driven. After the
validated commit is merged to `main`, create and push a semantic-version tag:

```console
git tag -a vX.Y.Z -m "EdgeWatch vX.Y.Z"
git push origin vX.Y.Z
```

The release workflow publishes Linux AMD64/ARM64 archives and checksums plus
the corresponding GHCR image with SBOM and provenance attestations. It also
updates `latest` for stable (non-prerelease) tags. For reproducible deployments,
pin Compose to the immutable release tag and digest after verifying the
published artifacts.

## License

MIT
