# EdgeWatch

EdgeWatch continuously scans infrastructure you are authorized to test, establishes an approved view of exposed ports, and notifies you when that view changes.

It is a small Go daemon around [Nmap](https://nmap.org/) with durable SQLite state and [Shoutrrr](https://containrrr.dev/shoutrrr/) notifications. TCP and UDP jobs can use any port or range from `1` through `65535`. IPv4, IPv6, hostnames, and bounded CIDRs are supported.

> [!WARNING]
> Only scan systems you own or have explicit permission to assess. Full-range UDP scans can take many hours and generate significant traffic. Start with common UDP ports and schedule deep UDP scans separately from TCP.

## Quick start

1. Copy the example and edit its targets:

   ```console
   cp config.example.yaml config.yaml
   ```

2. To enable notifications, create the notification file, add one Shoutrrr URL per line, and uncomment the marked `urls_file` and Compose volume lines. Keep this file out of source control:

   ```console
   cp notification-urls.example.txt notification-urls.txt
   ```

3. Start EdgeWatch:

   ```console
   docker compose pull
   docker compose up -d
   docker compose logs -f edgewatch
   ```

4. Open the local console at [http://127.0.0.1:8080](http://127.0.0.1:8080). The first-run setup token is printed once in the container logs:

   ```console
   docker compose logs edgewatch | grep setup_token
   ```

   Create the administrator, then create jobs from the Jobs screen. The setup
   token expires after 15 minutes. Use an SSH tunnel when the Docker host is
   remote, for example `ssh -L 8080:127.0.0.1:8080 host`.

The Compose service pulls the published GHCR image and uses host networking so IPv4 and IPv6 scans follow the host's routes. It exposes no listening port, drops all Linux capabilities except `NET_RAW`, uses a read-only root filesystem, and stores state in the local `./data` directory. It does **not** use privileged mode. Run `docker compose pull` explicitly when you want to update the `latest` image.

Leave `./data` absent on the first start so Docker creates it with the
container's writable ownership. If the directory already exists, make sure it
is writable by the container's root account (for example, `sudo chown root:root ./data`);
do not make it world writable. The container stays root only so Nmap can
perform SYN scans while all capabilities except `NET_RAW` remain dropped.

For reproducible production deployments, replace `latest` in `compose.yaml` with an immutable release tag and digest after reviewing the published image. Keep `latest` for installations that intentionally follow stable releases.

This deployment intentionally starts with fresh state in `./data`; it does not automatically migrate or read the previous Docker-managed `edgewatch-data` volume. Keep that old volume until you have confirmed the new deployment is working, then remove it separately if it is no longer needed. YAML jobs from pre-web releases are left inactive and are not imported; recreate them in the console after reviewing their scope.

Check status or run a scan manually:

```console
docker compose exec edgewatch edgewatch status --config /etc/edgewatch/config.yaml
docker compose exec edgewatch edgewatch scan --config /etc/edgewatch/config.yaml --job NAME
```

Replace `NAME` with a job created in the web console. The CLI can run and
inspect managed jobs, but it does not import or execute the legacy YAML job
definitions.

## Baseline and alert behavior

`baseline.samples` is the number of consecutive identical relevant scan results required before a baseline is accepted. A value of `1` accepts the first successful scan. Failed, timed-out, partial, or malformed scans never advance a baseline and are never interpreted as closed ports.

Once a baseline exists, `change.confirmations` controls how many consecutive observations are required to open or recover an incident. EdgeWatch sends one notification when the incident opens and one when it returns to baseline; unchanged scans remain quiet.

- TCP/UDP `open` is a confirmed exposure.
- UDP `open|filtered` is tracked separately as uncertain and reported at warning severity.
- Service fingerprints are compared only when `service_detection` is enabled.
- Hostnames are resolved on every scan. All A/AAAA addresses are scanned, ports are aggregated under the hostname, and DNS membership changes are tracked separately.
- In the web console, a security-relevant configuration change requires confirmation and starts a fresh candidate baseline; historical scans and audit records remain available.

Legitimate changes are never silently approved. Review a successful scan ID, then explicitly approve it:

```console
docker compose exec edgewatch edgewatch history --config /etc/edgewatch/config.yaml --job NAME --limit 5
docker compose exec edgewatch edgewatch baseline approve --config /etc/edgewatch/config.yaml --job NAME --scan-id SCAN_ID
```

Use `baseline reset` to discard a candidate and relearn it. Approval and reset operations are audited in SQLite.

## Configuration

Deployment configuration is strict and versioned. Unknown keys and unsafe values fail startup. Validate without scanning:

```console
edgewatch config validate --config config.yaml
```

Jobs are created in the web console. Each job has its own schedule, target set, protocols, ports, timeout, baseline policy, and host-discovery policy. Standard five-field cron expressions and IANA timezone names are used. Missed schedules are not backfilled and a job never overlaps itself. The YAML `jobs` key is retained only so older files can be recognized and warned about; it is not imported or scheduled in web-managed mode.

`assume_alive` defaults to `true`, which passes `-Pn` to Nmap and avoids relying on ICMP or other host-discovery probes. Set it to `false` for a job when Nmap host discovery is preferred. If discovery reports an expected target as down or omits it, the scan fails safely instead of treating the target as having no open ports.

Notification URLs can be listed directly, referenced as an entire environment value such as `${SHOUTRRR_URL}`, or read from `notifications.urls_file`. A secrets file is recommended because many Shoutrrr URLs contain credentials. URLs are redacted from logs and command output.

See [`config.example.yaml`](config.example.yaml) for all supported fields.

## CLI

```text
edgewatch daemon
edgewatch config validate
edgewatch scan --job NAME
edgewatch status [--job NAME]
edgewatch history [--job NAME] [--limit 50]
edgewatch baseline approve --job NAME --scan-id ID
edgewatch baseline reset --job NAME
edgewatch notify test
edgewatch admin reset-password --password-file PATH
edgewatch admin disable-totp
edgewatch health
edgewatch version
```

Commands accept `--config PATH`; data-producing commands accept `--output json`.

## Operations

- Back up `./data` (including the SQLite database, authentication state, job definitions, and audit history) while EdgeWatch is stopped. If online backup is required, use SQLite's backup tooling rather than copying only the main database file while WAL mode is active. Keep the deployment `config.yaml` and notification secret file in the same protected backup set.
- Normalized scan history is retained for 90 days by default. Baselines, active incidents, and audit events remain.
- Notification deliveries are persisted and retried three times. A failing destination does not block other destinations.
- `edgewatch health` verifies the daemon heartbeat used by the container healthcheck.
- Container images are intended for `linux/amd64` and `linux/arm64`.

## Development

Go 1.27.1 or newer is required.

```console
go test -race ./...
go vet ./...
npm ci
npm run build
npm run test:e2e
go build ./cmd/edgewatch
```

`npm run test:e2e` starts a local Vite preview and exercises setup, login, and
the TCP/UDP job builder in Chromium with deterministic API fixtures. For local
integration scans, install Nmap and run only against controlled test listeners.

## Releases

GitHub Actions verifies every pull request and push to `main`, including race-enabled Go tests, browser acceptance tests, and AMD64/ARM64 container builds. Releases are intentionally tag-driven; no additional registry credentials are required because the workflow uses the repository-scoped `GITHUB_TOKEN`.

Create and push a semantic-version tag when the commit on `main` is ready:

```console
git tag -a v0.3.0 -m "EdgeWatch v0.3.0"
git push origin v0.3.0
```

The tag publishes:

- a GitHub Release with Linux AMD64 and ARM64 archives plus `checksums.txt`;
- `ghcr.io/crypt0rr/edgewatch:0.3.0` and `:0.3`;
- `ghcr.io/crypt0rr/edgewatch:latest` for stable releases;
- a provenance-attested multi-architecture image for `linux/amd64` and `linux/arm64`.

Stable releases at version 1.0.0 or newer also receive a major tag such as `:1`. Prerelease tags such as `v0.3.0-rc.1` never update `latest`.

The workflow links the package to this repository so its access permissions can be inherited. Package visibility is controlled by GHCR package settings; verify it after the first release and set it to public if anonymous pulls are required. Earlier EdgeWatch packages are currently public.

## License

MIT
