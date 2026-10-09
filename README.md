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

## Quick start

Requirements: Docker Engine 25 or later and Docker Compose v2 on a host
supporting host networking and scanner capabilities. From a checkout of this repository:

```sh
cp config.example.yaml config.yaml
```

Create the data directory for your Docker mode. For standard rootful Docker:

```sh
sudo install -d -m 0750 -o 0 -g 0 ./data
```

For rootless Docker:

```sh
install -d -m 0750 ./data
```

With user-namespace remapping, use the host UID mapped to container UID 0. The
container runs as UID 0 with filesystem capabilities dropped; keep data owned
by that mapped identity and do not use world-writable permissions. For an
existing deployment, read the installation and backup guides before changing
ownership, mounts, or images.

```sh
docker compose pull
docker compose up -d
docker compose logs edgewatch | grep setup_token
```

Open **http://127.0.0.1:8080** and create the first administrator with the
one-time setup token, which expires after 15 minutes. The listener is
loopback-only. For a remote host, tunnel from your workstation:

```sh
ssh -L 8080:127.0.0.1:8080 user@docker-host
```

Then open **Jobs → New job** and follow the guided monitor setup to choose authorized targets, scan
coverage, a schedule, and alerts. You can also add and test a notification
destination during setup; operators can select existing destinations, and
choosing no alerts is supported. Review the scan estimate and budget before
creating the monitor. Runtime state and generated encryption keys live in
`./data`; back them up together. See the [first-scan guide](https://edgewatch.offsec.nl/getting-started/first-scan/)
for the initial scan and baseline workflow.

## Documentation

The full user, operator, and maintainer documentation is available at
[edgewatch.offsec.nl](https://edgewatch.offsec.nl). The website source lives in
[`docs/`](docs/README.md).

- [Installation](https://edgewatch.offsec.nl/getting-started/installation/) and [first scan](https://edgewatch.offsec.nl/getting-started/first-scan/)
- [Updates](https://edgewatch.offsec.nl/deployment/updates/), [reverse proxies](https://edgewatch.offsec.nl/deployment/reverse-proxies/), and [container hardening](https://edgewatch.offsec.nl/deployment/container-hardening/)
- [Jobs and incidents](https://edgewatch.offsec.nl/user-guide/jobs-baselines-incidents/), [scanning](https://edgewatch.offsec.nl/user-guide/scanning/), and [notifications](https://edgewatch.offsec.nl/user-guide/notifications/)
- [Accounts and public status](https://edgewatch.offsec.nl/administration/accounts-public-status/) and [business units](https://edgewatch.offsec.nl/administration/business-units/)
- [Configuration](https://edgewatch.offsec.nl/reference/configuration/), [CLI](https://edgewatch.offsec.nl/reference/cli/), [database compatibility](https://edgewatch.offsec.nl/reference/database-compatibility/), and [API compatibility](https://edgewatch.offsec.nl/reference/api-compatibility/)
- [Backup and recovery](https://edgewatch.offsec.nl/operations/backup-recovery/) and [local development](https://edgewatch.offsec.nl/maintainers/development/)

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

Copyright (c) 2026 Bart. Released under [AGPL-3.0-only](LICENSE); bundled
components retain their separate licenses in [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
Releases before v0.25.0 retain their published MIT terms. See the
[license and source-code guide](https://edgewatch.offsec.nl/reference/license/)
for the source link requirements when deploying a modified build.
