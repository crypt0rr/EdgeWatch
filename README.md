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

Requirements: Docker Engine and Docker Compose v2 on a host supporting host
networking and scanner capabilities. From a checkout of this repository:

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

Then add notification destinations and create your first monitoring job in the
console. Runtime state and generated encryption keys live in `./data`; back
them up together.

## Documentation

The full documentation lives in [`docs/`](docs/README.md) and is being prepared
for [edgewatch.offsec.nl](https://edgewatch.offsec.nl). Until the website is
published, the source guides below are available in this branch.

- [Installation](docs/src/content/docs/getting-started/installation.md) and [first scan](docs/src/content/docs/getting-started/first-scan.md)
- [Updates](docs/src/content/docs/deployment/updates.md), [reverse proxies](docs/src/content/docs/deployment/reverse-proxies.md), and [container hardening](docs/src/content/docs/deployment/container-hardening.md)
- [Jobs and incidents](docs/src/content/docs/user-guide/jobs-baselines-incidents.md), [scanning](docs/src/content/docs/user-guide/scanning.md), and [notifications](docs/src/content/docs/user-guide/notifications.md)
- [Accounts and public status](docs/src/content/docs/administration/accounts-public-status.md) and [business units](docs/src/content/docs/administration/business-units.md)
- [Configuration](docs/src/content/docs/reference/configuration.md), [CLI](docs/src/content/docs/reference/cli.md), [database compatibility](docs/src/content/docs/reference/database-compatibility.md), and [API compatibility](docs/src/content/docs/reference/api-compatibility.md)
- [Backup and recovery](docs/src/content/docs/operations/backup-recovery.md) and [local development](docs/src/content/docs/maintainers/development.md)

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

Copyright (c) 2026 Bart. Released under [AGPL-3.0-only](LICENSE); bundled
components retain their separate licenses in [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
Releases before v0.25.0 retain their published MIT terms. See the
[license and source-code guide](docs/src/content/docs/reference/license.md)
for the source link requirements when deploying a modified build.
