---
title: Deploy and update safely
description: Update images, enable SYN discovery, and plan rollback before database upgrades.
---

The supplied `compose.yaml` pulls `ghcr.io/crypt0rr/edgewatch:latest`; it does not
build locally. Pull explicitly whenever you choose to update:

```console
docker compose pull
docker compose up -d
```

Before upgrading from v0.19.0 to v0.20.0, back up `./data` as described in
[Data, backup, and recovery](/operations/backup-recovery/). The first start of
v0.20.0 runs the schema 51 to 54 migrations, which move all existing data
into the default business unit. A v0.19.0 binary cannot open the upgraded
database, so a rollback means restoring that backup. What a single-unit
installation notices afterward is listed under
[Business units](/administration/business-units/).

The image uses a read-only root filesystem, drops all capabilities, and adds
`NET_RAW` for the default scanner modes. Host networking is intentional, and the
administration listener accepts only loopback addresses. Keep the service on
the Docker host or reach it through an authenticated SSH tunnel.

Naabu SYN discovery additionally needs `NET_ADMIN`. The normal Compose setup uses
connect discovery and does not grant that capability. If you have reviewed the
extra privilege and need SYN discovery, use the explicit override:

```console
docker compose -f compose.yaml -f compose.syn.yaml pull
docker compose -f compose.yaml -f compose.syn.yaml up -d
```

Adding the override does not change existing jobs or profiles to SYN. See
[Container runtime hardening](/deployment/container-hardening/) for the capability
matrix and hardening rationale.
