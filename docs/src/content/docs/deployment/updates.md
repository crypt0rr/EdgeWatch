---
title: Deploy and update safely
description: Update images, enable SYN discovery, and plan rollback before database upgrades.
---

The supplied `compose.yaml` pulls `ghcr.io/crypt0rr/edgewatch:latest`; it does not
build locally, and EdgeWatch never upgrades itself. Update deliberately, and
prepare the rollback before you pull.

## Before every update

1. Note the version that is running now, which is also shown in the console
   sidebar, next to your account:

   ```console
   docker compose exec edgewatch edgewatch version
   ```

2. Take a backup as described in [Backup and recovery](/operations/backup-recovery/).
   Keep it together with `notification.key`, `auth.key`, and `config.yaml`.
3. Read the release notes, and check
   [Database compatibility](/reference/database-compatibility/) for the schema
   the new release introduces.

Then pull and start the new image:

```console
docker compose pull
docker compose up -d
```

## Rollback

A release that raises the database schema version migrates the database on its
first start, and an older binary refuses a database with a newer schema. Such
an update is forward-only: a rollback means restoring the backup taken before
the update **and** running the version you noted. Because `compose.yaml` follows
`latest`, pin the noted version in a `compose.override.yaml` next to it:

```yaml
services:
  edgewatch:
    image: ghcr.io/crypt0rr/edgewatch:0.25.23
```

Replace `0.25.23` with the noted version, without the leading `v`. Compose
reads `compose.override.yaml` automatically only when you pass no `-f` option;
with the SYN override, add it explicitly:
`docker compose -f compose.yaml -f compose.syn.yaml -f compose.override.yaml up -d`. Stop the
service, restore the backup as described in
[Backup and recovery](/operations/backup-recovery/), and start it again with
`docker compose up -d`. Remove the override to follow `latest` again. A release
that keeps the schema version can be rolled back by pinning the earlier image
alone.

The upgrade from v0.19.0 to v0.20.0 is an example of a forward-only update: it
runs the schema 51 to 54 migrations, which move all existing data into the
default business unit. What a single-unit installation notices afterward is
listed under [Business units](/administration/business-units/).

## Runtime privileges

The image uses a read-only root filesystem, drops all capabilities, and adds
`NET_RAW` for the default scanner modes, plus `SETUID`, `SETGID` and `KILL` so
EdgeWatch can run Nmap and Naabu in the
[scanner sandbox](/deployment/container-hardening/#scanner-sandbox). A
`compose.yaml` from a release before v0.27.0 lacks the last three; add them
when you update, or the scanners keep running as UID 0 and EdgeWatch warns.
Where the kernel provides Landlock, EdgeWatch also restricts the files the
scanners can open; this needs no Compose change. See
[Landlock](/deployment/container-hardening/#landlock). Host networking is intentional, and the administration
listener accepts only loopback addresses. Keep the service on the Docker host
or reach it through an authenticated SSH tunnel.

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
