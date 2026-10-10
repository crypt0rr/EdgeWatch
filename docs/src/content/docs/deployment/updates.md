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
   the new release introduces and the oldest schema it upgrades. From v0.36.0,
   that is schema 54, of v0.20.0; an older installation updates through
   v0.35.0 first, see
   [Upgrade from a release before v0.20.0](#upgrade-from-a-release-before-v0200).

Then pull and start the new image:

```console
docker compose pull
docker compose up -d
```

## Verify a release

The [release workflow](https://github.com/crypt0rr/EdgeWatch/blob/main/.github/workflows/release.yml)
builds each release from a commit on `main` whose CI passed. Before it
publishes a release, it scans the image for known vulnerabilities and runs it
on AMD64 and ARM64, including with the bundled `compose.yaml`. It publishes
signed build provenance for the image and for each archive: an attestation
that the file was built by that workflow from the tagged commit. Check it with
the [GitHub CLI](https://cli.github.com/) before you deploy a release, and
note the digest of the image you verified:

```console
gh attestation verify oci://ghcr.io/crypt0rr/edgewatch:0.33.0 \
  --repo crypt0rr/EdgeWatch \
  --signer-workflow crypt0rr/EdgeWatch/.github/workflows/release.yml \
  --source-ref refs/tags/v0.33.0
docker buildx imagetools inspect ghcr.io/crypt0rr/edgewatch:0.33.0 \
  --format '{{.Manifest.Digest}}'
```

Replace `0.33.0` with the version, and `v0.33.0` with its tag. The first
command exits with status 0 only when the image has provenance from the
release workflow for that tag. The provenance names the digest of the image
index, which covers both platforms.

A tag can be moved to another image; a digest cannot. To run exactly the
image you verified, pin its digest in a `compose.override.yaml` next to
`compose.yaml`:

```yaml
services:
  edgewatch:
    image: ghcr.io/crypt0rr/edgewatch:0.33.0@sha256:<digest>
```

Docker pulls the digest and ignores the tag, which keeps the version
readable. Compose reads the override as described under [Rollback](#rollback).
Verify the next release and update the pin when you update.

To verify a release archive, download it with `checksums.txt`, check the
checksum, and verify the archive's provenance:

```console
gh release download v0.33.0 --repo crypt0rr/EdgeWatch \
  --pattern 'EdgeWatch_0.33.0_linux_amd64.tar.gz' --pattern checksums.txt
sha256sum --ignore-missing --check checksums.txt
gh attestation verify EdgeWatch_0.33.0_linux_amd64.tar.gz \
  --repo crypt0rr/EdgeWatch \
  --signer-workflow crypt0rr/EdgeWatch/.github/workflows/release.yml \
  --source-ref refs/tags/v0.33.0
```

Use `EdgeWatch_0.33.0_linux_arm64.tar.gz` for ARM64. The provenance covers
each archive, not `checksums.txt` itself. The release's
`release-manifest.json` records the source commit, the toolchain, and the
Naabu release of the build.

The image also carries an SPDX software bill of materials for each platform:

```console
docker buildx imagetools inspect ghcr.io/crypt0rr/edgewatch:0.33.0 \
  --format '{{json (index .SBOM "linux/amd64").SPDX}}'
```

Tags named `candidate-<run>-<attempt>` are staging images that the release
workflow pushes before it has verified them. Do not deploy them: deploy a
version tag, such as `0.33.0`, or `latest`, which point only to images that
passed every release check.

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

Replace `0.25.23` with the noted version, without the leading `v`, and add
the digest you [verified](#verify-a-release), as in
`ghcr.io/crypt0rr/edgewatch:0.25.23@sha256:<digest>`, to run exactly that
image. Compose
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

## Upgrade from a release before v0.20.0

From v0.36.0, EdgeWatch upgrades a database written by v0.20.0 or a later
release, which has schema 54 or later; see
[Upgrade floor](/reference/database-compatibility/#upgrade-floor). It refuses
an older database before it changes anything, and the service exits with
`database schema version N is older than schema 54, the oldest that this
release upgrades; upgrade through v0.35.0 first`. Update such an installation
in two steps, each with the preparation under
[Before every update](#before-every-update):

1. Pin v0.35.0, which still upgrades every older schema, in a
   `compose.override.yaml` next to `compose.yaml`, as under
   [Rollback](#rollback):

   ```yaml
   services:
     edgewatch:
       image: ghcr.io/crypt0rr/edgewatch:0.35.0
   ```

2. Start it with `docker compose up -d` and wait until
   `docker compose exec edgewatch edgewatch health` reports `ready`. Its
   migration and startup phases have then finished.
3. Take a backup, remove the override, and update to the current release with
   `docker compose pull` and `docker compose up -d`.

A rollback to the release before v0.20.0 means restoring the backup taken
before the first step.

## Runtime privileges

The image uses a read-only root filesystem, drops all capabilities, and adds
`NET_RAW` for the default scanner modes, plus `SETUID`, `SETGID` and `KILL` so
EdgeWatch can run Nmap and Naabu in the
[scanner sandbox](/deployment/container-hardening/#scanner-sandbox), and the
notification process in its
[own sandbox](/deployment/container-hardening/#notification-sandbox). A
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
