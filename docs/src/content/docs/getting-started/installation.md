---
title: Install with Docker
description: Deploy EdgeWatch with Docker Compose and create your first administrator account.
---

## Requirements

You need Docker Engine and Docker Compose v2 on a host that supports Docker
host networking and the required scanner capabilities.

## Configure storage

From a checkout of this repository:

```console
cp config.example.yaml config.yaml
```

Choose the data-directory owner for your Docker mode. The container runs as
UID 0 with filesystem capabilities dropped. The data directory must have mode
`0750` and be owned by the host identity mapped to container UID 0.

For standard rootful Docker:

```console
sudo install -d -m 0750 -o 0 -g 0 ./data
```

For rootless Docker:

```console
install -d -m 0750 ./data
```

## Start EdgeWatch

```console
docker compose pull
docker compose up -d
```

The container uses host networking so scanners can reach the same networks as
the Docker host. Runtime state, the SQLite database, and generated encryption
keys are stored in `./data`.

The container runs as UID 0 with filesystem capabilities dropped. The `0750`
data directory must be owned by the host identity mapped to container UID 0:
host root for standard rootful Docker, the invoking host user for rootless
Docker, or the mapped host UID when user-namespace remapping is enabled.

## Permissions and existing installations

For an existing rootful deployment whose data directory was created by another
user, stop EdgeWatch before correcting ownership:

```console
docker compose down
sudo chown -R 0:0 ./data
sudo chmod 0750 ./data
docker compose up -d
```

Notification destinations are added in the web console, so a new deployment
needs no notification URL file. For a rootful installation, create any
separately mounted secret file, such as the key for
`notifications.encryption_key_file` or `web.auth_key_file`, as host root with
mode `0600`. For rootless Docker, create it as the invoking user instead.

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
  -c 'cat /run/secrets/edgewatch-notification-key >/dev/null'
```

If you are upgrading from a deployment that used the old named
`edgewatch-data` volume, the bind mount starts with fresh state. That volume is
left untouched and is not read or migrated automatically; restore or copy its
data only through a deliberate, stopped-database recovery procedure.

## Create the first administrator

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

A platform administrator, who manages business units, is created the same
way once the first administrator exists; see
[Business units](/administration/business-units/).

## Next steps

- [Create your first monitoring job](/getting-started/first-scan/).
- [Configure HTTPS access](/deployment/reverse-proxies/).
- [Review container privileges](/deployment/container-hardening/).
