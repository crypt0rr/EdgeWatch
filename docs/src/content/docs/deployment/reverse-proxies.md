---
title: Tailscale Serve and reverse proxies
description: Configure HTTPS access, host validation, and trusted proxy headers.
---

Keep EdgeWatch bound to loopback when exposing it through Tailscale Serve or a
reverse proxy. Serve the public hostname over HTTPS and add the hostname that
users open to `web.allowed_hosts`:

```yaml
web:
  listen: 127.0.0.1:8080
  allowed_hosts:
    - edgewatch.example.ts.net
  forwarded_header: x-forwarded-for
  trusted_proxies:
    - 127.0.0.1/32
    - ::1/128
```

Replace `edgewatch.example.ts.net` with your tailnet or proxy hostname. Use the
bare hostname only; do not include `https://`, a path, or a port. EdgeWatch
checks the forwarded `Host` value before authentication, so an unlisted proxy
hostname is rejected with `421 Misdirected Request` even when the loopback
listener is healthy. Approved non-loopback hostnames receive Secure session
cookies; direct loopback HTTP remains available for local administration and
SSH tunnels. The example trusts a local proxy and its sanitized
`X-Forwarded-For` client address; replace these networks with the addresses that
actually connect to EdgeWatch when the proxy runs elsewhere. If a
TLS-terminating proxy rewrites the upstream `Host` to a loopback address, list
the proxy address or network in `web.trusted_proxies` so EdgeWatch can trust its
`X-Forwarded-Proto: https` (or RFC 7239 `Forwarded: ...;proto=https`) signal
and keep the session cookie Secure. Trust only proxies you control, and configure them to sanitize forwarding
headers.

After changing the bind-mounted configuration, recreate the container:

```console
docker compose up -d --force-recreate edgewatch
```

You can verify both paths from the Docker host (replace the example hostname
with the one configured above):

```console
curl -i http://127.0.0.1:8080/api/v1/setup/status
curl -i -H 'Host: edgewatch.example.ts.net:8443' \
  http://127.0.0.1:8080/api/v1/setup/status
```

Both requests should return a successful response. If the direct request works
but the request with the proxy `Host` returns `421`, correct
`web.allowed_hosts`. The listener remains loopback-only; this setting approves
the public name, not a new network bind address.

## Live updates

The console receives live updates over one long-lived Server-Sent Events
response from `/api/v1/stream`. EdgeWatch writes a heartbeat comment every 25
seconds and sends `X-Accel-Buffering: no`, which nginx honors by default. Make
sure the proxy:

- passes each event through as it is written instead of buffering the
  response;
- keeps an idle upstream read open for longer than the 25-second heartbeat;
- does not compress or cache `text/event-stream` responses.

A minimal nginx location:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_buffering off;
    proxy_read_timeout 120s;
}
```

Overwriting `X-Forwarded-For` with `$remote_addr` keeps a client-supplied header
from reaching EdgeWatch. Tailscale Serve and Caddy stream responses without
extra settings. When a proxy buffers the stream anyway, the console shows
**Reconnecting…** or updates only after a reload, while ordinary pages keep
working.
