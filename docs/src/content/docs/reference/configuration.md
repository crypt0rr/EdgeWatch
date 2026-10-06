---
title: Deployment configuration
description: Understand deployment settings, defaults, rate limits, and legacy configuration.
---

config.yaml contains deployment settings. Create monitoring jobs and manage
users, destinations, scanner profiles, baselines, and public status in the web
console. See [config.example.yaml](https://github.com/crypt0rr/EdgeWatch/blob/docs/website-preview/config.example.yaml) for the complete
validated schema.

| Configuration | Managed in | Purpose |
| --- | --- | --- |
| database, retention | YAML | SQLite location and history retention. |
| timezone | YAML | Optional IANA timezone for log, CLI, notification, and console times, and the default for new jobs. |
| web.listen, web.allowed_hosts, web.trusted_proxies, web.forwarded_header | YAML | Loopback listener, approved proxy host names, trusted proxy networks, and the single forwarding header used for client IPs. |
| scheduler.* | YAML | Concurrent scans and probe budgets. |
| scanner.target_exclusions | YAML | Addresses that may never be scanned. |
| enrichment.rdap.enabled | YAML | Enable or disable on-demand public network-registration lookups. |
| updates.enabled | YAML | Enable or disable the three-hour stable-release check. |
| notifications.encryption_key_file | YAML/secrets | Optional separate key for the encrypted notification destinations. |
| notifications.urls, urls_file | YAML/secrets | Deprecated. Imported once as web-managed destinations; see [Notifications](/user-guide/notifications/). |
| Jobs, users, profiles, notification destinations | Web console | Runtime administration stored in SQLite. |

The YAML jobs section from older deployments is not imported into the scheduler.
Such jobs remain inactive and EdgeWatch shows a startup warning so they can be
recreated and reviewed explicitly in the console.

## Important defaults

- `timezone` is omitted by default: the daemon and CLI keep the process
  timezone (UTC in the container image), and each signed-in console shows its
  browser's timezone. Set it to an IANA name such as `Europe/Amsterdam` to use
  one timezone everywhere. The public status page keeps the visitor's browser
  timezone and never receives the configured value. Invalid names stop
  startup; host recovery commands ignore them.
- The web listener defaults to 127.0.0.1:8080; non-loopback listeners are
  rejected.
- Requests using a proxy or tunnel host must match `web.allowed_hosts`; foreign
  Host headers are rejected before authentication. Keep this list limited to
  names you control.
- Forwarding headers are ignored unless the connecting proxy addresses are
  explicitly listed in web.trusted_proxies. By default, EdgeWatch reads only
  web.forwarded_header: x-forwarded-for; set it to forwarded only when your
  trusted proxy controls that header, or none to ignore forwarded client IPs.
  EdgeWatch never combines the two conventions, so configure the header that
  your proxy sanitizes or constructs for the trusted proxy chain.
- Session cookies use the same trusted-proxy boundary for forwarded HTTPS
  protocol headers. A trusted TLS-terminating proxy must send
  X-Forwarded-Proto: https or Forwarded: ...;proto=https when it forwards a
  loopback Host; otherwise EdgeWatch keeps the direct-loopback HTTP behavior.
- If a tunnel or reverse proxy is not listed in web.trusted_proxies, every
  client may appear as the same loopback peer. After five failed login or TOTP
  attempts within five minutes, all logins through that shared peer receive a
  short two-second cooldown instead of a five-minute lockout. A successful
  sign-in through the peer, with any account, does not reset the count; each
  failure expires five minutes after it happened. Applying the same
  cooldown to known and unknown usernames avoids revealing account existence.
  The first-run setup, the platform setup, and account activation through that
  peer get the same cooldown after five wrong tokens, so wrong tokens cannot
  block them for five minutes. Password and TOTP confirmations through that
  peer are limited per account: an account that fails five confirmations
  within five minutes is refused for five minutes, and other accounts, in any
  unit or on the platform, are not affected. Configure the proxy network and
  forwarding header when you need per-client rate limits and audit
  identities. EdgeWatch logs a startup warning when approved proxy hosts lack
  trusted client-IP forwarding.
- A client identified by its own address may fail five sign-ins within five
  minutes. Every failed sign-in counts the same: an unknown username, a
  disabled account, an account whose unit is not active, and a wrong
  password, one-time code, or recovery code. After that, every sign-in from
  that client, with any username, receives the same 429 rate_limited answer
  for five minutes, so neither the answer nor the number of attempts left
  reveals which accounts exist. A successful sign-in does not reset the
  count; each failure expires five minutes after it happened. Clients that
  share one address, such as the clients of an untrusted proxy on another
  host, share this budget, and a hundred wrong setup or activation tokens from
  that address block setup and activation for all of them for five minutes.
  When requests come through a proxy that EdgeWatch does not trust, EdgeWatch
  logs a warning at most once an hour and shows the proxy's address on the
  dashboard of a single unit's administrators and on the platform status
  page. Such a proxy is a peer that is not listed in web.trusted_proxies and
  sends X-Forwarded-For or Forwarded, such as an unlisted proxy on the host,
  or, behind the listed proxies, the first unlisted address in the forwarding
  chain when the chain names another client before it, such as an unlisted
  proxy on another host in front of the proxy on the host. A client can send
  these headers itself and have its own address shown, so add the address to
  web.trusted_proxies only when it is a proxy that you run.
- Sessions end after 24 hours without activity and 30 days after sign-in; the
  daemon removes ended sessions at startup and once a day. An account keeps
  at most 20 sessions: a new sign-in beyond that ends the account's least
  recently used session. A TOTP code or recovery code counts as used only
  when its sign-in creates a session.
- By default, scanner.target_exclusions covers the loopback and link-local
  ranges 127.0.0.0/8, ::1/128, 169.254.0.0/16, and fe80::/10. The IPv4
  link-local range includes the 169.254.169.254 cloud metadata endpoint. Other
  metadata endpoints are not excluded by default; add the ones your provider
  uses, such as fd00:ec2::254/128 on AWS with the IPv6 instance metadata
  endpoint enabled or 100.100.100.200/32 on Alibaba Cloud. An explicit list
  replaces the defaults, so keep the default ranges when you add entries.
  Change scanner.target_exclusions only when you understand the host-network
  exposure.
- RDAP is enabled by default and is requested only when an authenticated user
  opens a public host. Private and special-use addresses are never queried.
  Set enrichment.rdap.enabled: false for isolated or privacy-sensitive
  deployments.
- Update checks are enabled by default, run at startup and every three hours,
  and consider stable GitHub releases only. Set updates.enabled: false for
  offline deployments. Checks reveal the host's public IP and EdgeWatch user
  agent to GitHub; EdgeWatch reports updates but never upgrades itself.

## Validate changes

```sh
docker compose exec edgewatch edgewatch config validate \
  --config /etc/edgewatch/config.yaml
```

After editing the bind-mounted configuration, recreate the container:

```sh
docker compose up -d --force-recreate edgewatch
```
