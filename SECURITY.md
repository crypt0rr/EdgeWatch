# Security policy

Please report security vulnerabilities privately through GitHub's security advisory feature for this repository. Do not open a public issue containing exploit details, credentials, notification URLs, or target information.

EdgeWatch executes Nmap with validated argument arrays and does not expose arbitrary Nmap flags. Treat its configuration, SQLite volume, notification URL file, and notification encryption key as sensitive. Only configure targets you own or are explicitly authorized to scan.

TCP jobs may use the optional Naabu discovery-to-Nmap pipeline. Both scanners
are fixed, image-bundled executables (`/usr/local/bin/naabu` and
`/usr/bin/nmap`); administrators can edit only validated argument arrays and
approved placeholders. EdgeWatch invokes them directly without a shell, so
shell syntax, alternate binaries, arbitrary output paths, and unapproved NSE
scripts are rejected. Naabu discovery is JSONL and Nmap confirmation remains
authoritative for baselines and incidents. EdgeWatch parses Naabu output as a
stream, rejects records for addresses outside the invocation, keeps each
distinct result once, and stops the child on an oversized line or an
implausible number of repeated records. Connect discovery is the least
privileged default; SYN discovery additionally requires the explicitly opted-in
`NET_ADMIN` and `NET_RAW` container capabilities.

The final image intentionally retains UID 0 because the supported Docker
capability model does not reliably expose raw packet privileges to an
unprivileged process. Nmap UDP/SYN and Naabu SYN fail closed without those
privileges. The compatibility matrix, bind-mount ownership guidance, and
reconsideration criteria are maintained in
[`docs/container-hardening.md`](docs/container-hardening.md).

The administration console is bound to a loopback address by default and uses
server-side sessions, CSRF protection, and Argon2id password storage. Keep the
Docker host and any SSH tunnel access restricted to trusted administrators.
When an untrusted tunnel or reverse proxy makes every remote client appear as
the same loopback peer, all login attempts are throttled after five failed
password or TOTP attempts in five minutes with a short two-second retry delay.
The shared response avoids both a long lockout and revealing account existence,
but cannot provide per-client attribution. For per-client rate limits and audit
identities, configure only the actual proxy addresses in `web.trusted_proxies`
and the sanitized `web.forwarded_header`.
EdgeWatch logs a startup warning when proxy hostnames are approved without
trusted client-IP forwarding. Failed login and TOTP attempts, along with
rate-limit events, are written to the security audit log; they do not currently
send notification-channel alerts.

Setting up or replacing an authenticator requires the account password, plus
the current authenticator or a recovery code when TOTP is already enabled. The
new secret then stays pending for ten minutes and accepts at most five incorrect
verification codes. A mistyped code can be retried against the same secret;
after the fifth incorrect code, or once the ten minutes pass, the pending secret
is discarded and setup must start again.

## Live-update streams and session revocation

The authenticated live-update stream (`/api/v1/stream`) is authorized to the
specific browser session that opened it. Two browser sessions for the same
account are independent: revoking one session does not grant, revoke, or close
the other. Disabling an account, changing its role, changing its password
(including by redeeming an administrator-issued password-reset link), or
changing its TOTP settings revokes the affected sessions, and a stream stops
delivering once its next authorization check observes that revocation.

The stream rechecks its session before the initial response, before delivering
events, and on its 25-second heartbeat. To avoid a database lookup for every
event, successful checks are cached for at most two seconds. Consequently, a
quiet stream can remain connected until its next heartbeat, while activity
causes a revoked stream to close within the two-second authorization-cache
bound. Stream connections, reconnects, heartbeats, and subscriber-limit
responses use read-only authentication and do not extend the session's idle
timeout. Security mutations handled by the running web process cancel matching
streams immediately and invalidate their cached authorization; a TOTP change
that deliberately preserves the current browser session leaves only that
session's stream connected. Revocations performed by another process (such as
host recovery tooling) use the bounded revalidation fallback. Server shutdown
closes all live streams. These bounds are a security property, not a
replacement for revoking a compromised account or session.

Other authenticated API reads, including the status and page-polling requests,
also validate sessions without refreshing their idle timestamp. Actual browser
pointer, keyboard, click, or scroll input and authorized state-changing
requests refresh the idle timestamp through a CSRF-protected activity path.
Refreshes are coalesced to at most one database write per session every five
minutes. The activity write has a short timeout so SQLite writer contention
cannot delay normal read-only requests. A session with no real activity expires
after 24 hours; polling in an unattended tab does not keep it alive. The
absolute session lifetime remains 30 days.

Web-managed Shoutrrr destinations are write-only through the API. Their URLs
are encrypted at rest with AES-256-GCM; the key is stored in
`./data/notification.key` unless `notifications.encryption_key_file` is
configured. Protect that key as a credential, keep it mode `0600`, and include
it in backups of the corresponding SQLite database. An explicitly configured
key is checked at startup and must be present, valid, and owner-readable.
Deployment URL files are likewise checked at startup, must be regular files
with mode `0400` or `0600`, and are capped at 1 MiB. Do not report
notification URLs or key material in issues, logs, screenshots, or audit
records.

Notification delivery health is exposed only as named-destination counts and
timestamps. Terminal drops store a stable destination/error fingerprint and a
bounded error code; raw provider responses, URLs, and credentials are not
included in API responses, logs, or system events.

Optional TOTP seeds are encrypted independently with AES-256-GCM. The default
authentication key is `./data/auth.key`; set `web.auth_key_file` for a separate
mode-`0600` mount. Back up that key with the database. If it is unavailable,
TOTP verification fails closed while password reset or the host recovery
command can still disable TOTP and invalidate sessions.

If the key is lost or replaced, web-managed destinations become unavailable;
they cannot be recovered from the database alone. Restore the original key and
database together, or delete and recreate the affected destinations after
confirming that the old credentials are revoked. A database upgraded to schema
48 must not be opened by an older EdgeWatch binary; downgrade by restoring the
complete pre-upgrade `./data` backup before starting the old version. The
daemon and the host commands that write to the database, including `backup`,
refuse a schema newer than the binary supports before they write anything.

Recovery codes are stored in the salted `v2` representation. Schema 38 removes
legacy unsalted SHA-256 recovery-code digests and records only their count in
the security audit; generate new recovery codes from the Security page after
an upgrade. The old plaintext cannot be recovered or safely re-hashed.

Single-file restores create a new notification epoch. Pending deliveries are
quarantined by default so alerts from the backup cannot be replayed; operators
may explicitly choose `--pending-deliveries discard` or
`--pending-deliveries preserve` when running the host restore command. The
choice and a bounded count are recorded in a redacted audit event. Quarantined
payloads remain in the restored database but are never claimed by the delivery
worker.

Host CLI commands that change state (`scan`, `baseline approve` and `reset`,
`notify test`, `backup`, `restore`, and administrator recovery) record a
security audit entry with the actor `host-cli`. The details are bounded to job
IDs, file base names, and outcomes; they never include scan targets,
notification URLs, or full paths. A CLI scan uses the same
`scan.run_requested` action as a run started from the console. Read-only
commands, including `restore --dry-run`, write no audit entries.

By default, EdgeWatch checks the latest stable release on GitHub at startup and
every three hours. This outbound request reveals the Docker host's public IP
and the EdgeWatch user agent to GitHub; set `updates.enabled: false` for
isolated or privacy-sensitive deployments.

Retention pruning deliberately keeps the security audit log indefinitely.
Only completed scans, historical events, sent or terminally failed outbox
deliveries, and superseded job revisions are eligible for automatic removal;
active baselines, current revisions, and pending deliveries are protected.
