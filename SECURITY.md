# Security policy

Please report security vulnerabilities privately through GitHub's security advisory feature for this repository. Do not open a public issue containing exploit details, credentials, notification URLs, or target information.

EdgeWatch executes Nmap with validated argument arrays and does not expose arbitrary Nmap flags. Treat its configuration, SQLite volume, notification URL file, and notification encryption key as sensitive. Only configure targets you own or are explicitly authorized to scan.

TCP jobs may use the optional Naabu discovery-to-Nmap pipeline. Both scanners
are fixed, image-bundled executables (`/usr/local/bin/naabu` and
`/usr/bin/nmap`); administrators can edit only validated argument arrays and
approved placeholders. EdgeWatch invokes them directly without a shell, so
shell syntax, alternate binaries, arbitrary output paths, and unapproved NSE
scripts are rejected. Naabu discovery is JSONL and Nmap confirmation remains
authoritative for baselines and incidents. Connect discovery is the least
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
34 must not be opened by an older EdgeWatch binary; downgrade by restoring the
complete pre-upgrade `./data` backup before starting the old version.

By default, EdgeWatch checks the latest stable release on GitHub at startup and
every three hours. This outbound request reveals the Docker host's public IP
and the EdgeWatch user agent to GitHub; set `updates.enabled: false` for
isolated or privacy-sensitive deployments.

Retention pruning deliberately keeps the security audit log indefinitely.
Only completed scans, historical events, sent or terminally failed outbox
deliveries, and superseded job revisions are eligible for automatic removal;
active baselines, current revisions, and pending deliveries are protected.
