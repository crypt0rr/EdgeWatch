# Security policy

Please report security vulnerabilities privately through GitHub's security advisory feature for this repository. Do not open a public issue containing exploit details, credentials, notification URLs, or target information.

EdgeWatch executes Nmap with validated argument arrays and does not expose arbitrary Nmap flags. Treat its configuration, SQLite volume, notification encryption key, and any remaining notification URL file as sensitive. Only configure targets you own or are explicitly authorized to scan.

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

## Business units and the platform administrator (experimental)

Business units are under development and stay off unless
`experimental.business_units` is `true`. While the flag is off, EdgeWatch
refuses to issue a platform setup token or to create a platform
administrator, and a single unit behaves as before.

### Trust boundary

Business units separate teams that trust the deployment's operators. The
application enforces the separation in the console, the API, the live-update
stream, and the public pages. Units share one process, one SQLite database,
and the notification and authentication keys (`notification.key` and
`auth.key`, or the configured key files). Anyone with access to the Docker
host, the container, the host commands, the database file, or a backup can
read and change every unit's data: host commands reach any unit with
`--tenant`, and a backup or restore covers every unit together. Run separate
deployments for parties that must not trust each other or the operators.

Every API request passes its route's permission check before the handler
runs, and the handler reads and writes through a store bound to the
session's unit; the platform console's handlers use the platform's store and
never a unit's. An ID of another unit's job, scan, host, account, scanner
profile, or notification destination gets a response byte-identical to an
unknown ID's. That is a 404, except where both get another answer:
cancelling a scan answers any scan that is not running in the unit with 409
`scan_not_active`, and validating or previewing a scanner profile checks only
the submitted definition.

### The platform administrator

A platform administrator is a separate account without a unit. It manages
the units and their administrators and holds no permission on any unit's
jobs, scans, baselines, incidents, notifications, or public status: every
route of a unit's console refuses it except its own account's password,
TOTP, session, and sign-out routes. The platform console's API, under
`/api/v1/platform/`, and the unit audit, `/api/v1/audit`, exist only while
the flag is on; otherwise every request to them is refused exactly like an
unknown route. With the flag off, a platform administrator can still sign
in, but its session holds only its own account's self-service, and the
console shows it only a notice that business units are turned off, with
sign-out. Only a platform administrator reaches the platform routes,
and they never return a unit's data: a unit appears with its name, slug,
state, and counts of its accounts, administrators, jobs, and scan slots in
use; its accounts as summaries without credentials; and its capacity as
numbers. The platform's own notification destinations are write-only like a
unit's, and the platform cannot read, select, or change a unit's
destinations. Usernames stay unique across every unit and the platform.

Only the host creates the first platform administrator: `edgewatch admin
platform-setup-token` prints a one-time token, valid for 15 minutes, once the
first administrator exists and while no enabled platform administrator does,
at most once a minute, and replaces an unused token only with `--force`. The
token cannot complete the first setup, and the first setup token cannot
create a platform administrator. The console's setup page redeems it through
`POST /api/v1/setup/platform`, which exists only while the flag is on, checks
the browser origin, and applies the first setup's per-client failure budget;
a wrong, used, or expired token gets one generic answer, and each failure is
recorded in platform scope. While the token is valid, `/api/v1/setup/status`
reports `platform_setup_available`, which the sign-in page uses to offer the
setup; with the flag off the key is absent. An enabled platform
administrator can then invite another after confirming its password; the
invited account stays pending and disabled until it redeems its one-time
link, which expires after 30 minutes. A platform administrator can disable
or enable another, never its own account, and disabling one ends its
sessions and revokes the links it issued or received.

A platform administrator invites only unit administrators, and resets only
unit administrators' passwords; a unit's administrators invite and reset the
accounts of their own unit, including its operators and viewers, and cannot
reach another unit's accounts or a platform administrator. The rule follows
the target account's role and unit, not the request. No platform
administrator can reset another through the product; the host commands
`admin reset-password` and `admin disable-totp` remain the break-glass path
for every account. Each unit keeps at least one enabled administrator, and
the platform at least one enabled platform administrator, whose role never
changes. Creating and renaming a unit and changing its capacity need only a
platform administrator's session. Disabling, enabling, and deleting a unit,
inviting a unit or platform administrator, issuing a password reset, ending
an account's sessions, enabling or disabling a platform administrator, and
every change to the platform's notification destinations and routing also
require its password, and deleting also the unit's typed name.

The platform administrator is trusted with the units' accounts, not their
data, and the product makes its reach visible rather than impossible.
Inviting a unit administrator and issuing a password reset return the
one-time link to the platform administrator, who could redeem it and sign in
to the unit. Both are recorded in the unit's audit as platform actions, and
an invited account appears among the unit's users. A password reset keeps
the account's TOTP secret and recovery codes, so it lets nobody sign in to an
administrator who has enrolled TOTP without that authenticator; the reset
response reports `totp_enrolled`. It does not protect an administrator who
has not enrolled yet, because the new password is enough to enrol a new
authenticator. Keep unit administrators on TOTP and have them review the
platform actions in their audit. The platform administrator also sees each
unit's account list, with usernames, display names, roles, TOTP state, and
last sign-in, and every unit's account records in the platform audit,
including the source addresses of sign-in attempts.

Once more than one unit exists, every unit administrator and platform
administrator must use TOTP. Until one without TOTP enrols, its sessions
report `totp_enrollment_required` and may only use its own account's
settings (password, TOTP enrolment, display name, and sessions) and sign
out; everything else is refused. Units that are disabled or being deleted
count, and the rule follows the number of units, not the flag. If the units
cannot be counted, the restriction applies. With a single unit nothing
changes.

### Public pages, audit, and deletion

Each unit's public status page is served at `/public/<slug>` and
`/api/public/v1/dashboard/<slug>`, from that unit's published hosts only;
`/public` keeps serving the default unit's page. An unknown slug, a unit's
page that is not enabled, a paused unit, a unit being deleted, and every slug
while the flag is off get the same 404 `public_disabled` answer as a disabled
page, so the address does not reveal whether a unit has that slug. Each page
has its own per-client rate limit and its own cache: a busy page does not
throttle another, and saving one page does not drop another page's cache.

A platform administrator's action on a unit's account, and a change of the
unit's capacity, is recorded in that unit's security audit with the
`platform` actor kind, so the unit's administrators see it. The unit's
lifecycle changes, the platform administrator's other actions, sign-in
attempts on its account, and sign-in attempts with a username that no
account has are recorded in platform scope, outside every unit's audit. A
unit's administrators read their unit's audit, which hides the source address
of a platform administrator's actions; the platform audit shows the records
in platform scope and every unit's account and platform records, never a
unit's data records. Both views are read-only.

Disabling a unit ends its sessions and revokes its open invitations in the
same transaction; from then on its accounts cannot sign in or redeem a link,
and a sign-in gets the answer of a wrong password. Deleting a unit erases its
rows in bounded batches with SQLite's `secure_delete` on, then compacts the
search indexes and truncates the write-ahead log. Backups taken before the
deletion still hold the unit's data, and the records of platform
administrators' actions on it stay in the platform audit.

### Signals between units

Some signals cross units by design:

- Usernames are unique across the deployment, so inviting a name that another
  unit or the platform uses fails with `username is not available`, which
  tells the inviting administrator that the name exists elsewhere.
- The RDAP cache is shared. It holds only public registry data, never which
  unit observed an address, but a lookup can come back as `cached`, with its
  original fetch time, because another unit opened the same public address
  first.
- The scan slots and the scanning host are shared: a unit's scans can wait
  while other units' scans hold the slots, and every unit's probes leave from
  the same host. A slot cap limits a unit but reserves nothing for it.
- Live-update event IDs, the replay window, and the deployment-wide stream
  limit are shared; see
  [Live-update streams and session revocation](#live-update-streams-and-session-revocation).
- The default unit's status reports the size of the whole database, which
  grows with every unit's data.
- Anonymous callers of `/api/v1/setup/status` can tell from the presence of
  `platform_setup_available` whether the flag is on.
- Behind a proxy that is not listed in `web.trusted_proxies`, the shared
  sign-in cooldown applies to the accounts of every unit.

Other signals are closed. Once more than one unit exists, a unit's status
leaves out the deployment-wide live-update counters, whether the flag is on
or off, and it leaves them out too when the units cannot be counted. A
unit's status counts, notification totals, and telemetry cover its own rows
only, its scan slots and probe budgets are its own limits, the Hosts view
keeps each unit's newest observation of an address apart, and a public slug
does not reveal whether a unit has it.

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

Each live update has one audience, and replay after a reconnect is filtered
the same way. A business unit's streams receive only that unit's updates: its
jobs, scans, incidents, baselines, scan cycles, scanner profiles and
notification destinations, and the unit's own copy of an update alert. The
notice that the application update status changed carries no unit's data and
reaches every stream. Platform administrators hold no stream permission and
receive no live updates; the platform's copy of an update alert is addressed
to platform streams only, and a platform stream would never receive a unit's
update. Disabling or deleting a unit through the running daemon ends the
unit's open streams at once; the change also ends the unit's sessions, so a
disable from another process takes effect through the revalidation fallback.
Once more than one unit exists, each unit (and the platform) may hold at most
64 of the 256 streams that the deployment allows, so one unit cannot lock the
others out; a stream over either limit receives the in-band `stream_limit`
backoff. With a single unit only the deployment-wide limit applies. Event IDs
and the in-memory replay window are shared by every unit: a unit can tell
from gaps in its event IDs that other units received updates, but not what
they were, and a burst in another unit can shorten its replay window, after
which a reconnecting browser receives a full-refresh marker instead. The
deployment-wide replay counters (`live_updates` in `/api/v1/status`) are
left out of a unit's status once more than one unit exists, whether business
units are on or off, and when the units cannot be counted.

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
configured. The default key always sits next to the database file, also when
`database` is a `file:` URI. Protect that key as a credential, keep it mode
`0600`, and include it in backups of the corresponding SQLite database. An explicitly configured
key is checked at startup and must be present, valid, and owner-readable.
Do not report notification URLs or key material in issues, logs, screenshots,
or audit records.

Notification secrets now live encrypted in the database. The
`notifications.urls` and `notifications.urls_file` keys in config.yaml are
deprecated: on its first start, the daemon imports each configured URL once as
an encrypted web-managed destination, in one transaction that also moves the
job routing, update-alert routing, queued alerts, and delivery health to it.
The import uses the same key, and creates the default key exactly as the
first web-managed destination does. After the import, EdgeWatch no longer
reads those URLs for delivery; remove them, and any mounted URL file, from the
deployment, because the file keeps a second plaintext copy of the credentials.
Back up `notification.key` with the database: without it, the imported
destinations are locked and cannot be recovered from config.yaml. An import
that cannot complete, for example because the key is missing, unreadable, or
cannot decrypt the existing destinations, imports nothing and leaves delivery
on the configured URLs. Logs, the `edgewatch health` warning, and the
`notifications.config_imported` audit record contain only counts, destination
IDs, and a bounded reason, never a URL or its digest. While a URL file is
still configured, it is checked at startup, must be a regular file with mode
`0400` or `0600`, and is capped at 1 MiB. A later release will refuse to start
while either key is set.

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
confirming that the old credentials are revoked. After restoring a key, run
`notify test` or the console notification test: it fails while any enabled
web-managed destination is still locked. A database upgraded to schema
54 must not be opened by an older EdgeWatch binary; downgrade by restoring the
complete pre-upgrade `./data` backup before starting the old version. The
daemon and the host commands that write to the database, including `backup`,
refuse a schema newer than the binary supports before they write anything.
Schema 51 keeps every security audit record, attributes it to the default
tenant, and adds a category derived from its action. Update alert routing and
the public status publication move to the default tenant unchanged: alerts go
to the same destinations, and the public page still shows only the explicitly
published hosts. Schema 52 rebuilds the users, jobs, scanner profiles, and
notification destinations tables with the tenant that owns each row, and
removes the legacy administrator row. Sign-in, password and TOTP
confirmation, first setup, and the host recovery commands use only the users
table, so a leftover legacy row can no longer authenticate or recreate an
administrator. Schema 53 attributes each scan, event, and notification
delivery to the tenant of its job, and database triggers refuse a scan or
event in another tenant than its job, a new scan or event for a tenant that
is being deleted, a later change of that tenant, and a published host whose
job belongs to another tenant than the public page. An update alert has one
copy for the platform, which belongs to no tenant, and one for each active
tenant; each copy and its deliveries belong to their owner, reach only the
owner's destinations, and appear only in the owner's history. Schema 54
keeps the newest observation of an address per tenant, and a database
trigger refuses a latest-host row in another tenant than its scan or for a
tenant that is being deleted. Back up the complete `./data` directory before
the upgrade.

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
worker. A restore also clears the daemon and scan leases copied from the
backup, because no process runs on the restored copy. It still refuses to
replace a database whose own daemon heartbeat is recent, unless the operator
passes the emergency `--allow-active-daemon` override.

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
