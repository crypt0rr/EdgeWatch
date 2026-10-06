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
[`docs/src/content/docs/deployment/container-hardening.md`](docs/src/content/docs/deployment/container-hardening.md).

The administration console is bound to a loopback address by default and uses
server-side sessions, CSRF protection, and Argon2id password storage. Keep the
Docker host and any SSH tunnel access restricted to trusted administrators.
When an untrusted tunnel or reverse proxy makes every remote client appear as
the same loopback peer, all login attempts are throttled after five failed
password or TOTP attempts in five minutes with a short two-second retry delay.
A successful sign-in through the peer, with any account, does not reset those
failures; each one expires five minutes after it happened, so signing in
between failed attempts gains no further attempts.
The shared response avoids both a long lockout and revealing account existence,
but cannot provide per-client attribution. The first-run setup, the platform
setup, and account activation through such a shared loopback peer get the
same two-second cooldown after five wrong tokens, instead of the five-minute
block that a hundred failures from one address otherwise cause. Password and
TOTP confirmations of signed-in accounts through such a peer count each
failure against the confirming account only: an account that fails five
confirmations within five minutes is refused for five minutes, while every
other account, in any unit or on the platform, keeps confirming, and the peer
is never blocked after a hundred failed confirmations as an address that is
not loopback is. For per-client rate limits and audit identities, configure
only the actual proxy addresses in `web.trusted_proxies` and the sanitized
`web.forwarded_header`.
A client identified by its own address has a budget of five failed sign-ins
in five minutes. Every failed sign-in costs it the same, whether the username
is unknown, the account is disabled or its unit is not active, or the
password, one-time code, or recovery code is wrong. Once it is used, every
sign-in from that client is refused with the same `429 rate_limited` answer
for five minutes, whether or not the username exists, so neither the answer
nor the number of attempts left reveals which accounts exist. A refused
sign-in answers without waiting for its `auth.rate_limited` record, which is
written in the background, so the refusal takes as long for every username.
A successful sign-in does not reset the budget, so a client that holds one
valid account cannot sign in between failed attempts to gain more. Other
clients are not affected; clients that share one address, such as the clients
of an untrusted proxy on another host, share the budget, and they share the
backstop of the setups and activation, which blocks the address for five
minutes after a hundred wrong tokens. EdgeWatch keeps these limits for an
address that is not loopback. When requests come through a proxy that
EdgeWatch does not trust, it logs a warning that recommends
`web.trusted_proxies`, at most once an hour, and the console shows the
proxy's address to the administrators of a deployment with one unit and on
the platform status page, until a day after its last request. Such a proxy
is a directly connected peer that is not listed in `web.trusted_proxies` and
sends `X-Forwarded-For` or `Forwarded`, such as an unlisted proxy on the
host, which connects from a loopback address; or, behind listed proxies, the
first address from the right of the configured forwarding header that is not
listed, when the header names another client before it, such as an unlisted
proxy on another host in front of the listed proxy on the host. A client can
send these headers itself and have its own address shown, so list an address
only when it is a proxy that you run. The notice never changes the address
that EdgeWatch uses for a client. EdgeWatch also logs a startup warning when
proxy hostnames are approved without trusted client-IP forwarding. Failed
login and TOTP attempts, along with rate-limit events, are written to the
security audit log; they do not currently send notification-channel alerts.

Setting up or replacing an authenticator requires the account password, plus
the current authenticator or a recovery code when TOTP is already enabled. The
new secret then stays pending for ten minutes and accepts at most five incorrect
verification codes. A mistyped code can be retried against the same secret;
after the fifth incorrect code, or once the ten minutes pass, the pending secret
is discarded and setup must start again. The code that confirms the new secret
counts as used for its time step, as a code accepted at sign-in or for a TOTP
confirmation does, so neither accepts it again; the first sign-in after
enrolment takes the authenticator's next code. A sign-in records its TOTP time
step, or marks its recovery code used, in the transaction that creates its
session. A sign-in that creates no session, because the security audit or the
session cannot be written, the password-check queue is full, or the
account's credentials change at the same moment, leaves the code unused, and
of two sign-ins with the same code only one gets a session.

Activation and password-reset links are single-use, expire after 30 minutes,
and are stored only as the SHA-256 digest of their token. An account has one
usable link at a time: issuing a new link stops the older ones. A link also
stops working, whoever issued it, when the account's password changes in any
other way (its own change, the host's `admin reset-password`, or the
redemption of another link), when its role changes, and when the account is
disabled; the links an administrator issued stop when that administrator is
demoted or disabled. A role change stops a pending account's activation link
too, so a link issued for one role, such as a platform administrator's reset
link for a unit administrator, never sets the password of the account in
another role; the account then needs a new link. Each stopped link that could
still have been used is recorded, in the same transaction as the change and
with its actor, as `user.activation_revoked`, or
`platform_admin.activation_revoked` for a platform administrator, naming the
account. A browser that holds a session never redeems a link with it: the
console asks the visitor to sign out first and keeps the link until then.

## Business units and the platform administrator

Every installation has at least one business unit, the default unit, which
holds everything that existed before business units. A single unit behaves
as before, apart from the unit audit, the `/public/default` alias of the
public page, the `--tenant` option of the host commands, and the platform
setup token that the host can issue.

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
TOTP, session, and sign-out routes. Only a platform administrator reaches
the platform console's API, under `/api/v1/platform/`, and it never returns
a unit's data: a unit appears with its name, slug, state, and counts of its
accounts, administrators, jobs, stored scans, and scan slots in use; its
accounts as summaries without credentials; and its
capacity as numbers. The stored scan count is a number of rows, never a
scan's content. The platform's own notification destinations are
write-only like a unit's, and the platform cannot read, select, or change a
unit's destinations. Usernames stay unique across every unit and the
platform.

Only the host creates the first platform administrator: `edgewatch admin
platform-setup-token` prints a one-time token, valid for 15 minutes, once the
first administrator exists and while no enabled platform administrator does,
at most once a minute, and replaces an unused token only with `--force`. The
token cannot complete the first setup, and the first setup token cannot
create a platform administrator. The console's setup page redeems it through
`POST /api/v1/setup/platform`, which checks the browser origin and applies
the first setup's per-client failure budget; a wrong, used, or expired token
gets one generic answer, and each failure is recorded in platform scope.
While the token is valid, `/api/v1/setup/status` reports
`platform_setup_available`, which the sign-in page uses to offer the setup.
Once the first administrator exists, the setup page never shows the first-run
form.
An enabled platform
administrator can then invite another after confirming its password; the
invited account stays pending and disabled until it redeems its one-time
link, which expires after 30 minutes. Until then, a platform administrator
can revoke the invitation, which stops the link; a pending account is neither
enabled nor disabled. A platform administrator can also renew a pending
account's invitation, including one that expired or was revoked: the new
one-time link is returned once, and every earlier link stops working. It can
remove a pending account, with its links, so the username can be invited
again; an account that redeemed its link is never removed, only disabled.
A platform administrator can disable or enable another, never its own
account, and disabling one ends its sessions and revokes the links it issued
or received.

A platform administrator invites only unit administrators, and resets only
unit administrators' passwords; a unit's administrators invite and reset the
accounts of their own unit, including its operators and viewers, and cannot
reach another unit's accounts or a platform administrator. The rule follows
the target account's role and unit, not the request. No platform
administrator can reset another through the product; the host commands
`admin reset-password` and `admin disable-totp` remain the break-glass path
for every account. Each unit keeps at least one enabled administrator, and
the platform at least one enabled platform administrator, whose role never
changes. The platform console's changes to units, their capacity and
accounts, the platform administrators, and the platform's notifications each
check in their own transaction that the acting account is still an enabled
platform administrator. Creating and renaming a unit and changing its
capacity need only a platform administrator's session.
Disabling, enabling, and deleting a unit, inviting a unit or platform
administrator, renewing or revoking a platform administrator's invitation,
removing a pending platform administrator, issuing a password reset, ending
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
count. If the units cannot be counted, the restriction applies. With a
single unit nothing changes.

### Public pages, audit, and deletion

Each unit's public status page is served at `/public/<slug>` and
`/api/public/v1/dashboard/<slug>`, from that unit's published hosts only;
`/public` keeps serving the default unit's page. An unknown slug, a unit's
page that is not enabled, a paused unit, and a unit being deleted get the
same 404 `public_disabled` answer as a disabled page, so the address does not
reveal whether a unit has that slug. Each page
has its own per-client rate limit and its own cache: a busy page does not
throttle another, and saving one page does not drop another page's cache.

A platform administrator's action on a unit's account, and a change of the
unit's capacity, is recorded in that unit's security audit with the
`platform` actor kind, so the unit's administrators see it. The unit's
lifecycle changes, the platform administrator's other actions, sign-in
attempts on its account, and sign-in attempts with a username that no
account has are recorded in platform scope, outside every unit's audit. The
record that a sign-in, password confirmation, or TOTP confirmation became
rate limited follows the same rule: it belongs to the unit of the account it
names, or to platform scope for a platform administrator or an unknown
username. A failed redemption of an activation or password-reset link, and
the record that its redemptions became rate limited, belong to the unit of
the link's account, or to platform scope for a platform administrator's
invitation, where the link's successful redemption is recorded too; that
holds for an expired or used link and a link of a disabled unit. A token that
matches no link names no account, so its records stay in the default unit,
whose console serves activation. Such rate-limit records are coalesced per
client, operation and scope for five minutes, so a client throttled on
accounts of several units gets a record in each of them. A unit's
administrators read their unit's audit, which hides the source address of a
platform administrator's actions; the platform audit shows the records in
platform scope and every unit's account and platform records, never a unit's
data records. Both views are read-only.

Disabling a unit ends its sessions and revokes its open invitations in the
same transaction; from then on its accounts cannot sign in or redeem a link,
and a sign-in gets the answer of a wrong password, whatever one-time code or
recovery code comes with it. The sign-in is refused before it uses up that
code, so a recovery code presented while the unit is disabled still works
once the unit is enabled again. A unit administrator's
account changes, including new invitations and password-reset links, check
again when they are written that the administrator is still an enabled
administrator of an active unit. A request that is still in progress when
the administrator is demoted or disabled, or the unit is disabled, is
refused with `403 forbidden` and writes nothing, so no link outlives the
change. Deleting a unit erases its rows in bounded batches with SQLite's
`secure_delete` on, then compacts the search indexes and truncates the
write-ahead log, both of which may still hold copies of the erased rows.
Between the two it clears the database's free pages, which may hold rows of
the unit that other writers, such as retention, deleted without
`secure_delete` while it existed, or search terms of it that a retention
merge freed during the deletion: a database with incremental auto-vacuum,
the mode of every database created by v0.18.31 or later, returns them to the
file system, and in a database without auto-vacuum, which `edgewatch verify`
reports as `auto_vacuum` `none`, the purge allocates every free page to a
scratch table and frees them again with `secure_delete` on, so SQLite
overwrites each of them with zeros. The pages in use are not rewritten, so
stale bytes in their unused space are not covered. The unit stays in the
deleting state until the compaction and the overwrite have finished and a
checkpoint has truncated the log: each purge pass continues them within a
bounded time, and a reader that holds an older snapshot of the database,
such as a running backup, keeps the log from being truncated until it ends,
which the daemon logs as a warning. Deleting a destination removes its
delivery health; the purge also erases the delivery health that earlier
releases kept for deleted destinations, which names no owner and counts in
no unit's totals. Backups taken before the deletion still hold the unit's
data, and the records of platform administrators' actions on it stay in the
platform audit. Releases before schema 55 marked a unit deleted before the
compaction and the truncation had finished, so after such a deletion the
search index segments, which backups copy, and the log may still hold
copies of the erased rows. When the database holds a deleted unit, the
upgrade to schema 55 records a one-time cleanup that the daemon runs in the
background with the same bounded, resumable passes: it compacts every search
index and then truncates the log, again waiting for a reader that holds an
older snapshot, and while a unit is being deleted it leaves the work to that
unit's deletion. `edgewatch health` reports the cleanup as `maintenance`
until it has finished, and `edgewatch verify` lists its
`legacy_tenant_purge_maintenance` checkpoint. Backups taken before it has
finished may still hold the erased rows of those units. Releases before
schema 56 did not overwrite free pages, so in a database without
auto-vacuum the free pages, which raw copies of `./data` include, may still
hold rows of the units they deleted. When such a database holds a deleted
unit, the upgrade to schema 56 records the same cleanup as pending again
from its overwrite of free pages, which then truncates the log without
compacting the indexes again, and sends a deletion that had reached its
log truncation back to the overwrite.

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
- Anonymous callers of `/api/v1/setup/status` can tell from
  `platform_setup_available` whether a platform setup token is waiting to be
  used.
- Behind a proxy that is not listed in `web.trusted_proxies`, the shared
  sign-in cooldown applies to the accounts of every unit. Password and TOTP
  confirmations there are limited per account, so they do not cross units.
- A redemption with a token that matches no link, such as a mistyped link of
  any unit or of a platform administrator's invitation, is recorded in the
  default unit's audit with its source address, because the token names no
  account.

Other signals are closed. Once more than one unit exists, a unit's status
leaves out the deployment-wide live-update counters, and it leaves them out
too when the units cannot be counted. A
unit's status counts, notification totals, and telemetry cover its own rows
only, its scan slots and probe budgets are its own limits, the Hosts view
keeps each unit's newest observation of an address apart, and a public slug
does not reveal whether a unit has it. The inactive YAML jobs in config.yaml
belong to the default unit, so only its status names them.

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
left out of a unit's status once more than one unit exists, and when the
units cannot be counted.

Other authenticated API reads, including the status and page-polling requests,
also validate sessions without refreshing their idle timestamp. Actual browser
pointer, keyboard, click, or scroll input and authorized state-changing
requests refresh the idle timestamp through a CSRF-protected activity path.
Refreshes are coalesced to at most one database write per session every five
minutes. The activity write has a short timeout so SQLite writer contention
cannot delay normal read-only requests. A session with no real activity expires
after 24 hours; polling in an unattended tab does not keep it alive. The
absolute session lifetime remains 30 days. The daemon removes sessions past
either limit when it starts and once a day. An account keeps at most 20
sessions: a sign-in beyond that ends the account's least recently used
session, whose live-update stream stops at its next authorization check.

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
timestamps. A unit sees the health of its own destinations only, and the
platform console that of the platform's own destinations only. Terminal drops
store a stable destination/error fingerprint and a bounded error code; raw
provider responses, URLs, and credentials are not included in API responses,
logs, or system events. Once a destination's URL replacement is saved, an
alert raised afterwards is sent only to the new URL, even while a delivery
worker is still reading the destinations from before the replacement.

Optional TOTP seeds are encrypted independently with AES-256-GCM. The default
authentication key is `./data/auth.key`; set `web.auth_key_file` for a separate
mode-`0600` mount. Back up that key with the database. If it is unavailable,
TOTP verification fails closed while password reset or the host recovery
command can still disable TOTP and invalidate sessions.

If the key is lost or replaced, web-managed destinations become unavailable;
they cannot be recovered from the database alone. Restore the original key and
database together, or delete and recreate the affected destinations after
confirming that the old credentials are revoked. After restoring a key, run
`notify test`: it fails while any enabled web-managed destination of any unit
or of the platform is still locked, whichever unit `--tenant` selects, and
reports that count as `deployment_locked`, never a URL. The console
notification test covers only the unit's own destinations, so a unit's
administrators learn nothing about another unit's or the platform's. A
database upgraded to schema 64 must not be opened by an older EdgeWatch
binary; downgrade by restoring the complete pre-upgrade `./data` backup
before starting the old version. The
daemon and the host commands that write to the database, including `backup`,
refuse a schema newer than the binary supports before they write anything.
Schema 63 also marks legacy unsent deliveries with at least eight attempts
and a retry scheduled before v0.22.1 as terminal; deliveries still retrying
under the newer fifteen-attempt policy remain eligible. Schema 64 adds an
index for pruning old restore-quarantine records without rewriting delivery
history.
Only the daemon migrates. The host commands that act on business units or
accounts (`admin`, `scan`, `status`, `history`, `baseline`, and `notify
test`) refuse a schema that the daemon has not upgraded yet, such as a
restored backup of an older release, before they read or write anything, so
account recovery never reports an existing account as missing. The daemon
checks `web.auth_key_file`, `notifications.encryption_key_file`, and the
notification URLs in config.yaml before it opens the database, so a start
that these refuse never migrates it; `config validate` runs the same checks.
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
tenant that is being deleted. Schema 55 changes no table: when a tenant has
been deleted, it records the one-time cleanup after deleted tenants
described under [Public pages, audit, and deletion](#public-pages-audit-and-deletion),
and sends a deletion that was already compacting the search indexes back to
the start of its compaction. Schema 56 changes no table either: in a
database without auto-vacuum that holds a deleted tenant, it records that
cleanup as pending again at its overwrite of free pages, and it sends a
deletion that had reached its log truncation back to that overwrite. Schema
57 records whether a unit has a high-cost grant. A unit without one, as
every new unit starts, keeps its probe budgets for a job approved for
high-cost work, whatever config.yaml sets; earlier releases stored the
budgets in force at the unit's creation as its ceiling, which let such an
approval raise the budgets once config.yaml lowered them. The upgrade removes that ceiling from every unit
other than the default one whose capacity no platform administrator has
saved, and a database check keeps a unit without a grant from holding a
ceiling. A ceiling that a platform administrator saved stays a grant, so
review the ceiling of those units after the upgrade. Back up the complete
`./data` directory before the upgrade.

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
worker; records older than the configured history retention are pruned in
bounded batches. Records owned by a unit whose deletion is pending are left to
that unit's purge. Restore policies count, quarantine, or discard only
claimable pending deliveries; terminal failures stay in the outbox. A restore
also clears the daemon and scan leases copied from the
backup, because no process runs on the restored copy. It still refuses to
replace a database whose own daemon heartbeat is recent, unless the operator
passes the emergency `--allow-active-daemon` override.

Restore and dry-run commands cancel staging on `SIGINT` or `SIGTERM` and
remove the temporary copy. The next restore or dry run removes abandoned
`.edgewatch-restore-*` staging directories left by a process killed outright
or by a host crash. On Linux, concurrent restore commands are serialized with
an advisory lock on the database directory, without leaving a lock file
behind. Other platforms skip automatic orphan removal when cross-process
locking is unavailable.

A backup can hold sessions, activation and password-reset links, and a setup
or platform setup token that were revoked, redeemed, or replaced after it was
taken. In the same transaction that clears the leases, a restore therefore
deletes the copied sessions and marks every unused link and setup token in
the copy as used, so none of them works again; the dry run does the same to
its private copy. Administrators issue new links after the restore, the host
prints a new platform setup token with `admin platform-setup-token`, and
while no administrator exists the daemon prints a new setup token at startup.

Host CLI commands that change state (`scan`, `baseline approve` and `reset`,
`notify test`, `backup`, `restore`, and administrator recovery) record a
security audit entry with the actor `host-cli`. The details are bounded to job
IDs, file base names, and outcomes, and for `admin reset-password` and
`admin disable-totp` the username and ID of the account changed with its unit,
or the platform; they never include scan targets, notification URLs, full
paths, passwords, or TOTP secrets. A CLI scan uses the same
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
