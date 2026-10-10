---
title: Security
description: Protect scanner access, accounts, encryption keys, and shared deployment boundaries.
---

Only scan systems you own or are authorized to assess. Keep access to the
Docker host, database, backups, and encryption keys restricted to trusted
operators. The repository's [security policy](https://github.com/crypt0rr/EdgeWatch/blob/main/SECURITY.md)
is the canonical reference for security guarantees and vulnerability reporting.
Report vulnerabilities privately through GitHub's security advisory feature;
do not put exploit details, target information, or credentials in public issues.

## Scanner access

EdgeWatch invokes fixed Nmap and Naabu executables directly with validated
argument arrays. Browser settings do not provide arbitrary shell execution,
scanner binaries, output paths, or unrestricted NSE scripts. Naabu discoveries
must be confirmed by Nmap before they affect baselines or incidents.

Keep [target exclusions and probe budgets](/reference/configuration/) intact.
Review [container capabilities](/deployment/container-hardening/) before opting
into SYN discovery; the default deployment grants only `NET_RAW`.

## Accounts and network access

Keep the application listener on loopback. Use an SSH tunnel or an HTTPS
reverse proxy, approve its hostname, and trust only proxies you control.
Sanitize forwarding headers so rate limits and audit records identify the
right client. Follow [Reverse proxies](/deployment/reverse-proxies/) and the
[configuration defaults](/reference/configuration/#important-defaults).

Use the least powerful account role appropriate to each person. Enroll
administrators in TOTP, keep recovery codes private, and review active sessions
and audit records. With multiple business units, TOTP is required for unit
administrators and platform administrators. An `auth.second_factor_locked`
record means that an account received ten wrong one-time or recovery codes
within a day, each with its right password or from its own session. Unless
the account's owner sent them, someone holds the password, so change it; see
[the configuration defaults](/reference/configuration/#important-defaults). See
[Accounts and public status](/administration/accounts-public-status/) and
[Business units](/administration/business-units/).

## Secrets and backups

Notification credentials, supplied as provider fields or a Shoutrrr URL, are
write-only in the API and saved as encrypted URLs with `notification.key`.
TOTP seeds use the independent `auth.key`. Separate configured
key files must be regular files: the notification key with mode `0400` or
`0600`, and the authentication key without group or other permissions. Back up the original
keys with the corresponding database; the database alone cannot recover them.
Never commit keys, passwords, setup tokens, notification credentials or URLs,
or runtime data.

After a successful legacy notification import, remove plaintext URLs and URL
file mounts from the deployment. Rotate credentials through the console.
[Notifications](/user-guide/notifications/) explains import and delivery behavior.

[Restore](/operations/backup-recovery/) onto a stopped service. Restores end
copied sessions and one-time links, clear copied leases, and quarantine pending
notifications by default. They refuse a backup whose destinations or TOTP
seeds the configured keys cannot open unless `--allow-key-mismatch` is given;
`verify --from` runs the same check on a backup file while EdgeWatch runs.
Scheduled backups and backups taken with the backup command hold every unit's
data: keep them, and the keys, as private as `./data`. Check [database compatibility](/reference/database-compatibility/)
before upgrading or restoring an older backup.

## Business-unit boundaries

Units share one process, database, and encryption keys. The product isolates
unit data in its console, API, streams, and public pages, but host operators
can access every unit. Backups and restores cover all units together. Use
separate deployments for parties that must not trust the same operators.

The platform administrator manages unit lifecycle and accounts without direct
access to unit scan data. Account invitations and password resets are still
trusted operations: keep unit administrators on TOTP and review platform
account actions in the unit audit. The security policy describes these trust
boundaries and the signals that units can observe about one another.

## Public and outbound information

Publish only intended hosts on each unit's public status page. The public
projection excludes raw scan evidence, private fingerprints, and credentials.
RDAP uses public registry data only; update checks contact GitHub and disclose
the host's public address and EdgeWatch user agent. Disable either feature in
[deployment configuration](/reference/configuration/) when required. Update
checks and notifications use the daemon's proxy variables, but RDAP lookups
connect directly, so disable RDAP where only a proxy reaches the internet.

A unit's notification destinations cannot use the addresses that
`scanner.target_exclusions` refuses, or loopback, link-local, and unspecified
addresses, so a unit administrator cannot make the daemon send requests to the
host's own services or to a cloud metadata endpoint; see
[destination addresses](/user-guide/notifications/#destination-addresses).
