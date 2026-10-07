---
title: Business units
description: Manage platform administrators, unit accounts, capacity, and unit lifecycle.
---

Business units let several internal teams share one deployment and its
database. Each unit has its own accounts, jobs, scans, baselines, incidents,
notification destinations, custom scanner profiles, and public status page.
EdgeWatch enforces the separation in the application, not in the host or the
database; see [Limits](/administration/business-units/#limits).

Every installation starts with one unit, the default unit, named `Default`
with the slug `default`. The upgrade to schema 54 moves everything that
existed into it, and every account keeps its role there, so existing
administrators administer the default unit. There is nothing to configure.
While the default unit is the only one, jobs, schedules, notifications,
public status, and optional TOTP work as before. After upgrading, an
administrator notices only this:

- administrators get a read-only **Audit** page with the unit's security
  audit;
- the public status page is also served at `/public/default`;
- host commands accept `--tenant`, and `admin reset-password` and
  `admin disable-totp` print the account's unit and role before they act
  (see [Useful commands](/reference/cli/));
- the host can create a platform administrator, who creates further units
  (see [The platform administrator](/administration/business-units/#the-platform-administrator)).

A `config.yaml` written for the preview of business units may still contain
`experimental.business_units`. EdgeWatch ignores that setting and logs a
warning at startup; remove the `experimental` section.

## The platform administrator

A platform administrator is a separate account that belongs to no unit. It
creates, renames, disables, and deletes units, sets their capacity, invites
and resets their administrators, can sign out any of their accounts, manages
the other platform administrators and the platform's own notification
destinations, and reads the platform audit and status. It never sees a
unit's jobs, scans, hosts, baselines, incidents, destinations, or public
status settings: the platform console shows each unit with its name, slug,
state, and counts of accounts, administrators, jobs, stored scans, and scan
slots in use, and lists the unit's accounts without credentials. The
**Stored scans** count includes every scan in the unit's history, including scans for archived
jobs. Retention reduces this count. While a unit is being deleted, the count
shows the scans that remain to be erased.

The host creates the first platform administrator, after the first
administrator exists. Print a one-time platform setup token:

```console
docker compose exec edgewatch edgewatch admin platform-setup-token \
  --config /etc/edgewatch/config.yaml
```

The token is valid for 15 minutes. While it is valid, the sign-in page links
to the setup page, where the token, a username, and a password create the
account. Without a valid token, the setup page says that EdgeWatch is already
set up and links to sign-in; print a token and reload the page. When the token
expires, or someone else uses it, while the page is open, the page says so and
keeps what was typed; print a new token and paste it. The command is refused
once an enabled platform administrator exists, and it replaces an unused token
only with `--force`. An
existing platform administrator invites the others from **Platform admins**.
An invited account stays pending until its one-time link is redeemed, and
the link expires after 30 minutes. For a pending account, **Renew
invitation** shows a new link once and stops every earlier one, which
recovers an invitation that expired or was revoked. **Revoke invitation**
stops the link, and **Remove** deletes the pending account so its username
can be invited again. Each needs your password.

## Units and their accounts

Create a unit on the **Units** page of the platform console. Its name has at
most 80 characters and is unique without regard to case. Its slug, derived
from the name when left empty, has 2 to 40 lowercase letters, digits, or
hyphens and cannot be a reserved word such as `api`, `platform`, or `public`.
Then invite the unit's first administrator from the unit's **Accounts** tab.

The platform administrator invites and resets only unit administrators, and
receives each one-time link to pass on. It does both only while the unit is
active: the **Accounts** tab of a disabled unit offers only to sign an
account out. The unit's administrators invite and
manage every account of their unit on **Users**, including further
administrators, operators, and viewers, and cannot reach another unit's
accounts or a platform administrator. Each unit keeps at least one enabled
administrator. Usernames are unique across every unit and the platform.

Once more than one unit exists, counting disabled units and units being
deleted, every unit administrator and platform administrator must use TOTP.
Operators and viewers are not affected. An administrator without TOTP gets a
forced enrollment screen after signing in, which offers only the authenticator
setup, a password change, and sign-out; until TOTP is on, the session can
manage only its own account. A console that is already open switches to that
screen as soon as the server refuses one of its requests, and the platform
administrator's console does so right after it creates the second unit.
After enabling TOTP and saving the recovery codes, sign out and sign in
again with the authenticator's next code; the code that enabled TOTP counts
as used. Enroll the existing administrators before you create the second unit.
The host command `admin disable-totp` stays the recovery path, and the
account then enrolls again.

## What belongs to each unit

- **Notifications:** each unit adds and routes its own destinations; jobs can
  select only their unit's destinations. URLs from `notifications.urls` and
  `urls_file` in `config.yaml` are imported into the default unit only. The
  platform has its own destinations on the platform console's
  **Notifications** page.
- **Update alerts:** each active unit gets its own copy of an update alert,
  routed by its own **Update alerts** selection, and an empty selection
  silences it. A new unit starts with update alerts off: its copy goes to
  none of its destinations until its administrators select some on
  **Notifications**. The default unit keeps its behavior from before
  business units: until its administrators save a selection, it sends update
  alerts to all of its enabled destinations. The platform's copy goes only to
  the platform destinations selected there; none are selected until a
  platform administrator chooses them. When an update check cannot read the
  list of units, it records no copy, and a later check records every copy.
- **Scanner profiles:** the built-in profiles are shared and read-only. Custom
  profiles belong to the unit that created them.
- **YAML jobs:** the inactive jobs in `config.yaml` belong to the default unit.
  Only its administrators and operators see them listed on **Overview**, and
  `edgewatch status` lists them for the default unit only.
- **Public status:** each unit's administrators publish its page at
  `/public/<slug>`; `/public` keeps serving the default unit's page. An unknown
  slug, a page that is not enabled, and a unit that is disabled or being
  deleted get the same answer as a page that is not enabled. Each page has
  its own anonymous rate limit and cache. Changing a unit's slug changes its
  public address.
- **Capacity:** the `scheduler` settings in `config.yaml` stay the deployment's
  limits. On a unit's **Capacity** tab, a platform administrator can cap the
  unit's scan slots and its Nmap and Naabu probe budgets below those limits,
  or keep the deployment's setting. A save changes only the settings that
  were edited on the tab, and EdgeWatch rejects it with a conflict when
  another change to the unit was saved after the tab read its capacity; the
  tab then shows the current values with the edits, to review before saving
  again. API clients send the `revision` from the capacity they read. A slot
  cap is a limit, not a reservation: free slots go in turn to the units that
  have queued scans, up to each unit's cap. A unit's **Overview** shows its
  own limit, the cap where it has one and the deployment's setting
  otherwise, as "N scans at a time", and
  the API's status reports the unit's own slots and probe budgets the same
  way. The high-cost ceiling is the most probes that a job approved
  for high-cost work may send. A new unit has none: its **Capacity** tab
  shows the ceiling as **Not granted**, and such an approval raises neither
  probe budget, whatever `config.yaml` sets now or later, until a platform
  administrator chooses **Grant a ceiling** and enters one. A granted
  ceiling stays in force when `config.yaml` later lowers the deployment's
  budgets below it; choose **Not granted** to take it away. Saving the tab
  keeps a ceiling that was not granted as it is. The default unit keeps the
  high-cost behavior from before business units.
- **Audit:** a unit's administrators read its security audit on **Audit**,
  including a platform administrator's actions on the unit's accounts and
  capacity, without the platform administrator's source address. The platform
  audit shows the records that belong to no unit, such as each unit's
  creation, rename, disabling, enabling, and deletion, and every unit's
  account records, never its data records. A failed redemption of an
  activation or password-reset link, and its rate-limit record, are in the
  audit of the link's unit, or in the platform audit for a platform
  administrator's invitation; a token that matches no link is recorded in
  the default unit's audit. Both views are read-only. The
  platform audit filters by unit, by the start of the action, which is
  lowercase, and by day; a day is a calendar day in the configured
  `timezone`, in which the entries are shown, or in the browser's timezone
  when it is omitted.

## Disabling and deleting a unit

Disabling a unit, from its **Danger zone** tab with the platform
administrator's password, pauses it and keeps its data:

- its sessions end, its open invitations are revoked, and sign-in fails as it
  does with a wrong password, without using up the one-time or recovery code
  it presents;
- its running scans are canceled without changing baselines, its queued runs
  fail, and its jobs leave the schedule;
- a scan that finishes after the disable, including a host `edgewatch scan`
  that the daemon cannot cancel, is recorded as canceled and changes no
  baseline, incident, or alert; a resumable cycle that such a scan completed
  is discarded, so enabling the unit again does not apply it;
- its undelivered alerts are held, including one that a delivery pass has
  picked up but not yet sent, and it gets no copy of new update alerts;
- its public page answers as a page that is not enabled;
- retention keeps removing its expired history.

Enabling it again restores sign-in and the schedule and delivers the held
alerts; revoked invitations stay revoked. The default unit can be disabled
but never deleted.

Deleting a unit needs a disabled unit, its exact name typed, and the platform
administrator's password. Its jobs are archived at once, and the daemon then
erases its data in small batches, compacts the search indexes, and truncates
the database's write-ahead log, so neither keeps copies of the erased data.
Before it truncates the log, it also clears the database's free pages, which
can still hold the unit's history that retention removed while the unit
existed: a database created by v0.18.31 or later returns them to the file
system, and in an older one, which keeps them in the file and whose
`auto_vacuum` mode `edgewatch verify` reports as `none`, the deletion
overwrites every one of them with zeros. The deletion continues in the
background, resumes after a restart, and waits for a running scan to finish;
a running backup delays its last step until the backup ends. The unit's page
shows its progress. The records of platform administrators' actions and of
the deletion stay in the platform audit; the unit's other audit records are
erased. Afterwards the unit's name and slug can be used again. Backups taken
before the deletion still contain the unit. Releases before schema 55 could
finish a deletion before the compaction and the log truncation had, and
releases before schema 56 did not overwrite free pages; the upgrades to
schema 55 and 56 finish that work once, as described in
[Data, backup, and recovery](/operations/backup-recovery/).

## Limits

The separation of units is enforced by the console, the API, live updates,
and the public pages. Units share the process, the database, and the
`notification.key` and `auth.key`, so anyone with access to the Docker host,
the container, the host commands, the database, or a backup can read and
change every unit's data. A backup and a restore always cover every unit
together. Use business units for teams that trust the deployment's operators,
and separate deployments for parties that must not share them.
[SECURITY.md](https://github.com/crypt0rr/EdgeWatch/blob/main/SECURITY.md) describes the trust boundary, the platform
administrator's reach, and the signals that units can still observe about
each other.
