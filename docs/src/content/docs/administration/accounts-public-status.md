---
title: Accounts and public status
description: Manage roles, account activation, TOTP, and explicitly published status pages.
---

The first account is an administrator. Administrators can invite additional
accounts with single-use activation links. Every user can manage their own
display name, password, and optional TOTP protection. Usernames can use at most
80 bytes of UTF-8 text, so accented and non-Latin characters count as 2 to 4
bytes each, and cannot contain control characters, `/`, `\`, or `:`.

## Activation links and session changes

New activation and password-reset links keep their one-time token in the URL
fragment, which is not sent in the HTTP request to EdgeWatch or a reverse proxy.
EdgeWatch removes it from the browser address bar as soon as the activation page
opens. Previously issued query-string links remain usable only until their
existing 30-minute expiry and are also removed from browser history on arrival.
If the browser is already signed in, EdgeWatch does not redeem the link in
that session. The console identifies the signed-in account and offers to sign
out before opening the activation page. The token stays in the address bar
until then. **Return to the console** keeps the session and leaves the link unused.

The console shows the data of one account at a time. When its session ends, or
when a session read finds that the browser is now signed in as another account,
for example after a sign-in in another tab, the console drops the data that it
loaded before it shows the sign-in page or the other account. If a request fails without ending the session, for example while EdgeWatch
restarts, the console stays open and preserves your input. It shows that it is
reconnecting and checks the session again every few seconds until EdgeWatch
responds.

An account has one usable link at a time: issuing a new link invalidates older links. A
link also stops working when the account's password changes in any other way
(the account's own change, `edgewatch admin reset-password` on the host, or
redeeming another link), when the account's role changes, and when the account
is disabled. The links that an administrator issued, such as a pending
account's activation link, stop working when that administrator is demoted or
disabled. A role change stops a pending account's activation link too, so
issue a new link after changing the role of an account that has not activated
yet. Each stopped link that could still have been used is recorded in the
security audit as `user.activation_revoked`, with the name of the account
whose link stopped and the reason, by whoever made the change. A link that
had already expired is not recorded.

A disabled account gets no new activation or password-reset link until it is
enabled again; the request is refused with `409 user_disabled`. That also
holds for a request that was already on its way when the account was
disabled, so enabling the account again never revives a link. A pending
account, which stays disabled until it activates, can always get a new
activation link.

To sign another account out of every browser, for example when you suspect
that someone else holds its session, choose **Revoke sessions** on its row
in **Users** and confirm with your password. The account's password,
authenticator, and links do not change, and it can sign in again. The unit's
audit records the action as `user.sessions_revoked`. The action is offered
for enabled accounts that have activated; disabling an account already ended
its sessions. To end your own sessions, use **Log out all sessions** on
**Security**.

## Roles

| Role | Access |
| --- | --- |
| Administrator | Full administration, users, destinations, profiles, jobs, baselines, incidents, and public status. |
| Operator | Configure and run jobs; approve or reset baselines; accept or suppress incidents; review evidence; and select existing destinations for jobs. Cannot manage destinations, users, or scanner profiles, permanently delete archived jobs, or approve high-cost scans; an operator's scope change clears an existing high-cost approval. |
| Viewer | Read-only jobs and baseline information. |

## Public status

An administrator can enable **Public status** and explicitly publish selected
effective hosts. The unauthenticated `/public` page contains only the chosen job
names, latest successful scan time, positive ports, service names, and cached
normalized network-registration data. It does not expose raw Nmap evidence,
product fingerprints, credentials, or an arbitrary RDAP proxy.

Each business unit publishes its own page; see
[Business units](/administration/business-units/).

A public-status save applies only to the configuration the editor loaded. If
another administrator saved in the meantime, EdgeWatch rejects the save with a
conflict and the editor reloads the current settings, so an outdated editor
cannot republish a withdrawn page. An editor with unsaved changes keeps them
when the console refreshes in the background, and says when another
administrator has saved; **Discard my changes and load theirs** reloads the
current settings at once. API clients send the `updated_at` value from
`GET /api/v1/public-dashboard` with each `PUT`.
