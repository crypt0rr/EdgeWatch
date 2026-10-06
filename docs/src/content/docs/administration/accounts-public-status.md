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
A browser that is already signed in never uses a link with its session: the
console names the signed-in account and offers to sign out, and then opens the
activation page with the link's token, which stays in the address bar until
then. **Return to the console** keeps the session and leaves the link unused.

The console shows the data of one account at a time. When its session ends, or
when a session read finds that the browser is now signed in as another account,
for example after a sign-in in another tab, the console drops the data that it
loaded before it shows the sign-in page or the other account. A request that
fails without ending the session, as while EdgeWatch restarts, keeps the open
console and what was typed in it: the console says that it is reconnecting and
reads its session again every few seconds until EdgeWatch answers.

An account has one usable link at a time: a new link stops the older ones. A
link also stops working when the account's password changes in any other way
(the account's own change, `edgewatch admin reset-password` on the host, or
redeeming another link), when the account's role changes, and when the account
is disabled. A role change stops a pending account's activation link too, so
issue a new link after changing the role of an account that has not activated
yet. Each stopped link that could still have been used is recorded in the
security audit as `user.activation_revoked`, with the account's name.

## Roles

| Role | Access |
| --- | --- |
| Administrator | Full administration, users, destinations, profiles, jobs, baselines, incidents, and public status. |
| Operator | Configure and run jobs; approve or reset baselines; accept or suppress incidents; review evidence; and select existing destinations for jobs. Cannot manage destinations, users, or scanner profiles, permanently delete archived jobs, or approve high-cost scans; an operator's scope change clears an existing high-cost approval. |
| Viewer | Read-only jobs and baseline information. |

## Public status

An administrator can enable **Public status** and explicitly publish selected
effective hosts. The unauthenticated /public page contains only the chosen job
names, latest successful scan time, positive ports, service names, and cached
normalized network-registration data. It does not expose raw Nmap evidence,
product fingerprints, credentials, or an arbitrary RDAP proxy.

Each business unit publishes its own page; see
[Business units](/administration/business-units/).

A public-status save applies only to the configuration the editor loaded. If
another administrator saved in the meantime, EdgeWatch rejects the save with a
conflict and the editor reloads the current settings, so an outdated editor
cannot re-publish a withdrawn page. API clients send the `updated_at` value from
`GET /api/v1/public-dashboard` with each `PUT`.
