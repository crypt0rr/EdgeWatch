---
title: Local development
description: Set up the Go backend and React console, then run the checks appropriate to your change.
---

EdgeWatch uses a Go backend, SQLite storage, and a React/TypeScript web console.
The production binary embeds the console; Node.js is needed for development
and builds, but is not included in the production image.

## Requirements

The project uses Go 1.27.2 or newer and Node.js 24.16.0 or newer within the
Node 24 release line. CI and the container build are pinned to 24.21.0; local
version managers can use [.node-version](https://github.com/crypt0rr/EdgeWatch/blob/main/.node-version).
The daemon and real-stack browser tests run on Linux. The migration and
restore directory lock required for safe daemon startup is implemented only
on Linux; attempting to start the daemon on macOS, BSD, or another non-Linux
system fails closed before migration, even when that platform provides
`flock`. Use a Linux host or Linux container to run the daemon and real-stack
tests.

Use the commands in the repository’s Makefile, package.json, and CI. Read the
[agent guide](https://github.com/crypt0rr/EdgeWatch/blob/main/AGENTS.md) for repository conventions and the
[security policy](https://github.com/crypt0rr/EdgeWatch/blob/main/SECURITY.md) before security-sensitive changes.

## Build the application

From the repository root:

```sh
npm ci
npm run build
go build -trimpath -o edgewatch ./cmd/edgewatch
```

`make build` installs frontend dependencies and builds the console and binary
with version flags. Build the frontend before testing behavior that depends
on embedded assets.

## Develop the console

```sh
npm run dev
```

Vite serves the console on `127.0.0.1:5173` and proxies `/api` to a backend on
`127.0.0.1:8080`. Configure the backend using the
[deployment configuration](/reference/configuration/).
Edit frontend source in `src/`. Generated assets in `internal/webui/dist/`
are not committed; preserve its tracked `.gitkeep`. The generated API types
in `src/generated/` are committed instead; see
[Generated API types](#generated-api-types).

## Generated API types

`src/generated/api-types.ts` declares the TypeScript types of API responses
that Go structs write: the console status (`GET /api/v1/status`), the platform
status, the notification status, and scans with their summaries and
snapshots. `go run ./scripts/gen-api-types` writes it from the structs that
`ResponseTypes` in `internal/web/api_types.go` lists, by reflection on their
`json` tags:

- A field with `omitempty` or `omitzero` is optional (`?`), so a smaller
  response, such as a viewer's status, still type-checks.
- A pointer, slice, or map without either option admits `null`, because
  `encoding/json` writes `null` for a nil value.
- A field of a named struct refers to that struct's declaration, so every
  named struct that a listed struct contains must be listed too.

The file is generated but committed source, unlike the build output in
`internal/webui/dist/`. Do not edit it by hand. After changing a listed
struct, or adding one to `ResponseTypes`, run the command from the repository
root and commit the result with the consumers that use it:

```sh
go run ./scripts/gen-api-types
```

Import a generated type from `src/generated/api-types` rather than declaring
the same shape again in `src/types.ts` or `src/api.ts`. The generator refuses
an exported field without a `json` tag, an embedded field, a type with its own
`MarshalJSON` or `MarshalText` other than `time.Time`, and a named struct that
is not listed. `go test ./internal/web/` checks the tags of every listed
struct, and `go test ./scripts/gen-api-types/` and CI's `go-checks` job fail
when the committed file differs from what the command writes.

## API routes

`apiRoutes` in `internal/web/permissions.go` is the endpoint route table of
the console API under `/api/v1` and the public API under `/api/public/v1`.
Each entry lists a route's method, its path template, which with the method
and API base is its `net/http` ServeMux pattern, the capability that it
requires, an example path for the tests, and its handler. `Server.Handler`
uses the outer ServeMux to identify the broad API namespaces and its other
fixed handlers. Before the outer mux can redirect an API request, it sends
the original path to the matching API handler. `internal/web/routes.go`
registers endpoint entries and runs the gate: an unauthenticated route is
served after the browser origin check for a state-changing request; any other
console request needs a session, a CSRF token when it changes state, and the
entry's permission, which also holds a session that must enroll TOTP to its
own account. The gate resolves the session's unit store once and hands it to
the handler.

To add a route:

- Add an entry with `Method`, `Template`, `Permission`, `Mutates`,
  `Example`, and `Handle`. A `{name}` segment matches one path segment,
  which the handler reads with `r.PathValue("name")`; a `{name...}` segment,
  the last, matches the rest of the path. The adapters in `routes.go`, such
  as `tenantHandler` and `sessionTenantIDHandler`, pass a handler the
  session, the unit's store, or the `{id}` value.
- Give an action that a query selects on the same method and path its own
  entry with `Query`, as `DELETE /jobs/{id}?permanent=true` has, with its
  own permission and handler.
- Set `TrailingSlash` only where the route's family accepts one trailing
  slash.
- List a scanner profile route once, under `/scanner-profiles`.
  `withPathAlias` copies it to the `/scanner/profiles` spelling with the
  same permission and handler, so the two spellings cannot differ.
- Teach `TestIsolationMatrix` a new path placeholder, and follow the tenancy
  rules in the repository's `AGENTS.md`.

Each API route table uses its ServeMux only to find a request's endpoint, so
it never redirects or answers `405`. `Server.Handler` dispatches requests
from an API namespace, including paths the outer mux would clean into or out
of that namespace, with the original path intact. A request that no route
serves gets `401` without a session, `403 csrf` for a mutation without the
CSRF token, and otherwise `403` with the permission `route`; the public API
answers it with `404 not_found`. Paths outside the APIs retain the outer
ServeMux behavior. `go test ./internal/web/` checks that every entry is
registered once, has its handler, and is reached by its example; that the
table refuses ambiguous patterns; these fail-closed answers; that no other
function reads the request path or registers a ServeMux pattern; and that a
handler reads only the path values of its template.
`TestRouteInventoryGateMatrix` sends every entry as each role.
The few paths served outside the two APIs, such as `/healthz` and
`/metrics`, are registered in `Server.Handler` and listed in
`handlerPatterns` in `internal/web/route_drift_test.go`.

## Notification destination policy

The notification child applies the unit destination policy at the provider's
actual connection path. HTTP uses a guarded dial to the checked numeric IP,
while leaving the request URL hostname intact for the HTTP `Host` header and
TLS SNI; every redirect is checked before it is followed. SMTP uses
`net.Dial`/`tls.Dial`, so the child installs a Go resolver with
`PreferGo` and `StrictErrors` and filters every A and AAAA answer the standard
library may return. Literal hosts and hosts-file results are checked in the
child preflight. The resolver packet filter does not observe hosts-file reads;
the host operator controls that file and its stability during the short send
is part of the threat model.

The production notification child sends once and keeps its destination guards
installed until that process exits; the parent process is unaffected. Scoped
in-process helpers restore the guards when their send returns.

The pinned Shoutrrr v0.8.0 provider inventory is split by destination:

- URL hostname: bark, generic, Google Chat, Gotify, Hangouts, Matrix,
  Mattermost, ntfy, Opsgenie, Rocket.Chat, SMTP, and Zulip.
- Teams: the `host` query property, or `outlook.office.com` when omitted or
  empty. Query keys are case-insensitive; conflicting case variants are all
  checked because Shoutrrr's map iteration can select either one.
- Fixed public service hostname: Discord, IFTTT, Join, logger, Pushbullet,
  Pushover, Slack, and Telegram. These URLs carry tokens or IDs in their host
  component. Their actual HTTP connections still use the guarded transport.

The HTTP providers use `http.DefaultClient`, `http.Post`, or Shoutrrr's
`jsonclient`. Telegram's package-level `jsonclient.DefaultClient` captures the
original `http.DefaultClient` pointer during package initialization, so the
child guards the captured client's existing transport rather than replacing
that pointer. Gotify is the only pinned provider with a private `http.Client`;
the child clones and guards its transport, preserving its TLS settings and
originally direct proxy behavior. Shoutrrr's default environment proxy is
refused when it selects a proxy, and uninspectable custom proxy functions are
refused; direct transports and environment `NO_PROXY` paths remain direct.

`TestDestinationProviderInventoryMatchesPinnedShoutrrr` compares this host
classification with `ServiceRouter.ListServices()`. It fails when an upgrade
adds or removes a provider without an explicit inventory review. For every
Shoutrrr dependency update, also inspect the pinned source for new or changed
HTTP clients, transports, redirect handling, SMTP/raw dial paths, and provider
target construction. Update the inventory and add a controlled listener or
fake-resolver regression for any new path; preserve TLS SNI, provider URL
options, proxy behavior, secret redaction, and notification sandboxing. The
inventory test alone does not prove that a provider's transport path stayed
guarded.

## Validate changes

| Change | Checks |
| --- | --- |
| Go code | `gofmt` on changed files, `go vet ./...`, `go test -race -timeout=25m ./...` |
| A struct that `ResponseTypes` lists | `go run ./scripts/gen-api-types`, commit `src/generated/`, then the console checks |
| Console code | `npm run lint`, `npm run build`, `npm run test:coverage` |
| Browser behavior | `npm run test:e2e` |
| Database schema | Migration tests and `./scripts/check-schema-docs.sh` |
| Container image or `compose.yaml` | `./scripts/verify-compose-deployment.sh IMAGE` and `./scripts/scan-image-vulnerabilities.sh IMAGE PLATFORM` on a built image |
| CI or release workflows | `node --test scripts/release-workflow.test.mjs` |
| Documentation website | `npm --prefix docs ci`, `npm --prefix docs run build`, browser review |

`make check` verifies Go formatting, runs vet and race tests, checks console
types, and runs `make security`. It does not replace frontend builds,
frontend tests, browser tests, or container checks.

CI also collects an atomic coverage profile for the sandbox supervisor and
private-temporary helpers in its existing AMD64 container job. The job runs
`scripts/collect-sandbox-privileged-coverage.sh IMAGE OUTPUT_DIRECTORY` against
the image it just built, then the required Go coverage job merges that profile
with the four race-enabled test shards. This exercises credential and helper
paths that need the scanner control capabilities; it does not replace the
race-enabled suite or change its coverage gates.

Runtime changes to notification delivery rows go through
`applyOutboxTransition` in `internal/store/outbox_transitions.go`, using a
named transition whose column dispositions are checked against the migrated
`outbox` schema. `TestRuntimeOutboxUpdatesUseNamedTransitions` scans the
store's non-test Go source and rejects direct `UPDATE outbox` SQL literals;
schema migration backfills remain separate because they are one-time data
transforms, not runtime delivery transitions. Its regression fixture is parsed
from source text, so it tests the lint itself rather than relying on a Go
overlay that a filesystem-based source scan cannot see.

Install Chromium before the first browser test:

```sh
npx playwright install --with-deps chromium
npm run test:e2e
```

Application browser tests build and serve the console on `127.0.0.1:4173` and
require Go for real-stack tests. Set `PLAYWRIGHT_PORT` to use another port.
An occupied port stops the run. Use `PLAYWRIGHT_REUSE_SERVER=1` only for a
preview of this checkout that you started yourself.

## Work safely

Use controlled listeners for integration scans and scan only authorized
targets. Keep runtime configuration, databases, keys, notification URLs,
passwords, and authentication tokens out of source control. Keep build
output out of it too: `npm run test:coverage` runs
`scripts/repository-files.test.mjs`, which fails when a tracked file is a
compiled executable or larger than 10 MB.

Use temporary databases and preserve migration compatibility and tenant
isolation. Add regression coverage for changed behavior, using nearby tests
as examples. Review the working tree and diffs before committing.

For documentation authoring and Cloudflare Pages setup, read
[Documentation and hosting](/maintainers/documentation/).

## Run the backend

Create a local configuration from `config.example.yaml`, keep the listener on
`127.0.0.1:8080`, and use a private data directory with ownership appropriate
to the local process. Run this daemon on Linux; an attempt to start it on a
non-Linux system intentionally fails closed because the cross-process
migration lock is Linux-only. After building the console and binary:

```sh
./edgewatch daemon --config config.yaml
```

The console development server proxies its API requests to this backend.
Scanner executables and privileges must match the configured profiles; see
[Scanning and profiles](/user-guide/scanning/) and
[Container runtime hardening](/deployment/container-hardening/).

## Compatibility changes

Update the [API compatibility guide](/reference/api-compatibility/) when response
shapes change, and regenerate the [API types](#generated-api-types) when a
listed struct changes. For database migrations, update
[Database compatibility](/reference/database-compatibility/) and the root
`SECURITY.md`, then run `./scripts/check-schema-docs.sh`. A new migration
upgrades from the previous schema; a new database starts from the frozen
schema 54 baseline in `internal/store/schema_baseline.go`, which must not
change, and then runs every later migration.
