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

`apiRoutes` in `internal/web/permissions.go` is the route table of the
console API under `/api/v1` and the public API under `/api/public/v1`. Each
entry lists a route's method, its path template, which with the method and
the API base is its `net/http` ServeMux pattern, the capability that it
requires, an example path for the tests, and its handler. Nothing else
routes a request. `internal/web/routes.go` registers the entries and runs
the gate: an unauthenticated route is served after the browser origin check
for a state-changing request; any other console request needs a session, a
CSRF token when it changes state, and the entry's permission, which also
holds a session that must enroll TOTP to its own account. The gate resolves
the session's unit store once and hands it to the handler.

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

The route table uses the ServeMux only to find a request's route, so the
ServeMux never redirects or answers `405`. A request that no route serves
gets `401` without a session, `403 csrf` for a mutation without the CSRF
token, and otherwise `403` with the permission `route`; the public API
answers it with `404 not_found`. `go test ./internal/web/` checks that every
entry is registered once, has its handler, and is reached by its example;
that the table refuses ambiguous patterns; these fail-closed answers; that no
other function reads the request path or registers a ServeMux pattern; and
that a handler reads only the path values of its template.
`TestRouteInventoryGateMatrix` sends every entry as each role.

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
passwords, and authentication tokens out of source control.

Use temporary databases and preserve migration compatibility and tenant
isolation. Add regression coverage for changed behavior, using nearby tests
as examples. Review the working tree and diffs before committing.

For documentation authoring and Cloudflare Pages setup, read
[Documentation and hosting](/maintainers/documentation/).

## Run the backend

Create a local configuration from `config.example.yaml`, keep the listener on
`127.0.0.1:8080`, and use a private data directory with ownership appropriate
to the local process. After building the console and binary:

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
`SECURITY.md`, then run `./scripts/check-schema-docs.sh`.
