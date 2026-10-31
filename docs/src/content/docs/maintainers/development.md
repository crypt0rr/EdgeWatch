---
title: Local development
description: Set up the Go backend and React console, then run the checks appropriate to your change.
---

EdgeWatch uses a Go backend, SQLite storage, and a React/TypeScript web console.
The production binary embeds the console; Node.js is needed for development
and builds, but is not included in the production image.

## Requirements

The project uses Go 1.27.3 or newer and Node.js 24.16.0 or newer within the
Node 24 release line. CI, the release workflow, and the container build are
pinned to 24.22.2 along with this guide. The documentation workflow and local
version managers read
[.node-version](https://github.com/crypt0rr/EdgeWatch/blob/main/.node-version),
and the pull-request title check uses the same runtime pin.
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

## Console routes

`e2e/console-routes.ts` lists a concrete path for every page the console
renders: the unit console's routes in `Shell` in `src/main.tsx`, including the
guided job-creation steps of `JobCreationJourney`, the platform console's in
`PlatformShell`, each `UnitDetail` tab, and the pages outside either shell:
sign-in, first-run setup, activation, the account-link notice that a
signed-in browser shows for an activation or password-reset link, the forced
TOTP enrolment, and the public status pages. The axe audit in
`e2e/route-accessibility.spec.ts` visits every entry; the role matrix in
`e2e/role-matrix.spec.ts` visits the console routes, but not the pages outside
both shells (`entrySurfaces`).

`src/console-route-inventory.test.ts`, which `npm run test:coverage` runs
before the browser tests, keeps that list complete. A policy that fails closed
by construction keeps every way to choose a page where the check can see it.
The JSX route reader then reads the routes of the router files, and the check
resolves each inventory path against them with React Router, so a `:id`
parameter matches any value. It fails when a route, a page chosen from the
path, or a tab has no entry, and when an entry no longer reaches the route it
stands for. A route that renders no page of its own, such as a catch-all
redirect outside the console shells, goes in `routesWithoutInventoryEntry`
with its reason instead.

### The policy

The policy reads every non-test TypeScript module in `src/`, including
`src/generated/`, but not `src/test/` or `*.test.ts(x)` files. It refuses:

- `Route` or `Routes` imported anywhere but the modules in `routerFiles`.
  Other names from `react-router-dom` must be in `routerExports`; route-table
  APIs such as `useRoutes`, `createBrowserRouter`, and `RouterProvider` are
  missing on purpose, because they build routes that the reader cannot read.
- A value imported from a package that `knownPackages` does not list, by exact
  specifier, with the reason it cannot render a page that the inventory
  misses. It lists nine today. Package values are imported by name: default
  and namespace imports are refused, and so is any re-export of a package. A
  TypeScript path alias, a `#` package-import-map specifier, a URL, or a
  `node:` built-in is a package that the list does not name.
- A local value import that does not resolve to a checked module. The check
  resolves as Vite does: the path as written, then `.mjs`, `.js`, `.mts`,
  `.ts`, `.jsx`, `.tsx`, and `.json`, then the same `index` files. An import
  that reaches a JavaScript or JSON file first, a test, or a file outside
  `src/` fails; a side-effect import of a CSS file is fine. A file or
  directory under `src/` that resolves outside it, as through a symbolic
  link, fails the scan.
- A read of a global that the module neither declares nor imports, unless
  `knownGlobals` lists it, and a member of `window`, `globalThis`, or `self`
  that neither `knownGlobals` nor `knownWindowMembers` lists. A global that
  code outside the bundle sets, such as a component registry on `window`,
  could hold a page that the check cannot see. Add a standard browser global
  when the console starts to use it.
- A runtime module load or element factory: `import()`, `import.meta.glob`,
  `require` in any form, including `module.require` and
  `import x = require()`, and React's `lazy`, `createElement`, and
  `cloneElement`, whether imported, read as a member, or destructured. An
  entry in `runtimeAllowances` names the module, the construct, and why it
  cannot hide a page. An allowed load must still name, as a literal, a module
  that the policy accepts.

Every read of a path is classified too: each `.pathname` read or destructure,
and each use of `matchPath`, `matchRoutes`, `useMatch`, or `useMatches`,
counted by the top-level declaration that holds it. `pathReaders` gives each
such declaration its count and a reason. When the reads choose a page outside
every `<Route>`, as `AppContent` chooses the public status pages and the
account-link notice, `serves` lists the route patterns of those pages. The
check treats them as a router named after the declaration, so each pattern
needs an entry surface whose `router` names it. A new read changes the count
and fails the check until its entry says which page it serves or why it
serves none, such as a breadcrumb, an active navigation link, or a `returnTo`
path.

### The JSX route reader

The reader reads the `<Routes>` elements of the router files with the
TypeScript parser that Vite ships, so formatting, attribute order, and
conditional routes do not change what it reads. Each `<Routes>` is a router
named after the component that renders it; a second router with the same name
gets a `#2` suffix, in file order. It refuses forms that could hide a route:

- `Route` or `Routes` used other than as a JSX tag name, such as an alias, a
  prop value, a function argument, a re-export, or a parameter that shadows
  it.
- A `<Routes>` child other than `<Route>`, a fragment (`<>` or a named
  `Fragment` import), or a `&&`, conditional, or array expression of those.
  A `children` prop, a prop spread, or a `location` prop on `<Routes>`, and a
  `<Routes>` outside a named component, fail too.
- A `<Route>` with a prop spread, a `children` attribute, or a `lazy` prop; a
  `path` that is not a string literal; an `index` or `caseSensitive` prop
  that is not shorthand or a boolean literal; and a splat that is not `*` or a
  final `/*` segment. Only shorthand `index` and `index={true}` make an index
  route. Literal `caseSensitive` props are kept in the modeled route table.
- A `<Route>` outside every `<Routes>`.

A route whose element renders a router by name mounts it: a router declared in
the same file, or one imported by name from the router file that declares it,
under any export or import name. Its routes resolve under the route's path, as
`JobCreationJourney`'s do under `/jobs/new/*`. A router that no route mounts
fails unless a scope in `consoleScopeRouters` or an entry surface names it, so
a router rendered beside another or through a wrapper cannot stay unaudited.

A wildcard route (`*` or a path ending in `/*`) hands the rest of the address
to what it renders, so it may render only a nested router, a redirect or
another component imported by name from a known package, and markup. Its
`element`, `errorElement`, and `hydrateFallbackElement` props must be literal
JSX, a primitive, `null`, or a conditional or logical expression of those, and
every component in that JSX must be a nested router or a known-package
component. A local component that renders no `<Routes>` of its own, a member
tag such as `<Pages.Fallback>`, a component chosen at runtime, a prop spread,
and a runtime child fail. `Component`, `ErrorBoundary`, and `HydrateFallback`
must name a nested router or a known-package component. A name that a router
file binds more than once is shadowed somewhere, so the reader does not
resolve it. To show a page for unknown addresses, give the page a route of its
own and redirect the catch-all to it.

To add a console page, add its `<Route>` to a router file, then an entry with
its scope and permission to `unitConsoleRoutes` or `platformConsoleRoutes`, or
to `entrySurfaces` for a page outside both shells. A page chosen from the path
needs its pattern in `serves` and an entry surface that names its declaration
as the router.

### The axe audit

The axe audit fails on serious and critical violations, on visible link or
button text missing from the accessible name, and on the moderate
`heading-order`, `page-has-heading-one`, and `landmark-*` rules. Besides each
route in its default fixture state, it audits an open dialog, a failed
confirmation, failed page reads, an empty investigation inbox, a job without a
baseline, pending baseline changes, a near-capacity scan-slot demand notice,
and every step of a monitor setup that Perimeter prefilled. A separate
`requiredStateSurfaceManifest` ensures removing a required fixture or entry
also fails when its generating case disappears; keep it independent of the
arrays that generate the audits. An `allowedPath` with a different
destination is an alias and does not receive a separate axe run; when
`allowedPath` equals the requested path, the route is still audited.
Accept a violation only with an `axeAllowances` entry in the spec that names
the rule, a distinct audited surface key, the node, and the reason.
The reason must contain non-whitespace text.
Console routes and entry surfaces use different keys even when they share a
path, and the spec rejects duplicate keys. It also fails when an allowance
names a surface it does not audit or when an entry no longer matches a
violation. One allowance covers at most one matching violation node, and route
permissions are checked before shared-scope access.

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
  component, so the destination inventory records each provider's actual API
  host instead. Their HTTP connections still use the guarded transport.

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
classification with `ServiceRouter.ListServices()`. The table-driven
`TestGuardedChildCoversEveryDestinationProviderAgainstLoopback` also sends
every listed scheme through the notification child with localhost, a fake
hosts-file alias, IPv4 loopback, and IPv4-mapped IPv6 loopback answers, and
asserts that no controlled listener accepts a connection. The networkless
logger provider has an explicit no-connection case. For every Shoutrrr
dependency update, also inspect the pinned source for new or changed HTTP
clients, transports, redirect handling, SMTP/raw dial paths, and provider
target construction. Update the inventory and add a controlled listener or
fake-resolver regression for any new path; preserve TLS SNI, provider URL
options, proxy behavior, secret redaction, and notification sandboxing.

## Validate changes

| Change | Checks |
| --- | --- |
| Go code | `gofmt` on changed files, `go vet ./...`, `go test -race -timeout=25m ./...` |
| A struct that `ResponseTypes` lists | `go run ./scripts/gen-api-types`, commit `src/generated/`, then the console checks |
| Console code | `npm run lint` (type-checks `src/`, `e2e/`, `playwright.config.ts`, and `vitest.config.ts`), `npm run build`, `npm run test:coverage` |
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
