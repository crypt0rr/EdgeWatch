# Agent guide for EdgeWatch

EdgeWatch schedules network scans, records baselines, and sends Shoutrrr notifications when the observed network surface changes.
It uses a Go backend, SQLite storage, and a React/TypeScript web console.

## Start here

- Read [README.md](README.md) for the overview and quick start. Full guides live in [docs/src/content/docs/](docs/src/content/docs/), including [deployment configuration](docs/src/content/docs/reference/configuration.md) and [local development](docs/src/content/docs/maintainers/development.md).
- Read [SECURITY.md](SECURITY.md) before changes to authentication, scanning, secrets, or storage.
- Check [config.example.yaml](config.example.yaml) for deployment settings.
- Use [Makefile](Makefile), [package.json](package.json), and [CI](.github/workflows/ci.yml) as the sources for build and validation commands.
- Inspect the working tree before edits and preserve unrelated changes.

## Repository map

| Path | Responsibility |
| --- | --- |
| `cmd/edgewatch/` | CLI commands and daemon startup |
| `internal/app/` | Application coordination, scan lifecycle, and resumable work |
| `internal/config/` | Configuration validation and scanner profiles |
| `internal/scanner/` | Nmap and Naabu execution, parsing, and scan plans |
| `internal/sandbox/` | The unprivileged identities, capabilities, and Landlock restrictions scanner and notification processes start with |
| `internal/engine/` | Baseline comparison and change detection |
| `internal/model/` | Shared domain types |
| `internal/store/` | SQLite queries, migrations, history, backup, and restore |
| `internal/auth/` | Authentication and permissions |
| `internal/web/` | HTTP handlers, authorization, public status, and live updates |
| `internal/notify/` | Notification delivery and secret handling |
| `internal/rdap/`, `internal/updatecheck/` | Network metadata and release checks |
| `src/` | React pages, components, API client, types, and frontend tests |
| `internal/webui/` | Embedded frontend assets |
| `e2e/` | Playwright browser tests |
| `scripts/`, `.github/workflows/` | Build, validation, and release automation |

## Build and local development

Use the Go version in `go.mod` and the Node.js version in `.github/workflows/ci.yml`.
Run commands from the repository root.

```sh
npm ci
npm run build
go build -trimpath -o edgewatch ./cmd/edgewatch
```

`make build` installs frontend dependencies, builds the frontend, and builds the Go binary with version flags.
Build the frontend before you test behavior that depends on embedded assets.
The tracked `internal/webui/dist/.gitkeep` permits Go compilation before the frontend build.

For frontend development, run `npm run dev`.
Vite serves the console on port 5173 and proxies `/api` to a backend on `127.0.0.1:8080`.
Follow [the development guide](docs/src/content/docs/maintainers/development.md) to configure the backend.

Edit frontend source in `src/`.
Do not edit generated files in `internal/webui/dist/` or commit build output.
Preserve the tracked `.gitkeep` file.

## Validation

Choose checks that cover the changed behavior.
Add regression tests for bug fixes and changed behavior, using nearby tests as examples.
Documentation-only changes need a diff review and checks of referenced paths and commands.

| Change | Checks |
| --- | --- |
| Go code | Format changed Go files with `gofmt`; run `go vet ./...` and `go test -race -timeout=25m ./...` |
| Frontend code | `npm run lint`, `npm run build`, and `npm run test:coverage` |
| Browser behavior | `npm run test:e2e` |
| Documentation website | `npm --prefix docs ci`, `npm --prefix docs run build`, and browser review for visible changes |
| Database schema | Store migration tests and `./scripts/check-schema-docs.sh` |
| Compose configuration | Run `docker compose config --quiet` and `docker compose -f compose.yaml -f compose.syn.yaml config --quiet`, then verify the rendered capability, hardening, image, and storage policies described in `docs/src/content/docs/deployment/container-hardening.md` and the CI `Validate Compose deployment` step; build the image and run `./scripts/verify-compose-deployment.sh IMAGE`, which starts it with `compose.yaml` and requires both sandboxes enforced |
| Image packages or bundled binaries | Build the image and run `./scripts/scan-image-vulnerabilities.sh IMAGE PLATFORM`, which runs govulncheck on the bundled Naabu and Grype on the Alpine packages; pin every `apk add` package to a version that Renovate's repology manager tracks, and accept a finding only after triage, in `scripts/naabu-vulncheck-allowlist.txt` or `.grype.yaml` with its reason |
| Scanner dependency pin | `./scripts/verify-naabu-pin.sh`, then the image vulnerability scan above |
| Scanner execution or sandbox | Build the image and run `./scripts/verify-scanner-sandbox.sh IMAGE`, which needs Docker and a kernel with Landlock; it compares real sandboxed, Landlock-only, and unconfined scans of local listeners, tries Landlock escapes, and checks the seccomp filter, core limits, and a sandboxed notification delivery; CI runs it on AMD64 and ARM64 runners, and the release runs it on both against the candidate image |
| Release helper scripts | `./scripts/test-release-artifacts.sh`; this uses fixture binaries and does not build a release candidate |
| CI or release workflows | `node --test scripts/release-workflow.test.mjs`, which enforces the release gates and the supply-chain rules under "Behavior to preserve" |
| Release workflow or GoReleaser configuration | Follow the exact GoReleaser check and immutable-candidate gates in `.github/workflows/release.yml`; the candidate, publication, image, and runtime smoke gates run only for tags |

Install Chromium before the first browser test with `npx playwright install --with-deps chromium`.
The real-stack browser tests also require Go.
Browser tests build the console and serve it on `127.0.0.1:4173`; set `PLAYWRIGHT_PORT` to use another port.
If that port is already in use, the run stops before any test instead of testing whatever server is listening there.
Set `PLAYWRIGHT_REUSE_SERVER=1` only to reuse a preview of the same checkout that you started yourself; CI always starts a fresh server.

`make check` checks Go formatting, runs vet and race tests, checks frontend types, and runs `make security`.
`make security` runs pinned Go lint, `govulncheck`, and the npm audit at the high-severity threshold.
It does not replace frontend builds, frontend tests, browser tests, or container checks.
CI defines the normal pull-request gates, but tag-only release candidate, publication, image, and runtime smoke checks remain part of release validation.

Before committing, inspect `git status --short`, run `git diff --check` and `git diff --cached --check`, and review both `git diff` and `git diff --cached` for unrelated edits or generated files.
Remember that untracked files appear in status but not in either diff until added.
Report the checks you ran and any failures or checks you could not run.

## Behavior to preserve

- Use controlled listeners for integration scans and scan only authorized targets.
- Preserve target exclusions, probe budgets, cancellation, and resumable scan behavior.
- Keep scanner execution shell-free on fixed executables with validated argument arrays and `exec.CommandContext`; preserve the minimal environment, private temporary inputs and outputs, bounded diagnostic and structured output, and child termination when those bounds are exceeded.
- Start every Nmap and Naabu process through the scanner's sandbox policy (`internal/sandbox`): pass private files with `InheritFile` rather than by path, read-only or write-only as the scanner uses them, and confine the command after that, because the Landlock restriction lets a scanner reopen only the files it inherited. Confined processes keep only `NET_RAW` and `NET_ADMIN` as ambient capabilities, and the bundled Compose capability set stays exact.
- Start every notification child through `runNotificationProcess`, which confines it with the policy that `notify.SetSandbox` installed: its own identity without capabilities and the Landlock notifier profile, which writes no file.
- Keep `sandbox.HardenProcess` the first call in `main`, so no EdgeWatch process, including the scanners and the notification child it starts, can dump core.
- Keep UDP scans on Nmap and require Nmap confirmation before Naabu discoveries enter baselines or incidents.
- Preserve job profile revisions so profile edits do not silently change scheduled jobs.
- Preserve baseline state for failed or incomplete observations and retain scan history when users accept changes.
- Enforce permissions in backend handlers and test each affected role.
- Keep business unit data isolated in the application.
  Classify each new table in `tenancyTables` in `internal/store/tenancy_tables.go` and give a table with unit data its step in `tenantPurgeSteps`.
  Unit data carries `tenant_id` or inherits it from a parent row.
  A unit's requests reach it only through `TenantStore` and anonymous requests only through `PublicStore`, whose queries put the tenant predicate inline in their `WHERE` or `ON` clauses, which `TestTenantSQLLint` enforces; the daemon's work across units belongs to `SystemStore`.
  Give each exported `TenantStore` or `PublicStore` method a case in `tenantStoreLeakCases` or `publicStoreCases`.
  `PlatformStore` returns a unit only as its identity, counts, capacity, and account summaries, never its data; give each new audit action its category in `auditActionCategories`, which decides whether the platform audit shows it.
  Add each new route to `apiRoutes` in `internal/web/permissions.go` and send each live update through `broadcastTo` with an explicit audience.
  `TestIsolationMatrix` sends every route in `apiRoutes` as each role, including `platform_admin`, and requires another unit's ID to get the same response as an unknown ID; teach it any new path placeholder.
- Keep public status limited to explicitly published data and exclude private fingerprints and raw scan evidence.
- Preserve secret redaction in logs and API responses, including the write-only contract for notification URLs.
- Never commit notification URLs, authentication tokens, passwords, or encryption keys.
- Use temporary databases in tests and preserve migration compatibility, transaction boundaries, and restore checks.
  For a fresh database, use `openTestStore` in `internal/store` and `storetest.OpenFresh` or `storetest.FreshPath` elsewhere; these copy a migrated template.
  Migrate from scratch only in tests that need it, such as migration, setup, and restore tests, because a full migration takes seconds under `-race`.
- When the schema changes, update [database compatibility](docs/src/content/docs/reference/database-compatibility.md) and `SECURITY.md`.
- Keep runtime configuration, databases, keys, and generated assets out of source control.

For container changes, read [docs/src/content/docs/deployment/container-hardening.md](docs/src/content/docs/deployment/container-hardening.md).
Preserve the default capability limits and the explicit SYN override.
For release changes, preserve the immutable candidate build implemented in
`.github/workflows/release.yml`, and these workflow rules:

- A job that holds a write scope runs no npm packages; npm runs in read-only jobs that pass artifacts.
- Every `actions/checkout` step sets `persist-credentials: false`.
- The release restores no cache: the image builds with `no-cache: true`, and Go and Node run without Actions caches.
- Pin every action by commit SHA and every image that a step starts by digest, in a form that a Renovate manager in `renovate.json` updates.
- The release publishes only a commit on `main` with a passing CI run, after the vulnerability scan and the AMD64 and ARM64 smoke jobs pass.

## Change scope and pull requests

Follow the conventions in nearby code and keep each change focused on the requested behavior.
Update API types and consumers together when response shapes change.
Documentation updates are mandatory whenever a change affects documented behavior, including new features, configuration, commands, APIs, permissions, deployment, or recovery.
Update the affected guides in `docs/src/content/docs/` in the same change; the website is the canonical detailed documentation.
Update the README quick start and `SECURITY.md` when their content is affected, and run `npm --prefix docs run build`.
A change requiring documentation is not complete until its guides are updated and the corresponding website deployment is verified.

Use a concise commit subject consistent with recent history, such as `docs:`, `fix:`, or `feat:`.
Describe the resulting behavior and relevant validation in the pull request.
Call out compatibility changes and unresolved failures that affect review.
Do not commit, push, open or merge pull requests, tag, publish releases, or perform other external writes unless the user explicitly requested that action.
Keep Renovate Dependency Dashboard issue `#8` open; it is an intentionally persistent tracking issue and must not be closed during issue cleanup.
