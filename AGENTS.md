# Agent guide for EdgeWatch

EdgeWatch schedules network scans, records baselines, and sends Shoutrrr notifications when the observed network surface changes.
It uses a Go backend, SQLite storage, and a React/TypeScript web console.

## Start here

- Read [README.md](README.md) for product behavior, deployment, and development requirements.
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
Follow the README to configure the backend.

Edit frontend source in `src/`.
Do not edit generated files in `internal/webui/dist/` or commit build output.
Preserve the tracked `.gitkeep` file.

## Validation

Choose checks that cover the changed behavior.
Add regression tests for bug fixes and changed behavior, using nearby tests as examples.
Documentation-only changes need a diff review and checks of referenced paths and commands.

| Change | Checks |
| --- | --- |
| Go code | Format changed Go files with `gofmt`; run `go vet ./...` and `go test -race ./...` |
| Frontend code | `npm run lint`, `npm run build`, and `npm run test:coverage` |
| Browser behavior | `npm run test:e2e` |
| Database schema | Store migration tests and `./scripts/check-schema-docs.sh` |
| Compose configuration | `docker compose config --quiet` and `docker compose -f compose.yaml -f compose.syn.yaml config --quiet` |
| Scanner dependency pin | `./scripts/verify-naabu-pin.sh` |
| Release artifacts | `./scripts/test-release-artifacts.sh` |

Install Chromium before the first browser test with `npx playwright install --with-deps chromium`.
The real-stack browser tests also require Go.

`make check` checks Go formatting, runs vet and race tests, checks frontend types, and runs `make security`.
`make security` runs pinned Go lint, `govulncheck`, and the npm audit at the high-severity threshold.
It does not replace frontend builds, frontend tests, browser tests, or container checks.
CI defines the complete checks for pull requests.

Before committing, run `git diff --check` and review the diff for unrelated edits or generated files.
Report the checks you ran and any failures or checks you could not run.

## Behavior to preserve

- Use controlled listeners for integration scans and scan only authorized targets.
- Preserve target exclusions, probe budgets, cancellation, and resumable scan behavior.
- Keep scanner execution on fixed executables with validated argument arrays and `exec.CommandContext`.
- Keep UDP scans on Nmap and require Nmap confirmation before Naabu discoveries enter baselines or incidents.
- Preserve job profile revisions so profile edits do not silently change scheduled jobs.
- Preserve baseline state for failed or incomplete observations and retain scan history when users accept changes.
- Enforce permissions in backend handlers and test each affected role.
- Keep public status limited to explicitly published data and exclude private fingerprints and raw scan evidence.
- Preserve secret redaction in logs and API responses, including the write-only contract for notification URLs.
- Never commit notification URLs, authentication tokens, passwords, or encryption keys.
- Use temporary databases in tests and preserve migration compatibility, transaction boundaries, and restore checks.
- When the schema changes, update compatibility guidance in both `README.md` and `SECURITY.md`.
- Keep runtime configuration, databases, keys, and generated assets out of source control.

For container changes, read [docs/container-hardening.md](docs/container-hardening.md).
Preserve the default capability limits and the explicit SYN override.
For release changes, preserve the immutable candidate build described in the README and `.github/workflows/release.yml`.

## Change scope and pull requests

Follow the conventions in nearby code and keep each change focused on the requested behavior.
Update API types and consumers together when response shapes change.
Update operator documentation when configuration, commands, or visible behavior changes.

Use a concise commit subject consistent with recent history, such as `docs:`, `fix:`, or `feat:`.
Describe the resulting behavior and relevant validation in the pull request.
Call out compatibility changes and unresolved failures that affect review.
