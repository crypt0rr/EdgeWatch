---
title: Architecture and contributing
description: Find the code responsible for a change and preserve scanner, storage, and authorization contracts.
---

EdgeWatch combines a Go daemon, SQLite storage, and an embedded React/TypeScript
console. Start with [Local development](/maintainers/development/) for builds
and checks. The repository's [AGENTS.md](https://github.com/crypt0rr/EdgeWatch/blob/main/AGENTS.md)
contains the detailed change rules and validation matrix.

## Code map

| Path | Responsibility |
| --- | --- |
| `cmd/edgewatch/` | CLI commands and daemon startup |
| `internal/app/` | Application coordination, scan lifecycle, and resumable work |
| `internal/config/` | Configuration validation and scanner profiles |
| `internal/scanner/` | Nmap and Naabu execution, parsing, and scan plans |
| `internal/engine/` | Baseline comparison and change detection |
| `internal/addrspace/` | Address-range arithmetic (merge, subtract, cover, pack) for perimeter coverage |
| `internal/model/` | Shared domain types |
| `internal/store/` | SQLite queries, migrations, history, backup, and restore |
| `internal/auth/` | Authentication and permissions |
| `internal/web/` | HTTP handlers, authorization, public status, and live updates |
| `internal/apitypes/` | TypeScript declarations of the API response structs |
| `internal/notify/` | Notification delivery and secret handling |
| `internal/rdap/`, `internal/updatecheck/` | Network metadata and release checks |
| `src/` | Console pages, components, API client, types, and tests |
| `src/generated/` | API types generated from the Go response structs, committed |
| `internal/webui/` | Embedded console assets |
| `e2e/` | Browser tests |
| `scripts/`, `.github/workflows/` | Build, validation, and release automation |
| `docs/` | Starlight website and user, operator, and maintainer guides |

## Preserve the application contracts

- Keep scanner execution shell-free on fixed executables with validated arguments,
  bounded output, cancellation, target exclusions, and probe budgets.
- Keep UDP on Nmap and require Nmap confirmation of Naabu discoveries.
- Preserve profile revisions and resumable scan settings. Failed and incomplete
  observations must not alter the expected surface.
- Enforce role and business-unit permissions in backend handlers and stores;
  cover affected roles and isolation cases. Filter live updates by audience.
- Keep credentials write-only and redacted, and public status limited to
  explicitly published data.
- Preserve migration compatibility, transaction boundaries, and safe restore
  behavior. Use temporary databases in tests.

The [security policy](https://github.com/crypt0rr/EdgeWatch/blob/main/SECURITY.md)
contains the exact security and session-revocation guarantees.

## Submit a focused change

Inspect the working tree and preserve unrelated work. Follow nearby conventions,
update API types and consumers together, and document visible behavior changes
in the relevant guide. When a response struct that `src/generated/api-types.ts`
is generated from changes, regenerate the file with
`go run ./scripts/gen-api-types` and commit it; see
[Generated API types](/maintainers/development/#generated-api-types).
Add regression coverage for bugs and changed behavior.
Run the checks appropriate to the change from [Local development](/maintainers/development/)
and the agent guide.

Use a concise commit subject consistent with history, such as `docs:`, `fix:`,
or `feat:`. Describe the resulting behavior and validation in the pull request,
including compatibility changes and any unresolved failures. Review the diff
for secrets, unrelated edits, and generated assets before committing.

Pull request titles become the default squash-merge subjects and appear in
release notes. Start each title with `feat`, `fix`, `perf`, `test`, `docs`,
`chore`, `refactor`, `ci`, or `build`, optionally followed by a nonempty scope
in parentheses, then a colon and a space. CI checks the title when a pull
request is opened or edited.

## Required documentation updates

Documentation updates are mandatory when a change introduces a feature or
changes documented behavior. This includes configuration, commands, APIs,
permissions, deployment, scanning, notifications, and backup or recovery.

Update the affected guides in `docs/src/content/docs/` in the same pull request
as the implementation. The website is the canonical detailed documentation;
update the README quick start and `SECURITY.md` too when their content changes.
Run `npm --prefix docs run build` and review the branch preview before merging.
After merging, verify that the Pages production deployment contains the updated
guides. A change requiring documentation is not complete until the guides and
website are updated. Describe the documentation changes and validation in the
pull request.

## Release automation

The [release workflow](https://github.com/crypt0rr/EdgeWatch/blob/main/.github/workflows/release.yml)
is the authority for release validation and publication. It builds one immutable
candidate, which downstream publication and smoke jobs consume. Preserve this
contract when changing release automation; normal pull-request checks do not
replace the tag-only candidate, image, publication, and runtime smoke gates.

Tag only a commit on `main` whose CI passed. The workflow refuses any other
tag before it builds anything, and waits for CI on the tagged commit before
it stages a release. A later push to `main` can cancel that commit's CI run;
re-run it, or run CI on the tag with `gh workflow run ci.yml --ref <tag>`.
When a dispatched run has no pull-request or push base, Go lint uses the
merge base with fetched `origin/main`, then falls back to the selected
commit's first parent. If neither provides a non-`HEAD` base, it fails clearly
instead of reporting an empty lint diff.

The Dockerfile keeps `npm ci` and the frontend build in its local-build path.
Release image builds copy the verified frontend artifact from the candidate;
they fail if that artifact has no `index.html` instead of rebuilding it.
Before the release is published and the image is promoted, the workflow:

- builds the image from scratch, without registry or Actions caches, with
  BuildKit, QEMU and the SBOM generator pinned by digest;
- rebuilds the candidate's AMD64 and ARM64 Go binaries with GoReleaser in a
  separate job that runs no npm code, then compares both binaries byte for byte
  with the immutable candidate before packaging;
- records each Linux archive's `edgewatch` member digest in schema 2 of
  `release-manifest.json`, compares the staged per-architecture executable to
  that archive member, and compares the executable copied from each candidate
  image to the same digest;
- scans both platforms of the image for known vulnerabilities;
- runs the AMD64 image and archive on an AMD64 runner and the ARM64 image and
  archive on an ARM64 runner, including the runtime matrix, the real sandboxed
  scans, and the bundled `compose.yaml`.

`scripts/release-workflow.test.mjs` enforces these gates and the supply-chain
rules of both workflows: a job that holds a write scope runs no npm packages;
the scripts reachable from those jobs also run no npm packages; every action
is pinned to a 40-character commit SHA; no checkout keeps the job token; the
release restores no cache; and every image that a workflow step or the scan
script starts is pinned by digest, in a form that Renovate updates. CI runs it,
and so does the release; run `node --test scripts/release-workflow.test.mjs`
after changing a workflow.

The release npm guard roots its Dockerfile stage graph at the target configured
on the exact image build action, or at the final stage when no target is set.
It analyzes the file selected by that action and requires the repository-root
context (`context: .`) with the default `Dockerfile` or explicit
`file: Dockerfile`. Dynamic or alternate contexts and files, and an unexpected
inline Dockerfile input, fail closed. The test accepts only the reviewed plain
build-step fields and action-input keys, plus the literal `build-args` block;
quoted keys or values, flow syntax, anchors, merge keys, duplicate fields or
inputs, and unexpected indentation fail closed.
It follows stage inheritance, `COPY --from`, and `RUN --mount=from`. For every
reachable stage, the test approves the exact ordered list of complete `RUN`
instructions in the current Dockerfile. An added, removed, reordered,
duplicated, or changed reachable `RUN` fails closed, even when its command does
not mention npm. The test resolves the two reviewed release conditionals using
the build arguments from that image action and checks stage `ARG` defaults and
values against their allowed forms. A reachable `ENV` or `SHELL`, a global
`ARG`, or a dynamic base or stage dependency also fails closed. Triggered
`ONBUILD` instructions fail because they can add commands or hidden stage
dependencies; an untriggered `ONBUILD` remains dormant in that build.

This is a static contract for the checked-in Dockerfile, target, and build
arguments, including the pinned Dockerfile syntax directive. It does not
emulate a general shell, resolve bare command names
through `PATH`, parse copied scripts, inspect binaries, or protect against a
malicious pinned base image or executable replacement. It relies on the pinned
stage images and does not prove BuildKit isolation. Any change to a reachable
`RUN`, its `ARG` declarations, or the image build target needs a matching guard
review and regression case.

The same checks keep dependency provenance current. Renovate reads the
golangci-lint pin from `.golangci-lint-version` using GitHub Releases, and its
Alpine package manager must match every Alpine minor version used by the
Dockerfile. The workflow test parses continued `apk add` commands so every
package stays version-pinned and Renovate-managed. It also compares the bundled
Naabu version and immutable commit in `THIRD_PARTY_LICENSES.md` with the
Dockerfile arguments. The release manifest takes its GoReleaser version from
the release workflow's canonical pin; an explicit `GORELEASER_VERSION` must
match that pin or manifest generation fails.

CI's Go jobs and GoReleaser, which builds the release binaries, use the Go
release that the `go` line in `go.mod` names. The Dockerfile's `golang` images
build Naabu, and build EdgeWatch in every image build without
`PREBUILT_EDGEWATCH=1`, such as CI's multi-platform and native ARM64 images;
the release image ships the GoReleaser binaries instead. The workflow test
requires `go.mod`, both `golang` images, and the minimum Go version in
[Local development](/maintainers/development/) to name the same release.
Renovate bumps the `go` line, which it leaves alone by default, and proposes
all of them in one `Go toolchain` pull request. That pull request fails the
test until it contains every part, for example while the `golang` image for a
new Go release is not yet published.

The Dockerfile's `node` image sets the Node.js release. The workflow test
requires every `setup-node` pin, the release workflow's `NODE_VERSION`,
`.node-version`, and the pin in [Local development](/maintainers/development/)
to name the same release. Renovate proposes each Node 24 release for all of
them in one `Node.js runtime` pull request. Its group matches the dependency
name `node`, because Renovate looks `setup-node` versions up as the package
`actions/node-versions`. Those versions, the `node` image, and the nodejs.org
releases behind `.node-version` publish separately, so that pull request can
first change only some of the pins and fail the test until the last of them
is published.

For release helper scripts, run `./scripts/test-release-artifacts.sh`; it uses
fixture binaries and does not build a release candidate. Follow the workflow's
exact GoReleaser and candidate gates when changing release configuration.
Its opening comments explain how to retry failed publication jobs while retaining
the verified candidate.

### Vulnerability scan failures

`scripts/scan-image-vulnerabilities.sh IMAGE PLATFORM` runs in CI's
`container` job, in the release, and every day on the published image. It
exports the image's filesystem without starting the image and fails when:

- govulncheck finds a vulnerable symbol in the bundled Naabu that
  `scripts/naabu-vulncheck-allowlist.txt` does not accept. Renovate proposes
  each Naabu release; update when one removes the finding. Otherwise, triage
  it and add its OSV ID to the allowlist with the module, the fixed version,
  and why it is accepted. The scan names allowlisted IDs that it no longer
  finds, so they can be removed;
- Grype finds a vulnerability of high or critical severity in an Alpine
  package that a newer package fixes. Pin the fixed version in the
  Dockerfile's `apk add` line and add the package to the repology manager in
  `renovate.json`, which the workflow test requires for every pin. Accept a
  finding only after triage, with a narrow ignore rule and its reason in
  `.grype.yaml`.

Grype ignores Go modules because govulncheck checks the Go binaries more
precisely. `make vulncheck` checks EdgeWatch's own module and the standard
library of the Go version that runs it.

### Scheduled checks

The `Scheduled checks` workflow runs every day and on demand. It checks what
changes outside the repository, so it can fail without a new commit:

- `./scripts/check-apk-pins.sh` compares every `apk add` pin in the Dockerfile
  with the current Alpine package index for x86_64 and aarch64. A stable
  Alpine branch keeps only the newest build of each package and removes the
  pinned build when it publishes an update. CI keeps passing because its image
  builds reuse a cached layer, but the release builds without a cache and
  fails. When the check fails, update each stale pin to the version it lists;
  Renovate proposes the same update once Repology lists it;
- the vulnerability scan runs on both platforms of the published `latest`
  image, so a finding in the bundled Naabu or the Alpine packages that is
  published after a release fails the run. Fix or triage the finding as
  described above, then publish a patch release;
- `make vulncheck` runs on the source of the latest published release, with
  the Go version in that release's `go.mod`, which built its binaries. A new
  advisory for a module EdgeWatch calls or for that Go release fails the run.
  Update the module, or move `go.mod`, the Dockerfile's `golang` images, and
  the development guide to the fixed Go release, then publish a patch release.

Before you tag a release, run `./scripts/check-apk-pins.sh` or start the
workflow with `gh workflow run scheduled.yml`. GitHub reports a failed
scheduled run to whoever last changed its schedule.

For documentation changes, follow [Documentation and hosting](/maintainers/documentation/).
