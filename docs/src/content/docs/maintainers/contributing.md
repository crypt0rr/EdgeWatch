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
no checkout keeps the job token; the release restores no cache; and every
image that a workflow step or the scan script starts is pinned by digest, in
a form that Renovate updates. CI runs it, and so does the release; run
`node --test scripts/release-workflow.test.mjs` after changing a workflow.

The release npm guard roots its Dockerfile stage graph at the target configured
on the exact image build action, or at the final stage when no target is set.
It follows stage inheritance, `COPY --from`, and `RUN --mount=from`, and
resolves static `ARG` and `ENV` values used by reachable `RUN` commands.
Triggered `ONBUILD` instructions are rejected conservatively because their
execution can add commands or hidden stage dependencies. The guard examines
inline command text; it does not parse build-context scripts, so reachable
explicit shell, source, or direct local-script execution fails closed. An
untriggered `ONBUILD` instruction remains dormant in that build. The guard
allows only the Dockerfile's reviewed `git rev-parse` and Go ELF-interpreter
command substitutions; other `$()`, backtick, or process-substitution syntax
fails closed anywhere in a reachable `RUN`, including arguments. This is a
bounded policy check rather than a general shell parser.

The same checks keep dependency provenance current. Renovate reads the
golangci-lint pin from `.golangci-lint-version` using GitHub Releases, and its
Alpine package manager must match every Alpine minor version used by the
Dockerfile. The workflow test parses continued `apk add` commands so every
package stays version-pinned and Renovate-managed. It also compares the bundled
Naabu version and immutable commit in `THIRD_PARTY_LICENSES.md` with the
Dockerfile arguments. The release manifest takes its GoReleaser version from
the release workflow's canonical pin; an explicit `GORELEASER_VERSION` must
match that pin or manifest generation fails.

For release helper scripts, run `./scripts/test-release-artifacts.sh`; it uses
fixture binaries and does not build a release candidate. Follow the workflow's
exact GoReleaser and candidate gates when changing release configuration.
Its opening comments explain how to retry failed publication jobs while retaining
the verified candidate.

### Vulnerability scan failures

`scripts/scan-image-vulnerabilities.sh IMAGE PLATFORM` runs in CI's
`container` job and in the release. It exports the image's filesystem without
starting the image and fails when:

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
precisely. `make vulncheck` checks EdgeWatch's own module.

For documentation changes, follow [Documentation and hosting](/maintainers/documentation/).
