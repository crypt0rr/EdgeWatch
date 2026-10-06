---
title: Architecture and contributing
description: Find the code responsible for a change and preserve scanner, storage, and authorization contracts.
---

EdgeWatch combines a Go daemon, SQLite storage, and an embedded React/TypeScript
console. Start with [Local development](/maintainers/development/) for builds
and checks. The repository's [AGENTS.md](https://github.com/crypt0rr/EdgeWatch/blob/docs/website-preview/AGENTS.md)
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
| `internal/notify/` | Notification delivery and secret handling |
| `internal/rdap/`, `internal/updatecheck/` | Network metadata and release checks |
| `src/` | Console pages, components, API client, types, and tests |
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

The [security policy](https://github.com/crypt0rr/EdgeWatch/blob/docs/website-preview/SECURITY.md)
contains the exact security and session-revocation guarantees.

## Submit a focused change

Inspect the working tree and preserve unrelated work. Follow nearby conventions,
update API types and consumers together, and document visible behavior changes
in the relevant guide. Add regression coverage for bugs and changed behavior.
Run the checks appropriate to the change from [Local development](/maintainers/development/)
and the agent guide.

Use a concise commit subject consistent with history, such as `docs:`, `fix:`,
or `feat:`. Describe the resulting behavior and validation in the pull request,
including compatibility changes and any unresolved failures. Review the diff
for secrets, unrelated edits, and generated assets before committing.

## Release automation

The [release workflow](https://github.com/crypt0rr/EdgeWatch/blob/docs/website-preview/.github/workflows/release.yml)
is the authority for release validation and publication. It builds one immutable
candidate, which downstream publication and smoke jobs consume. Preserve this
contract when changing release automation; normal pull-request checks do not
replace the tag-only candidate, image, publication, and runtime smoke gates.

For release helper scripts, run `./scripts/test-release-artifacts.sh`; it uses
fixture binaries and does not build a release candidate. Follow the workflow's
exact GoReleaser and candidate gates when changing release configuration.
Its opening comments explain how to retry failed publication jobs while retaining
the verified candidate.

For documentation changes, follow [Documentation and hosting](/maintainers/documentation/).
