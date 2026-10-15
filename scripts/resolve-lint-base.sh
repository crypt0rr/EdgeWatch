#!/usr/bin/env bash
set -euo pipefail

resolve_commit() {
  local object
  object="$(git rev-parse --verify --quiet --end-of-options "$1" 2>/dev/null)" || return 1
  git rev-parse --verify --quiet "${object}^{commit}" 2>/dev/null
}

head_commit="$(resolve_commit HEAD)" || {
  echo "could not resolve HEAD for golangci-lint" >&2
  exit 1
}

base_commit=""
requested_base="${GOLANGCI_LINT_BASE:-}"
if [[ -n "$requested_base" ]]; then
  base_commit="$(resolve_commit "$requested_base" || true)"
fi

# An empty CI event field, an unavailable push-before object, or a base equal
# to HEAD must not turn golangci-lint into an empty-diff success. Try the
# fetched main merge base, then the commit's parent for dispatch/detached runs.
if [[ -z "$base_commit" || "$base_commit" == "$head_commit" ]]; then
  base_commit="$(git merge-base HEAD origin/main 2>/dev/null || true)"
fi
if [[ -z "$base_commit" || "$base_commit" == "$head_commit" ]]; then
  base_commit="$(resolve_commit 'HEAD^' || true)"
fi
if [[ -z "$base_commit" || "$base_commit" == "$head_commit" ]]; then
  echo "could not find a non-HEAD golangci-lint base; HEAD must have a parent commit" >&2
  exit 1
fi

printf '%s\n' "$base_commit"
