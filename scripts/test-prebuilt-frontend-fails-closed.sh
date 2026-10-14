#!/usr/bin/env bash

# Build only the production frontend stage with PREBUILT_FRONTEND=1 and no
# generated frontend assets. It must stop at the missing-artifact check rather
# than silently falling back to npm.
set -euo pipefail

repository="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
context="$(mktemp -d)"
log="$(mktemp)"
cleanup() {
  rm -rf "$context"
  rm -f "$log"
}
trap cleanup EXIT

git -C "$repository" archive --format=tar HEAD | tar -xf - -C "$context"
# Use the checked-out candidate Dockerfile so the test can be run before the
# change is committed. The archive supplies the rest of the tracked context;
# generated internal/webui/dist assets are intentionally absent from it.
cp "$repository/Dockerfile" "$context/Dockerfile"
if [[ -e "$context/internal/webui/dist/index.html" ]]; then
  echo "test context unexpectedly contains generated frontend assets" >&2
  exit 1
fi

if docker buildx build --no-cache --progress=plain --target frontend \
  --build-arg PREBUILT_FRONTEND=1 -t edgewatch:missing-prebuilt-frontend \
  -f "$context/Dockerfile" "$context" >"$log" 2>&1; then
  echo "prebuilt frontend build unexpectedly accepted missing assets" >&2
  cat "$log" >&2
  exit 1
fi
if ! grep -Fq 'prebuilt frontend is missing index.html' "$log"; then
  echo "prebuilt frontend build failed for a reason other than the missing asset guard" >&2
  cat "$log" >&2
  exit 1
fi
printf '%s\n' 'prebuilt frontend build rejected missing assets before fallback'
