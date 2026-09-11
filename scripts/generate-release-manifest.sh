#!/usr/bin/env bash

# Generate the immutable manifest shared by the release binaries and image.
# The manifest intentionally contains hashes and build inputs only; it never
# includes source contents or credentials.
set -euo pipefail

tag="${1:?usage: $0 <tag> [manifest-path]}"
manifest="${2:-dist/release-manifest.json}"

if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?$ ]]; then
  echo "invalid release tag: $tag" >&2
  exit 1
fi

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
command -v node >/dev/null || { echo "node is required" >&2; exit 1; }
command -v go >/dev/null || { echo "go is required" >&2; exit 1; }

version="${tag#v}"
commit="$(git rev-parse HEAD)"
go_version="$(go env GOVERSION)"
node_version="$(node --version)"
goreleaser_version="${GORELEASER_VERSION:-v2.18.0}"
repository="${GITHUB_REPOSITORY:-crypt0rr/EdgeWatch}"
naabu_version="$(awk '$1 == "ARG" && $2 ~ /^NAABU_VERSION=/ { sub(/^NAABU_VERSION=/, "", $2); print $2; exit }' Dockerfile)"
naabu_commit="$(awk '$1 == "ARG" && $2 ~ /^NAABU_COMMIT=/ { sub(/^NAABU_COMMIT=/, "", $2); print $2; exit }' Dockerfile)"

if [[ -z "$naabu_version" || -z "$naabu_commit" ]]; then
  echo "could not read the pinned Naabu inputs from Dockerfile" >&2
  exit 1
fi

if [[ ! -f internal/webui/dist/index.html ]]; then
  echo "frontend assets are missing; run the production frontend build first" >&2
  exit 1
fi

# Hash the ordered path/hash stream so the exact embedded frontend can be
# compared by downstream jobs without storing generated files in Git.
frontend_hash="$({
  while IFS= read -r -d '' file; do
    relative="${file#internal/webui/dist/}"
    printf '%s  ' "$relative"
    sha256sum "$file"
  done < <(find internal/webui/dist -type f -print0 | LC_ALL=C sort -z)
} | sha256sum | awk '{print $1}')"

artifact_json='[]'
for artifact in dist/*.tar.gz dist/checksums.txt; do
  [[ -f "$artifact" ]] || continue
  name="$(basename "$artifact")"
  sha256="$(sha256sum "$artifact" | awk '{print $1}')"
  size="$(stat -c '%s' "$artifact")"
  artifact_json="$(jq -c --arg name "$name" --arg sha256 "$sha256" --argjson size "$size" '. + [{name: $name, sha256: $sha256, size: $size}]' <<<"$artifact_json")"
done

if [[ "$artifact_json" == '[]' ]]; then
  echo "no release artifacts found in dist" >&2
  exit 1
fi

mkdir -p "$(dirname "$manifest")"
tmp="${manifest}.tmp"
jq -n \
  --arg schema_version "1" \
  --arg repository "$repository" \
  --arg tag "$tag" \
  --arg version "$version" \
  --arg commit "$commit" \
  --arg go_version "$go_version" \
  --arg node_version "$node_version" \
  --arg goreleaser_version "$goreleaser_version" \
  --arg naabu_version "$naabu_version" \
  --arg naabu_commit "$naabu_commit" \
  --arg frontend_sha256 "$frontend_hash" \
  --argjson artifacts "$artifact_json" \
  '{schema_version: ($schema_version | tonumber), repository: $repository, tag: $tag, version: $version, source_commit: $commit, toolchain: {go: $go_version, node: $node_version, goreleaser: $goreleaser_version}, dependencies: {naabu_version: $naabu_version, naabu_commit: $naabu_commit}, frontend_sha256: $frontend_sha256, artifacts: $artifacts}' \
  > "$tmp"
mv "$tmp" "$manifest"
printf 'release manifest: %s (%s)\n' "$manifest" "$commit"
