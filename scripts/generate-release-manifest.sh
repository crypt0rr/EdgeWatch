#!/usr/bin/env bash

# Generate the immutable manifest shared by the release binaries and image.
# The manifest intentionally contains hashes and build inputs only; it never
# includes source contents or credentials.
set -euo pipefail

tag="${1:?usage: $0 <tag> [manifest-path]}"
dist_dir="${DIST_DIR:-dist}"
frontend_dist="${FRONTEND_DIST:-internal/webui/dist}"
binary_dir="${RELEASE_BINARIES:-release-binaries}"
manifest="${2:-$dist_dir/release-manifest.json}"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd -- "$script_dir/.." && pwd)"
release_workflow="$repository_root/.github/workflows/release.yml"
dockerfile="$repository_root/Dockerfile"

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
goreleaser_version="$(awk '
  $1 == "GORELEASER_VERSION:" {
    count++
    if (NF != 2 || $2 !~ /^v?[0-9]+\.[0-9]+\.[0-9]+$/) invalid = 1
    version = $2
  }
  END {
    if (count != 1 || invalid) exit 1
    print version
  }
' "$release_workflow")" || {
  echo "expected exactly one valid GORELEASER_VERSION in .github/workflows/release.yml" >&2
  exit 1
}
if [[ ${GORELEASER_VERSION+x} == x && "$GORELEASER_VERSION" != "$goreleaser_version" ]]; then
  printf 'GORELEASER_VERSION=%s does not match .github/workflows/release.yml pin %s\n' \
    "$GORELEASER_VERSION" "$goreleaser_version" >&2
  exit 1
fi
repository="${GITHUB_REPOSITORY:-crypt0rr/EdgeWatch}"
naabu_version="$(awk '$1 == "ARG" && $2 ~ /^NAABU_VERSION=/ { sub(/^NAABU_VERSION=/, "", $2); print $2; exit }' "$dockerfile")"
naabu_commit="$(awk '$1 == "ARG" && $2 ~ /^NAABU_COMMIT=/ { sub(/^NAABU_COMMIT=/, "", $2); print $2; exit }' "$dockerfile")"
naabu_x_net_version="$(awk '$1 == "ARG" && $2 ~ /^NAABU_X_NET_VERSION=/ { sub(/^NAABU_X_NET_VERSION=/, "", $2); print $2; exit }' "$dockerfile")"
naabu_goldmark_version="$(awk '$1 == "ARG" && $2 ~ /^NAABU_GOLDMARK_VERSION=/ { sub(/^NAABU_GOLDMARK_VERSION=/, "", $2); print $2; exit }' "$dockerfile")"
naabu_compress_version="$(awk '$1 == "ARG" && $2 ~ /^NAABU_COMPRESS_VERSION=/ { sub(/^NAABU_COMPRESS_VERSION=/, "", $2); print $2; exit }' "$dockerfile")"

if [[ -z "$naabu_version" || -z "$naabu_commit" \
  || ! "$naabu_x_net_version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ \
  || ! "$naabu_goldmark_version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ \
  || ! "$naabu_compress_version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "could not read the pinned Naabu inputs and module versions from Dockerfile" >&2
  exit 1
fi

if [[ ! -f "$frontend_dist/index.html" ]]; then
  echo "frontend assets are missing; run the production frontend build first" >&2
  exit 1
fi

# Hash the ordered path/hash stream so the exact embedded frontend can be
# compared by downstream jobs without storing generated files in Git.
frontend_hash="$({
  while IFS= read -r -d '' file; do
    relative="${file#"$frontend_dist"/}"
    digest="$(sha256sum "$file" | awk '{print $1}')"
    printf '%s  %s\n' "$relative" "$digest"
  done < <(find "$frontend_dist" -type f ! -name '.gitkeep' -print0 | LC_ALL=C sort -z)
} | sha256sum | awk '{print $1}')"

artifact_json='[]'
for artifact in "$dist_dir"/*.tar.gz "$dist_dir"/checksums.txt; do
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

binary_json='[]'
declare -A binary_arch_seen=()
for archive in "$dist_dir"/*.tar.gz; do
  [[ -f "$archive" ]] || continue
  name="$(basename "$archive")"
  case "$name" in
    *_Linux_x86_64.tar.gz|*_linux_amd64.tar.gz|*_Linux_amd64.tar.gz) arch=amd64 ;;
    *_Linux_arm64.tar.gz|*_linux_arm64.tar.gz) arch=arm64 ;;
    *) echo "unsupported release archive: $name" >&2; exit 1 ;;
  esac
  if [[ -n "${binary_arch_seen[$arch]:-}" ]]; then
    echo "multiple release archives found for linux/$arch" >&2
    exit 1
  fi
  binary_arch_seen[$arch]=1

  binary_info="$("$script_dir/hash-release-binary.sh" "$archive")"
  IFS=$'\t' read -r member archive_sha256 <<< "$binary_info"
  extracted_binary="$binary_dir/linux_$arch/edgewatch"
  if [[ ! -f "$extracted_binary" || -L "$extracted_binary" || ! -x "$extracted_binary" ]]; then
    echo "prepared release binary is missing or invalid: $extracted_binary" >&2
    exit 1
  fi
  extracted_sha256="$(sha256sum "$extracted_binary" | awk '{print $1}')"
  if [[ "$extracted_sha256" != "$archive_sha256" ]]; then
    echo "prepared release binary does not match archive member: $name" >&2
    exit 1
  fi
  binary_json="$(jq -c --arg arch "$arch" --arg archive "$name" --arg member "$member" --arg sha256 "$archive_sha256" '. + [{arch: $arch, archive: $archive, member: $member, sha256: $sha256}]' <<<"$binary_json")"
done
for arch in amd64 arm64; do
  if [[ -z "${binary_arch_seen[$arch]:-}" ]]; then
    echo "release archive missing for linux/$arch" >&2
    exit 1
  fi
done

mkdir -p "$(dirname "$manifest")"
tmp="${manifest}.tmp"
jq -n \
  --arg schema_version "2" \
  --arg repository "$repository" \
  --arg tag "$tag" \
  --arg version "$version" \
  --arg commit "$commit" \
  --arg go_version "$go_version" \
  --arg node_version "$node_version" \
  --arg goreleaser_version "$goreleaser_version" \
  --arg naabu_version "$naabu_version" \
  --arg naabu_commit "$naabu_commit" \
  --arg naabu_x_net_version "$naabu_x_net_version" \
  --arg naabu_goldmark_version "$naabu_goldmark_version" \
  --arg naabu_compress_version "$naabu_compress_version" \
  --arg frontend_sha256 "$frontend_hash" \
  --argjson artifacts "$artifact_json" \
  --argjson binaries "$binary_json" \
  '{schema_version: ($schema_version | tonumber), repository: $repository, tag: $tag, version: $version, source_commit: $commit, toolchain: {go: $go_version, node: $node_version, goreleaser: $goreleaser_version}, dependencies: {naabu_version: $naabu_version, naabu_commit: $naabu_commit, naabu_x_net_version: $naabu_x_net_version, naabu_goldmark_version: $naabu_goldmark_version, naabu_compress_version: $naabu_compress_version}, frontend_sha256: $frontend_sha256, binaries: $binaries, artifacts: $artifacts}' \
  > "$tmp"
mv "$tmp" "$manifest"
printf 'release manifest: %s (%s)\n' "$manifest" "$commit"
