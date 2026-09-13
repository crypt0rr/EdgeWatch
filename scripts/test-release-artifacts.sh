#!/usr/bin/env bash

# Deterministic contract test for the release helper scripts. It uses tiny
# fixture binaries so CI can exercise checksum/manifest coverage without
# building a second release candidate.
set -euo pipefail

root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT
mkdir -p "$root/dist/edgewatch_0.0.0_Linux_x86_64" "$root/dist/edgewatch_0.0.0_Linux_arm64"

for arch in x86_64 arm64; do
  printf '#!/bin/sh\nexit 0\n' > "$root/dist/edgewatch_0.0.0_Linux_$arch/edgewatch"
  chmod 0755 "$root/dist/edgewatch_0.0.0_Linux_$arch/edgewatch"
  tar -czf "$root/dist/edgewatch_0.0.0_Linux_$arch.tar.gz" -C "$root/dist" "edgewatch_0.0.0_Linux_$arch"
done

(cd "$root/dist" && sha256sum -- *.tar.gz > checksums.txt)
artifacts='[]'
for artifact in "$root/dist"/*.tar.gz "$root/dist"/checksums.txt; do
  name="$(basename "$artifact")"
  sha256="$(sha256sum "$artifact" | awk '{print $1}')"
  size="$(stat -c '%s' "$artifact")"
  artifacts="$(jq -c --arg name "$name" --arg sha256 "$sha256" --argjson size "$size" '. + [{name:$name,sha256:$sha256,size:$size}]' <<<"$artifacts")"
done
jq -n --arg tag v0.0.0 --arg commit "fixture-commit" --argjson artifacts "$artifacts" \
  '{schema_version:1,tag:$tag,source_commit:$commit,frontend_sha256:("a"*64),artifacts:$artifacts}' \
  > "$root/dist/release-manifest.json"

./scripts/prepare-release-binaries.sh "$root/dist" "$root/release-binaries"
./scripts/verify-release-artifacts.sh "$root/dist" "$root/dist/release-manifest.json" v0.0.0 fixture-commit
test -x "$root/release-binaries/linux_amd64/edgewatch"
test -x "$root/release-binaries/linux_arm64/edgewatch"

# Keep the verifier's contract covered by deterministic corrupted fixtures as
# well as the valid fixture above. Each mutation is isolated so a newly
# weakened validation rule makes exactly one case pass unexpectedly.
cases="$root/cases"
mkdir -p "$cases"

expect_rejected() {
  local name="$1"
  shift
  local case_dir="$cases/$name"
  cp -a "$root/dist" "$case_dir"
  "$@" "$case_dir"
  if ./scripts/verify-release-artifacts.sh "$case_dir" "$case_dir/release-manifest.json" v0.0.0 fixture-commit >"$case_dir/verify.log" 2>&1; then
    echo "negative release-artifact case passed unexpectedly: $name" >&2
    cat "$case_dir/verify.log" >&2
    exit 1
  fi
  printf 'negative case rejected: %s\n' "$name"
}

remove_checksums() { rm "$1/checksums.txt"; }
remove_manifest() { rm "$1/release-manifest.json"; }
remove_archives() { rm "$1"/*.tar.gz; }
remove_checksum_entry() { sed -i '$d' "$1/checksums.txt"; }
duplicate_checksum_entry() {
  local file="$1/checksums.txt"
  local first
  first="$(head -n 1 "$file")"
  sed -i "2c\\$first" "$file"
}
corrupt_checksum_digest() {
  sed -i '1s/^[0-9a-f]*/0000000000000000000000000000000000000000000000000000000000000000/' "$1/checksums.txt"
}
corrupt_manifest_schema() {
  jq '.schema_version = 2' "$1/release-manifest.json" >"$1/manifest.tmp"
  mv "$1/manifest.tmp" "$1/release-manifest.json"
}
corrupt_manifest_tag() {
  jq '.tag = "v9.9.9"' "$1/release-manifest.json" >"$1/manifest.tmp"
  mv "$1/manifest.tmp" "$1/release-manifest.json"
}
corrupt_manifest_commit() {
  jq '.source_commit = "wrong-commit"' "$1/release-manifest.json" >"$1/manifest.tmp"
  mv "$1/manifest.tmp" "$1/release-manifest.json"
}
corrupt_manifest_frontend_hash() {
  jq '.frontend_sha256 = "not-a-hash"' "$1/release-manifest.json" >"$1/manifest.tmp"
  mv "$1/manifest.tmp" "$1/release-manifest.json"
}
remove_manifest_artifact() {
  jq '.artifacts = .artifacts[:-1]' "$1/release-manifest.json" >"$1/manifest.tmp"
  mv "$1/manifest.tmp" "$1/release-manifest.json"
}
duplicate_manifest_artifact() {
  jq '.artifacts[1].name = .artifacts[0].name' "$1/release-manifest.json" >"$1/manifest.tmp"
  mv "$1/manifest.tmp" "$1/release-manifest.json"
}
corrupt_manifest_hash() {
  jq '.artifacts[0].sha256 = "0000000000000000000000000000000000000000000000000000000000000000"' "$1/release-manifest.json" >"$1/manifest.tmp"
  mv "$1/manifest.tmp" "$1/release-manifest.json"
}
corrupt_manifest_size() {
  jq '.artifacts[0].size += 1' "$1/release-manifest.json" >"$1/manifest.tmp"
  mv "$1/manifest.tmp" "$1/release-manifest.json"
}

expect_rejected missing-checksums remove_checksums
expect_rejected missing-manifest remove_manifest
expect_rejected no-archives remove_archives
expect_rejected checksum-coverage remove_checksum_entry
expect_rejected duplicate-checksum duplicate_checksum_entry
expect_rejected checksum-integrity corrupt_checksum_digest
expect_rejected manifest-schema corrupt_manifest_schema
expect_rejected manifest-tag corrupt_manifest_tag
expect_rejected manifest-commit corrupt_manifest_commit
expect_rejected manifest-frontend-hash corrupt_manifest_frontend_hash
expect_rejected manifest-count remove_manifest_artifact
expect_rejected manifest-duplicate duplicate_manifest_artifact
expect_rejected manifest-hash corrupt_manifest_hash
expect_rejected manifest-size corrupt_manifest_size
