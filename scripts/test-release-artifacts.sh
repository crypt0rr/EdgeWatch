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
