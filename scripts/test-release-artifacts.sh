#!/usr/bin/env bash

# Deterministic contract test for the release helper scripts. It uses tiny
# fixture binaries so CI can exercise checksum/manifest coverage without
# building a second release candidate.
set -euo pipefail

root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT
mkdir -p "$root/dist/edgewatch_0.0.0_Linux_x86_64" "$root/dist/edgewatch_0.0.0_Linux_arm64" "$root/frontend-dist"
printf 'fixture frontend\n' > "$root/frontend-dist/index.html"

for arch in x86_64 arm64; do
  printf '#!/bin/sh\n# fixture architecture: %s\nexit 0\n' "$arch" > "$root/dist/edgewatch_0.0.0_Linux_$arch/edgewatch"
  cp LICENSE LICENSE.md README.md THIRD_PARTY_LICENSES.md "$root/dist/edgewatch_0.0.0_Linux_$arch/"
  chmod 0755 "$root/dist/edgewatch_0.0.0_Linux_$arch/edgewatch"
  tar -czf "$root/dist/edgewatch_0.0.0_Linux_$arch.tar.gz" -C "$root/dist" "edgewatch_0.0.0_Linux_$arch"
done

# GoReleaser archives must be reproducible when the same tag and commit are
# rebuilt. Exercise the archive contract with fixed ordering, ownership, and
# timestamps; a future packaging change that leaks filesystem metadata fails
# this deterministic comparison before it can reach a release.
for output in "$root/repro-a.tar.gz" "$root/repro-b.tar.gz"; do
  tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner -C "$root/dist" -cf - edgewatch_0.0.0_Linux_x86_64 | gzip -n > "$output"
done
cmp "$root/repro-a.tar.gz" "$root/repro-b.tar.gz"

(
  cd "$root/dist"
  sha256sum -- *.tar.gz > checksums.txt
)
./scripts/prepare-release-binaries.sh "$root/dist" "$root/release-binaries"
fixture_commit="$(git rev-parse HEAD)"
canonical_goreleaser="$(awk '$1 == "GORELEASER_VERSION:" { print $2 }' .github/workflows/release.yml)"
test -n "$canonical_goreleaser"
env -u GORELEASER_VERSION DIST_DIR="$root/dist" FRONTEND_DIST="$root/frontend-dist" RELEASE_BINARIES="$root/release-binaries" \
  ./scripts/generate-release-manifest.sh v0.0.0 "$root/dist/release-manifest.json"
test "$(jq -r '.toolchain.goreleaser' "$root/dist/release-manifest.json")" = "$canonical_goreleaser"
GORELEASER_VERSION="$canonical_goreleaser" DIST_DIR="$root/dist" FRONTEND_DIST="$root/frontend-dist" RELEASE_BINARIES="$root/release-binaries" \
  ./scripts/generate-release-manifest.sh v0.0.0 "$root/dist/release-manifest-explicit.json"
test "$(jq -r '.toolchain.goreleaser' "$root/dist/release-manifest-explicit.json")" = "$canonical_goreleaser"
if GORELEASER_VERSION=v0.0.0 DIST_DIR="$root/dist" FRONTEND_DIST="$root/frontend-dist" RELEASE_BINARIES="$root/release-binaries" \
  ./scripts/generate-release-manifest.sh v0.0.0 "$root/dist/release-manifest-mismatch.json" >"$root/goreleaser-mismatch.log" 2>&1; then
  echo "manifest accepted a GoReleaser version that differs from the release workflow pin" >&2
  exit 1
fi
grep -Fq "GORELEASER_VERSION=v0.0.0 does not match .github/workflows/release.yml pin $canonical_goreleaser" "$root/goreleaser-mismatch.log"
FRONTEND_DIST="$root/frontend-dist" ./scripts/verify-release-artifacts.sh \
  "$root/dist" "$root/dist/release-manifest.json" v0.0.0 "$fixture_commit" "$root/release-binaries"
test -x "$root/release-binaries/linux_amd64/edgewatch"
test -x "$root/release-binaries/linux_arm64/edgewatch"
test "$(jq -r '.schema_version' "$root/dist/release-manifest.json")" = 2
for arch in amd64 arm64; do
  archive="$(jq -r --arg arch "$arch" '.binaries[] | select(.arch == $arch) | .archive' "$root/dist/release-manifest.json")"
  archive_info="$(./scripts/hash-release-binary.sh "$root/dist/$archive")"
  IFS=$'\t' read -r _ archive_sha256 <<< "$archive_info"
  test "$(jq -r --arg arch "$arch" '.binaries[] | select(.arch == $arch) | .sha256' "$root/dist/release-manifest.json")" = "$archive_sha256"
done

# The candidate artifact crosses job boundaries through upload/download, which
# normalizes executable modes. Verification is about the exact bytes; the
# Dockerfile later sets the image binary mode with `install -m 0755`.
artifact_mode="$root/artifact-mode"
cp -a "$root/release-binaries" "$artifact_mode"
chmod 0644 "$artifact_mode"/linux_*/edgewatch
test "$(stat -c '%a' "$artifact_mode/linux_amd64/edgewatch")" = 644
test -r "$artifact_mode/linux_amd64/edgewatch"
test ! -x "$artifact_mode/linux_amd64/edgewatch"
FRONTEND_DIST="$root/frontend-dist" ./scripts/verify-release-artifacts.sh \
  "$root/dist" "$root/dist/release-manifest.json" v0.0.0 "$fixture_commit" "$artifact_mode"

# The image verifier copies the actual executable from the digest-pinned
# image. A tiny fake Docker CLI exercises its architecture selection and hash
# comparison without claiming to replace the BuildKit/image smoke gates.
fakebin="$root/fakebin"
mkdir -p "$fakebin"
cat > "$fakebin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  create)
    shift
    if [[ "${1:-}" == --platform ]]; then
      [[ "$2" == "$FAKE_EXPECTED_PLATFORM" ]]
      shift 2
    else
      [[ -z "${FAKE_EXPECTED_PLATFORM:-}" ]]
    fi
    [[ "${1:-}" == "$FAKE_EXPECTED_IMAGE" ]]
    printf '%s\n' fixture-container
    ;;
  cp)
    [[ "$2" == fixture-container:/usr/local/bin/edgewatch ]]
    cp "$FAKE_IMAGE_BINARY" "$3"
    ;;
  rm)
    [[ "$2" == -f && "$3" == fixture-container ]]
    ;;
  *) echo "unexpected fake docker command: $*" >&2; exit 2 ;;
esac
EOF
chmod 0755 "$fakebin/docker"
image_ref='ghcr.io/crypt0rr/edgewatch@sha256:1111111111111111111111111111111111111111111111111111111111111111'
FAKE_EXPECTED_IMAGE="$image_ref" FAKE_EXPECTED_PLATFORM=linux/amd64 \
  FAKE_IMAGE_BINARY="$root/release-binaries/linux_amd64/edgewatch" PATH="$fakebin:$PATH" \
  ./scripts/verify-release-image-binary.sh "$image_ref" "$root/dist/release-manifest.json" amd64 linux/amd64
if FAKE_EXPECTED_IMAGE="$image_ref" FAKE_EXPECTED_PLATFORM=linux/arm64 \
  FAKE_IMAGE_BINARY="$root/release-binaries/linux_amd64/edgewatch" PATH="$fakebin:$PATH" \
  ./scripts/verify-release-image-binary.sh "$image_ref" "$root/dist/release-manifest.json" arm64 linux/arm64 >"$root/image-mismatch.log" 2>&1; then
  echo "image verifier accepted a binary for the wrong architecture" >&2
  exit 1
fi
grep -Fq 'does not match the linux/arm64 release archive digest' "$root/image-mismatch.log"

# Archive-only verification still accepts already-published schema-1
# manifests. Current candidate/image paths pass an explicit binary mode and
# therefore require schema 2.
jq 'del(.binaries) | .schema_version = 1' "$root/dist/release-manifest.json" > "$root/legacy-manifest.json"
FRONTEND_DIST="$root/frontend-dist" ./scripts/verify-release-artifacts.sh \
  "$root/dist" "$root/legacy-manifest.json" v0.0.0 "$fixture_commit"
if FRONTEND_DIST="$root/frontend-dist" ./scripts/verify-release-artifacts.sh \
  "$root/dist" "$root/legacy-manifest.json" v0.0.0 "$fixture_commit" - >"$root/legacy-candidate.log" 2>&1; then
  echo "candidate verification accepted a schema-1 manifest without binary digests" >&2
  exit 1
fi
grep -Fq 'requires release manifest schema 2 binary digests' "$root/legacy-candidate.log"

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
  if FRONTEND_DIST="$root/frontend-dist" ./scripts/verify-release-artifacts.sh "$case_dir" "$case_dir/release-manifest.json" v0.0.0 "$fixture_commit" >"$case_dir/verify.log" 2>&1; then
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
malformed_checksum() { printf 'not-a-checksum line\n' > "$1/checksums.txt"; }
corrupt_manifest_schema() {
  jq '.schema_version = 3' "$1/release-manifest.json" >"$1/manifest.tmp"
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
corrupt_manifest_binary_hash() {
  jq '.binaries[0].sha256 = "0000000000000000000000000000000000000000000000000000000000000000"' "$1/release-manifest.json" >"$1/manifest.tmp"
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
replace_archive_binary_without_updating_binary_binding() {
  local case_dir="$1"
  local archive name member extract hash size checksums_hash checksums_size
  name="$(jq -r '.binaries[] | select(.arch == "amd64") | .archive' "$case_dir/release-manifest.json")"
  archive="$case_dir/$name"
  member="$(jq -r '.binaries[] | select(.arch == "amd64") | .member' "$case_dir/release-manifest.json")"
  extract="$(mktemp -d)"
  tar -xzf "$archive" -C "$extract"
  printf 'tampered archive binary\n' > "$extract/$member"
  tar -czf "$archive" -C "$extract" .
  rm -rf "$extract"
  (cd "$case_dir" && sha256sum -- *.tar.gz > checksums.txt)
  hash="$(sha256sum "$archive" | awk '{print $1}')"
  size="$(stat -c '%s' "$archive")"
  checksums_hash="$(sha256sum "$case_dir/checksums.txt" | awk '{print $1}')"
  checksums_size="$(stat -c '%s' "$case_dir/checksums.txt")"
  jq --arg name "$name" --arg hash "$hash" --argjson size "$size" \
     --arg checksums_hash "$checksums_hash" --argjson checksums_size "$checksums_size" \
    '(.artifacts[] | select(.name == $name) | .sha256) = $hash |
     (.artifacts[] | select(.name == $name) | .size) = $size |
     (.artifacts[] | select(.name == "checksums.txt") | .sha256) = $checksums_hash |
     (.artifacts[] | select(.name == "checksums.txt") | .size) = $checksums_size' \
    "$case_dir/release-manifest.json" > "$case_dir/manifest.tmp"
  mv "$case_dir/manifest.tmp" "$case_dir/release-manifest.json"
}

expect_rejected missing-checksums remove_checksums
expect_rejected missing-manifest remove_manifest
expect_rejected no-archives remove_archives
expect_rejected checksum-coverage remove_checksum_entry
expect_rejected duplicate-checksum duplicate_checksum_entry
expect_rejected checksum-integrity corrupt_checksum_digest
expect_rejected checksum-format malformed_checksum
expect_rejected manifest-schema corrupt_manifest_schema
expect_rejected manifest-tag corrupt_manifest_tag
expect_rejected manifest-commit corrupt_manifest_commit
expect_rejected manifest-frontend-hash corrupt_manifest_frontend_hash
expect_rejected manifest-binary-hash corrupt_manifest_binary_hash
expect_rejected manifest-count remove_manifest_artifact
expect_rejected manifest-duplicate duplicate_manifest_artifact
expect_rejected manifest-hash corrupt_manifest_hash
expect_rejected manifest-size corrupt_manifest_size
expect_rejected archive-binary-binding replace_archive_binary_without_updating_binary_binding

# Even a candidate whose ordinary archive checksums and artifact entries were
# updated cannot substitute an executable without changing the independently
# recorded archive-member digest.
candidate_mismatch="$cases/candidate-binary-mismatch"
expect_candidate_rejected() {
  local name="$1"
  shift
  local case_dir="$cases/$name"
  mkdir -p "$case_dir"
  cp -a "$root/dist" "$case_dir/dist"
  cp -a "$root/release-binaries" "$case_dir/release-binaries"
  "$@" "$case_dir"
  if FRONTEND_DIST="$root/frontend-dist" ./scripts/verify-release-artifacts.sh \
    "$case_dir/dist" "$case_dir/dist/release-manifest.json" v0.0.0 "$fixture_commit" "$case_dir/release-binaries" >"$case_dir/verify.log" 2>&1; then
    echo "candidate binary case passed unexpectedly: $name" >&2
    cat "$case_dir/verify.log" >&2
    exit 1
  fi
  printf 'candidate binary case rejected: %s\n' "$name"
}
candidate_binary_path() { printf '%s/linux_amd64/edgewatch' "$1/release-binaries"; }
candidate_binary_mismatch() { printf 'tampered extracted binary\n' > "$(candidate_binary_path "$1")"; }
candidate_binary_symlink() {
  local path
  path="$(candidate_binary_path "$1")"
  rm "$path"
  ln -s ../linux_arm64/edgewatch "$path"
}
candidate_binary_nonregular() {
  local path
  path="$(candidate_binary_path "$1")"
  rm "$path"
  mkdir "$path"
}
candidate_binary_unreadable() {
  chmod 000 "$(candidate_binary_path "$1")"
}

expect_candidate_rejected mismatched-bytes candidate_binary_mismatch
expect_candidate_rejected symlink-binary candidate_binary_symlink
expect_candidate_rejected nonregular-binary candidate_binary_nonregular
expect_candidate_rejected unreadable-binary candidate_binary_unreadable
