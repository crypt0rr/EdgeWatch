#!/usr/bin/env bash

# Scan one platform of an EdgeWatch image for known vulnerabilities in the
# parts that `make vulncheck` does not cover, which checks EdgeWatch's own Go
# module:
# - govulncheck checks the bundled Naabu binary for the vulnerable symbols it
#   contains, from the build information that Go keeps in stripped binaries.
#   Each finding fails the scan unless scripts/naabu-vulncheck-allowlist.txt
#   accepts it.
# - Grype checks the Alpine packages of the image and fails on a
#   vulnerability of high or critical severity that a newer package fixes,
#   unless an ignore rule in .grype.yaml accepts it.
# The image is never started. Its root filesystem is exported and scanned on
# disk, and Grype runs from a digest-pinned image without capabilities, with
# that filesystem mounted read-only. Set GRYPE_DB_CACHE_DIR to share Grype's
# vulnerability database between scans.
set -euo pipefail

usage="usage: $0 IMAGE PLATFORM"
image="${1:?$usage}"
platform="${2:?$usage}"
case "$platform" in
  linux/amd64) go_arch=amd64 apk_arch=x86_64 ;;
  linux/arm64) go_arch=arm64 apk_arch=aarch64 ;;
  *) echo "unsupported platform: $platform" >&2; exit 2 ;;
esac

# Renovate updates the tag and digest of this image together.
grype_image=docker.io/anchore/grype:v0.120.1@sha256:e4a44ef45d285b829ce6efe2642980329661bd2d18eab5fc539138d4adaebbbe
allowlist=scripts/naabu-vulncheck-allowlist.txt
grype_config=.grype.yaml
for file in Makefile "$allowlist" "$grype_config"; do
  if [[ ! -f "$file" ]]; then
    echo "$file not found; run this script from the repository root" >&2
    exit 2
  fi
done
govulncheck_version="$(sed -n 's/^GOVULNCHECK_VERSION ?= *//p' Makefile)"
if [[ -z "$govulncheck_version" ]]; then
  echo "could not read GOVULNCHECK_VERSION from Makefile" >&2
  exit 2
fi
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

workdir="$(mktemp -d)"
container=""
# shellcheck disable=SC2317 # The EXIT trap calls it.
cleanup() {
  if [[ -n "$container" ]]; then
    docker rm "$container" >/dev/null 2>&1 || true
  fi
  # The exported filesystem keeps the image's directory modes.
  chmod -R u+w "$workdir" 2>/dev/null || true
  rm -rf "$workdir"
}
trap cleanup EXIT

container="$(docker create --platform "$platform" "$image")"
docker cp "$container:/usr/local/bin/naabu" "$workdir/naabu"
mkdir "$workdir/rootfs"
docker export "$container" | tar -x --no-same-owner -C "$workdir/rootfs"
docker rm "$container" >/dev/null
container=""

# A reference that names an image index resolves to the local platform when
# the requested one is missing, so check what was exported.
if ! go version -m "$workdir/naabu" | grep -Eq "^[[:space:]]+build[[:space:]]+GOARCH=${go_arch}\$"; then
  echo "$image did not provide a $platform Naabu binary" >&2
  exit 1
fi
if [[ "$(cat "$workdir/rootfs/etc/apk/arch")" != "$apk_arch" ]]; then
  echo "$image did not provide a $platform root filesystem" >&2
  exit 1
fi

failed=0

echo "govulncheck $govulncheck_version: Naabu in $image ($platform)"
GOTOOLCHAIN="$(go env GOVERSION)" go run "golang.org/x/vuln/cmd/govulncheck@${govulncheck_version}" \
  -mode=binary -format json "$workdir/naabu" > "$workdir/naabu-vulncheck.json"
# A finding whose trace names a function is a vulnerable symbol in the
# binary; the module and package findings of the same advisory precede it.
jq -r -s '
  (map(select(.osv) | {key: .osv.id, value: .osv.summary}) | from_entries) as $summary
  | map(select(.finding and .finding.trace[0].function) | .finding)
  | unique_by(.osv)
  | .[] | [.osv, "\(.trace[0].module)@\(.trace[0].version)", (.fixed_version // "no fixed version"), ($summary[.osv] // "")] | @tsv
' "$workdir/naabu-vulncheck.json" > "$workdir/findings.tsv"
awk '$1 !~ /^#/ && NF { print $1 }' "$allowlist" | LC_ALL=C sort -u > "$workdir/accepted.txt"
unexpected=0
while IFS=$'\t' read -r id module fixed summary; do
  if grep -qxF "$id" "$workdir/accepted.txt"; then
    status=accepted
  else
    status=NEW
    unexpected=$((unexpected + 1))
  fi
  printf '%-8s %-14s %s (fixed: %s): %s\n' "$status" "$id" "$module" "$fixed" "$summary"
done < "$workdir/findings.tsv"
cut -f1 "$workdir/findings.tsv" | LC_ALL=C sort -u > "$workdir/found.txt"
while IFS= read -r id; do
  echo "$id is accepted in $allowlist but was not found in this binary; remove it once no platform reports it"
done < <(LC_ALL=C comm -23 "$workdir/accepted.txt" "$workdir/found.txt")
if [[ "$unexpected" -gt 0 ]]; then
  echo "govulncheck found $unexpected vulnerabilities in Naabu that $allowlist does not accept" >&2
  failed=1
else
  echo "govulncheck: Naabu contains no vulnerability beyond the accepted ones"
fi

echo "Grype: Alpine packages of $image ($platform)"
cache="${GRYPE_DB_CACHE_DIR:-$workdir/grype-db}"
mkdir -p "$cache/tmp"
if docker run --rm --read-only --tmpfs /tmp:size=64m,mode=1777 \
  --cap-drop ALL --security-opt no-new-privileges:true --user "$(id -u):$(id -g)" \
  --env GRYPE_DB_CACHE_DIR=/cache --env GRYPE_CHECK_FOR_APP_UPDATE=false --env TMPDIR=/cache/tmp \
  --volume "$cache:/cache" \
  --volume "$PWD/$grype_config:/etc/grype.yaml:ro" \
  --volume "$workdir/rootfs:/image:ro" \
  "$grype_image" --config /etc/grype.yaml --only-fixed --fail-on high --name "$image ($platform)" dir:/image; then
  echo "Grype: no fixed vulnerability of high or critical severity"
else
  echo "Grype found a fixed vulnerability of high or critical severity, or could not scan $image ($platform)" >&2
  failed=1
fi

exit "$failed"
