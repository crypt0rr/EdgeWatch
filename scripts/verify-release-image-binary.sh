#!/usr/bin/env bash

# Compare the executable copied from an immutable image with the digest of
# that architecture's executable member in the attested release archive.
set -euo pipefail

image="${1:?usage: $0 <digest-pinned-image> <manifest> <arch> [platform]}"
manifest="${2:?usage: $0 <digest-pinned-image> <manifest> <arch> [platform]}"
arch="${3:?usage: $0 <digest-pinned-image> <manifest> <arch> [platform]}"
platform="${4:-}"

if [[ ! "$image" =~ ^[a-z0-9./:_-]+@sha256:[0-9a-f]{64}$ ]]; then
  echo "image reference must be pinned by digest" >&2
  exit 1
fi
case "$arch" in
  amd64|arm64) ;;
  *) echo "unsupported image architecture: $arch" >&2; exit 1 ;;
esac
if [[ -n "$platform" && "$platform" != "linux/$arch" ]]; then
  echo "platform does not match image architecture: $platform vs linux/$arch" >&2
  exit 1
fi

if [[ "$(jq -r '.schema_version // empty' "$manifest")" != "2" ]]; then
  echo "release image verification requires manifest schema 2" >&2
  exit 1
fi
matches="$(jq --arg arch "$arch" '[.binaries[]? | select(.arch == $arch)] | length' "$manifest")"
if [[ "$matches" != "1" ]]; then
  echo "release manifest must contain one binary digest for linux/$arch" >&2
  exit 1
fi
expected="$(jq -r --arg arch "$arch" '.binaries[] | select(.arch == $arch) | .sha256' "$manifest")"
if [[ ! "$expected" =~ ^[0-9a-f]{64}$ ]]; then
  echo "release manifest has an invalid binary digest for linux/$arch" >&2
  exit 1
fi

workdir="$(mktemp -d)"
container=""
cleanup() {
  if [[ -n "$container" ]]; then
    docker rm -f "$container" >/dev/null 2>&1 || true
  fi
  rm -rf "$workdir"
}
trap cleanup EXIT

if [[ -n "$platform" ]]; then
  container="$(docker create --platform "$platform" "$image")"
else
  container="$(docker create "$image")"
fi
if [[ -z "$container" ]]; then
  echo "could not create a container from $image" >&2
  exit 1
fi
docker cp "$container:/usr/local/bin/edgewatch" "$workdir/edgewatch"
actual="$(sha256sum "$workdir/edgewatch" | awk '{print $1}')"
if [[ "$actual" != "$expected" ]]; then
  echo "image EdgeWatch binary does not match the linux/$arch release archive digest" >&2
  exit 1
fi
printf 'image EdgeWatch binary verified for linux/%s (%s)\n' "$arch" "$actual"
