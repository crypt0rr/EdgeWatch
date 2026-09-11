#!/usr/bin/env bash

# Extract the architecture-specific EdgeWatch binaries from GoReleaser
# archives so the container build can consume the exact candidate outputs.
set -euo pipefail

dist="${1:-dist}"
output="${2:-release-binaries}"

if [[ "$output" == "/" || "$output" == "." || "$output" == "$PWD" ]]; then
  echo "refusing to use a broad output directory: $output" >&2
  exit 1
fi
rm -rf "$output/linux_amd64" "$output/linux_arm64"
mkdir -p "$output"
shopt -s nullglob
archives=("$dist"/*.tar.gz)
if [[ "${#archives[@]}" -eq 0 ]]; then
  echo "no release archives found in $dist" >&2
  exit 1
fi

for archive in "${archives[@]}"; do
  case "$(basename "$archive")" in
    *_Linux_x86_64.tar.gz|*_linux_amd64.tar.gz|*_Linux_amd64.tar.gz) arch=amd64 ;;
    *_Linux_arm64.tar.gz|*_linux_arm64.tar.gz) arch=arm64 ;;
    *) echo "unsupported release archive: $archive" >&2; exit 1 ;;
  esac

  extract="$(mktemp -d)"
  tar -xzf "$archive" -C "$extract"
  binary="$(find "$extract" -type f -name edgewatch -print -quit)"
  if [[ -z "$binary" ]]; then
    echo "EdgeWatch binary missing from $archive" >&2
    rm -rf "$extract"
    exit 1
  fi
  mkdir -p "$output/linux_$arch"
  install -m 0755 "$binary" "$output/linux_$arch/edgewatch"
  rm -rf "$extract"
done

for arch in amd64 arm64; do
  test -x "$output/linux_$arch/edgewatch"
done
