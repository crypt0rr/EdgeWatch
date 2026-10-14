#!/usr/bin/env bash

# Extract the architecture-specific EdgeWatch binaries from GoReleaser
# archives so the container build can consume the exact candidate outputs.
set -euo pipefail

dist="${1:-dist}"
output="${2:-release-binaries}"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if [[ "$output" == "/" || "$output" == "." || "$output" == "$PWD" ]]; then
  echo "refusing to use a broad output directory: $output" >&2
  exit 1
fi
rm -rf "$output/linux_amd64" "$output/linux_arm64"
mkdir -p "$output"
declare -A seen_arch=()
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

  if [[ -n "${seen_arch[$arch]:-}" ]]; then
    echo "multiple release archives found for linux/$arch" >&2
    exit 1
  fi
  seen_arch[$arch]=1

  binary_info="$("$script_dir/hash-release-binary.sh" "$archive")"
  IFS=$'\t' read -r member archive_sha256 <<< "$binary_info"

  extract="$(mktemp -d)"
  if ! tar -xzf "$archive" -C "$extract" -- "$member"; then
    echo "EdgeWatch binary could not be extracted from $archive" >&2
    rm -rf "$extract"
    exit 1
  fi
  binary="$extract/$member"
  if [[ ! -f "$binary" || -L "$binary" ]]; then
    echo "EdgeWatch archive member is not a regular file: $archive:$member" >&2
    rm -rf "$extract"
    exit 1
  fi
  extracted_sha256="$(sha256sum "$binary" | awk '{print $1}')"
  if [[ "$extracted_sha256" != "$archive_sha256" ]]; then
    echo "EdgeWatch extracted binary does not match archive member: $archive" >&2
    rm -rf "$extract"
    exit 1
  fi
  mkdir -p "$output/linux_$arch"
  install -m 0755 "$binary" "$output/linux_$arch/edgewatch"
  rm -rf "$extract"
done

for arch in amd64 arm64; do
  if [[ -z "${seen_arch[$arch]:-}" ]]; then
    echo "release archive missing for linux/$arch" >&2
    exit 1
  fi
  test -x "$output/linux_$arch/edgewatch"
done
