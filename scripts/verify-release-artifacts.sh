#!/usr/bin/env bash

# Verify a candidate manifest and its archive/checksum set. This is used both
# before publication and by the post-publication smoke job.
set -euo pipefail

artifact_dir="${1:?usage: $0 <artifact-dir> <manifest> <tag> [commit]}"
manifest="${2:?usage: $0 <artifact-dir> <manifest> <tag> [commit]}"
tag="${3:?usage: $0 <artifact-dir> <manifest> <tag> [commit]}"
expected_commit="${4:-}"
binary_dir="${5:-}"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
checksums="$artifact_dir/checksums.txt"
test -f "$checksums"
test -f "$manifest"

mapfile -t archives < <(find "$artifact_dir" -maxdepth 1 -type f -name '*.tar.gz' -printf '%f\n' | LC_ALL=C sort)
if [[ "${#archives[@]}" -eq 0 ]]; then
  echo "no release archives found" >&2
  exit 1
fi

# sha256sum accepts several whitespace-separated variants and, without
# --strict, silently skips malformed lines. Validate the exact manifest shape
# before checking any digest so a damaged checksum file cannot pass coverage.
if ! awk 'NF != 2 || $1 !~ /^[0-9a-fA-F]{64}$/ || $2 !~ /^\*?[A-Za-z0-9][A-Za-z0-9._+-]*$/ { bad=1 } END { exit bad }' "$checksums"; then
  echo "checksums.txt contains a malformed line" >&2
  exit 1
fi

mapfile -t listed < <(awk 'NF >= 2 { sub(/^\*/, "", $2); print $2 }' "$checksums" | LC_ALL=C sort)
if [[ "${#archives[@]}" -ne "${#listed[@]}" ]]; then
  echo "checksum coverage does not match release archives" >&2
  exit 1
fi

for archive in "${archives[@]}"; do
  count="$(awk -v name="$archive" '$2 == name { count++ } END { print count + 0 }' "$checksums")"
  if [[ "$count" -ne 1 ]]; then
    echo "archive $archive must appear exactly once in checksums.txt" >&2
    exit 1
  fi
done

for name in "${listed[@]}"; do
  found=0
  for archive in "${archives[@]}"; do
    if [[ "$name" == "$archive" ]]; then
      found=1
      break
    fi
  done
  if [[ "$found" -ne 1 ]]; then
    echo "checksums.txt contains an unexpected asset: $name" >&2
    exit 1
  fi
done

(cd "$artifact_dir" && sha256sum --strict --quiet -c checksums.txt)

for archive in "${archives[@]}"; do
  members="$(tar -tzf "$artifact_dir/$archive" | sed 's#^\./##')" || {
    echo "release archive $archive could not be read" >&2
    exit 1
  }
  for notice in LICENSE LICENSE.md THIRD_PARTY_LICENSES.md README.md; do
    if ! grep -Eq "^([^/]+/)?${notice//./\\.}$" <<<"$members"; then
      echo "release archive $archive is missing $notice" >&2
      exit 1
    fi
  done
done

schema_version="$(jq -r '.schema_version // empty' "$manifest")"
if ! jq -e --arg tag "$tag" --arg commit "$expected_commit" '
  (.schema_version == 1 or .schema_version == 2) and .tag == $tag and ($commit == "" or .source_commit == $commit) and
  (.artifacts | length > 0) and (.frontend_sha256 | type == "string" and test("^[0-9a-f]{64}$"))
' "$manifest" >/dev/null; then
  echo "release manifest metadata is invalid" >&2
  exit 1
fi
if [[ -n "$binary_dir" && "$schema_version" != "2" ]]; then
  echo "candidate artifact verification requires release manifest schema 2 binary digests" >&2
  exit 1
fi
if [[ "$schema_version" == "2" ]] && ! jq -e '
  (.binaries | type == "array" and length == 2) and
  ([.binaries[].arch] | sort == ["amd64", "arm64"]) and
  ([.binaries[].archive] | unique | length == 2) and
  all(.binaries[];
    (.archive | type == "string" and endswith(".tar.gz")) and
    (.member | type == "string" and endswith("edgewatch")) and
    (.sha256 | type == "string" and test("^[0-9a-f]{64}$"))
  )
' "$manifest" >/dev/null; then
  echo "release manifest binary bindings are invalid" >&2
  exit 1
fi

frontend_dir="${FRONTEND_DIST:-internal/webui/dist}"
if [[ ! -d "$frontend_dir" ]]; then
  echo "frontend asset directory is required to verify the release manifest: $frontend_dir" >&2
  exit 1
fi
frontend_hash="$({
  while IFS= read -r -d '' file; do
    relative="${file#"$frontend_dir"/}"
    digest="$(sha256sum "$file" | awk '{print $1}')"
    printf '%s  %s\n' "$relative" "$digest"
  done < <(find "$frontend_dir" -type f ! -name '.gitkeep' -print0 | LC_ALL=C sort -z)
} | sha256sum | awk '{print $1}')"
if [[ "$(jq -r '.frontend_sha256' "$manifest")" != "$frontend_hash" ]]; then
  echo "release manifest frontend hash does not match the built assets" >&2
  exit 1
fi

manifest_count="$(jq '.artifacts | length' "$manifest")"
expected_manifest_count=$(( ${#archives[@]} + 1 ))
if [[ "$manifest_count" -ne "$expected_manifest_count" ]]; then
  echo "release manifest does not cover every archive and checksums.txt exactly once" >&2
  exit 1
fi
for name in "${archives[@]}" checksums.txt; do
  count="$(jq -r --arg name "$name" '[.artifacts[] | select(.name == $name)] | length' "$manifest")"
  if [[ "$count" -ne 1 ]]; then
    echo "release manifest must contain $name exactly once" >&2
    exit 1
  fi
done

while IFS=$'\t' read -r name sha256 size; do
  file="$artifact_dir/$name"
  test -f "$file" || { echo "manifest artifact missing: $name" >&2; exit 1; }
  test "$(sha256sum "$file" | awk '{print $1}')" = "$sha256" || { echo "manifest hash mismatch: $name" >&2; exit 1; }
  test "$(stat -c '%s' "$file")" = "$size" || { echo "manifest size mismatch: $name" >&2; exit 1; }
done < <(jq -r '.artifacts[] | [.name, .sha256, (.size | tostring)] | @tsv' "$manifest")

if [[ "$schema_version" == "2" ]]; then
  while IFS=$'\t' read -r arch archive member expected_sha256; do
    archive_file=""
    for candidate in "${archives[@]}"; do
      if [[ "$candidate" == "$archive" ]]; then
        archive_file="$artifact_dir/$candidate"
        break
      fi
    done
    if [[ -z "$archive_file" ]]; then
      echo "binary manifest references an unknown release archive: $archive" >&2
      exit 1
    fi
    case "$archive" in
      *_Linux_x86_64.tar.gz|*_linux_amd64.tar.gz|*_Linux_amd64.tar.gz) archive_arch=amd64 ;;
      *_Linux_arm64.tar.gz|*_linux_arm64.tar.gz) archive_arch=arm64 ;;
      *) echo "unsupported binary archive name: $archive" >&2; exit 1 ;;
    esac
    if [[ "$archive_arch" != "$arch" ]]; then
      echo "binary manifest architecture does not match archive name: $archive" >&2
      exit 1
    fi

    binary_info="$("$script_dir/hash-release-binary.sh" "$archive_file")"
    IFS=$'\t' read -r archive_member archive_sha256 <<< "$binary_info"
    if [[ "$archive_member" != "$member" || "$archive_sha256" != "$expected_sha256" ]]; then
      echo "release manifest binary digest does not match archive member: $archive" >&2
      exit 1
    fi

    if [[ -n "$binary_dir" && "$binary_dir" != "-" ]]; then
      extracted="$binary_dir/linux_$arch/edgewatch"
      # actions/upload-artifact normalizes downloaded file modes to 0644.
      # The image build restores executable mode with `install -m 0755`; here
      # require a regular, non-symlink file and verify its bytes instead.
      if [[ ! -f "$extracted" || -L "$extracted" || ! -r "$extracted" ]]; then
        echo "prepared release binary is missing or invalid: $extracted" >&2
        exit 1
      fi
      extracted_sha256="$(sha256sum "$extracted" | awk '{print $1}')"
      if [[ "$extracted_sha256" != "$expected_sha256" ]]; then
        echo "prepared release binary does not match archive member: $archive" >&2
        exit 1
      fi
    fi
  done < <(jq -r '.binaries[] | [.arch, .archive, .member, .sha256] | @tsv' "$manifest" | LC_ALL=C sort)
fi

echo "release artifacts verified for $tag"
