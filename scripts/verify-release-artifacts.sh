#!/usr/bin/env bash

# Verify a candidate manifest and its archive/checksum set. This is used both
# before publication and by the post-publication smoke job.
set -euo pipefail

artifact_dir="${1:?usage: $0 <artifact-dir> <manifest> <tag> [commit]}"
manifest="${2:?usage: $0 <artifact-dir> <manifest> <tag> [commit]}"
tag="${3:?usage: $0 <artifact-dir> <manifest> <tag> [commit]}"
expected_commit="${4:-}"

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
checksums="$artifact_dir/checksums.txt"
test -f "$checksums"
test -f "$manifest"

mapfile -t archives < <(find "$artifact_dir" -maxdepth 1 -type f -name '*.tar.gz' -printf '%f\n' | LC_ALL=C sort)
if [[ "${#archives[@]}" -eq 0 ]]; then
  echo "no release archives found" >&2
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

(cd "$artifact_dir" && sha256sum -c checksums.txt)

if ! jq -e --arg tag "$tag" --arg commit "$expected_commit" '
  .schema_version == 1 and .tag == $tag and ($commit == "" or .source_commit == $commit) and
  (.artifacts | length > 0) and (.frontend_sha256 | type == "string" and length == 64)
' "$manifest" >/dev/null; then
  echo "release manifest metadata is invalid" >&2
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

echo "release artifacts verified for $tag"
