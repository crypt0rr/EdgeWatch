#!/usr/bin/env bash

# Print the one regular `edgewatch` archive member and its digest, hashing the
# bytes streamed directly from the archive rather than a staged extraction.
set -euo pipefail

archive="${1:?usage: $0 <release-archive>}"
if [[ ! -f "$archive" ]]; then
  echo "release archive is missing: $archive" >&2
  exit 1
fi

listing="$(tar -tzf "$archive")" || {
  echo "release archive could not be read: $archive" >&2
  exit 1
}
members=()
while IFS= read -r member; do
  member="${member#./}"
  [[ "${member##*/}" == edgewatch ]] || continue
  members+=("$member")
done <<< "$listing"

if [[ "${#members[@]}" -ne 1 ]]; then
  echo "release archive must contain exactly one edgewatch binary: $archive" >&2
  exit 1
fi
member="${members[0]}"

# GoReleaser stores only source-controlled asset names beside the executable.
# Refuse paths that could escape an extraction directory or confuse tar's
# option parsing before passing the exact member to tar.
if [[ "$member" == /* || "$member" == *$'\n'* || "$member" == *$'\r'* || "$member" == *"\\"* ]]; then
  echo "release archive has an unsafe edgewatch member path: $member" >&2
  exit 1
fi
IFS='/' read -r -a components <<< "$member"
for component in "${components[@]}"; do
  if [[ -z "$component" || "$component" == . || "$component" == .. ]]; then
    echo "release archive has an unsafe edgewatch member path: $member" >&2
    exit 1
  fi
done

verbose="$(tar -tvzf "$archive" -- "$member")" || {
  echo "release archive binary member could not be inspected: $member" >&2
  exit 1
}
if [[ "${verbose:0:1}" != "-" ]]; then
  echo "release archive edgewatch member is not a regular file: $member" >&2
  exit 1
fi

sha256="$(tar -xOzf "$archive" -- "$member" | sha256sum | awk '{print $1}')"
if [[ ! "$sha256" =~ ^[0-9a-f]{64}$ ]]; then
  echo "could not hash release archive binary: $archive" >&2
  exit 1
fi
printf '%s\t%s\n' "$member" "$sha256"
