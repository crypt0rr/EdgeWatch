#!/bin/sh

# Keep the operator-facing compatibility guidance synchronized with the
# authoritative store schema constant. This intentionally checks only the
# current version phrase, allowing historical migration numbers elsewhere in
# the documentation.
set -eu

schema=$(sed -nE 's/^const schemaVersion = ([0-9]+)$/\1/p' internal/store/migrations.go | head -n 1)
if [ -z "$schema" ]; then
  echo "schema version constant not found" >&2
  exit 1
fi

compatibility_path=docs/src/content/docs/reference/database-compatibility.md
compatibility=$(tr '\n' ' ' < "$compatibility_path")
security=$(tr '\n' ' ' < SECURITY.md)
if ! printf '%s' "$compatibility" | grep -Eq "current schema is[[:space:]]+version ${schema}"; then
  echo "${compatibility_path} does not document current schema ${schema}" >&2
  exit 1
fi
if ! printf '%s' "$security" | grep -Eq "schema[[:space:]]+${schema}[[:space:]]+must not"; then
	echo "SECURITY.md does not document current schema ${schema}" >&2
	exit 1
fi

# Keep the upgrade floor, the oldest schema that the daemon upgrades and the
# release to upgrade an older database through, synchronized with the store
# constants in the guide and the security policy.
baseline_path=internal/store/schema_baseline.go
floor=$(sed -nE 's/^const minimumUpgradeSchema = ([0-9]+)$/\1/p' "$baseline_path" | head -n 1)
release=$(sed -nE 's/^const upgradeFloorRelease = "([^"]+)"$/\1/p' "$baseline_path" | head -n 1)
if [ -z "$floor" ] || [ -z "$release" ]; then
	echo "upgrade floor constants not found in ${baseline_path}" >&2
	exit 1
fi
release_pattern=$(printf '%s' "$release" | sed 's/[.]/[.]/g')
if ! printf '%s' "$compatibility" | grep -Eq "older than schema ${floor}, the oldest that this release upgrades; upgrade through ${release_pattern} first"; then
	echo "${compatibility_path} does not document upgrade floor schema ${floor} and ${release}" >&2
	exit 1
fi
if ! printf '%s' "$security" | grep -Eq "schema older than[[:space:]]+${floor},.*upgrade through[[:space:]]+${release_pattern}[[:space:]]+first"; then
	echo "SECURITY.md does not document upgrade floor schema ${floor} and ${release}" >&2
	exit 1
fi

echo "schema documentation matches version ${schema} and upgrade floor ${floor}"
