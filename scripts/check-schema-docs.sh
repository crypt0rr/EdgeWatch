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

readme=$(tr '\n' ' ' < README.md)
security=$(tr '\n' ' ' < SECURITY.md)
if ! printf '%s' "$readme" | grep -Eq "current schema is[[:space:]]+version ${schema}"; then
  echo "README.md does not document current schema ${schema}" >&2
  exit 1
fi
if ! printf '%s' "$security" | grep -Eq "schema[[:space:]]+${schema}[[:space:]]+must not"; then
	echo "SECURITY.md does not document current schema ${schema}" >&2
	exit 1
fi

# Keep the recovery-code retirement note tied to the migration that actually
# deletes legacy digests. This prevents a later schema bump from silently
# changing the historical migration number in the security guidance.
recovery_schema=$(awk '
    /^[[:space:]]*[0-9]+: \{/ {
        version = $1
        sub(/:/, "", version)
    }
    /DELETE FROM recovery_codes WHERE substr\(id_hash,1,3\) <> '\''v2\$'\''/ {
        print version
        exit
    }
' internal/store/migrations.go)
if [ -z "$recovery_schema" ]; then
	echo "recovery-code retirement migration not found" >&2
	exit 1
fi
if ! printf '%s' "$security" | grep -Eq "Recovery codes are stored.*Schema[[:space:]]+${recovery_schema}[[:space:]]+removes"; then
	echo "SECURITY.md does not document recovery-code retirement schema ${recovery_schema}" >&2
	exit 1
fi

echo "schema documentation matches version ${schema}"
