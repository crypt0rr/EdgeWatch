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

echo "schema documentation matches version ${schema}"
