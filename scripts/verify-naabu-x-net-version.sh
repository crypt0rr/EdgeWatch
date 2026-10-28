#!/bin/sh

# Keep the release manifest's Dockerfile pin truthful by checking Go's
# selected module graph after the requested version has been added.
set -eu

expected="${1:?usage: $0 <expected-x-net-version>}"
if ! printf '%s\n' "$expected" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "invalid requested x/net version: $expected" >&2
  exit 2
fi

resolved="$(go list -m -f '{{.Version}}' golang.org/x/net)"
if [ "$resolved" != "$expected" ]; then
  printf 'Go selected golang.org/x/net %s, expected %s\n' "${resolved:-<missing>}" "$expected" >&2
  exit 1
fi

printf 'Go selected golang.org/x/net %s\n' "$resolved"
