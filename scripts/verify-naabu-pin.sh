#!/bin/sh

# Verify that the Naabu release tag still resolves to the immutable commit
# used by the Docker build. This intentionally checks the peeled commit for
# annotated tags and falls back to the lightweight-tag ref when necessary.
set -eu

dockerfile=${NAABU_DOCKERFILE:-Dockerfile}
if [ "$#" -gt 2 ]; then
  echo "usage: $0 [version] [commit]" >&2
  exit 2
fi
if [ ! -f "$dockerfile" ]; then
  echo "Dockerfile not found: ${dockerfile}" >&2
  exit 2
fi
if [ "$#" -ge 1 ]; then
  version=$1
else
  version=$(awk '$1 == "ARG" && $2 ~ /^NAABU_VERSION=/ { sub(/^NAABU_VERSION=/, "", $2); print $2; exit }' "$dockerfile")
fi
if [ "$#" -ge 2 ]; then
  expected=$2
else
  expected=$(awk '$1 == "ARG" && $2 ~ /^NAABU_COMMIT=/ { sub(/^NAABU_COMMIT=/, "", $2); print $2; exit }' "$dockerfile")
fi
if [ -z "$version" ] || [ -z "$expected" ]; then
  echo "could not read NAABU_VERSION and NAABU_COMMIT from ${dockerfile}" >&2
  exit 2
fi
remote=https://github.com/projectdiscovery/naabu.git

actual=$(git ls-remote "$remote" "refs/tags/${version}^{}" | awk 'NR == 1 { print $1 }')
if [ -z "$actual" ]; then
  actual=$(git ls-remote "$remote" "refs/tags/${version}" | awk 'NR == 1 { print $1 }')
fi

if [ "$actual" != "$expected" ]; then
  echo "Naabu ${version} resolves to ${actual:-<missing>}, expected ${expected}" >&2
  exit 1
fi

echo "Naabu ${version} is pinned to ${expected}"
