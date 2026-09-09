#!/bin/sh

# Verify that the Naabu release tag still resolves to the immutable commit
# used by the Docker build. This intentionally checks the peeled commit for
# annotated tags and falls back to the lightweight-tag ref when necessary.
set -eu

version=${1:-v2.6.1}
expected=${2:-5a0ca8bde91b5bb16213e9e8b5c6871eac954bd8}
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
