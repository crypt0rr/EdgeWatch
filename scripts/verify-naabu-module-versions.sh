#!/bin/sh

# Keep the release manifest's Dockerfile pins truthful by checking Go's
# selected module graph after the requested versions have been added.
set -eu

expected_x_net="${1:?usage: $0 <x-net> <goldmark> <compress>}"
expected_goldmark="${2:?usage: $0 <x-net> <goldmark> <compress>}"
expected_compress="${3:?usage: $0 <x-net> <goldmark> <compress>}"

check_module() {
  module="$1"
  expected="$2"
  if ! printf '%s\n' "$expected" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
    echo "invalid requested ${module} version: ${expected}" >&2
    exit 2
  fi
  resolved="$(go list -m -f '{{.Version}}' "$module")"
  if [ "$resolved" != "$expected" ]; then
    printf 'Go selected %s %s, expected %s\n' "$module" "${resolved:-<missing>}" "$expected" >&2
    exit 1
  fi
  printf 'Go selected %s %s\n' "$module" "$resolved"
}

check_module golang.org/x/net "$expected_x_net"
check_module github.com/yuin/goldmark "$expected_goldmark"
check_module github.com/klauspost/compress "$expected_compress"
