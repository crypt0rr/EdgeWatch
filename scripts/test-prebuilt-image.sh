#!/usr/bin/env bash

# Smoke-test an image assembled from release-style prebuilt inputs. The checks
# deliberately exercise the image on the requested architecture, including a
# read-only daemon with only NET_RAW: the capabilities of a Compose file from
# before v0.27.0. The daemon starts, but scanner launches fail closed while
# the scanner identity pool is unavailable. scripts/verify-compose-deployment.sh
# starts the bundled compose.yaml, which enables the sandbox.
set -euo pipefail

image="${1:?image reference is required}"
platform="${2:?platform is required (for example linux/amd64)}"
version="${3:?embedded version is required}"
arch="${platform#linux/}"
case "$arch" in
  amd64|arm64) ;;
  *) echo "unsupported platform: $platform" >&2; exit 1 ;;
esac

actual_arch="$(docker image inspect --format '{{.Architecture}}' "$image")"
test "$actual_arch" = "$arch"
test "$(docker image inspect --format '{{json .Config.Entrypoint}}' "$image")" = '["edgewatch"]'

edgewatch_version_output="$(docker run --rm --platform "$platform" --read-only --tmpfs /tmp:size=128m,mode=1777 "$image" version)"
grep -Fqx "EdgeWatch $version" <<<"$edgewatch_version_output"
nmap_version_output="$(docker run --rm --platform "$platform" --read-only --entrypoint /usr/bin/nmap "$image" --version)"
grep -Eq '^Nmap version ' <<<"$nmap_version_output"
naabu_version_output="$(docker run --rm --platform "$platform" --read-only --entrypoint /usr/local/bin/naabu "$image" -version 2>&1)"
grep -Eiq 'Naabu|current version' <<<"$naabu_version_output"

root="$(mktemp -d "${TMPDIR:-/tmp}/edgewatch-smoke.XXXXXXXXXX")"
port="$((18080 + ($$ % 1000)))"
container_id=""
context_probe_image="edgewatch-dockerignore-probe:$$"
cleanup() {
  if [[ -n "$container_id" ]]; then
    docker stop "$container_id" >/dev/null 2>&1 || true
    docker rm "$container_id" >/dev/null 2>&1 || true
  fi
  docker image rm "$context_probe_image" >/dev/null 2>&1 || true
  if [[ -d "$root/data" ]]; then
    docker run --rm --volume "$root/data:/data" --entrypoint /bin/sh "$image" \
      -c 'rm -rf /data/* /data/.[!.]* /data/..?*' >/dev/null 2>&1 || true
  fi
  rm -rf "$root"
}
trap cleanup EXIT

context_probe="$root/dockerignore-probe"
mkdir -p "$context_probe"
cp .dockerignore "$context_probe/.dockerignore"
for ignored_path in docs/node_modules/sentinel.txt docs/dist/sentinel.txt test-results/sentinel.txt; do
  mkdir -p "$context_probe/${ignored_path%/*}"
  printf 'probe\n' > "$context_probe/$ignored_path"
  printf 'FROM scratch\nCOPY %s /sentinel.txt\n' "$ignored_path" > "$context_probe/Dockerfile"
  if docker build --no-cache --progress=plain --tag "$context_probe_image" \
    --file "$context_probe/Dockerfile" "$context_probe" >"$context_probe/build.log" 2>&1; then
    docker image rm "$context_probe_image" >/dev/null
    echo "Docker context unexpectedly included $ignored_path" >&2
    exit 1
  fi
  if ! grep -F "$ignored_path" "$context_probe/build.log" | grep -Fq 'not found'; then
    cat "$context_probe/build.log" >&2
    echo "Docker context probe failed for a reason other than excluding $ignored_path" >&2
    exit 1
  fi
done
cat > "$root/config.yaml" <<EOF
database: /var/lib/edgewatch/edgewatch.db
retention: 90d
web:
  listen: 127.0.0.1:${port}
scheduler:
  max_concurrent_scans: 1
notifications:
  urls: []
updates:
  enabled: false
enrichment:
  rdap:
    enabled: false
EOF
mkdir -p "$root/data"
./scripts/prepare-container-smoke-data.sh "$image" "$root/data"

container_id="$(docker run -d --platform "$platform" --network host --read-only \
  --tmpfs /tmp:size=128m,mode=1777 --cap-drop ALL --cap-add NET_RAW --security-opt no-new-privileges:true \
  -v "$root/config.yaml:/etc/edgewatch/config.yaml:ro" \
  -v "$root/data:/var/lib/edgewatch" \
  "$image" daemon --config /etc/edgewatch/config.yaml)"

for _ in {1..30}; do
  if curl --fail --silent "http://127.0.0.1:${port}/" > "$root/index.html"; then
    break
  fi
  if [[ "$(docker inspect --format '{{.State.Running}}' "$container_id" 2>/dev/null || true)" != "true" ]]; then
    docker inspect --format 'container state={{.State.Status}} exit={{.State.ExitCode}} error={{.State.Error}}' "$container_id" >&2 || true
    docker logs "$container_id" >&2 || true
    exit 1
  fi
  sleep 1
done

grep -Fq 'EdgeWatch' "$root/index.html"
favicon_content_type="$(curl --fail --silent --show-error --output "$root/favicon.svg" \
  --write-out '%{content_type}' "http://127.0.0.1:${port}/favicon.svg")"
if [[ "$favicon_content_type" != "image/svg+xml" ]]; then
  echo "expected /favicon.svg to be served as image/svg+xml, got ${favicon_content_type:-<empty>}" >&2
  exit 1
fi
docker exec "$container_id" /bin/sh -c 'test -s /var/lib/edgewatch/edgewatch.db'
