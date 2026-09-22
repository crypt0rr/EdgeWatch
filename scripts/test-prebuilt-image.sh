#!/usr/bin/env bash

# Smoke-test an image assembled from release-style prebuilt inputs. The checks
# deliberately exercise the image on the requested architecture, including a
# read-only daemon with only the capabilities used by the default Compose
# deployment.
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

root="$(mktemp -d)"
port="$((18080 + ($$ % 1000)))"
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

container_id=""
cleanup() {
  if [[ -n "$container_id" ]]; then
    docker stop "$container_id" >/dev/null 2>&1 || true
    docker rm "$container_id" >/dev/null 2>&1 || true
  fi
  if [[ -d "$root/data" ]]; then
    docker run --rm --volume "$root/data:/data" --entrypoint /bin/sh "$image" \
      -c 'rm -rf /data/* /data/.[!.]* /data/..?*' >/dev/null 2>&1 || true
  fi
  rm -rf "$root"
}
trap cleanup EXIT

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
docker exec "$container_id" /bin/sh -c 'test -s /var/lib/edgewatch/edgewatch.db'
