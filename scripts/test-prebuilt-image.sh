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

edgewatch_version_output="$(docker run --rm --platform "$platform" --read-only --tmpfs /tmp:size=32m,mode=1777 "$image" version)"
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
# The daemon runs as UID 0 with all Linux capabilities dropped. A bind mount
# owned by the host runner therefore needs an explicit write bit for the
# container process, just like a freshly-created Compose data directory.
chmod 0777 "$root/data"

container_id=""
cleanup() {
  if [[ -n "$container_id" ]]; then
    docker rm -f "$container_id" >/dev/null 2>&1 || true
  fi
  rm -rf "$root"
}
trap cleanup EXIT

container_id="$(docker run -d --rm --platform "$platform" --network host --read-only \
  --tmpfs /tmp:size=32m,mode=1777 --cap-drop ALL --security-opt no-new-privileges:true \
  -v "$root/config.yaml:/etc/edgewatch/config.yaml:ro" \
  -v "$root/data:/var/lib/edgewatch" \
  "$image" daemon --config /etc/edgewatch/config.yaml)"

for _ in {1..30}; do
  if curl --fail --silent --show-error "http://127.0.0.1:${port}/" > "$root/index.html"; then
    break
  fi
  if [[ "$(docker inspect --format '{{.State.Running}}' "$container_id" 2>/dev/null || true)" != "true" ]]; then
    docker logs "$container_id" >&2 || true
    exit 1
  fi
  sleep 1
done

grep -Fq 'EdgeWatch' "$root/index.html"
test -s "$root/data/edgewatch.db"
