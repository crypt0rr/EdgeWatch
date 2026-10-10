#!/usr/bin/env bash

# Start an image with the bundled compose.yaml, as a deployment does, and
# require the daemon to become healthy with the scanner and notification
# sandboxes enforced. A generated override changes only the image and the
# container name. The ./config.yaml and ./data binds of compose.yaml resolve
# to a disposable project directory, so the capabilities, TMPDIR, memory
# limit, read-only root filesystem, and healthcheck are the ones users run.
set -euo pipefail

image="${1:?usage: $0 IMAGE}"
repository="$PWD"
if [[ ! -f "$repository/compose.yaml" ]]; then
  echo "compose.yaml not found; run this script from the repository root" >&2
  exit 2
fi
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

project_dir="$(mktemp -d)"
project="edgewatch-compose-smoke-$$"
compose=(docker compose --project-name "$project" --project-directory "$project_dir"
  -f "$repository/compose.yaml" -f "$project_dir/compose.override.yaml")
# shellcheck disable=SC2317 # The EXIT trap calls it.
cleanup() {
  "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
  if [[ -d "$project_dir/data" ]]; then
    docker run --rm --volume "$project_dir/data:/data" --entrypoint /bin/sh "$image" \
      -c 'rm -rf /data/* /data/.[!.]* /data/..?*' >/dev/null 2>&1 || true
  fi
  rm -rf "$project_dir"
}
trap cleanup EXIT
fail() {
  echo "Compose deployment check failed: $*" >&2
  "${compose[@]}" logs --no-color 2>&1 | tail -60 >&2 || true
  exit 1
}

port="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
cat > "$project_dir/config.yaml" <<EOF
database: /var/lib/edgewatch/edgewatch.db
retention: 24h
web:
  listen: 127.0.0.1:${port}
scheduler:
  max_concurrent_scans: 1
  max_probe_count: 1000
notifications:
  urls: []
updates:
  enabled: false
EOF
chmod 0644 "$project_dir/config.yaml"
install -d -m 0750 "$project_dir/data"
./scripts/prepare-container-smoke-data.sh "$image" "$project_dir/data"
cat > "$project_dir/compose.override.yaml" <<EOF
services:
  edgewatch:
    image: ${image}
    container_name: ${project}
EOF

echo "Rendered Compose deployment:"
"${compose[@]}" config
"${compose[@]}" up --detach --pull never

# compose.yaml checks health every five seconds during its start period.
health=""
for _ in $(seq 1 60); do
  health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$project" 2>/dev/null || true)"
  if [[ "$health" == healthy ]]; then
    break
  fi
  if [[ "$(docker inspect --format '{{.State.Running}}' "$project" 2>/dev/null || true)" != true ]]; then
    fail "the daemon exited during startup"
  fi
  sleep 2
done
[[ "$health" == healthy ]] || fail "the Compose healthcheck reports '${health:-no status}', want 'healthy'"

caps="$(docker inspect --format '{{join .HostConfig.CapAdd " "}}' "$project" | tr ' ' '\n' | sed 's/^CAP_//' | LC_ALL=C sort | paste -sd, -)"
[[ "$caps" == KILL,NET_RAW,SETGID,SETUID ]] || fail "the container adds the capabilities '$caps', want those of compose.yaml"
[[ "$(docker inspect --format '{{.HostConfig.Memory}}' "$project")" == 536870912 ]] || fail "the container is not limited to the 512M of compose.yaml"
docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$project" | grep -qx 'TMPDIR=/var/lib/edgewatch/tmp' ||
  fail "the container does not set the TMPDIR of compose.yaml"

curl --fail --silent --max-time 5 "http://127.0.0.1:${port}/" | grep -q 'EdgeWatch' || fail "the console is not served"
"${compose[@]}" exec -T edgewatch /bin/sh -c 'test -s /var/lib/edgewatch/edgewatch.db' || fail "the database was not created"
health_json="$("${compose[@]}" exec -T edgewatch edgewatch health --config /etc/edgewatch/config.yaml --output json)" ||
  fail "edgewatch health failed"
echo "Health of the Compose deployment:"
jq . <<<"$health_json"
for sandbox in scanner_sandbox notification_sandbox; do
  state="$(jq -r --arg sandbox "$sandbox" '.[$sandbox].state' <<<"$health_json")"
  [[ "$state" == enforced ]] || fail "$sandbox is '$state', want 'enforced'"
done

echo "Compose deployment verified for $image"
