#!/bin/sh
set -eu

image=${1:?usage: verify-container-runtime.sh IMAGE}
network_args="--network host"
runtime_args="--read-only --tmpfs /tmp:size=128m,mode=1777"

root_caps=$(docker run --rm $runtime_args --cap-drop ALL --cap-add NET_RAW --entrypoint /bin/sh "$image" -c "id -u; awk '/^CapEff:/{print \$2}' /proc/self/status")
root_uid=$(printf '%s\n' "$root_caps" | sed -n '1p')
root_eff=$(printf '%s\n' "$root_caps" | sed -n '2p')
test "$root_uid" = 0
test "$root_eff" = 0000000000002000

nonroot_eff=$(docker run --rm $runtime_args --user 65532:65532 --cap-drop ALL --cap-add NET_RAW --entrypoint /bin/sh "$image" -c "awk '/^CapEff:/{print \$2}' /proc/self/status")
test "$nonroot_eff" = 0000000000000000

# The unprivileged matrix covers the modes that do not require raw packets.
docker run --rm $network_args $runtime_args --user 65532:65532 --cap-drop ALL --entrypoint /usr/local/bin/naabu "$image" \
  -host 127.0.0.1 -p 1 -silent -no-stdin -disable-update-check -json >/dev/null
docker run --rm $network_args $runtime_args --user 65532:65532 --cap-drop ALL --entrypoint /usr/bin/nmap "$image" \
  -n -Pn -sT -p 1 127.0.0.1 >/dev/null

# Raw-packet modes must fail closed when the process is unprivileged.
if docker run --rm $network_args $runtime_args --user 65532:65532 --cap-drop ALL --entrypoint /usr/bin/nmap "$image" \
  -n -Pn -sS -p 1 127.0.0.1 >/dev/null 2>&1; then
  echo "non-root Nmap SYN unexpectedly succeeded" >&2
  exit 1
fi
if docker run --rm $network_args $runtime_args --user 65532:65532 --cap-drop ALL --entrypoint /usr/bin/nmap "$image" \
  -n -Pn -sU -p 53 127.0.0.1 >/dev/null 2>&1; then
  echo "non-root Nmap UDP unexpectedly succeeded" >&2
  exit 1
fi

# The supported root matrix covers the base Nmap modes and the explicit Naabu
# SYN override. The small localhost probes keep this a capability test rather
# than a network-performance test.
docker run --rm $network_args $runtime_args --cap-drop ALL --cap-add NET_RAW --entrypoint /usr/bin/nmap "$image" \
  -n -Pn -sS -p 1 127.0.0.1 >/dev/null
docker run --rm $network_args $runtime_args --cap-drop ALL --cap-add NET_RAW --entrypoint /usr/bin/nmap "$image" \
  -n -Pn -sU -p 53 127.0.0.1 >/dev/null
syn_output=$(docker run --rm $network_args $runtime_args --cap-drop ALL --cap-add NET_RAW --cap-add NET_ADMIN --entrypoint /usr/local/bin/naabu "$image" \
  -host 127.0.0.1 -p 1 -scan-type s -no-stdin -disable-update-check -json 2>&1)
printf '%s\n' "$syn_output" | grep -Eiq 'running[[:space:]]+syn|syn[[:space:]]+scan'
if printf '%s\n' "$syn_output" | grep -Eiq 'connect scan|running[[:space:]]+connect'; then
  echo "Naabu SYN probe fell back to CONNECT" >&2
  exit 1
fi

workdir=$(mktemp -d)
daemon_container=
cleanup() {
  if [ -n "$daemon_container" ]; then
    docker stop "$daemon_container" >/dev/null 2>&1 || true
    docker rm "$daemon_container" >/dev/null 2>&1 || true
  fi
  if [ -d "$workdir/data" ]; then
    docker run --rm --volume "$workdir/data:/data" --entrypoint /bin/sh "$image" \
      -c 'rm -rf /data/* /data/.[!.]* /data/..?*' >/dev/null 2>&1 || true
  fi
  rm -rf "$workdir"
}
trap cleanup EXIT
install -d -m 0750 "$workdir/data"
./scripts/prepare-container-smoke-data.sh "$image" "$workdir/data"
install -d -m 0733 "$workdir/secret-fixtures"
secret_marker=edgewatch-secret-read-smoke
docker run --rm $runtime_args --cap-drop ALL -v "$workdir/secret-fixtures:/fixtures:rw" --entrypoint /bin/sh "$image" -c 'umask 077 && printf "%s\n" "$1" > /fixtures/notification-urls.txt' sh "$secret_marker"
docker run --rm $runtime_args --user 65532:65532 --cap-drop ALL -v "$workdir/secret-fixtures:/fixtures:rw" --entrypoint /bin/sh "$image" -c 'umask 077 && printf "%s\n" "$1" > /fixtures/notification-urls-unreadable.txt' sh "$secret_marker"
test "$(stat -c '%a' "$workdir/data")" = 750
cat >"$workdir/config.yaml" <<'EOF'
database: /var/lib/edgewatch/edgewatch.db
retention: 24h
web:
  listen: 127.0.0.1:18080
scheduler:
  max_concurrent_scans: 1
notifications:
  urls: []
EOF
# Read-only diagnostic commands intentionally refuse to create or migrate a
# database. Bootstrap the disposable fixture through the daemon, which is the
# sole owner of migrations and startup reconciliation, before checking status
# and the persisted SQLite file.
daemon_container=$(docker run -d $network_args $runtime_args \
  --cap-drop ALL --cap-add NET_RAW \
  -v "$workdir/config.yaml:/etc/edgewatch/config.yaml:ro" \
  -v "$workdir/data:/var/lib/edgewatch:rw" "$image" daemon --config /etc/edgewatch/config.yaml)
for attempt in $(seq 1 30); do
  # The database file appears before schema migrations finish; wait until the
  # daemon is serving requests so the following read-only check cannot race it.
  if curl --fail --silent "http://127.0.0.1:18080/" >/dev/null; then
    break
  fi
  if [ -z "$(docker ps -q --filter "id=$daemon_container")" ]; then
    docker logs "$daemon_container"
    exit 1
  fi
  sleep 1
  if [ "$attempt" = 30 ]; then
    docker logs "$daemon_container"
    exit 1
  fi
done
docker exec "$daemon_container" /bin/sh -c 'test -s /var/lib/edgewatch/edgewatch.db'
docker stop "$daemon_container" >/dev/null
docker rm "$daemon_container" >/dev/null
daemon_container=
docker run --rm $runtime_args --cap-drop ALL --cap-add NET_RAW \
  -v "$workdir/config.yaml:/etc/edgewatch/config.yaml:ro" \
  -v "$workdir/data:/var/lib/edgewatch:rw" "$image" status --config /etc/edgewatch/config.yaml

test "$(stat -c '%a' "$workdir/data")" = 750

# Model the container's effective UID 0 ownership (host root in standard
# rootful Docker, or its mapped host identity in rootless/userns deployments).
# A second fixture owned by an unrelated UID proves restricted UID 0 cannot
# bypass mode 0600 after Docker drops filesystem capabilities.
docker run --rm $runtime_args --cap-drop ALL \
  -v "$workdir/secret-fixtures:/fixtures:ro" \
  --entrypoint /bin/sh "$image" \
  -c 'test "$(stat -c %u:%g /fixtures/notification-urls.txt)" = 0:0 && test "$(stat -c %a /fixtures/notification-urls.txt)" = 600 && test "$(stat -c %u:%g /fixtures/notification-urls-unreadable.txt)" = 65532:65532 && test "$(stat -c %a /fixtures/notification-urls-unreadable.txt)" = 600'

secret_output=$(docker run --rm $runtime_args --cap-drop ALL --cap-add NET_RAW \
  -v "$workdir/secret-fixtures/notification-urls.txt:/run/secrets/edgewatch-test:ro" \
  --entrypoint /bin/sh "$image" \
  -c 'cat /run/secrets/edgewatch-test')
test "$secret_output" = "$secret_marker"

if docker run --rm $runtime_args --cap-drop ALL --cap-add NET_RAW \
  -v "$workdir/secret-fixtures/notification-urls-unreadable.txt:/run/secrets/edgewatch-test:ro" \
  --entrypoint /bin/sh "$image" \
  -c 'cat /run/secrets/edgewatch-test' >/dev/null 2>&1; then
  echo "restricted container unexpectedly read a secret owned by another UID" >&2
  exit 1
fi

echo "container runtime compatibility matrix passed for $image"
