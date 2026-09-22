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
    docker rm -f "$daemon_container" >/dev/null 2>&1 || true
  fi
  rm -rf "$workdir"
}
trap cleanup EXIT
install -d -m 0750 "$workdir/data"
install -m 0600 /dev/null "$workdir/notification-urls.txt"
install -m 0600 /dev/null "$workdir/notification-urls-unreadable.txt"
secret_marker=edgewatch-secret-read-smoke
printf '%s\n' "$secret_marker" >"$workdir/notification-urls.txt"
printf '%s\n' "$secret_marker" >"$workdir/notification-urls-unreadable.txt"
test "$(stat -c '%a' "$workdir/data")" = 750
test "$(stat -c '%a' "$workdir/notification-urls.txt")" = 600
test "$(stat -c '%a' "$workdir/notification-urls-unreadable.txt")" = 600
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
# Docker user namespaces can map container root away from the host owner of a
# bind-mounted directory. Temporarily relax only this disposable directory for
# bootstrap and diagnostics, then restore and assert the hardened mode below.
chmod 0777 "$workdir/data"
daemon_container=$(docker run -d $network_args $runtime_args \
  --cap-drop ALL --cap-add NET_RAW \
  -v "$workdir/config.yaml:/etc/edgewatch/config.yaml:ro" \
  -v "$workdir/data:/var/lib/edgewatch:rw" "$image" daemon --config /etc/edgewatch/config.yaml)
for attempt in $(seq 1 30); do
  if test -s "$workdir/data/edgewatch.db"; then
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
docker rm -f "$daemon_container" >/dev/null
daemon_container=
docker run --rm $runtime_args \
  -v "$workdir/config.yaml:/etc/edgewatch/config.yaml:ro" \
  -v "$workdir/data:/var/lib/edgewatch:rw" "$image" status --config /etc/edgewatch/config.yaml
chmod 0750 "$workdir/data"
test -s "$workdir/data/edgewatch.db"
test "$(stat -c '%a' "$workdir/data")" = 750

# Model the documented rootful Compose ownership explicitly: the process is
# UID 0, so the owner-only secret must be owned by host root. A second fixture
# owned by an unrelated UID proves root cannot bypass mode 0600 after Docker
# drops all capabilities except the Compose NET_RAW capability.
docker run --rm $runtime_args \
  -v "$workdir:/fixtures:rw" \
  --entrypoint /bin/sh "$image" \
  -c 'chown 0:0 "$1" && chmod 0600 "$1" && chown 65532:65532 "$2" && chmod 0600 "$2"' \
  sh /fixtures/notification-urls.txt /fixtures/notification-urls-unreadable.txt
test "$(stat -c '%u:%g' "$workdir/notification-urls.txt")" = 0:0
test "$(stat -c '%u:%g' "$workdir/notification-urls-unreadable.txt")" = 65532:65532

secret_output=$(docker run --rm $runtime_args --cap-drop ALL --cap-add NET_RAW \
  -v "$workdir/notification-urls.txt:/run/secrets/edgewatch-test:ro" \
  --entrypoint /bin/sh "$image" \
  -c 'cat /run/secrets/edgewatch-test')
test "$secret_output" = "$secret_marker"

if docker run --rm $runtime_args --cap-drop ALL --cap-add NET_RAW \
  -v "$workdir/notification-urls-unreadable.txt:/run/secrets/edgewatch-test:ro" \
  --entrypoint /bin/sh "$image" \
  -c 'cat /run/secrets/edgewatch-test' >/dev/null 2>&1; then
  echo "restricted container unexpectedly read a secret owned by another UID" >&2
  exit 1
fi

echo "container runtime compatibility matrix passed for $image"
