#!/bin/sh
set -eu

image=${1:?usage: verify-container-runtime.sh IMAGE}
network_args="--network host"
runtime_args="--read-only --tmpfs /tmp:size=32m,mode=1777"

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
docker run --rm $network_args $runtime_args --cap-drop ALL --cap-add NET_RAW --cap-add NET_ADMIN --entrypoint /usr/local/bin/naabu "$image" \
  -host 127.0.0.1 -p 1 -scan-type s -silent -no-stdin -disable-update-check -json >/dev/null

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT
mkdir "$workdir/data"
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
docker run --rm $runtime_args \
  -v "$workdir/config.yaml:/etc/edgewatch/config.yaml:ro" \
  -v "$workdir/data:/var/lib/edgewatch:rw" "$image" status --config /etc/edgewatch/config.yaml
test -s "$workdir/data/edgewatch.db"

echo "container runtime compatibility matrix passed for $image"
