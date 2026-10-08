#!/usr/bin/env bash
set -euo pipefail

# Run real Nmap TCP SYN and UDP scans and a Naabu discovery of local
# listeners through EdgeWatch, with the scanner sandbox enforced, with only
# its Landlock restriction (the capabilities of a Compose file from before
# v0.27.0), and with it off, and require the same results from all of them.
# With the sandbox enforced, also require that a running Nmap is UID 65532
# holding only NET_RAW, that cancelling it works, that the sandbox identity
# can neither list the data directory nor read the configuration, and that a
# process restricted with Landlock cannot do so even as UID 0.
image=${1:?usage: verify-scanner-sandbox.sh IMAGE}

workdir=$(mktemp -d)
container=
listener_pid=
cleanup() {
  if [ -n "$container" ]; then
    docker logs "$container" >"$workdir/last-daemon.log" 2>&1 || true
    docker rm -f "$container" >/dev/null 2>&1 || true
  fi
  if [ -n "$listener_pid" ]; then
    kill "$listener_pid" >/dev/null 2>&1 || true
  fi
  for data in "$workdir"/data-*; do
    [ -d "$data" ] || continue
    docker run --rm --volume "$data:/data" --entrypoint /bin/sh "$image" \
      -c 'rm -rf /data/* /data/.[!.]* /data/..?*' >/dev/null 2>&1 || true
  done
  rm -rf "$workdir"
}
trap cleanup EXIT
fail() {
  echo "scanner sandbox check failed: $*" >&2
  if [ -n "$container" ]; then
    docker logs "$container" 2>&1 | tail -40 >&2 || true
  fi
  exit 1
}

free_port() {
  python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'
}
tcp_open=$(free_port)
tcp_closed=$(free_port)
udp_open=$(free_port)
python3 - "$tcp_open" "$udp_open" <<'PY' &
import socket
import sys
import time

tcp = socket.socket()
tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcp.bind(("127.0.0.1", int(sys.argv[1])))
tcp.listen(16)
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.bind(("127.0.0.1", int(sys.argv[2])))
time.sleep(3600)
PY
listener_pid=$!

cat >"$workdir/driver.py" <<'PY'
"""Drive the EdgeWatch API for verify-scanner-sandbox.sh."""
import json
import sys
import time
import urllib.error
import urllib.request

PASSWORD = "sandbox-verification-password"


def request(base, state, method, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(base + "/api/v1" + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if state.get("cookie"):
        req.add_header("Cookie", state["cookie"])
    if state.get("csrf") and method != "GET":
        req.add_header("X-CSRF-Token", state["csrf"])
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            raw = response.read()
            cookie = response.headers.get("Set-Cookie")
            if cookie:
                state["cookie"] = cookie.split(";", 1)[0]
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as error:
        raise SystemExit(f"{method} {path}: {error.code} {error.read().decode(errors='replace')}")


def load(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def save(path, state):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(state, handle)


def create_job(base, state, name, tcp_ports, udp_ports, timing):
    job = {
        "name": name, "schedule": "0 0 1 1 *", "timezone": "UTC", "targets": ["127.0.0.1"],
        "tcp": {"ports": tcp_ports, "mode": "syn", "service_detection": False, "engine": "nmap"},
        "assume_alive": True, "timing": timing, "timeout": "10m", "baseline_samples": 1,
        "change_confirmations": 1, "enabled": True, "notification_destinations": [],
    }
    if udp_ports:
        job["udp"] = {"ports": udp_ports, "service_detection": False, "engine": "nmap"}
    return request(base, state, "POST", "/jobs", job)["id"]


def create_naabu_job(base, state, name):
    # A fast connect profile keeps the full-range discovery of one loopback
    # address to seconds. SYN discovery of loopback drops ports at any rate
    # whether or not it is sandboxed, so it cannot give comparable results.
    profile = request(base, state, "POST", "/scanner-profiles", {
        "name": name + "-profile", "engine": "naabu_nmap", "password": PASSWORD,
        "naabu": {"scan_type": "connect", "rate": 10000, "workers": 100, "retries": 2, "timeout_ms": 1000,
                  "warm_up_seconds": 1, "verify": False, "address_batch_size": 16},
    })
    job = {
        "name": name, "schedule": "0 0 1 1 *", "timezone": "UTC", "targets": ["127.0.0.1"],
        "tcp": {"ports": "1-65535", "mode": "syn", "service_detection": False, "engine": "naabu_nmap",
                "profile_id": profile["id"], "profile_revision": profile["revision"]},
        "assume_alive": True, "timing": "fast", "timeout": "10m", "baseline_samples": 1,
        "change_confirmations": 1, "enabled": True, "notification_destinations": [],
    }
    return request(base, state, "POST", "/jobs", job)["id"]


def wait_for_scan(base, state, job_id, statuses, timeout=240):
    deadline = time.time() + timeout
    while time.time() < deadline:
        scans = request(base, state, "GET", f"/jobs/{job_id}/scans")["scans"]
        for scan in scans:
            if scan["status"] in statuses:
                return scan
        time.sleep(1)
    raise SystemExit(f"job {job_id} produced no scan with status {statuses}")


def main():
    command, base, state_path = sys.argv[1:4]
    args = sys.argv[4:]
    state = {} if command == "setup" else load(state_path)
    if command == "setup":
        request(base, state, "POST", "/setup", {"token": args[0], "password": PASSWORD})
        request(base, state, "POST", "/auth/login", {"username": "admin", "password": PASSWORD})
        state["csrf"] = request(base, state, "GET", "/auth/session")["csrf_token"]
    elif command in ("scan", "naabu"):
        if command == "scan":
            name, tcp_ports, udp_ports = args
            job_id = create_job(base, state, name, tcp_ports, udp_ports, "fast")
        else:
            name, wanted = args
            job_id = create_naabu_job(base, state, name)
        request(base, state, "POST", f"/jobs/{job_id}/run")
        scan = wait_for_scan(base, state, job_id, {"success", "incomplete", "failed", "timed_out", "canceled"})
        if scan["status"] != "success":
            raise SystemExit(f"scan {scan['id']} ended {scan['status']}: {scan.get('error', '')}")
        results = request(base, state, "GET", f"/jobs/{job_id}/scans/{scan['id']}/results?limit=100")["results"]
        observed = sorted(
            (unit["protocol"], port["port"], port["state"])
            for unit in results for port in unit.get("ports") or []
        )
        if command == "naabu":
            # A full-range discovery of loopback also finds the host's own
            # services, which can change between runs. Report the listener.
            observed = [entry for entry in observed if entry[1] == int(wanted)]
        print(json.dumps(observed))
    elif command == "start":
        name, tcp_ports = args
        job_id = create_job(base, state, name, tcp_ports, "", "conservative")
        request(base, state, "POST", f"/jobs/{job_id}/run")
        deadline = time.time() + 60
        while time.time() < deadline:
            active = request(base, state, "GET", "/scans/active")["scans"]
            for scan in active:
                if scan.get("job_id") == job_id:
                    print(json.dumps({"job_id": job_id, "scan_id": scan["id"]}))
                    save(state_path, state)
                    return
            time.sleep(0.5)
        raise SystemExit("the slow scan never became active")
    elif command == "cancel":
        job_id, scan_id = args
        request(base, state, "POST", f"/scans/{scan_id}/cancel")
        scan = wait_for_scan(base, state, job_id, {"canceled", "success", "failed", "timed_out", "incomplete"}, timeout=60)
        print(scan["status"])
    else:
        raise SystemExit(f"unknown command {command}")
    save(state_path, state)


main()
PY

# The capabilities of the bundled Compose file.
bundled_caps=(NET_RAW SETUID SETGID KILL)

# run_daemon NAME MODE CAPABILITY... starts a daemon whose configuration sets
# scanner.sandbox to MODE, with the given capabilities, waits until it serves
# requests, and signs in as its administrator.
run_daemon() {
  local name=$1 mode=$2
  shift 2
  local caps=()
  for capability in "$@"; do
    caps+=(--cap-add "$capability")
  done
  local data="$workdir/data-$name"
  web_port=$(free_port)
  install -d -m 0750 "$data"
  ./scripts/prepare-container-smoke-data.sh "$image" "$data"
  cat >"$workdir/config-$name.yaml" <<EOF
database: /var/lib/edgewatch/edgewatch.db
retention: 24h
web:
  listen: 127.0.0.1:$web_port
scheduler:
  max_concurrent_scans: 1
scanner:
  target_exclusions: []
  sandbox: $mode
updates:
  enabled: false
EOF
  chmod 0644 "$workdir/config-$name.yaml"
  container=$(docker run -d --network host --read-only --tmpfs /tmp:size=128m,mode=1777 \
    --cap-drop ALL "${caps[@]}" \
    --security-opt no-new-privileges:true --env TMPDIR=/var/lib/edgewatch/tmp \
    --volume "$workdir/config-$name.yaml:/etc/edgewatch/config.yaml:ro" \
    --volume "$data:/var/lib/edgewatch:rw" "$image" daemon --config /etc/edgewatch/config.yaml)
  base="http://127.0.0.1:$web_port"
  for attempt in $(seq 1 60); do
    if curl --fail --silent "$base/api/v1/setup/status" >/dev/null; then
      break
    fi
    if [ -z "$(docker ps -q --filter "id=$container")" ]; then
      fail "the $name daemon exited during startup"
    fi
    sleep 1
    if [ "$attempt" = 60 ]; then
      fail "the $name daemon did not start serving requests"
    fi
  done
  token=$(docker logs "$container" 2>&1 | sed -n 's/.*"setup_token":"\([A-Z0-9]*\)".*/\1/p' | tail -1)
  [ -n "$token" ] || fail "the $name daemon logged no setup token"
  state="$workdir/state-$name.json"
  python3 "$workdir/driver.py" setup "$base" "$state" "$token"
}

stop_daemon() {
  docker rm -f "$container" >/dev/null
  container=
}

# health_state prints the sandbox state, the scanner UID, the capabilities,
# and the Landlock state that the health command reports.
health_state() {
  docker exec "$container" edgewatch health --config /etc/edgewatch/config.yaml --output json |
    python3 -c 'import json, sys; sandbox = json.load(sys.stdin)["scanner_sandbox"]; print(sandbox["state"], sandbox.get("process_uid"), ",".join(sandbox.get("capabilities") or []) or "-", "landlock:" + sandbox["landlock"]["state"])'
}

expect_health() {
  local want=$1 got
  got=$(health_state)
  [ "$got" = "$want" ] || fail "health reports the sandbox as '$got', want '$want'"
}

# landlocked runs a command in the daemon's container as UID 0, restricted
# with Landlock as scanner processes are.
landlocked() {
  docker exec "$container" edgewatch sandbox-exec --files 0 -- "$@"
}

tcp_ports="$tcp_open,$tcp_closed"
udp_ports="$udp_open"

# The bundled Compose deployment: the sandbox keeps NET_RAW only.
run_daemon base auto "${bundled_caps[@]}"
expect_health "enforced 65532 NET_RAW landlock:enforced"
sandboxed=$(python3 "$workdir/driver.py" scan "$base" "$state" sandboxed "$tcp_ports" "$udp_ports")

# Landlock restricts a process whatever its identity: as UID 0, which owns
# the database, a restricted process can neither read it nor list the data
# directory, read the configuration, write outside /tmp, or execute a file it
# wrote. The unrestricted reads show that only Landlock refuses them; the
# read-only root filesystem already refuses writes elsewhere.
docker exec "$container" cat /var/lib/edgewatch/edgewatch.db >/dev/null || fail "UID 0 could not read the database without Landlock"
docker exec "$container" cat /etc/edgewatch/config.yaml >/dev/null || fail "UID 0 could not read the configuration without Landlock"
landlocked /bin/cat /etc/hosts >/dev/null || fail "a restricted process could not read /etc/hosts"
landlocked /bin/sh -c 'echo scanner >/tmp/edgewatch-landlock && rm /tmp/edgewatch-landlock' || fail "a restricted process could not use /tmp"
for escape in "cat /var/lib/edgewatch/edgewatch.db" "ls /var/lib/edgewatch" "cat /etc/edgewatch/config.yaml" \
  "touch /var/lib/edgewatch/escape" "cp /bin/true /tmp/escape && /tmp/escape"; do
  if output=$(landlocked /bin/sh -c "$escape" 2>&1); then
    fail "a restricted UID 0 process succeeded at: $escape"
  fi
  printf '%s\n' "$output" | grep -qi 'permission denied' || fail "'$escape' failed for another reason than Landlock: $output"
done

# The sandbox identity cannot list the data directory or reach the
# configuration, whatever the files' own modes.
if docker exec --user 65532:65532 "$container" ls /var/lib/edgewatch >/dev/null 2>&1; then
  fail "UID 65532 listed the data directory"
fi
if docker exec --user 65532:65532 "$container" cat /etc/edgewatch/config.yaml >/dev/null 2>&1; then
  fail "UID 65532 read the configuration"
fi

# Observe a running Nmap: it must be UID 65532 with only NET_RAW effective,
# and cancelling the scan must stop it.
started=$(python3 "$workdir/driver.py" start "$base" "$state" slow "1-20000")
job_id=$(printf '%s' "$started" | python3 -c 'import json, sys; print(json.load(sys.stdin)["job_id"])')
scan_id=$(printf '%s' "$started" | python3 -c 'import json, sys; print(json.load(sys.stdin)["scan_id"])')
nmap_identity=
for attempt in $(seq 1 60); do
  nmap_identity=$(docker exec "$container" /bin/sh -c 'for status in /proc/[0-9]*/status; do if grep -q "^Name:[[:space:]]*nmap$" "$status" 2>/dev/null; then awk "/^Uid:/{uid=\$2} /^Gid:/{gid=\$2} /^Groups:/{groups=\$2} /^CapEff:/{cap=\$2} END{print uid, gid, (groups == \"\" ? \"-\" : groups), cap}" "$status"; break; fi; done' 2>/dev/null || true)
  [ -n "$nmap_identity" ] && break
  sleep 0.5
done
[ "$nmap_identity" = "65532 65532 - 0000000000002000" ] || fail "running Nmap identity is '$nmap_identity', want '65532 65532 - 0000000000002000'"
cancelled=$(python3 "$workdir/driver.py" cancel "$base" "$state" "$job_id" "$scan_id")
[ "$cancelled" = canceled ] || fail "the cancelled scan ended '$cancelled'"
if docker exec "$container" /bin/sh -c 'grep -l "^Name:[[:space:]]*nmap$" /proc/[0-9]*/status' >/dev/null 2>&1; then
  fail "Nmap kept running after the scan was cancelled"
fi
stop_daemon

# The SYN override: a sandboxed Naabu keeps NET_RAW and NET_ADMIN, and
# discovers ports with the target list it reads through its descriptor.
run_daemon syn auto "${bundled_caps[@]}" NET_ADMIN
expect_health "enforced 65532 NET_RAW,NET_ADMIN landlock:enforced"
naabu_sandboxed=$(python3 "$workdir/driver.py" naabu "$base" "$state" naabu-sandboxed "$tcp_open")
stop_daemon

# A Compose file from before v0.27.0 grants no SETUID, SETGID, or KILL:
# scanner processes stay UID 0, restricted only by Landlock.
run_daemon legacy auto NET_RAW NET_ADMIN
expect_health "unavailable 0 - landlock:enforced"
landlock_only=$(python3 "$workdir/driver.py" scan "$base" "$state" landlock-only "$tcp_ports" "$udp_ports")
naabu_landlock_only=$(python3 "$workdir/driver.py" naabu "$base" "$state" naabu-landlock-only "$tcp_open")
stop_daemon

run_daemon off off "${bundled_caps[@]}" NET_ADMIN
expect_health "disabled 0 - landlock:disabled"
unconfined=$(python3 "$workdir/driver.py" scan "$base" "$state" unconfined "$tcp_ports" "$udp_ports")
naabu_unconfined=$(python3 "$workdir/driver.py" naabu "$base" "$state" naabu-unconfined "$tcp_open")
stop_daemon

[ "$sandboxed" = "$unconfined" ] || fail "sandboxed Nmap results $sandboxed differ from unconfined results $unconfined"
[ "$landlock_only" = "$unconfined" ] || fail "Nmap results with only Landlock $landlock_only differ from unconfined results $unconfined"
[ "$naabu_landlock_only" = "$naabu_unconfined" ] || fail "Naabu results with only Landlock $naabu_landlock_only differ from unconfined results $naabu_unconfined"
printf '%s\n' "$sandboxed" | grep -q "\"tcp\", $tcp_open, \"open\"" || fail "the open TCP listener was not reported open: $sandboxed"
[ "$naabu_sandboxed" = "$naabu_unconfined" ] || fail "sandboxed Naabu results $naabu_sandboxed differ from unconfined results $naabu_unconfined"
[ "$naabu_sandboxed" = "[[\"tcp\", $tcp_open, \"open\"]]" ] || fail "Naabu did not report the open TCP listener: $naabu_sandboxed"

echo "scanner sandbox verified for $image: Nmap $sandboxed, Naabu $naabu_sandboxed"
