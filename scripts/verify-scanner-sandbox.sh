#!/usr/bin/env bash
set -euo pipefail

# Run real Nmap TCP SYN and UDP scans and a Naabu discovery of local
# listeners through EdgeWatch, with the scanner sandbox enforced, with only
# its Landlock restriction (the capabilities of a Compose file from before
# v0.27.0), and with it off, and require the same results from all of them.
# With the sandbox enforced, also require that a running Nmap is UID 65532
# holding only NET_RAW, that cancelling it works, that the sandbox identity
# can neither list the data directory nor read the configuration, and that a
# process restricted with Landlock cannot do so even as UID 0. Deliver a test
# notification to a local webhook and require that the notification process
# runs as UID 65531 without capabilities. Require that both run with the
# seccomp filter, one more than the daemon's, and that no process dumps core.
# Require that a running Nmap has the scanner's resource limits. Without
# TMPDIR, require that the files of running Nmap and Naabu scans lie in the
# scanner files directory, where no other sandboxed process can open them,
# and that cancelling a Naabu scan stops it. Require that cancelling a scan of
# a stand-in Nmap that leaves background processes stops every one of them,
# also one that tries to leave its process group, and that a sandboxed Nmap
# dies with the edgewatch scan command that started it.
image=${1:?usage: verify-scanner-sandbox.sh IMAGE}

workdir=$(mktemp -d)
container=
listener_pid=
webhook_pid=
cleanup() {
  if [ -n "$container" ]; then
    docker logs "$container" >"$workdir/last-daemon.log" 2>&1 || true
    docker rm -f "$container" >/dev/null 2>&1 || true
  fi
  if [ -n "$listener_pid" ]; then
    kill "$listener_pid" >/dev/null 2>&1 || true
  fi
  if [ -n "$webhook_pid" ]; then
    kill "$webhook_pid" >/dev/null 2>&1 || true
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

# The webhook records each notification and answers after a pause, so the
# notification process can be observed while it waits.
webhook_port=$(free_port)
python3 - "$webhook_port" "$workdir/notifications.log" <<'PY' &
import http.server
import sys
import time


class Hook(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        time.sleep(3)
        with open(sys.argv[2], "ab") as log:
            log.write(body + b"\n")
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args):
        pass


http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Hook).serve_forever()
PY
webhook_pid=$!

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


def create_naabu_job(base, state, name, rate=10000):
    # A fast connect profile keeps the full-range discovery of one loopback
    # address to seconds. SYN discovery of loopback drops ports at any rate
    # whether or not it is sandboxed, so it cannot give comparable results.
    # A rate of 1 keeps the discovery running until it is cancelled.
    profile = request(base, state, "POST", "/scanner-profiles", {
        "name": name + "-profile", "engine": "naabu_nmap", "password": PASSWORD,
        "naabu": {"scan_type": "connect", "rate": rate, "workers": 100, "retries": 2, "timeout_ms": 1000,
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
    elif command in ("start", "start-naabu"):
        if command == "start":
            name, tcp_ports = args
            job_id = create_job(base, state, name, tcp_ports, "", "conservative")
        else:
            name, = args
            job_id = create_naabu_job(base, state, name, rate=1)
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
    elif command == "create":
        name, tcp_ports = args
        print(create_job(base, state, name, tcp_ports, "", "conservative"))
    elif command == "notify":
        name, url = args
        request(base, state, "POST", "/notifications/destinations", {"name": name, "url": url, "enabled": True, "password": PASSWORD})
        print(json.dumps(request(base, state, "POST", "/notifications/test")))
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
# requests, and signs in as its administrator. It sets TMPDIR as the bundled
# compose.yaml does unless daemon_tmpdir is empty, and adds the docker run
# arguments in daemon_mounts.
daemon_tmpdir=/var/lib/edgewatch/tmp
daemon_mounts=()
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
  local env=()
  if [ -n "$daemon_tmpdir" ]; then
    env=(--env "TMPDIR=$daemon_tmpdir")
  fi
  container=$(docker run -d --network host --read-only --tmpfs /tmp:size=128m,mode=1777 \
    --cap-drop ALL "${caps[@]}" \
    --security-opt no-new-privileges:true "${env[@]}" "${daemon_mounts[@]}" \
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
    python3 -c 'import json, sys; sandbox = json.load(sys.stdin)["scanner_sandbox"]; limits = sandbox.get("limits"); print(sandbox["state"], sandbox.get("process_uid"), ",".join(sandbox.get("capabilities") or []) or "-", "landlock:" + sandbox["landlock"]["state"], "seccomp:" + sandbox["seccomp"]["state"], "limits:" + ("%s,%s" % (limits["oom_score_adj"], limits["max_open_files"]) if limits else "-"))'
}

# process_limits PID prints the oom_score_adj and the soft and hard open file
# limits of a process in the daemon's container.
process_limits() {
  docker exec "$container" /bin/sh -c 'cat "/proc/$1/oom_score_adj"; awk "/^Max open files/{print \$4, \$5}" "/proc/$1/limits"' sh "$1" | tr '\n' ' ' | sed 's/ $//'
}

# expect_scanner_limits NAME PID requires the resource limits of a running
# scanner: the out-of-memory killer's first choice and at most 65536 open
# files.
expect_scanner_limits() {
  local name=$1 got oom soft hard
  got=$(process_limits "$2")
  read -r oom soft hard <<<"$got"
  if [ "$oom" != 1000 ] || ! [ "${soft:-x}" -le 65536 ] 2>/dev/null || ! [ "${hard:-x}" -le 65536 ] 2>/dev/null; then
    fail "the $name process has oom_score_adj and open file limits '$got', want '1000' and at most 65536"
  fi
}

# scanner_pid NAME prints the ID of the running process with that name.
scanner_pid() {
  local pid=
  for attempt in $(seq 1 120); do
    pid=$(docker exec "$container" /bin/sh -c 'for status in /proc/[0-9]*/status; do if grep -q "^Name:[[:space:]]*$1$" "$status" 2>/dev/null; then pid=${status#/proc/}; echo "${pid%/status}"; break; fi; done' sh "$1" 2>/dev/null || true)
    [ -n "$pid" ] && break
    sleep 0.5
  done
  printf '%s\n' "$pid"
}

# scan_file PATTERN prints the path of a running scan's private file whose
# name matches PATTERN, which the daemon keeps in the scanner files
# directory.
scan_file() {
  local path=
  for attempt in $(seq 1 60); do
    path=$(docker exec "$container" find /var/lib/edgewatch/tmp/scanner -type f -name "$1" 2>/dev/null | head -1 || true)
    [ -n "$path" ] && break
    sleep 0.5
  done
  printf '%s\n' "$path"
}

# expect_private_scan_file NAME PATTERN requires that a running scan's file
# lies in the scanner files directory, whatever TMPDIR names, and that
# neither the sandbox identity nor a process restricted with Landlock, as
# Nmap or as Naabu is, can open it.
expect_private_scan_file() {
  local name=$1 path output
  path=$(scan_file "$2")
  [ -n "$path" ] || fail "no $name file was found in /var/lib/edgewatch/tmp/scanner"
  # Naabu's own temporary directories in /tmp belong to UID 65532, so find
  # cannot read them; only the daemon's files are looked for.
  if [ -n "$(docker exec "$container" find /tmp -name 'edgewatch-*' 2>/dev/null || true)" ]; then
    fail "a scan file was created in /tmp"
  fi
  for open in "cat '$path'" "echo forged >>'$path'"; do
    if output=$(docker exec --user 65532:65532 "$container" /bin/sh -c "$open" 2>&1); then
      fail "UID 65532 succeeded at: $open"
    fi
    printf '%s\n' "$output" | grep -qi 'permission denied' || fail "'$open' as UID 65532 failed for another reason: $output"
    for profile in "--files 0" "--files 0 --tmp"; do
      # shellcheck disable=SC2086
      if output=$(docker exec "$container" edgewatch sandbox-exec --profile scanner $profile -- /bin/sh -c "$open" 2>&1); then
        fail "a restricted process ($profile) succeeded at: $open"
      fi
      printf '%s\n' "$output" | grep -qi 'permission denied' || fail "'$open' restricted ($profile) failed for another reason: $output"
    done
  done
}

# expect_no_scanner_processes requires that no process of the sandbox
# identity is left, other than zombies: the daemon, which is the container's
# PID 1, does not reap processes that it did not start.
expect_no_scanner_processes() {
  local left
  for attempt in $(seq 1 20); do
    left=$(docker exec "$container" /bin/sh -c 'for status in /proc/[0-9]*/status; do awk "/^Name:/{name=\$2} /^State:/{state=\$2} /^Uid:/{uid=\$2} END{if (uid == 65532 && state != \"Z\") print name}" "$status" 2>/dev/null; done' | tr '\n' ' ')
    [ -z "$left" ] && return
    sleep 0.5
  done
  fail "$1 left processes of UID 65532 running: $left"
}

# process_hardening PID prints the number of seccomp filters of a process in
# the daemon's container and its soft and hard core file size limits.
process_hardening() {
  docker exec "$container" /bin/sh -c 'awk "/^Seccomp_filters:/{print \$2}" "/proc/$1/status"; awk "/^Max core file size/{print \$5, \$6}" "/proc/$1/limits"' sh "$1" | tr '\n' ' ' | sed 's/ $//'
}

# expect_filtered NAME HARDENING requires a process's hardening to be one
# seccomp filter more than the daemon's and no core dumps.
expect_filtered() {
  local name=$1 got=$2 daemon_filters
  daemon_filters=$(process_hardening 1 | cut -d' ' -f1)
  [ "$got" = "$((daemon_filters + 1)) 0 0" ] || fail "the $name process has seccomp filters and core limits '$got', want '$((daemon_filters + 1)) 0 0'"
}

expect_health() {
  local want=$1 got
  got=$(health_state)
  [ "$got" = "$want" ] || fail "health reports the sandbox as '$got', want '$want'"
}

# notification_health_state prints the notification sandbox state, its UID,
# and its Landlock state that the health command reports.
notification_health_state() {
  docker exec "$container" edgewatch health --config /etc/edgewatch/config.yaml --output json |
    python3 -c 'import json, sys; sandbox = json.load(sys.stdin)["notification_sandbox"]; print(sandbox["state"], sandbox.get("process_uid"), "landlock:" + sandbox["landlock"]["state"], "seccomp:" + sandbox["seccomp"]["state"])'
}

expect_notification_health() {
  local want=$1 got
  got=$(notification_health_state)
  [ "$got" = "$want" ] || fail "health reports the notification sandbox as '$got', want '$want'"
}

# landlocked runs a command in the daemon's container as UID 0, restricted
# with Landlock as Nmap is; landlocked_naabu as Naabu is, which may also use
# /tmp; landlocked_notifier as the notification process is.
landlocked() {
  docker exec "$container" edgewatch sandbox-exec --profile scanner --files 0 -- "$@"
}
landlocked_naabu() {
  docker exec "$container" edgewatch sandbox-exec --profile scanner --files 0 --tmp -- "$@"
}
landlocked_notifier() {
  docker exec "$container" edgewatch sandbox-exec --profile notifier --files 0 -- "$@"
}

# deliver_notification NAME sends a test notification to the webhook and
# prints the identity of the notification process while it waits for the
# webhook's answer.
deliver_notification() {
  local name=$1 sent identity=
  python3 "$workdir/driver.py" notify "$base" "$state" "$name" "generic://127.0.0.1:$webhook_port/hook?disabletls=yes&template=json" >"$workdir/notify-$name.json" &
  sent=$!
  for attempt in $(seq 1 40); do
    identity=$(docker exec "$container" /bin/sh -c 'for process in /proc/[0-9]*; do if [ "$(tr "\0" " " <"$process/cmdline" 2>/dev/null)" = "/usr/local/bin/edgewatch notify-send " ]; then awk "/^Uid:/{uid=\$2} /^Gid:/{gid=\$2} /^Groups:/{groups=\$2} /^CapEff:/{cap=\$2} END{print uid, gid, (groups == \"\" ? \"-\" : groups), cap}" "$process/status"; echo "${process#/proc/}"; break; fi; done' 2>/dev/null || true)
    if [ -n "$identity" ]; then
      identity="$(printf '%s\n' "$identity" | head -1) | $(process_hardening "$(printf '%s\n' "$identity" | tail -1)")"
      break
    fi
    sleep 0.25
  done
  wait "$sent" || fail "the $name test notification failed: $(cat "$workdir/notify-$name.json" 2>/dev/null)"
  grep -q '"sent": 1' "$workdir/notify-$name.json" || fail "the $name test notification reported $(cat "$workdir/notify-$name.json")"
  printf '%s\n' "$identity"
}

tcp_ports="$tcp_open,$tcp_closed"
udp_ports="$udp_open"

# The bundled Compose deployment: the sandbox keeps NET_RAW only.
run_daemon base auto "${bundled_caps[@]}"
expect_health "enforced 65532 NET_RAW landlock:enforced seccomp:enforced limits:1000,65536"
[ "$(process_hardening 1 | cut -d' ' -f2-)" = "0 0" ] || fail "the daemon may dump core: $(process_hardening 1)"
sandboxed=$(python3 "$workdir/driver.py" scan "$base" "$state" sandboxed "$tcp_ports" "$udp_ports")

# Landlock restricts a process whatever its identity: as UID 0, which owns
# the database, a restricted process can neither read it nor list the data
# directory, read the configuration, write outside /tmp, or execute a file it
# wrote, and only Naabu's restriction lets it use /tmp at all. The
# unrestricted reads show that only Landlock refuses them; the read-only root
# filesystem already refuses writes elsewhere.
docker exec "$container" cat /var/lib/edgewatch/edgewatch.db >/dev/null || fail "UID 0 could not read the database without Landlock"
docker exec "$container" cat /etc/edgewatch/config.yaml >/dev/null || fail "UID 0 could not read the configuration without Landlock"
landlocked /bin/cat /etc/hosts >/dev/null || fail "a restricted process could not read /etc/hosts"
landlocked_naabu /bin/sh -c 'echo scanner >/tmp/edgewatch-landlock && rm /tmp/edgewatch-landlock' || fail "a process restricted as Naabu could not use /tmp"
if output=$(landlocked /bin/sh -c 'echo scanner >/tmp/edgewatch-landlock' 2>&1); then
  fail "a process restricted as Nmap created a file in /tmp"
fi
printf '%s\n' "$output" | grep -qi 'permission denied' || fail "creating a file in /tmp as Nmap failed for another reason than Landlock: $output"
for escape in "cat /var/lib/edgewatch/edgewatch.db" "ls /var/lib/edgewatch" "cat /etc/edgewatch/config.yaml" \
  "touch /var/lib/edgewatch/escape" "cp /bin/true /tmp/escape && /tmp/escape"; do
  if output=$(landlocked_naabu /bin/sh -c "$escape" 2>&1); then
    fail "a restricted UID 0 process succeeded at: $escape"
  fi
  printf '%s\n' "$output" | grep -qi 'permission denied' || fail "'$escape' failed for another reason than Landlock: $output"
done
# The notification process writes no file at all, not even in /tmp.
landlocked_notifier /bin/cat /etc/ssl/certs/ca-certificates.crt >/dev/null || fail "a restricted notification process could not read the system certificate authorities"
for escape in "cat /var/lib/edgewatch/edgewatch.db" "cat /etc/edgewatch/config.yaml" "echo x >/tmp/escape"; do
  if output=$(landlocked_notifier /bin/sh -c "$escape" 2>&1); then
    fail "a restricted notification process succeeded at: $escape"
  fi
  printf '%s\n' "$output" | grep -qi 'permission denied' || fail "'$escape' failed for another reason than Landlock: $output"
done

# A test notification reaches the webhook from a notification process that
# runs as UID 65531 with no capabilities.
expect_notification_health "enforced 65531 landlock:enforced seccomp:enforced"
notifier=$(deliver_notification base)
[ "${notifier%% | *}" = "65531 65531 - 0000000000000000" ] || fail "the notification process identity is '${notifier%% | *}', want '65531 65531 - 0000000000000000'"
expect_filtered notification "${notifier##* | }"

# A certificate authority the notification identity cannot read keeps the
# notification process as UID 0, so its TLS destinations keep working, though
# still restricted with Landlock, and health names the file.
docker exec "$container" /bin/sh -c 'umask 077 && echo private >/var/lib/edgewatch/private-ca.pem'
private_ca=$(docker exec -e SSL_CERT_FILE=/var/lib/edgewatch/private-ca.pem "$container" edgewatch health --config /etc/edgewatch/config.yaml --output json |
  python3 -c 'import json, sys; health = json.load(sys.stdin); sandbox = health["notification_sandbox"]; print(sandbox["state"], sandbox["landlock"]["state"], "|", sandbox.get("reason", ""), "|", any("the notification process runs as UID 0, restricted only by Landlock" in warning for warning in health.get("warnings") or []))')
case "$private_ca" in
  "unavailable enforced | "*"read SSL_CERT_FILE"*"permission denied"*" | True") ;;
  *) fail "an unreadable SSL_CERT_FILE gave the notification sandbox '$private_ca'" ;;
esac

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
  nmap_identity=$(docker exec "$container" /bin/sh -c 'for status in /proc/[0-9]*/status; do if grep -q "^Name:[[:space:]]*nmap$" "$status" 2>/dev/null; then awk "/^Uid:/{uid=\$2} /^Gid:/{gid=\$2} /^Groups:/{groups=\$2} /^CapEff:/{cap=\$2} END{print uid, gid, (groups == \"\" ? \"-\" : groups), cap}" "$status"; pid=${status#/proc/}; echo "${pid%/status}"; break; fi; done' 2>/dev/null || true)
  [ -n "$nmap_identity" ] && break
  sleep 0.5
done
nmap_pid=$(printf '%s\n' "$nmap_identity" | tail -1)
nmap_identity=$(printf '%s\n' "$nmap_identity" | head -1)
[ "$nmap_identity" = "65532 65532 - 0000000000002000" ] || fail "running Nmap identity is '$nmap_identity', want '65532 65532 - 0000000000002000'"
expect_filtered Nmap "$(process_hardening "$nmap_pid")"
expect_scanner_limits Nmap "$nmap_pid"
cancelled=$(python3 "$workdir/driver.py" cancel "$base" "$state" "$job_id" "$scan_id")
[ "$cancelled" = canceled ] || fail "the cancelled scan ended '$cancelled'"
if docker exec "$container" /bin/sh -c 'grep -l "^Name:[[:space:]]*nmap$" /proc/[0-9]*/status' >/dev/null 2>&1; then
  fail "Nmap kept running after the scan was cancelled"
fi

# A sandboxed Nmap that edgewatch scan started dies with it: the kernel keeps
# the parent-death signal across the change to UID 65532 and the executions
# of sandbox-exec and Nmap.
python3 "$workdir/driver.py" create "$base" "$state" orphaned "1-20000" >/dev/null
docker exec -d "$container" edgewatch scan --config /etc/edgewatch/config.yaml --job orphaned
nmap_pid=$(scanner_pid nmap)
[ -n "$nmap_pid" ] || fail "edgewatch scan started no Nmap"
scan_pid=$(docker exec "$container" awk '/^PPid:/{print $2}' "/proc/$nmap_pid/status")
docker exec "$container" kill -9 "$scan_pid"
for attempt in $(seq 1 20); do
  docker exec "$container" test -d "/proc/$nmap_pid" || break
  [ "$(docker exec "$container" awk '/^State:/{print $2}' "/proc/$nmap_pid/status" 2>/dev/null)" = Z ] && break
  sleep 0.5
  [ "$attempt" = 20 ] && fail "Nmap kept running after edgewatch scan was killed"
done
stop_daemon

# The SYN override: a sandboxed Naabu keeps NET_RAW and NET_ADMIN, and
# discovers ports with the target list it reads through its descriptor. This
# daemon runs without TMPDIR, as a deployment that does not copy compose.yaml
# does: the files of running scans still lie in the scanner files directory,
# where another sandboxed process can open none of them.
daemon_tmpdir=
run_daemon syn auto "${bundled_caps[@]}" NET_ADMIN
daemon_tmpdir=/var/lib/edgewatch/tmp
expect_health "enforced 65532 NET_RAW,NET_ADMIN landlock:enforced seccomp:enforced limits:1000,65536"
started=$(python3 "$workdir/driver.py" start "$base" "$state" slow-files "1-20000")
job_id=$(printf '%s' "$started" | python3 -c 'import json, sys; print(json.load(sys.stdin)["job_id"])')
scan_id=$(printf '%s' "$started" | python3 -c 'import json, sys; print(json.load(sys.stdin)["scan_id"])')
expect_private_scan_file "Nmap XML" 'edgewatch-nmap-*.xml'
cancelled=$(python3 "$workdir/driver.py" cancel "$base" "$state" "$job_id" "$scan_id")
[ "$cancelled" = canceled ] || fail "the cancelled Nmap scan ended '$cancelled'"
started=$(python3 "$workdir/driver.py" start-naabu "$base" "$state" slow-naabu)
job_id=$(printf '%s' "$started" | python3 -c 'import json, sys; print(json.load(sys.stdin)["job_id"])')
scan_id=$(printf '%s' "$started" | python3 -c 'import json, sys; print(json.load(sys.stdin)["scan_id"])')
naabu_pid=$(scanner_pid naabu)
[ -n "$naabu_pid" ] || fail "the slow Naabu scan started no Naabu"
expect_scanner_limits Naabu "$naabu_pid"
expect_private_scan_file "Naabu target list" 'edgewatch-naabu-targets-*'
cancelled=$(python3 "$workdir/driver.py" cancel "$base" "$state" "$job_id" "$scan_id")
[ "$cancelled" = canceled ] || fail "the cancelled Naabu scan ended '$cancelled'"
expect_no_scanner_processes "the cancelled Naabu scan"
naabu_sandboxed=$(python3 "$workdir/driver.py" naabu "$base" "$state" naabu-sandboxed "$tcp_open")
stop_daemon

# A stand-in Nmap that leaves a background process that ignores the hangup of
# its terminal, and tries to start another in a session of its own: the
# seccomp filter refuses the new session, and cancelling the scan stops the
# whole process group.
cat >"$workdir/forking-nmap" <<'SH'
#!/bin/sh
if [ "$1" = --version ]; then echo 'Nmap version 7.99 ( https://nmap.org )'; exit 0; fi
(trap '' HUP; exec sleep 600) &
setsid sleep 600 &
exec sleep 600
SH
chmod 0755 "$workdir/forking-nmap"
daemon_mounts=(--volume "$workdir/forking-nmap:/usr/bin/nmap:ro")
run_daemon forking auto "${bundled_caps[@]}"
daemon_mounts=()
expect_health "enforced 65532 NET_RAW landlock:enforced seccomp:enforced limits:1000,65536"
started=$(python3 "$workdir/driver.py" start "$base" "$state" forking "1-20000")
job_id=$(printf '%s' "$started" | python3 -c 'import json, sys; print(json.load(sys.stdin)["job_id"])')
scan_id=$(printf '%s' "$started" | python3 -c 'import json, sys; print(json.load(sys.stdin)["scan_id"])')
[ -n "$(scanner_pid sleep)" ] || fail "the forking stand-in started no background process"
sleep 1
cancelled=$(python3 "$workdir/driver.py" cancel "$base" "$state" "$job_id" "$scan_id")
[ "$cancelled" = canceled ] || fail "the cancelled forking scan ended '$cancelled'"
expect_no_scanner_processes "the cancelled forking scan"
stop_daemon

# A Compose file from before v0.27.0 grants no SETUID, SETGID, or KILL:
# scanner processes stay UID 0, restricted only by Landlock.
run_daemon legacy auto NET_RAW NET_ADMIN
expect_health "unavailable 0 - landlock:enforced seccomp:enforced limits:1000,65536"
expect_notification_health "unavailable 0 landlock:enforced seccomp:enforced"
deliver_notification legacy >/dev/null
landlock_only=$(python3 "$workdir/driver.py" scan "$base" "$state" landlock-only "$tcp_ports" "$udp_ports")
naabu_landlock_only=$(python3 "$workdir/driver.py" naabu "$base" "$state" naabu-landlock-only "$tcp_open")
stop_daemon

run_daemon off off "${bundled_caps[@]}" NET_ADMIN
expect_health "disabled 0 - landlock:disabled seccomp:disabled limits:-"
unconfined=$(python3 "$workdir/driver.py" scan "$base" "$state" unconfined "$tcp_ports" "$udp_ports")
naabu_unconfined=$(python3 "$workdir/driver.py" naabu "$base" "$state" naabu-unconfined "$tcp_open")
stop_daemon

[ "$sandboxed" = "$unconfined" ] || fail "sandboxed Nmap results $sandboxed differ from unconfined results $unconfined"
[ "$landlock_only" = "$unconfined" ] || fail "Nmap results with only Landlock $landlock_only differ from unconfined results $unconfined"
[ "$naabu_landlock_only" = "$naabu_unconfined" ] || fail "Naabu results with only Landlock $naabu_landlock_only differ from unconfined results $naabu_unconfined"
printf '%s\n' "$sandboxed" | grep -q "\"tcp\", $tcp_open, \"open\"" || fail "the open TCP listener was not reported open: $sandboxed"
[ "$naabu_sandboxed" = "$naabu_unconfined" ] || fail "sandboxed Naabu results $naabu_sandboxed differ from unconfined results $naabu_unconfined"
[ "$naabu_sandboxed" = "[[\"tcp\", $tcp_open, \"open\"]]" ] || fail "Naabu did not report the open TCP listener: $naabu_sandboxed"

[ "$(grep -c . "$workdir/notifications.log")" = 2 ] || fail "the webhook received $(grep -c . "$workdir/notifications.log") notifications, want 2"

echo "scanner and notification sandboxes verified for $image: Nmap $sandboxed, Naabu $naabu_sandboxed"
