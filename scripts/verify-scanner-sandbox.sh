#!/usr/bin/env bash
set -euo pipefail

# Run real Nmap TCP SYN and UDP scans and a Naabu discovery of local
# listeners through EdgeWatch with the scanner sandbox enforced, with a
# leased identity and seccomp but no Landlock, and with the scanner sandbox
# explicitly off; require the same results from supported modes.
# With the sandbox enforced, also require that a running Nmap uses a leased
# per-invocation UID holding only the configured capabilities, that cancelling
# it works, that one scanner identity
# can neither list the data directory nor read the configuration, and that a
# process restricted with Landlock cannot do so even as UID 0. Deliver a test
# notification to a local webhook and require that the notification process
# runs as UID 65531 without capabilities. Require that both run with the
# seccomp filter, one more than the daemon's, and that no process dumps core.
# Require that a running Nmap has the scanner's resource limits, including
# the Nmap-only RLIMIT_FSIZE bound in Landlock and identity-only helper modes.
# Require that
# Nmap's inherited files lie in the scanner files directory, while Naabu's
# temporary leaf uses the production helper's per-invocation path and is
# removed after success or cancellation. Require that cancelling a Naabu scan
# stops it. Require that cancelling a scan of a stand-in Nmap that leaves
# background processes stops every one of them,
# also one that tries to leave its process group, and that a sandboxed Nmap
# dies with the edgewatch scan command that started it.
image=${1:?usage: verify-scanner-sandbox.sh IMAGE}

workdir=$(mktemp -d)
container=
listener_pid=
webhook_pid=
proc_fd_probe=
cleanup() {
  local container_removed=1
  if [ -n "$container" ]; then
    docker logs "$container" >"$workdir/last-daemon.log" 2>&1 || true
    # Force removal is the failure-path cleanup. If Docker cannot confirm it,
    # make one bounded stop/remove attempt before preserving all bind sources.
    if ! docker rm -f "$container" >/dev/null 2>&1; then
      docker stop --timeout 10 "$container" >/dev/null 2>&1 || true
      if ! docker rm -f "$container" >/dev/null 2>&1; then
        container_removed=0
        printf 'warning: verifier could not confirm removal of owned container %s\n' "$container" >&2
      fi
    fi
  fi
  if [ -n "$listener_pid" ]; then
    kill "$listener_pid" >/dev/null 2>&1 || true
  fi
  if [ -n "$webhook_pid" ]; then
    kill "$webhook_pid" >/dev/null 2>&1 || true
  fi
  if [ "$container_removed" = 1 ]; then
    for data in "$workdir"/data-*; do
      [ -d "$data" ] || continue
      docker run --rm --volume "$data:/data" --entrypoint /bin/sh "$image" \
        -c 'rm -rf /data/* /data/.[!.]* /data/..?*' >/dev/null 2>&1 || true
    done
  else
    printf 'warning: leaving verifier data volumes intact because removal of owned container %s is unconfirmed\n' "$container" >&2
  fi
  if [ "$container_removed" = 1 ]; then
    rm -rf "$workdir"
  else
    printf 'warning: preserving verifier work directory for owned container %s at %s\n' "$container" "$workdir" >&2
  fi
}
trap cleanup EXIT
fail() {
  echo "scanner sandbox check failed: $*" >&2
  if [ -n "$container" ]; then
    docker logs "$container" 2>&1 | sed -E 's/("setup_token"[[:space:]]*:[[:space:]]*")[^"]*"/\1[REDACTED]"/g' | tail -80 >&2 || true
    # What was running, and what the daemon thought it was doing, when the
    # check gave up.
    echo "processes in the daemon container (name state ppid uid):" >&2
    docker exec "$container" /bin/sh -c 'for status in /proc/[0-9]*/status; do awk "/^Name:/{n=\$2} /^State:/{s=\$2} /^PPid:/{p=\$2} /^Uid:/{u=\$2} END{print n, s, p, u}" "$status" 2>/dev/null; done' >&2 || true
    if [ -n "${base:-}" ] && [ -n "${state:-}" ]; then
      python3 "$workdir/driver.py" diagnose "$base" "$state" >&2 || true
    fi
  fi
  exit 1
}

# A plain `docker exec --user UID:UID` drops every capability, so it does not
# model a sibling scanner. Build a small helper that launches a same-UID child
# with the exact capability profile of the scanner under test, then verifies
# that context before probing a path. It never adds SYS_PTRACE or DAC
# capabilities.
cat >"$workdir/proc-fd-probe.go" <<'GO'
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type capabilityProfile struct {
	launch string
	post   string
	ambient []uintptr
}

func profileFor(mask string) (capabilityProfile, error) {
	switch mask {
	case "0000000000002000": // NET_RAW-only daemon capability set.
		return capabilityProfile{launch: mask, post: mask, ambient: []uintptr{13}}, nil
	case "0000000000003000": // Explicit SYN scan: NET_ADMIN and NET_RAW.
		return capabilityProfile{launch: mask, post: "0000000000002000", ambient: []uintptr{12, 13}}, nil
	default:
		return capabilityProfile{}, fmt.Errorf("unsupported exact scanner capability profile %q", mask)
	}
}

func statusValue(status, name string) string {
	for _, line := range strings.Split(status, "\n") {
		if strings.HasPrefix(line, name+":") {
			return strings.TrimSpace(strings.TrimPrefix(line, name+":"))
		}
	}
	return ""
}

func requireScannerCredentials(uid uint32) (string, error) {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return "", fmt.Errorf("read probe status: %w", err)
	}
	status := string(data)
	for _, field := range []string{"Uid", "Gid"} {
		values := strings.Fields(statusValue(status, field))
		if len(values) != 4 {
			return "", fmt.Errorf("probe has malformed %s status", field)
		}
		for _, value := range values {
			if value != strconv.FormatUint(uint64(uid), 10) {
				return "", fmt.Errorf("probe %s is %q, want all credentials %d", field, value, uid)
			}
		}
	}
	if groups := statusValue(status, "Groups"); groups != "" {
		return "", fmt.Errorf("probe has supplementary groups %q", groups)
	}
	return status, nil
}

func requireNaabuInitialCapabilities(status string, profile capabilityProfile) error {
	for _, field := range []string{"CapPrm", "CapEff", "CapInh", "CapAmb"} {
		if got := statusValue(status, field); got != profile.launch {
			return fmt.Errorf("probe initial %s is %q, want exact launch capabilities %s", field, got, profile.launch)
		}
	}
	if got := statusValue(status, "NoNewPrivs"); got != "1" {
		return fmt.Errorf("probe NoNewPrivs is %q, want 1", got)
	}
	if got := statusValue(status, "Seccomp"); got != "2" {
		return fmt.Errorf("probe Seccomp is %q, want 2", got)
	}
	return nil
}

// Naabu v2.6.1's pkg/privileges/privileges_linux.go reads the capability
// state, replaces only Inheritable with CAP_NET_RAW, and writes it back. That
// keeps both permitted/effective network caps while the kernel drops
// CAP_NET_ADMIN from Ambient because ambient must remain a subset of
// inheritable. Reproduce that exact transition before checking/probing.
func applyNaabuCapabilityTransition() error {
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3, Pid: int32(os.Getpid())}
	data := unix.CapUserData{}
	if err := unix.Capget(&header, &data); err != nil {
		return fmt.Errorf("read capability state: %w", err)
	}
	data.Inheritable = 1 << unix.CAP_NET_RAW
	if err := unix.Capset(&header, &data); err != nil {
		return fmt.Errorf("apply Naabu inheritable capability state: %w", err)
	}
	return nil
}

func requireScannerIdentity(uid uint32, profile capabilityProfile) error {
	status, err := requireScannerCredentials(uid)
	if err != nil {
		return err
	}
	if got := statusValue(status, "CapPrm"); got != profile.launch {
		return fmt.Errorf("probe CapPrm is %q, want exact scanner permitted capabilities %s", got, profile.launch)
	}
	if got := statusValue(status, "CapEff"); got != profile.launch {
		return fmt.Errorf("probe CapEff is %q, want exact scanner effective capabilities %s", got, profile.launch)
	}
	for _, field := range []string{"CapInh", "CapAmb"} {
		if got := statusValue(status, field); got != profile.post {
			return fmt.Errorf("probe %s is %q, want exact post-transition inheritable/ambient capabilities %s", field, got, profile.post)
		}
	}
	if got := statusValue(status, "NoNewPrivs"); got != "1" {
		return fmt.Errorf("probe NoNewPrivs is %q, want 1", got)
	}
	if got := statusValue(status, "Seccomp"); got != "2" {
		return fmt.Errorf("probe Seccomp is %q, want 2", got)
	}
	return nil
}

func child(args []string) int {
	if len(args) != 5 || args[0] != "child" {
		fmt.Fprintln(os.Stderr, "usage: child UID PROFILE OP PATH")
		return 2
	}
	uid64, err := strconv.ParseUint(args[1], 10, 32)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid UID: %v\n", err)
		return 2
	}
	profile, err := profileFor(args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	// Keep the Go goroutine on the capability-adjusted OS thread through the
	// path check; Linux capability sets are per-thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	status, err := requireScannerCredentials(uint32(uid64))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 3
	}
	if err := requireNaabuInitialCapabilities(status, profile); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 3
	}
	if err := applyNaabuCapabilityTransition(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 3
	}
	if err := requireScannerIdentity(uint32(uid64), profile); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 3
	}
	path := args[4]
	switch args[3] {
	case "readlink":
		target, err := os.Readlink(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "readlink failed: %v\n", err)
			return 11
		}
		fmt.Println(target)
	case "open":
		file, err := os.Open(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "open failed: %v\n", err)
			return 12
		}
		if err := file.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "close failed: %v\n", err)
			return 13
		}
	case "read":
		file, err := os.Open(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "open failed: %v\n", err)
			return 12
		}
		// /proc/<pid>/fd/N refers to the scanner's shared open-file
		// description. ReadAt uses pread, so this positive control does not
		// advance Naabu's target-list offset while it is scanning.
		contents := make([]byte, 4096)
		count, readErr := file.ReadAt(contents, 0)
		closeErr := file.Close()
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			fmt.Fprintf(os.Stderr, "read failed: %v\n", readErr)
			return 14
		}
		if closeErr != nil {
			fmt.Fprintf(os.Stderr, "close failed: %v\n", closeErr)
			return 13
		}
		if _, err := os.Stdout.Write(contents[:count]); err != nil {
			fmt.Fprintf(os.Stderr, "write read result failed: %v\n", err)
			return 14
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown operation %q\n", args[2])
		return 2
	}
	return 0
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "child" {
		os.Exit(child(os.Args[1:]))
	}
	if len(os.Args) != 5 {
		fmt.Fprintln(os.Stderr, "usage: proc-fd-probe UID PROFILE OP PATH")
		os.Exit(2)
	}
	uid64, err := strconv.ParseUint(os.Args[1], 10, 32)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid UID: %v\n", err)
		os.Exit(2)
	}
	executable, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve probe executable: %v\n", err)
		os.Exit(2)
	}
	profile, err := profileFor(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	command := exec.Command(executable, "child", os.Args[1], os.Args[2], os.Args[3], os.Args[4])
	command.SysProcAttr = &syscall.SysProcAttr{
		Credential:  &syscall.Credential{Uid: uint32(uid64), Gid: uint32(uid64), Groups: []uint32{}},
		AmbientCaps: profile.ambient,
	}
	output, err := command.CombinedOutput()
	if len(output) != 0 {
		_, _ = os.Stdout.Write(output)
	}
	if err == nil {
		return
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		os.Exit(exitErr.ExitCode())
	}
	fmt.Fprintf(os.Stderr, "start probe child: %v\n", err)
	os.Exit(2)
}
GO
CGO_ENABLED=0 go build -trimpath -o "$workdir/proc-fd-probe" "$workdir/proc-fd-probe.go" || fail "could not build the scanner-identity proc-fd probe"
proc_fd_probe=/usr/local/bin/edgewatch-proc-fd-probe

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
    elif command == "establish-baseline":
        name, tcp_ports = args
        job_id = create_job(base, state, name, tcp_ports, "", "fast")
        request(base, state, "POST", f"/jobs/{job_id}/run")
        scan = wait_for_scan(base, state, job_id, {"success", "incomplete", "failed", "timed_out", "canceled"})
        if scan["status"] != "success":
            raise SystemExit(f"baseline scan {scan['id']} ended {scan['status']}: {scan.get('error', '')}")
        baseline = request(base, state, "GET", f"/jobs/{job_id}")["baseline"]
        if baseline.get("status") != "complete" or not baseline.get("scan_id"):
            raise SystemExit(f"baseline was not completed: {baseline}")
        print(json.dumps({"job_id": job_id, "baseline": baseline}))
    elif command == "expect-refused-run":
        job_id, expected_baseline_path = args
        with open(expected_baseline_path, encoding="utf-8") as baseline_file:
            expected_baseline = json.load(baseline_file)
        before = request(base, state, "GET", f"/jobs/{job_id}")["baseline"]
        if before.get("status") != "complete" or not before.get("scan_id"):
            raise SystemExit(f"refusal fixture has no completed baseline: {before}")
        if before != expected_baseline:
            raise SystemExit(f"baseline changed across the capability-only restart: before={expected_baseline}, after_restart={before}")
        before_scans = request(base, state, "GET", f"/jobs/{job_id}/scans")["scans"]
        before_ids = {scan["id"] for scan in before_scans}
        request_error = ""
        try:
            request(base, state, "POST", f"/jobs/{job_id}/run")
        except SystemExit as error:
            request_error = str(error)

        new_scans = []
        deadline = time.time() + 60
        while time.time() < deadline:
            scans = request(base, state, "GET", f"/jobs/{job_id}/scans")["scans"]
            new_scans = [scan for scan in scans if scan["id"] not in before_ids]
            active = request(base, state, "GET", "/scans/active")["scans"]
            if new_scans and all(scan["status"] in {"failed", "canceled", "incomplete", "success", "timed_out"} for scan in new_scans):
                break
            if request_error and not any(scan.get("job_id") == job_id for scan in active):
                break
            time.sleep(0.5)

        after = request(base, state, "GET", f"/jobs/{job_id}")["baseline"]
        if before != after:
            raise SystemExit(f"fail-closed launch changed the completed baseline: before={before}, after={after}")
        if len(new_scans) > 1:
            raise SystemExit(f"one refused launch created multiple scan records: {new_scans}")
        detail = " ".join([request_error] + [scan.get("error", "") for scan in new_scans]).lower()
        if not any(term in detail for term in ("unavailable", "fail closed", "could not start")):
            raise SystemExit(f"launch refusal did not report the scanner sandbox failure: {detail!r}")
        if new_scans and new_scans[0]["status"] == "success":
            raise SystemExit(f"scanner ran successfully without the required identity capabilities: {new_scans[0]}")
        active = request(base, state, "GET", "/scans/active")["scans"]
        if any(scan.get("job_id") == job_id for scan in active):
            raise SystemExit(f"refused launch left an active scan: {active}")
        print(json.dumps({"baseline_unchanged": True, "baseline_scan_id": before["scan_id"],
                          "new_scan_status": new_scans[0]["status"] if new_scans else None,
                          "refusal": detail}))
    elif command == "notify":
        name, url = args
        request(base, state, "POST", "/notifications/destinations", {"name": name, "url": url, "enabled": True, "password": PASSWORD})
        print(json.dumps(request(base, state, "POST", "/notifications/test")))
    elif command == "diagnose":
        print("active scans:", json.dumps(request(base, state, "GET", "/scans/active")))
        for job in request(base, state, "GET", "/jobs")["jobs"]:
            print("job", job["id"], job["job"]["name"], "scan cycle:", json.dumps(request(base, state, "GET", f"/jobs/{job['id']}/scan-cycle")))
        return
    elif command in ("cancel", "cancel-detail"):
        job_id, scan_id = args
        request(base, state, "POST", f"/scans/{scan_id}/cancel")
        scan = wait_for_scan(base, state, job_id, {"canceled", "success", "failed", "timed_out", "incomplete"}, timeout=60)
        if command == "cancel-detail":
            cycle_response = request(base, state, "GET", f"/jobs/{job_id}/scan-cycle")
            cycle = cycle_response.get("cycle") or {}
            print(json.dumps({"status": scan["status"], "error": scan.get("error", ""),
                              "cycle_last_error": cycle.get("last_error", "")}))
        else:
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
daemon_landlock=auto
daemon_scan_limit=1
daemon_mounts=()
daemon_data=
daemon_config=
daemon_port=
daemon_runtime_tmpdir=
run_daemon() {
  local name=$1 mode=$2
  shift 2
  # Fixture transitions must not orphan the previous daemon when its
  # database/configuration differs from the next run.
  if [ -n "$container" ]; then
    stop_daemon
  fi
  local caps=()
  for capability in "$@"; do
    caps+=(--cap-add "$capability")
  done
  daemon_data="$workdir/data-$name"
  web_port=$(free_port)
  daemon_port=$web_port
  install -d -m 0750 "$daemon_data"
  ./scripts/prepare-container-smoke-data.sh "$image" "$daemon_data"
  daemon_config="$workdir/config-$name.yaml"
  cat >"$daemon_config" <<EOF
database: /var/lib/edgewatch/edgewatch.db
retention: 24h
web:
  listen: 127.0.0.1:$web_port
scheduler:
  max_concurrent_scans: $daemon_scan_limit
scanner:
  target_exclusions: []
  sandbox: $mode
  landlock: $daemon_landlock
updates:
  enabled: false
EOF
  chmod 0644 "$workdir/config-$name.yaml"
  local env=()
  if [ -n "$daemon_tmpdir" ]; then
    env=(--env "TMPDIR=$daemon_tmpdir")
  fi
  daemon_runtime_tmpdir=$daemon_tmpdir
  container=$(docker run -d --network host --read-only --tmpfs /tmp:size=128m,mode=1777 \
    --cap-drop ALL "${caps[@]}" \
    --security-opt no-new-privileges:true "${env[@]}" "${daemon_mounts[@]}" \
    --volume "$daemon_config:/etc/edgewatch/config.yaml:ro" \
    --volume "$daemon_data:/var/lib/edgewatch:rw" "$image" daemon --config /etc/edgewatch/config.yaml)
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
  # Preserve the daemon's deferred database-lease release before restarting
  # against the same volume. The production shutdown bound is six minutes;
  # force removal is reserved for the EXIT cleanup path after a failed test.
  local exit_code
  if ! docker stop --time 360 "$container" >/dev/null; then
    fail "the daemon did not stop within its six-minute graceful-shutdown bound"
  fi
  exit_code=$(docker inspect --format '{{.State.ExitCode}}' "$container") || fail "could not inspect the stopped daemon's exit status"
  [ "$exit_code" = 0 ] || fail "the daemon did not complete graceful shutdown (exit code $exit_code); refusing to reuse its database"
  docker rm "$container" >/dev/null
  container=
}

# restart_daemon_with_caps NAME CAPABILITY... reuses the current daemon's
# database, configuration, and port while changing only its container
# capabilities. This models a deployment restart with an older Compose file.
restart_daemon_with_caps() {
  local name=$1
  shift
  local caps=() env=() probe_mount=(--volume "$workdir/proc-fd-probe:$proc_fd_probe:ro")
  for capability in "$@"; do
    caps+=(--cap-add "$capability")
  done
  [ -n "$daemon_data" ] && [ -n "$daemon_config" ] && [ -n "$daemon_port" ] || fail "cannot restart $name without an existing daemon fixture"
  stop_daemon
  if [ -n "$daemon_runtime_tmpdir" ]; then
    env=(--env "TMPDIR=$daemon_runtime_tmpdir")
  fi
  container=$(docker run -d --network host --read-only --tmpfs /tmp:size=128m,mode=1777 \
    --cap-drop ALL "${caps[@]}" \
    --security-opt no-new-privileges:true "${env[@]}" "${probe_mount[@]}" \
    --volume "$daemon_config:/etc/edgewatch/config.yaml:ro" \
    --volume "$daemon_data:/var/lib/edgewatch:rw" "$image" daemon --config /etc/edgewatch/config.yaml)
  base="http://127.0.0.1:$daemon_port"
  for attempt in $(seq 1 60); do
    if curl --fail --silent "$base/api/v1/setup/status" >/dev/null; then
      return
    fi
    if [ -z "$(docker ps -q --filter "id=$container")" ]; then
      fail "the $name daemon exited during startup"
    fi
    sleep 1
  done
  fail "the $name daemon did not start serving requests"
}

# health_state prints the sandbox state, the scanner UID, the capabilities,
# and the Landlock state that the health command reports.
health_state() {
  docker exec "$container" edgewatch health --config /etc/edgewatch/config.yaml --output json |
    python3 -c 'import json, sys; sandbox = json.load(sys.stdin)["scanner_sandbox"]; limits = sandbox.get("limits"); pool = sandbox.get("identity_pool") or {}; print(sandbox["state"], sandbox.get("process_uid", "-"), ",".join(sandbox.get("capabilities") or []) or "-", "landlock:" + sandbox["landlock"]["state"], "seccomp:" + sandbox["seccomp"]["state"], "limits:" + ("%s,%s" % (limits["oom_score_adj"], limits["max_open_files"]) if limits else "-"), "pool:%s,%s,%s-%s,%s" % (pool.get("state", "-"), pool.get("strategy", "-"), pool.get("uid_start", "-"), pool.get("uid_end", "-"), pool.get("max_parallel", "-")))'
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

# expect_nmap_file_size_limit NAME PID requires the helper-backed Nmap
# invocation's soft and hard per-file limit to equal the parser cap plus one
# byte. That extra byte makes an oversized XML result observable after Nmap
# exits, including when it exits before the output-polling ticker runs.
expect_nmap_file_size_limit() {
  local name=$1 got
  got=$(docker exec "$container" awk '/^Max file size/{print $4, $5}' "/proc/$2/limits")
  [ "$got" = "16777217 16777217" ] || fail "the $name process has Max file size '$got', want '16777217 16777217'"
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
# neither the sandbox identity nor a process restricted with Landlock can
# open it.
expect_private_scan_file() {
  local name=$1 pid=$2 pattern=$3 path output uid
  uid=$(scanner_uid "$pid")
  path=$(scan_file "$pattern")
  [ -n "$path" ] || fail "no $name file was found in /var/lib/edgewatch/tmp/scanner"
  for open in "cat '$path'" "echo forged >>'$path'"; do
    if output=$(docker exec --user "$uid:$uid" "$container" /bin/sh -c "$open" 2>&1); then
      fail "scanner UID $uid succeeded at: $open"
    fi
    printf '%s\n' "$output" | grep -qi 'permission denied' || fail "'$open' as scanner UID $uid failed for another reason: $output"
    if output=$(docker exec "$container" edgewatch sandbox-exec --profile scanner --files 0 -- /bin/sh -c "$open" 2>&1); then
      fail "a restricted process (--files 0) succeeded at: $open"
    fi
    printf '%s\n' "$output" | grep -qi 'permission denied' || fail "'$open' restricted (--files 0) failed for another reason: $output"
  done
}

# expect_private_naabu_tmp checks the active generated leaf and Naabu's
# temporary input and LevelDB files there. FD 3 remains the parent-created,
# scanner target file passed through InheritFile; that helper sets its
# descriptor-only read mode to 0604. Its parent run directory remains root
# private, so another identity cannot reach it by path. Naabu copies its
# contents into the leaf-local stdin-input file. Container root lacks
# CAP_SYS_PTRACE, so these checks do not inspect a scanner's environ.
expect_private_naabu_tmp() {
  local pid=$1 expected_pe=$2 expected_ia=$3 profile=$2 pid_starttime uid namespaces namespace leaves leaf namespace_stat leaf_stat candidate owner leaf_candidate
  local inputs input input_stat databases database database_stat current_stat current_contents manifest manifest_stat descriptor_path descriptor_stat descriptor_contents leaf_input_contents probe_output
  case "$expected_pe/$expected_ia" in
    0000000000002000/0000000000002000|0000000000003000/0000000000002000) ;;
    *) fail "unsupported exact Naabu probe profile: permitted/effective=$expected_pe inheritable/ambient=$expected_ia" ;;
  esac
  docker exec "$container" test -d "/proc/$pid" || fail "Naabu process $pid exited before its temporary files were inspected"
  pid_starttime=$(scanner_process_starttime "$pid") || fail "Naabu PID $pid has no readable starttime before its temporary files were inspected"
  [[ "$pid_starttime" =~ ^[0-9]+$ ]] || fail "Naabu PID $pid has an invalid starttime '$pid_starttime'"
  expect_scanner_identity "$pid" "$expected_pe" "$expected_ia"
  uid=$(scanner_uid "$pid")
  expect_scanner_starttime "$pid" "$pid_starttime" "after reading its UID"
  namespaces=$(docker exec "$container" find /tmp -mindepth 1 -maxdepth 1 -type d -name 'edgewatch-naabu-root-*' -print 2>/dev/null || true)
  namespace=
  leaf=
  while IFS= read -r candidate; do
    [ -n "$candidate" ] || continue
    [[ "$candidate" =~ ^/tmp/edgewatch-naabu-root-[a-f0-9]{32}$ ]] || fail "Naabu invocation namespace has an unexpected name: $candidate"
    leaves=$(docker exec "$container" find "$candidate" -mindepth 1 -maxdepth 1 -type d -name 'edgewatch-naabu-*' -print 2>/dev/null || true)
    while IFS= read -r leaf_candidate; do
      [ -n "$leaf_candidate" ] || continue
      [[ "$leaf_candidate" =~ ^/tmp/edgewatch-naabu-root-[a-f0-9]{32}/edgewatch-naabu-[a-f0-9]{32}$ ]] || fail "Naabu leaf has an unexpected name: $leaf_candidate"
      owner=$(docker exec "$container" stat -c '%u %g' "$leaf_candidate")
      if [ "$owner" = "$uid $uid" ]; then
        [ -z "$leaf" ] || fail "scanner UID $uid owns multiple active Naabu leaves"
        namespace=$candidate
        leaf=$leaf_candidate
      fi
    done <<< "$leaves"
  done <<< "$namespaces"
  [ -n "$namespace" ] && [ -n "$leaf" ] || fail "no Naabu invocation leaf belongs to live scanner UID $uid: $namespaces"
  namespace_stat=$(docker exec "$container" stat -c '%a %u %g' "$namespace")
  leaf_stat=$(docker exec "$container" stat -c '%a %u %g' "$leaf")
  [ "$namespace_stat" = "1733 0 0" ] || fail "Naabu invocation namespace is '$namespace_stat', want '1733 0 0'"
  [ "$leaf_stat" = "700 $uid $uid" ] || fail "Naabu invocation leaf is '$leaf_stat', want '700 $uid $uid'"
  inputs=$(docker exec --user "$uid:$uid" "$container" find "$leaf" -mindepth 1 -maxdepth 1 -type f -name 'stdin-input-*' -print 2>/dev/null || true)
  [ "$(printf '%s\n' "$inputs" | grep -c .)" = 1 ] || fail "Naabu created $(printf '%s\n' "$inputs" | grep -c .) temporary input files in its leaf: $inputs"
  input=$inputs
  input_stat=$(docker exec --user "$uid:$uid" "$container" stat -c '%a %u %g' "$input")
  [ "$input_stat" = "600 $uid $uid" ] || fail "Naabu temporary input is '$input_stat', want '600 $uid $uid'"
  databases=$(docker exec --user "$uid:$uid" "$container" find "$leaf" -mindepth 1 -maxdepth 1 -type d -name 'naabu*' -print 2>/dev/null || true)
  [ "$(printf '%s\n' "$databases" | grep -c .)" = 1 ] || fail "Naabu created $(printf '%s\n' "$databases" | grep -c .) LevelDB directories in its leaf: $databases"
  database=$databases
  [[ "$database" =~ /naabu[0-9]+$ ]] || fail "Naabu LevelDB directory has an unexpected name: $database"
  database_stat=$(docker exec --user "$uid:$uid" "$container" stat -c '%a %u %g' "$database")
  [ "$database_stat" = "700 $uid $uid" ] || fail "Naabu LevelDB directory is '$database_stat', want '700 $uid $uid'"
  docker exec --user "$uid:$uid" "$container" test -f "$database/CURRENT" || fail "Naabu LevelDB CURRENT file is missing from $database"
  current_stat=$(docker exec --user "$uid:$uid" "$container" stat -c '%a %u %g' "$database/CURRENT")
  [ "$current_stat" = "644 $uid $uid" ] || fail "Naabu LevelDB CURRENT file is '$current_stat', want '644 $uid $uid'"
  current_contents=$(docker exec --user "$uid:$uid" "$container" cat "$database/CURRENT") || fail "scanner UID $uid could not read its own LevelDB CURRENT file"
  manifest=$(docker exec --user "$uid:$uid" "$container" find "$database" -mindepth 1 -maxdepth 1 -type f -name 'MANIFEST-*' -print 2>/dev/null || true)
  [ "$(printf '%s\n' "$manifest" | grep -c .)" = 1 ] || fail "Naabu LevelDB manifest is missing or ambiguous in $database: $manifest"
  [ "$current_contents" = "$(basename "$manifest")" ] || fail "Naabu CURRENT names '$current_contents', want its readable manifest $(basename "$manifest")"
  manifest_stat=$(docker exec --user "$uid:$uid" "$container" stat -c '%a %u %g' "$manifest")
  [ "$manifest_stat" = "644 $uid $uid" ] || fail "Naabu LevelDB manifest is '$manifest_stat', want '644 $uid $uid'"
  expect_scanner_starttime "$pid" "$pid_starttime" "before checking its inherited target descriptor"
  descriptor_path=$(docker exec "$container" "$proc_fd_probe" "$uid" "$profile" readlink "/proc/$pid/fd/3" 2>&1) || fail "scanner UID $uid with scanner capabilities could not inspect its inherited target descriptor: $descriptor_path"
  [[ "$descriptor_path" =~ ^/var/lib/edgewatch/tmp/scanner/run-[0-9]+/edgewatch-naabu-targets-[0-9]+$ ]] ||
    fail "Naabu FD 3 points to unexpected source input '$descriptor_path'"
  descriptor_stat=$(docker exec "$container" stat -c '%a %u %g' "$descriptor_path")
  [ "$descriptor_stat" = "604 0 0" ] || fail "Naabu FD 3 source input is '$descriptor_stat', want parent-owned descriptor-read '604 0 0'"
  expect_scanner_starttime "$pid" "$pid_starttime" "after reading its inherited target descriptor"
  if ! probe_output=$(docker exec "$container" "$proc_fd_probe" "$uid" "$profile" open "/proc/$pid/fd/3" 2>&1); then
    fail "scanner UID $uid with scanner capabilities cannot open its live inherited target descriptor: $probe_output"
  fi
  expect_scanner_starttime "$pid" "$pid_starttime" "after opening its inherited target descriptor"
  expect_scanner_starttime "$pid" "$pid_starttime" "before reading its inherited target descriptor"
  descriptor_contents=$(docker exec "$container" "$proc_fd_probe" "$uid" "$profile" read "/proc/$pid/fd/3" 2>&1) || fail "scanner UID $uid with scanner capabilities could not read its live inherited target descriptor: $descriptor_contents"
  [ "$descriptor_contents" = '127.0.0.1' ] || fail "the inherited target descriptor contains unexpected targets: $descriptor_contents"
  expect_scanner_starttime "$pid" "$pid_starttime" "after reading its inherited target descriptor"
  leaf_input_contents=$(docker exec --user "$uid:$uid" "$container" cat "$input") || fail "scanner UID $uid could not read its leaf-local Naabu input"
  [ "$leaf_input_contents" = '127.0.0.1' ] || fail "the leaf-local Naabu input contains unexpected targets: $leaf_input_contents"
  docker exec "$container" test -d "/proc/$pid" || fail "Naabu process $pid exited while its temporary files were inspected"
  naabu_uid=$uid
  naabu_starttime=$pid_starttime
  naabu_namespace=$namespace
  naabu_leaf=$leaf
  naabu_input=$input
  naabu_source_input=$descriptor_path
  naabu_database=$database
  echo "verified live Naabu temporary artifacts: namespace=$namespace ($namespace_stat), leaf=$leaf ($leaf_stat), inherited source input=$descriptor_path ($descriptor_stat), leaf input=$input ($input_stat), LevelDB=$database ($database_stat), CURRENT=$current_stat, manifest=$manifest_stat"
}

expect_no_naabu_temporary_namespaces() {
  local remaining
  remaining=$(docker exec "$container" find /tmp -mindepth 1 -maxdepth 1 -type d -name 'edgewatch-naabu-root-*' -print 2>/dev/null || true)
  [ -z "$remaining" ] || fail "Naabu left invocation namespaces behind: $remaining"
}

expect_no_naabu_target_inputs() {
  local remaining
  remaining=$(docker exec "$container" find /var/lib/edgewatch/tmp/scanner -type f -name 'edgewatch-naabu-targets-*' -print 2>/dev/null || true)
  [ -z "$remaining" ] || fail "Naabu left target inputs behind: $remaining"
}

expect_legacy_tmp_grant_rejected() {
  if docker exec "$container" edgewatch sandbox-exec --profile scanner --files 0 --tmp -- /bin/true >/dev/null 2>&1; then
    fail "sandbox-exec accepted the removed broad temporary-directory grant"
  fi
}

scanner_uid() {
  docker exec "$container" awk '/^Uid:/{print $2; exit}' "/proc/$1/status"
}

scanner_process_starttime() {
  local starttime
  starttime=$(docker exec "$container" /bin/sh -c 'stat=$(cat "/proc/$1/stat") || exit 1; rest=${stat##*) }; set -- $rest; [ "$#" -ge 20 ] || exit 1; printf "%s\n" "${20}"' sh "$1") || return 1
  [[ "$starttime" =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "$starttime"
}

expect_scanner_starttime() {
  local pid=$1 expected=$2 context=$3 got
  got=$(scanner_process_starttime "$pid") || fail "Naabu PID $pid exited before its starttime was revalidated $context"
  [ "$got" = "$expected" ] || fail "Naabu PID $pid changed starttime $context: got $got, expected $expected"
}

scanner_pids() {
  docker exec "$container" /bin/sh -c 'for status in /proc/[0-9]*/status; do if grep -q "^Name:[[:space:]]*$1$" "$status" 2>/dev/null; then pid=$(echo "$status" | awk -F/ "{print \$3}"); echo "$pid"; fi; done' sh "$1" 2>/dev/null | sort -n
}

scanner_pids_live() {
  local pids pid state
  pids=$(scanner_pids "$1")
  while IFS= read -r pid; do
    [ -n "$pid" ] || continue
    state=$(docker exec "$container" awk '/^State:/{print $2; exit}' "/proc/$pid/status" 2>/dev/null || true)
    [ "$state" = Z ] || printf '%s\n' "$pid"
  done <<< "$pids"
}

wait_for_scanner_count() {
  local name=$1 wanted=$2 pids count
  for attempt in $(seq 1 120); do
    pids=$(scanner_pids_live "$name")
    count=$(printf '%s\n' "$pids" | grep -c . || true)
    if [ "$count" -eq "$wanted" ]; then
      printf '%s\n' "$pids"
      return
    fi
    if [ "$count" -gt "$wanted" ]; then
      fail "found $count live $name processes, expected $wanted: $pids"
    fi
    sleep 0.25
  done
  fail "found $count live $name processes after waiting for $wanted: $pids"
}

wait_for_new_scanner_pid() {
  local name=$1 old_pid=$2 pids pid state
  for attempt in $(seq 1 120); do
    pids=$(scanner_pids_live "$name")
    while IFS= read -r pid; do
      [ -n "$pid" ] || continue
      state=$(docker exec "$container" awk '/^State:/{print $2; exit}' "/proc/$pid/status" 2>/dev/null || true)
      if [ "$pid" != "$old_pid" ] && [ "$state" != Z ]; then
        printf '%s\n' "$pid"
        return
      fi
    done <<< "$pids"
    sleep 0.25
  done
  fail "no new live $name process appeared after quarantining scanner UID from PID $old_pid: $pids"
}

expect_scanner_identity() {
  local pid=$1 expected_pe=$2 expected_ia=$3 got uid euid suid fsuid gid egid sgid fsgid groups capprm capinh capeff capamb
  got=$(docker exec "$container" /bin/sh -c 'awk "/^Uid:/{uid=\$2; euid=\$3; suid=\$4; fsuid=\$5} /^Gid:/{gid=\$2; egid=\$3; sgid=\$4; fsgid=\$5} /^Groups:/{groups=\$2} /^CapPrm:/{capprm=\$2} /^CapInh:/{capinh=\$2} /^CapEff:/{capeff=\$2} /^CapAmb:/{capamb=\$2} END{print uid, euid, suid, fsuid, gid, egid, sgid, fsgid, (groups == \"\" ? \"-\" : groups), capprm, capinh, capeff, capamb}" "/proc/$1/status"' sh "$pid")
  read -r uid euid suid fsuid gid egid sgid fsgid groups capprm capinh capeff capamb <<< "$got"
  [ "$uid" -ge 60000 ] && [ "$uid" -lt 60064 ] || fail "scanner process $pid has unleased UID '$uid': $got"
  [ "$uid $euid $suid $fsuid $gid $egid $sgid $fsgid $groups $capprm $capinh $capeff $capamb" = \
    "$uid $uid $uid $uid $uid $uid $uid $uid - $expected_pe $expected_ia $expected_pe $expected_ia" ] ||
    fail "scanner process $pid credentials/capabilities are '$got', want one leased UID/GID with no supplementary groups, permitted/effective capabilities $expected_pe, and inheritable/ambient capabilities $expected_ia"
}

expect_peer_denied() {
  local peer_uid=$1 profile=$2 path=$3 description=$4 output operation=read
  if [[ "$path" == /proc/*/fd/* ]]; then
    operation=readlink
  fi
  if output=$(docker exec "$container" "$proc_fd_probe" "$peer_uid" "$profile" "$operation" "$path" 2>&1); then
    fail "peer scanner UID $peer_uid read another invocation's $description at $path"
  fi
  printf '%s\n' "$output" | grep -Eqi 'permission denied|operation not permitted' ||
    fail "peer scanner UID $peer_uid failed to read $description for an unexpected reason: $output"
}

expect_peer_denied_between_scanners() {
  local peer_uid=$1 profile=$2 path=$3 description=$4 target_pid=$5 target_starttime=$6 peer_pid=$7 peer_starttime=$8
  expect_scanner_starttime "$target_pid" "$target_starttime" "before the peer checks $description"
  expect_scanner_starttime "$peer_pid" "$peer_starttime" "before the peer checks $description"
  expect_peer_denied "$peer_uid" "$profile" "$path" "$description"
  expect_scanner_starttime "$target_pid" "$target_starttime" "after the peer checks $description"
  expect_scanner_starttime "$peer_pid" "$peer_starttime" "after the peer checks $description"
}

scanner_supervisor_pid() {
  local scanner_pid=$1 supervisor parent name children
  supervisor=$(docker exec "$container" awk '/^PPid:/{print $2; exit}' "/proc/$scanner_pid/status")
  [ -n "$supervisor" ] && [ "$supervisor" != 1 ] || fail "scanner PID $scanner_pid has no distinct supervisor parent"
  name=$(docker exec "$container" awk '/^Name:/{print $2; exit}' "/proc/$supervisor/status")
  parent=$(docker exec "$container" awk '/^PPid:/{print $2; exit}' "/proc/$supervisor/status")
  [ "$name" = edgewatch ] || fail "scanner parent PID $supervisor is '$name', not the EdgeWatch supervisor"
  [ "$parent" = 1 ] || fail "scanner supervisor PID $supervisor has parent $parent, want daemon PID 1"
  children=$(docker exec "$container" cat "/proc/$supervisor/task/$supervisor/children")
  case " $children " in
    *" $scanner_pid "*) ;;
    *) fail "scanner supervisor PID $supervisor does not list scanner PID $scanner_pid as its child: $children" ;;
  esac
  printf '%s\n' "$supervisor"
}

# expect_no_scanner_processes requires that no process of the sandbox
# identity is left, other than zombies: the daemon, which is the container's
# PID 1, does not reap processes that it did not start.
expect_no_scanner_processes() {
  local left
  for attempt in $(seq 1 20); do
    left=$(docker exec "$container" /bin/sh -c 'for status in /proc/[0-9]*/status; do awk "/^Name:/{name=\$2} /^State:/{state=\$2} /^Uid:/{uid=\$2} END{if (uid >= 60000 && uid < 60064 && state != \"Z\") print name}" "$status" 2>/dev/null; done' | tr '\n' ' ')
    [ -z "$left" ] && return
    sleep 0.5
  done
  fail "$1 left leased scanner processes running: $left"
}

# process_hardening PID prints the seccomp filter count, core file size limits,
# and coredump filter of a process in the daemon's container.
process_hardening() {
  docker exec "$container" /bin/sh -c 'awk "/^Seccomp_filters:/{print \$2}" "/proc/$1/status"; awk "/^Max core file size/{print \$5, \$6}" "/proc/$1/limits"; tr -d "[:space:]" <"/proc/$1/coredump_filter"; echo' sh "$1" | tr '\n' ' ' | sed 's/ $//'
}

# expect_zero_coredump_filter NAME HARDENING requires a process's mapping
# filter to be zero.
expect_zero_coredump_filter() {
  local name=$1 got=$2 filter=${2##* }
  case "$filter" in
    ''|*[!0]*) fail "the $name process has nonzero or unreadable coredump filter '$filter' in '$got'" ;;
  esac
}

# expect_filtered NAME HARDENING requires a process's hardening to be one
# seccomp filter more than the daemon's, zero core limits, and a zero mapping
# filter.
expect_filtered() {
  local name=$1 got=$2 daemon_filters filters core_soft core_hard filter
  daemon_filters=$(docker exec "$container" /bin/sh -c 'awk "/^Seccomp_filters:/{print \$2}" "/proc/$1/status"' sh 1)
  read -r filters core_soft core_hard filter <<< "$got"
  [ "$filters $core_soft $core_hard" = "$((daemon_filters + 1)) 0 0" ] || fail "the $name process has seccomp filters and core limits '$got', want '$((daemon_filters + 1)) 0 0 and a zero coredump filter"
  expect_zero_coredump_filter "$name" "$got"
}

expect_health() {
  local want=$1 got
  got=$(health_state)
  [ "$got" = "$want" ] || fail "health reports the sandbox as '$got', want '$want'"
}

expect_missing_identity_capabilities() {
  local reason capability
  reason=$(docker exec "$container" edgewatch health --config /etc/edgewatch/config.yaml --output json |
    python3 -c 'import json, sys; print(json.load(sys.stdin)["scanner_sandbox"].get("reason", ""))')
  for capability in SETUID SETGID KILL; do
    [[ "$reason" == *"$capability"* ]] || fail "identity pool refusal reason '$reason' does not identify missing $capability"
  done
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
# with Landlock as Nmap is; landlocked_notifier runs the notifier profile.
landlocked() {
  docker exec "$container" edgewatch sandbox-exec --profile scanner --files 0 -- "$@"
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

# The bundled Compose deployment: the scanner keeps NET_RAW only and uses a
# distinct leased UID/GID for each invocation.
run_daemon base auto "${bundled_caps[@]}"
expect_health "enforced - NET_RAW landlock:enforced seccomp:enforced limits:1000,65536 pool:enforced,per_invocation,60000-60063,64"
expect_legacy_tmp_grant_rejected
daemon_hardening=$(process_hardening 1)
read -r daemon_filters daemon_core_soft daemon_core_hard daemon_filter <<< "$daemon_hardening"
[ "$daemon_core_soft $daemon_core_hard" = "0 0" ] || fail "the daemon has nonzero core file limits: $daemon_hardening"
expect_zero_coredump_filter daemon "$daemon_hardening"
sandboxed=$(python3 "$workdir/driver.py" scan "$base" "$state" sandboxed "$tcp_ports" "$udp_ports")

# Landlock restricts a process whatever its identity: as UID 0, which owns
# the database, a restricted process can neither read it nor list the data
# directory, read the configuration, write in /tmp, or execute a file there.
# The unrestricted reads show that only Landlock refuses them; the read-only
# root filesystem already refuses writes elsewhere. Naabu receives access to
# its exact leaf only through its production scan helper.
docker exec "$container" cat /var/lib/edgewatch/edgewatch.db >/dev/null || fail "UID 0 could not read the database without Landlock"
docker exec "$container" cat /etc/edgewatch/config.yaml >/dev/null || fail "UID 0 could not read the configuration without Landlock"
landlocked /bin/cat /etc/hosts >/dev/null || fail "a restricted process could not read /etc/hosts"
if output=$(landlocked /bin/sh -c 'echo scanner >/tmp/edgewatch-landlock' 2>&1); then
  fail "a generic restricted process created a file in /tmp"
fi
printf '%s\n' "$output" | grep -qi 'permission denied' || fail "creating a file in /tmp failed for another reason than Landlock: $output"
docker exec "$container" /bin/sh -c "printf '#!/bin/sh\\nexit 0\\n' >/tmp/edgewatch-landlock-exec; chmod 0755 /tmp/edgewatch-landlock-exec"
if output=$(landlocked /tmp/edgewatch-landlock-exec 2>&1); then
  fail "a generic restricted process executed a file in /tmp"
fi
printf '%s\n' "$output" | grep -qi 'permission denied' || fail "executing a file in /tmp failed for another reason than Landlock: $output"
docker exec "$container" rm -f /tmp/edgewatch-landlock-exec
for escape in "cat /var/lib/edgewatch/edgewatch.db" "ls /var/lib/edgewatch" "cat /etc/edgewatch/config.yaml" \
  "touch /var/lib/edgewatch/escape" "cp /bin/true /tmp/escape && /tmp/escape"; do
  if output=$(landlocked /bin/sh -c "$escape" 2>&1); then
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
if docker exec --user 60000:60000 "$container" ls /var/lib/edgewatch >/dev/null 2>&1; then
  fail "a scanner-pool UID listed the data directory"
fi
if docker exec --user 60000:60000 "$container" cat /etc/edgewatch/config.yaml >/dev/null 2>&1; then
  fail "a scanner-pool UID read the configuration"
fi

# Observe a running Nmap: it must use one leased UID/GID with only NET_RAW,
# and cancelling the scan must stop it.
started=$(python3 "$workdir/driver.py" start "$base" "$state" slow "1-20000")
job_id=$(printf '%s' "$started" | python3 -c 'import json, sys; print(json.load(sys.stdin)["job_id"])')
scan_id=$(printf '%s' "$started" | python3 -c 'import json, sys; print(json.load(sys.stdin)["scan_id"])')
nmap_pid=$(scanner_pid nmap)
[ -n "$nmap_pid" ] || fail "running scan started no Nmap"
expect_scanner_identity "$nmap_pid" "0000000000002000" "0000000000002000"
expect_filtered Nmap "$(process_hardening "$nmap_pid")"
expect_scanner_limits Nmap "$nmap_pid"
expect_nmap_file_size_limit Nmap "$nmap_pid"
cancelled=$(python3 "$workdir/driver.py" cancel "$base" "$state" "$job_id" "$scan_id")
[ "$cancelled" = canceled ] || fail "the cancelled scan ended '$cancelled'"
if [ -n "$(scanner_pids nmap)" ]; then
  fail "Nmap kept running after the scan was cancelled"
fi

# A sandboxed Nmap that edgewatch scan started dies with it: the kernel keeps
# the parent-death signal across the change to its leased UID and the executions
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
daemon_scan_limit=2
daemon_mounts=(--volume "$workdir/proc-fd-probe:/usr/local/bin/edgewatch-proc-fd-probe:ro")
run_daemon syn auto "${bundled_caps[@]}" NET_ADMIN
daemon_mounts=()
daemon_scan_limit=1
daemon_tmpdir=/var/lib/edgewatch/tmp
expect_health "enforced - NET_RAW,NET_ADMIN landlock:enforced seccomp:enforced limits:1000,65536 pool:enforced,per_invocation,60000-60063,64"
started=$(python3 "$workdir/driver.py" start "$base" "$state" slow-files "1-20000")
job_id=$(printf '%s' "$started" | python3 -c 'import json, sys; print(json.load(sys.stdin)["job_id"])')
scan_id=$(printf '%s' "$started" | python3 -c 'import json, sys; print(json.load(sys.stdin)["scan_id"])')
expect_private_scan_file "Nmap XML" "$(scanner_pid nmap)" 'edgewatch-nmap-*.xml'
cancelled=$(python3 "$workdir/driver.py" cancel "$base" "$state" "$job_id" "$scan_id")
[ "$cancelled" = canceled ] || fail "the cancelled Nmap scan ended '$cancelled'"
started=$(python3 "$workdir/driver.py" start-naabu "$base" "$state" slow-naabu)
job_id=$(printf '%s' "$started" | python3 -c 'import json, sys; print(json.load(sys.stdin)["job_id"])')
scan_id=$(printf '%s' "$started" | python3 -c 'import json, sys; print(json.load(sys.stdin)["scan_id"])')
naabu_pid=$(scanner_pid naabu)
[ -n "$naabu_pid" ] || fail "the slow Naabu scan started no Naabu"
expect_scanner_limits Naabu "$naabu_pid"
expect_private_naabu_tmp "$naabu_pid" "0000000000003000" "0000000000002000"
expect_private_scan_file "Naabu target list" "$naabu_pid" 'edgewatch-naabu-targets-*'
cancelled=$(python3 "$workdir/driver.py" cancel "$base" "$state" "$job_id" "$scan_id")
[ "$cancelled" = canceled ] || fail "the cancelled Naabu scan ended '$cancelled'"
expect_no_scanner_processes "the cancelled Naabu scan"
expect_no_naabu_temporary_namespaces
expect_no_naabu_target_inputs

# Two live Naabu invocations must receive separate leased identities and
# private leaves. A peer UID must not reach the other's LevelDB files or its
# inherited target-list descriptor through /proc.
started_one=$(python3 "$workdir/driver.py" start-naabu "$base" "$state" concurrent-naabu-one)
job_one=$(printf '%s' "$started_one" | python3 -c 'import json, sys; print(json.load(sys.stdin)["job_id"])')
scan_one=$(printf '%s' "$started_one" | python3 -c 'import json, sys; print(json.load(sys.stdin)["scan_id"])')
started_two=$(python3 "$workdir/driver.py" start-naabu "$base" "$state" concurrent-naabu-two)
job_two=$(printf '%s' "$started_two" | python3 -c 'import json, sys; print(json.load(sys.stdin)["job_id"])')
scan_two=$(printf '%s' "$started_two" | python3 -c 'import json, sys; print(json.load(sys.stdin)["scan_id"])')
concurrent_pids=$(wait_for_scanner_count naabu 2)
naabu_pid_one=$(printf '%s\n' "$concurrent_pids" | sed -n '1p')
naabu_pid_two=$(printf '%s\n' "$concurrent_pids" | sed -n '2p')
expect_scanner_identity "$naabu_pid_one" "0000000000003000" "0000000000002000"
expect_scanner_identity "$naabu_pid_two" "0000000000003000" "0000000000002000"
expect_filtered "concurrent Naabu one" "$(process_hardening "$naabu_pid_one")"
expect_filtered "concurrent Naabu two" "$(process_hardening "$naabu_pid_two")"
expect_private_naabu_tmp "$naabu_pid_one" "0000000000003000" "0000000000002000"
naabu_uid_one=$naabu_uid
naabu_starttime_one=$naabu_starttime
naabu_leaf_one=$naabu_leaf
naabu_input_one=$naabu_input
naabu_source_input_one=$naabu_source_input
naabu_database_one=$naabu_database
expect_private_naabu_tmp "$naabu_pid_two" "0000000000003000" "0000000000002000"
naabu_uid_two=$naabu_uid
naabu_starttime_two=$naabu_starttime
naabu_leaf_two=$naabu_leaf
naabu_input_two=$naabu_input
naabu_source_input_two=$naabu_source_input
naabu_database_two=$naabu_database
[ "$naabu_uid_one" != "$naabu_uid_two" ] || fail "concurrent scanners shared leased UID $naabu_uid_one"
[ "$naabu_leaf_one" != "$naabu_leaf_two" ] || fail "concurrent scanners shared private leaf $naabu_leaf_one"
[ "$naabu_input_one" != "$naabu_input_two" ] || fail "concurrent scanners shared target input $naabu_input_one"
[ "$naabu_source_input_one" != "$naabu_source_input_two" ] || fail "concurrent scanners shared inherited source input $naabu_source_input_one"
[ "$naabu_database_one" != "$naabu_database_two" ] || fail "concurrent scanners shared LevelDB directory $naabu_database_one"
expect_peer_denied_between_scanners "$naabu_uid_two" "0000000000003000" "$naabu_database_one/CURRENT" "LevelDB CURRENT file" \
  "$naabu_pid_one" "$naabu_starttime_one" "$naabu_pid_two" "$naabu_starttime_two"
expect_peer_denied_between_scanners "$naabu_uid_one" "0000000000003000" "$naabu_database_two/CURRENT" "LevelDB CURRENT file" \
  "$naabu_pid_two" "$naabu_starttime_two" "$naabu_pid_one" "$naabu_starttime_one"
expect_peer_denied_between_scanners "$naabu_uid_two" "0000000000003000" "$naabu_source_input_one" "inherited source target input" \
  "$naabu_pid_one" "$naabu_starttime_one" "$naabu_pid_two" "$naabu_starttime_two"
expect_peer_denied_between_scanners "$naabu_uid_one" "0000000000003000" "$naabu_source_input_two" "inherited source target input" \
  "$naabu_pid_two" "$naabu_starttime_two" "$naabu_pid_one" "$naabu_starttime_one"
expect_peer_denied_between_scanners "$naabu_uid_two" "0000000000003000" "$naabu_input_one" "leaf-local Naabu input" \
  "$naabu_pid_one" "$naabu_starttime_one" "$naabu_pid_two" "$naabu_starttime_two"
expect_peer_denied_between_scanners "$naabu_uid_one" "0000000000003000" "$naabu_input_two" "leaf-local Naabu input" \
  "$naabu_pid_two" "$naabu_starttime_two" "$naabu_pid_one" "$naabu_starttime_one"
expect_peer_denied_between_scanners "$naabu_uid_two" "0000000000003000" "/proc/$naabu_pid_one/fd/3" "target-list descriptor" \
  "$naabu_pid_one" "$naabu_starttime_one" "$naabu_pid_two" "$naabu_starttime_two"
expect_peer_denied_between_scanners "$naabu_uid_one" "0000000000003000" "/proc/$naabu_pid_two/fd/3" "target-list descriptor" \
  "$naabu_pid_two" "$naabu_starttime_two" "$naabu_pid_one" "$naabu_starttime_one"
cancelled_one=$(python3 "$workdir/driver.py" cancel "$base" "$state" "$job_one" "$scan_one")
cancelled_two=$(python3 "$workdir/driver.py" cancel "$base" "$state" "$job_two" "$scan_two")
[ "$cancelled_one" = canceled ] || fail "the first concurrent Naabu scan ended '$cancelled_one'"
[ "$cancelled_two" = canceled ] || fail "the second concurrent Naabu scan ended '$cancelled_two'"
expect_no_scanner_processes "the concurrent Naabu scans"
expect_no_naabu_temporary_namespaces
expect_no_naabu_target_inputs
naabu_sandboxed=$(python3 "$workdir/driver.py" naabu "$base" "$state" naabu-sandboxed "$tcp_open")
expect_no_naabu_temporary_namespaces

# Restart the same database under a Compose capability set that predates
# per-invocation identities. A completed baseline must remain unchanged when
# the next scanner launch is refused before creating any scanner process.
baseline_fixture=$(python3 "$workdir/driver.py" establish-baseline "$base" "$state" legacy-baseline "$tcp_open")
legacy_job=$(printf '%s' "$baseline_fixture" | python3 -c 'import json, sys; print(json.load(sys.stdin)["job_id"])')
printf '%s' "$baseline_fixture" | python3 -c 'import json, sys; json.dump(json.load(sys.stdin)["baseline"], open(sys.argv[1], "w"))' "$workdir/legacy-baseline.json"
restart_daemon_with_caps legacy NET_RAW NET_ADMIN
expect_health "unavailable - - landlock:unavailable seccomp:enforced limits:- pool:unavailable,per_invocation,60000-60063,64"
expect_missing_identity_capabilities
expect_notification_health "unavailable 0 landlock:enforced seccomp:enforced"
deliver_notification legacy >/dev/null
refusal=$(python3 "$workdir/driver.py" expect-refused-run "$base" "$state" "$legacy_job" "$workdir/legacy-baseline.json")
printf '%s\n' "$refusal" | grep -q '"baseline_unchanged": true' || fail "legacy-capability refusal did not preserve its baseline: $refusal"
expect_no_scanner_processes "a scan refused without scanner identity capabilities"
expect_no_naabu_temporary_namespaces
expect_no_naabu_target_inputs
restart_daemon_with_caps restored "${bundled_caps[@]}"
expect_health "enforced - NET_RAW landlock:enforced seccomp:enforced limits:1000,65536 pool:enforced,per_invocation,60000-60063,64"

# Stop the trusted supervisor while a scanner is alive. Cancellation must
# fail closed when the result channel cannot prove subtree cleanup: its
# artifacts remain, and a later invocation receives a different leased UID.
started=$(python3 "$workdir/driver.py" start-naabu "$base" "$state" proof-timeout-naabu)
job_id=$(printf '%s' "$started" | python3 -c 'import json, sys; print(json.load(sys.stdin)["job_id"])')
scan_id=$(printf '%s' "$started" | python3 -c 'import json, sys; print(json.load(sys.stdin)["scan_id"])')
naabu_pid=$(scanner_pid naabu)
[ -n "$naabu_pid" ] || fail "the proof-timeout Naabu scan started no Naabu"
expect_private_naabu_tmp "$naabu_pid" "0000000000002000" "0000000000002000"
quarantined_uid=$naabu_uid
quarantined_pid=$naabu_pid
quarantined_namespace=$naabu_namespace
quarantined_leaf=$naabu_leaf
quarantined_target=$naabu_source_input
[ -n "$quarantined_target" ] || fail "the proof-timeout Naabu scan has no inherited target-list file"
supervisor_pid=$(scanner_supervisor_pid "$naabu_pid")
docker exec "$container" kill -STOP "$supervisor_pid" || fail "could not stop the verified scanner supervisor $supervisor_pid"
cancel_detail=$(python3 "$workdir/driver.py" cancel-detail "$base" "$state" "$job_id" "$scan_id")
cancel_status=$(printf '%s' "$cancel_detail" | python3 -c 'import json, sys; print(json.load(sys.stdin)["status"])')
cancel_error=$(printf '%s' "$cancel_detail" | python3 -c 'import json, sys; print(json.load(sys.stdin)["error"])')
cycle_last_error=$(printf '%s' "$cancel_detail" | python3 -c 'import json, sys; print(json.load(sys.stdin)["cycle_last_error"])')
[ "$cancel_status" = canceled ] || fail "a scan without supervisor cleanup proof ended '$cancel_status'"
[ "$cancel_error" = "scan canceled; progress was saved" ] || fail "proof-timeout cancellation returned unexpected public scan detail: $cancel_detail"
printf '%s\n' "$cycle_last_error" | grep -Fq 'scanner process-tree proof failed' ||
  fail "the resumable cycle did not retain the sanitized process-tree proof failure: $cancel_detail"
docker exec "$container" test -d "$quarantined_namespace" || fail "proof failure removed the quarantined Naabu namespace"
docker exec "$container" test -d "$quarantined_leaf" || fail "proof failure removed the quarantined Naabu leaf"
quarantined_namespace_stat=$(docker exec "$container" stat -c '%a %u %g' "$quarantined_namespace")
[ "$quarantined_namespace_stat" = "1733 0 0" ] || fail "proof failure changed the pinned Naabu namespace to '$quarantined_namespace_stat'"
quarantined_leaf_stat=$(docker exec "$container" stat -c '%a %u %g' "$quarantined_leaf")
[ "$quarantined_leaf_stat" = "700 $quarantined_uid $quarantined_uid" ] || fail "proof failure changed the pinned Naabu leaf to '$quarantined_leaf_stat'"
docker exec "$container" test -f "$quarantined_target" || fail "proof failure removed the quarantined target-list file"
quarantined_target_stat=$(docker exec "$container" stat -c '%a %u %g' "$quarantined_target")
[ "$quarantined_target_stat" = "604 0 0" ] || fail "proof failure changed the parent-owned target-list file to '$quarantined_target_stat'"
quarantined_journal_state=$(docker exec "$container" cat /var/lib/edgewatch/scanner-identities/leases.json | python3 -c 'import json, sys; journal=json.load(sys.stdin); print(journal.get("leases", {}).get(sys.argv[1], {}).get("state", "missing"))' "$quarantined_uid")
[ "$quarantined_journal_state" = quarantined ] || fail "proof failure left scanner UID $quarantined_uid in journal state '$quarantined_journal_state'"
child_leaf_contents=$(docker exec --user "$quarantined_uid:$quarantined_uid" "$container" find "$quarantined_leaf" -mindepth 1 -maxdepth 1 -print 2>/dev/null || true)
echo "verified failed-proof quarantine: UID=$quarantined_uid journal=$quarantined_journal_state namespace=$quarantined_namespace ($quarantined_namespace_stat), leaf=$quarantined_leaf ($quarantined_leaf_stat), parent-owned source=$quarantined_target ($quarantined_target_stat), child-owned leaf entries=${child_leaf_contents:-<empty>}"

started=$(python3 "$workdir/driver.py" start-naabu "$base" "$state" after-proof-timeout-naabu)
job_id=$(printf '%s' "$started" | python3 -c 'import json, sys; print(json.load(sys.stdin)["job_id"])')
scan_id=$(printf '%s' "$started" | python3 -c 'import json, sys; print(json.load(sys.stdin)["scan_id"])')
naabu_pid=$(wait_for_new_scanner_pid naabu "$quarantined_pid")
expect_scanner_identity "$naabu_pid" "0000000000002000" "0000000000002000"
followup_uid=$(scanner_uid "$naabu_pid")
[ "$followup_uid" != "$quarantined_uid" ] || fail "post-timeout scanner reused quarantined UID $quarantined_uid"
expect_private_naabu_tmp "$naabu_pid" "0000000000002000" "0000000000002000"
followup_leaf=$naabu_leaf
cancelled=$(python3 "$workdir/driver.py" cancel "$base" "$state" "$job_id" "$scan_id")
[ "$cancelled" = canceled ] || fail "the post-quarantine Naabu scan ended '$cancelled'"
expect_no_scanner_processes "the post-quarantine Naabu scan"
docker exec "$container" test ! -e "$followup_leaf" || fail "normal cleanup left the post-quarantine leaf $followup_leaf"
remaining_namespaces=$(docker exec "$container" find /tmp -mindepth 1 -maxdepth 1 -type d -name 'edgewatch-naabu-root-*' -print 2>/dev/null || true)
[ "$remaining_namespaces" = "$quarantined_namespace" ] || fail "the proof-timeout fixture left unexpected namespace state: $remaining_namespaces"
remaining_inputs=$(docker exec "$container" find /var/lib/edgewatch/tmp/scanner -type f -name 'edgewatch-naabu-targets-*' -print 2>/dev/null || true)
[ "$remaining_inputs" = "$quarantined_target" ] || fail "the proof-timeout fixture left unexpected target-input state: $remaining_inputs"

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
expect_health "enforced - NET_RAW landlock:enforced seccomp:enforced limits:1000,65536 pool:enforced,per_invocation,60000-60063,64"
started=$(python3 "$workdir/driver.py" start "$base" "$state" forking "1-20000")
job_id=$(printf '%s' "$started" | python3 -c 'import json, sys; print(json.load(sys.stdin)["job_id"])')
scan_id=$(printf '%s' "$started" | python3 -c 'import json, sys; print(json.load(sys.stdin)["scan_id"])')
[ -n "$(scanner_pid sleep)" ] || fail "the forking stand-in started no background process"
sleep 1
cancelled=$(python3 "$workdir/driver.py" cancel "$base" "$state" "$job_id" "$scan_id")
[ "$cancelled" = canceled ] || fail "the cancelled forking scan ended '$cancelled'"
expect_no_scanner_processes "the cancelled forking scan"
stop_daemon

# Keep identity confinement while disabling Landlock. Naabu still starts
# through the temporary-directory helper as a leased UID; the helper path is
# required to create and clean the per-invocation directory even though files
# elsewhere remain reachable under this explicit fallback.
daemon_landlock=off
daemon_mounts=(--volume "$workdir/proc-fd-probe:$proc_fd_probe:ro")
run_daemon identity-only auto "${bundled_caps[@]}"
daemon_mounts=()
daemon_landlock=auto
expect_health "enforced - NET_RAW landlock:disabled seccomp:enforced limits:- pool:enforced,per_invocation,60000-60063,64"
identity_only_scan=$(python3 "$workdir/driver.py" scan "$base" "$state" identity-only "$tcp_ports" "$udp_ports")
identity_only_naabu=$(python3 "$workdir/driver.py" naabu "$base" "$state" naabu-identity-only "$tcp_open")
expect_no_naabu_temporary_namespaces
started=$(python3 "$workdir/driver.py" start "$base" "$state" slow-identity-only "1-20000")
job_id=$(printf '%s' "$started" | python3 -c 'import json, sys; print(json.load(sys.stdin)["job_id"])')
scan_id=$(printf '%s' "$started" | python3 -c 'import json, sys; print(json.load(sys.stdin)["scan_id"])')
nmap_pid=$(scanner_pid nmap)
[ -n "$nmap_pid" ] || fail "the identity-only slow scan started no Nmap"
expect_scanner_identity "$nmap_pid" "0000000000002000" "0000000000002000"
expect_nmap_file_size_limit "identity-only Nmap" "$nmap_pid"
cancelled=$(python3 "$workdir/driver.py" cancel "$base" "$state" "$job_id" "$scan_id")
[ "$cancelled" = canceled ] || fail "the identity-only Nmap scan ended '$cancelled'"
expect_no_scanner_processes "the identity-only cancelled Nmap scan"
started=$(python3 "$workdir/driver.py" start-naabu "$base" "$state" slow-naabu-identity-only)
job_id=$(printf '%s' "$started" | python3 -c 'import json, sys; print(json.load(sys.stdin)["job_id"])')
scan_id=$(printf '%s' "$started" | python3 -c 'import json, sys; print(json.load(sys.stdin)["scan_id"])')
naabu_pid=$(scanner_pid naabu)
[ -n "$naabu_pid" ] || fail "the identity-only slow Naabu scan started no Naabu"
expect_scanner_identity "$naabu_pid" "0000000000002000" "0000000000002000"
expect_scanner_limits Naabu "$naabu_pid"
expect_private_naabu_tmp "$naabu_pid" "0000000000002000" "0000000000002000"
cancelled=$(python3 "$workdir/driver.py" cancel "$base" "$state" "$job_id" "$scan_id")
[ "$cancelled" = canceled ] || fail "the identity-only Naabu scan ended '$cancelled'"
expect_no_scanner_processes "the identity-only cancelled Naabu scan"
expect_no_naabu_temporary_namespaces
stop_daemon

run_daemon off off "${bundled_caps[@]}" NET_ADMIN
expect_health "disabled 0 - landlock:disabled seccomp:disabled limits:- pool:disabled,per_invocation,60000-60063,64"
unconfined=$(python3 "$workdir/driver.py" scan "$base" "$state" unconfined "$tcp_ports" "$udp_ports")
naabu_unconfined=$(python3 "$workdir/driver.py" naabu "$base" "$state" naabu-unconfined "$tcp_open")
expect_no_naabu_temporary_namespaces
stop_daemon

[ "$sandboxed" = "$unconfined" ] || fail "sandboxed Nmap results $sandboxed differ from unconfined results $unconfined"
[ "$identity_only_scan" = "$unconfined" ] || fail "identity-only Nmap results $identity_only_scan differ from unconfined results $unconfined"
[ "$identity_only_naabu" = "$naabu_unconfined" ] || fail "identity-only Naabu results $identity_only_naabu differ from unconfined results $naabu_unconfined"
printf '%s\n' "$sandboxed" | grep -q "\"tcp\", $tcp_open, \"open\"" || fail "the open TCP listener was not reported open: $sandboxed"
[ "$naabu_sandboxed" = "$naabu_unconfined" ] || fail "sandboxed Naabu results $naabu_sandboxed differ from unconfined results $naabu_unconfined"
[ "$naabu_sandboxed" = "[[\"tcp\", $tcp_open, \"open\"]]" ] || fail "Naabu did not report the open TCP listener: $naabu_sandboxed"

[ "$(grep -c . "$workdir/notifications.log")" = 2 ] || fail "the webhook received $(grep -c . "$workdir/notifications.log") notifications, want 2"

echo "scanner and notification sandboxes verified for $image: Nmap $sandboxed, Naabu $naabu_sandboxed"
