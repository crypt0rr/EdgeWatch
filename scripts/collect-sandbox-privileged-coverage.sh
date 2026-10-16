#!/usr/bin/env bash
set -euo pipefail

image="${1:?usage: $0 IMAGE OUTPUT_DIRECTORY}"
output_dir="${2:?usage: $0 IMAGE OUTPUT_DIRECTORY}"
command -v docker >/dev/null || { echo "docker is required" >&2; exit 2; }

temporary_root="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
workdir="$(mktemp -d "${temporary_root%/}/edgewatch-sandbox-coverage.XXXXXX")"
container_id=""
preserve_workdir=0
cleanup() {
	if [[ -n "$container_id" ]]; then
		if docker rm -f "$container_id" >/dev/null 2>&1; then
			container_id=""
		else
			docker stop --time 10 "$container_id" >/dev/null 2>&1 || true
			if docker rm -f "$container_id" >/dev/null 2>&1; then
				container_id=""
			else
				preserve_workdir=1
				echo "could not confirm removal of privileged coverage container $container_id; preserved $workdir" >&2
			fi
		fi
	fi
	if [[ "$preserve_workdir" -eq 0 && -n "$workdir" && -d "$workdir" ]]; then
		rm -rf "$workdir"
	fi
}
trap cleanup EXIT

test_binary="$workdir/sandbox-coverage.test"
coverage_export="$workdir/coverage-export"
coverage_archive="$workdir/coverage.tar"
mkdir -p "$coverage_export" "$output_dir"
rm -f "$output_dir/coverage.out" "$output_dir/go-coverage-summary.txt"
: >"$coverage_archive"
chmod 0666 "$coverage_archive"

# The image is Alpine/musl, so keep this helper binary static and atomic-mode.
# Normal CI still runs every Go shard with -race; this extra profile exists
# only to collect the opt-in process/credential paths that need container caps.
CGO_ENABLED=0 go test -covermode=atomic -c -o "$test_binary" ./internal/sandbox
chmod 0755 "$test_binary"

container_id="$(docker create \
	--network none \
	--read-only \
	--memory 512m \
	--pids-limit 128 \
	--security-opt no-new-privileges:true \
	--cap-drop ALL \
	--cap-add KILL \
	--cap-add NET_RAW \
	--cap-add SETGID \
	--cap-add SETUID \
	--tmpfs /tmp:rw,nosuid,nodev,noexec,mode=1777,size=64m \
	--tmpfs /coverage:rw,nosuid,nodev,mode=0770,uid=60000,gid=0,size=64m \
	--mount "type=bind,source=$test_binary,target=/edgewatch-sandbox-coverage.test,readonly" \
	--mount "type=bind,source=$coverage_archive,target=/coverage-export.tar" \
	--env GOCOVERDIR=/coverage \
	--env EDGEWATCH_TEST_PRIVILEGED_SCANNER_SUPERVISOR=1 \
	--env EDGEWATCH_TEST_PRIVILEGED_PRIVATE_TEMP=1 \
	--entrypoint /bin/sh \
	"$image" -ec 'test -d /coverage; if /edgewatch-sandbox-coverage.test -test.v -test.run="^(TestScannerSupervisorPrivilegedLifecycleCoverage|TestPrivateTemporaryPrivilegedLifecycleCoverage)$" -test.gocoverdir=/coverage; then test_status=0; else test_status=$?; fi; cd /coverage; tar -cf /coverage-export.tar covmeta.* covcounters.*; exit "$test_status"')"

start_status=0
docker start --attach "$container_id" >"$workdir/container.log" 2>&1 || start_status=$?
container_status="$(docker inspect --format '{{.State.ExitCode}}' "$container_id")"
cat "$workdir/container.log"
if [[ "$start_status" -ne 0 || "$container_status" != 0 ]]; then
	echo "privileged sandbox coverage container failed (start=$start_status exit=$container_status)" >&2
	exit 1
fi
for test_name in TestScannerSupervisorPrivilegedLifecycleCoverage TestPrivateTemporaryPrivilegedLifecycleCoverage; do
	if ! grep -Fq -- "--- PASS: $test_name " "$workdir/container.log"; then
		echo "privileged sandbox coverage did not pass $test_name" >&2
		exit 1
	fi
done

if [[ ! -s "$coverage_archive" ]]; then
	echo "privileged sandbox coverage archive was not exported" >&2
	exit 1
fi
python3 - "$coverage_archive" "$coverage_export" <<'PY'
import shutil
import sys
import tarfile
from pathlib import Path, PurePosixPath

archive_path, export_path = sys.argv[1:]
archive_size = Path(archive_path).stat().st_size
if archive_size > 128 * 1024 * 1024:
    raise SystemExit("privileged sandbox coverage archive exceeds its 128 MiB file bound")
export = Path(export_path)
metadata = False
counters = False
total_size = 0
seen = set()
with tarfile.open(archive_path, "r:") as archive:
    members = archive.getmembers()
    if not members:
        raise SystemExit("privileged sandbox coverage archive is empty")
    for member in members:
        name = member.name
        if not member.isfile() or name != PurePosixPath(name).name or "\\" in name:
            raise SystemExit(f"unsafe entry in privileged coverage archive: {name!r}")
        if name in seen:
            raise SystemExit(f"duplicate entry in privileged coverage archive: {name!r}")
        seen.add(name)
        if name.startswith("covmeta."):
            metadata = True
        elif name.startswith("covcounters."):
            counters = True
        else:
            raise SystemExit(f"unexpected entry in privileged coverage archive: {name!r}")
        total_size += member.size
        if member.size < 0 or total_size > 64 * 1024 * 1024:
            raise SystemExit("privileged sandbox coverage archive exceeds its 64 MiB tmpfs bound")
        source = archive.extractfile(member)
        if source is None:
            raise SystemExit(f"coverage archive entry has no file data: {name!r}")
        with source, (export / name).open("xb") as destination:
            shutil.copyfileobj(source, destination)
if not metadata or not counters:
    raise SystemExit("privileged sandbox coverage archive lacks metadata or counters")
PY
docker rm "$container_id" >/dev/null
container_id=""

go tool covdata textfmt -i="$coverage_export" -o="$output_dir/coverage.out"
if [[ ! -s "$output_dir/coverage.out" ]]; then
	echo "privileged sandbox coverage profile is empty" >&2
	exit 1
fi
if [[ "$(head -n 1 "$output_dir/coverage.out")" != "mode: atomic" ]]; then
	echo "privileged sandbox coverage profile is not atomic" >&2
	exit 1
fi
go tool cover -func="$output_dir/coverage.out" | awk '/^total:/ { print "ok  \tgithub.com/crypt0rr/edgewatch/internal/sandbox\tcoverage: " $3 " of statements" }' >"$output_dir/go-coverage-summary.txt"
if [[ ! -s "$output_dir/go-coverage-summary.txt" ]]; then
	echo "privileged sandbox coverage summary is missing" >&2
	exit 1
fi
