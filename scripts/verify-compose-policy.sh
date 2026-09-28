#!/usr/bin/env bash
set -euo pipefail

# Validate the rendered Compose policy rather than grepping YAML. The rendered
# JSON is what Docker will actually apply after interpolation and overrides.
mode="${1:-base}"
case "$mode" in
  base) rendered="$(docker compose config --format json)" ;;
  syn) rendered="$(docker compose -f compose.yaml -f compose.syn.yaml config --format json)" ;;
  *) echo "usage: $0 [base|syn]" >&2; exit 2 ;;
esac

COMPOSE_JSON="$rendered" python3 - "$mode" <<'PY'
import json
import os
import sys

mode = sys.argv[1]
value = json.loads(os.environ["COMPOSE_JSON"])
service = value.get("services", {}).get("edgewatch")
if not service:
    raise SystemExit("edgewatch service is missing")
if service.get("build") is not None:
    raise SystemExit("Compose must pull the published image; build is not allowed")
if not str(service.get("image", "")).startswith("ghcr.io/crypt0rr/edgewatch:"):
    raise SystemExit("Compose must use the published GHCR image")
if service.get("read_only") is not True:
    raise SystemExit("runtime root filesystem must be read-only")
if "ALL" not in service.get("cap_drop", []):
    raise SystemExit("all Linux capabilities must be dropped by default")
# Privileged mode grants every capability and host device, which silently
# cancels cap_drop: [ALL] and the exact cap_add set checked below.
if service.get("privileged", False) is not False:
    raise SystemExit("privileged mode is not allowed; it grants every capability")
security_options = [str(option) for option in service.get("security_opt") or []]
if "no-new-privileges:true" not in security_options:
    raise SystemExit("no-new-privileges must be enabled")
for option in security_options:
    if option.lower().endswith(("=unconfined", ":unconfined")):
        raise SystemExit(f"security_opt {option} is not allowed; keep the default seccomp and AppArmor confinement")
for namespace in ("pid", "ipc", "userns_mode"):
    if str(service.get(namespace) or "").lower() == "host":
        raise SystemExit(f"{namespace}: host is not allowed; it drops the container's namespace isolation from the host")
tmpfs_entries = service.get("tmpfs", [])
bounded_tmpfs = False
for entry in tmpfs_entries:
    if isinstance(entry, str):
        target, _, options = entry.partition(":")
        if target == "/tmp" and any(option.startswith("size=") and len(option) > 5 for option in options.split(",")):
            bounded_tmpfs = True
            break
if not bounded_tmpfs:
    raise SystemExit("/tmp must be backed by a bounded tmpfs")
if service.get("network_mode") != "host":
    raise SystemExit("host networking is required for scanner reachability")
caps = {str(cap) for cap in service.get("cap_add") or []}
if "NET_RAW" not in caps:
    raise SystemExit("NET_RAW is required for Nmap and Naabu")
if mode == "base" and "NET_ADMIN" in caps:
    raise SystemExit("base Compose must not grant NET_ADMIN")
if mode == "syn" and "NET_ADMIN" not in caps:
    raise SystemExit("SYN override must grant NET_ADMIN")
# The documented policy is an exact set, not a minimum: any extra entry,
# including ALL, would restore capabilities that cap_drop removed.
allowed_caps = {"NET_RAW", "NET_ADMIN"} if mode == "syn" else {"NET_RAW"}
unexpected_caps = sorted(caps - allowed_caps)
if unexpected_caps:
    raise SystemExit(
        f"{mode} Compose must add only {', '.join(sorted(allowed_caps))}; "
        f"unexpected cap_add: {', '.join(unexpected_caps)}"
    )
targets = {volume.get("target") for volume in service.get("volumes", [])}
if "/var/lib/edgewatch" not in targets:
    raise SystemExit("runtime data must be mounted at /var/lib/edgewatch")
print(f"{mode} Compose policy verified")
PY
