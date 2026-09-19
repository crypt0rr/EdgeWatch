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
caps = set(service.get("cap_add", []))
if "NET_RAW" not in caps:
    raise SystemExit("NET_RAW is required for Nmap and Naabu")
if mode == "base" and "NET_ADMIN" in caps:
    raise SystemExit("base Compose must not grant NET_ADMIN")
if mode == "syn" and "NET_ADMIN" not in caps:
    raise SystemExit("SYN override must grant NET_ADMIN")
targets = {volume.get("target") for volume in service.get("volumes", [])}
if "/var/lib/edgewatch" not in targets:
    raise SystemExit("runtime data must be mounted at /var/lib/edgewatch")
print(f"{mode} Compose policy verified")
PY
