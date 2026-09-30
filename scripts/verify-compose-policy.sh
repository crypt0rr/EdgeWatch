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
import posixpath
import re
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
for namespace in ("pid", "ipc", "uts", "cgroup", "userns_mode"):
    if str(service.get(namespace) or "").lower() == "host":
        raise SystemExit(f"{namespace}: host is not allowed; it drops the container's namespace isolation from the host")
# Host devices are one of the grants that the privileged check keeps out; a
# device node or device cgroup rule reaches host hardware whatever the
# capability set.
devices = service.get("devices") or []
if devices:
    names = ", ".join(str(device.get("source", device)) if isinstance(device, dict) else str(device) for device in devices)
    raise SystemExit(f"devices are not allowed: {names}; host devices bypass the capability and filesystem controls")
if service.get("device_cgroup_rules"):
    raise SystemExit("device_cgroup_rules are not allowed; they grant access to host devices")
# The kernel treats size=0 (and nr_blocks=0) as "no limit" for tmpfs, and a
# later option overrides an earlier one, so every size option of every /tmp
# entry must be a positive bound.
tmpfs_entries = service.get("tmpfs") or []
if isinstance(tmpfs_entries, str):
    tmpfs_entries = [tmpfs_entries]
for entry in tmpfs_entries:
    target, _, options = str(entry).partition(":")
    if target != "/tmp":
        raise SystemExit(f"tmpfs {target} is not allowed; only /tmp may be writable through a tmpfs")
    size_options = [option for option in options.split(",") if option.partition("=")[0] in ("size", "nr_blocks")]
    for option in size_options:
        bound = re.fullmatch(r"([0-9]+)[kmgtpe%]?", option.partition("=")[2], re.IGNORECASE)
        if bound is None or int(bound.group(1)) == 0:
            raise SystemExit(f"/tmp must be backed by a bounded tmpfs; {option} is not a positive size bound")
    if not any(option.startswith("size=") for option in size_options):
        raise SystemExit(f"/tmp must be backed by a bounded tmpfs; {entry} has no size= option")
if not tmpfs_entries:
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
# The container process is UID 0, so a mount of the Docker socket or of a host
# system directory hands it the host whatever its capabilities. The documented
# mounts are an exact set: the read-only configuration file, the ./data bind
# for SQLite state, and optional read-only secret files under /run/secrets/.
for key in ("volumes_from", "secrets", "configs"):
    if service.get(key):
        raise SystemExit(f"{key} is not allowed; mount configuration and secret files as read-only binds at the documented paths")
CONFIG_TARGET = "/etc/edgewatch/config.yaml"
DATA_TARGET = "/var/lib/edgewatch"
SECRETS_DIRECTORY = "/run/secrets/"
# Kernel interfaces and container runtime state and sockets, rejected for any
# bind; host system directories, rejected as the source of a writable bind; and
# top-level directories, rejected as a whole in any bind.
RUNTIME_TREES = ("/proc", "/sys", "/dev", "/run", "/var/run", "/boot", "/var/lib/docker", "/var/lib/containerd")
SYSTEM_TREES = ("/etc", "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32")
SYSTEM_DIRECTORIES = {"/", "/home", "/root", "/var", "/var/lib", "/opt", "/srv", "/mnt", "/media", "/tmp", "/var/tmp"}
SYSTEM_DIRECTORIES.update(RUNTIME_TREES, SYSTEM_TREES)


def normalized(path):
    # posixpath.normpath keeps a leading "//", which the kernel resolves as "/".
    return posixpath.normpath("/" + path.lstrip("/"))


def within(path, tree):
    return path == tree or path.startswith(tree + "/")


data_mounted = False
for volume in service.get("volumes") or []:
    if not isinstance(volume, dict):
        raise SystemExit(f"volume {volume} is not in the rendered long syntax")
    source = str(volume.get("source") or "")
    target = str(volume.get("target") or "")
    label = f"{source or '(anonymous)'}:{target}"
    if volume.get("type") != "bind":
        raise SystemExit(f"volume {label} of type {volume.get('type')} is not allowed; mount only the documented host files and ./data as binds")
    if not source.startswith("/") or not target.startswith("/"):
        raise SystemExit(f"volume {label} must bind an absolute host path to an absolute container path")
    read_only = volume.get("read_only") is True
    host_path = normalized(source)
    name = posixpath.basename(host_path)
    # A read-only bind does not stop connect() on a socket.
    if name.endswith(".sock") or ".sock." in name:
        raise SystemExit(f"volume source {source} is a socket; the Docker or another runtime socket gives the container control of the host")
    if host_path in SYSTEM_DIRECTORIES:
        raise SystemExit(f"volume source {source} is the host root or a host system directory")
    for tree in RUNTIME_TREES:
        if within(host_path, tree):
            raise SystemExit(f"volume source {source} is under {tree}, a host kernel or container runtime path")
    if not read_only:
        for tree in SYSTEM_TREES:
            if within(host_path, tree):
                raise SystemExit(f"writable volume source {source} is under the host system directory {tree}")
    container_path = normalized(target)
    if container_path == DATA_TARGET:
        data_mounted = True
    elif container_path == CONFIG_TARGET or container_path.startswith(SECRETS_DIRECTORY):
        if not read_only:
            raise SystemExit(f"volume {label} must be read-only")
    else:
        raise SystemExit(
            f"volume {label} is not allowed; only {CONFIG_TARGET}, {DATA_TARGET} and "
            f"read-only files under {SECRETS_DIRECTORY} may be mounted"
        )
if not data_mounted:
    raise SystemExit("runtime data must be mounted at /var/lib/edgewatch")
print(f"{mode} Compose policy verified")
PY
