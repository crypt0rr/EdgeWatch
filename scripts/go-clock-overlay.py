#!/usr/bin/env python3
"""Create a Go build overlay that shifts time.Now by a fixed number of days."""

import json
import subprocess
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: go-clock-overlay.py DAYS OVERLAY.json", file=sys.stderr)
        return 2

    try:
        days = int(sys.argv[1])
    except ValueError:
        print("DAYS must be a positive integer", file=sys.stderr)
        return 2
    if days < 1:
        print("DAYS must be a positive integer", file=sys.stderr)
        return 2

    try:
        goroot = Path(
            subprocess.run(
                ["go", "env", "GOROOT"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        )
    except (OSError, subprocess.CalledProcessError) as error:
        print(f"could not find the Go toolchain: {error}", file=sys.stderr)
        return 1

    source = goroot / "src/time/time.go"
    try:
        contents = source.read_text()
    except OSError as error:
        print(f"could not read {source}: {error}", file=sys.stderr)
        return 1

    anchor = "\tsec, nsec, mono := runtimeNow()\n"
    if contents.count(anchor) != 1:
        print(f"expected one time.Now clock source in {source}", file=sys.stderr)
        return 1

    overlay_path = Path(sys.argv[2]).resolve()
    overlay_path.parent.mkdir(parents=True, exist_ok=True)
    shifted_source = overlay_path.with_name(
        f"{overlay_path.stem}.time-{days}d.go"
    )
    shifted_source.write_text(
        contents.replace(
            anchor,
            anchor + f"\tsec += {days} * 24 * 60 * 60\n",
            1,
        )
    )
    overlay_path.write_text(
        json.dumps({"Replace": {str(source): str(shifted_source)}}) + "\n"
    )
    print(f"created {days}-day Go clock overlay at {overlay_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
