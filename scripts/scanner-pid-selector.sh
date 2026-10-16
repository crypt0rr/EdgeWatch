#!/bin/sh
set -eu

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
	printf '%s\n' 'usage: scanner-pid-selector.sh PROC_ROOT NAME [REQUIRED_ARG]' >&2
	exit 2
fi

proc_root=$1
expected_name=$2
required_arg=${3-}

for status in "$proc_root"/[0-9]*/status; do
	[ -r "$status" ] || continue
	name=$(sed -n 's/^Name:[[:space:]]*//p' "$status" | sed -n '1p')
	[ "$name" = "$expected_name" ] || continue
	state=$(awk '/^State:/{print $2; exit}' "$status" 2>/dev/null || true)
	[ "$state" != Z ] || continue

	pid=${status%/status}
	pid=${pid##*/}
	if [ -n "$required_arg" ]; then
		cmdline=$proc_root/$pid/cmdline
		[ -r "$cmdline" ] || continue
		tr '\000' '\n' <"$cmdline" | grep -F -x -q -- "$required_arg" || continue
	fi

	printf '%s\n' "$pid"
	exit 0
done

exit 1
