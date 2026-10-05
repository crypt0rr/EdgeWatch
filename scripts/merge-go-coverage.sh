#!/bin/sh

# Merge the coverage of sharded `go test -coverprofile` runs into one profile
# and one package summary for check-go-coverage.sh and check-diff-coverage.mjs.
#
# Shards may split one package's tests, so the same block can appear in
# several profiles. The merged profile lists each block once with the sum of
# its counts, and each package that a shard summary reports gets one summary
# line whose percentage is recomputed from the merged profile.
#
# Usage: merge-go-coverage.sh OUT_PROFILE OUT_SUMMARY SHARD_DIR...
# Each SHARD_DIR holds the coverage.out and go-coverage-summary.txt of a shard.
set -eu

if [ "$#" -lt 3 ]; then
	echo "usage: $0 OUT_PROFILE OUT_SUMMARY SHARD_DIR..." >&2
	exit 2
fi
out_profile=$1
out_summary=$2
shift 2

for shard in "$@"; do
	for file in coverage.out go-coverage-summary.txt; do
		if [ ! -s "$shard/$file" ]; then
			echo "shard coverage is missing or empty: $shard/$file" >&2
			exit 1
		fi
	done
done

mode=
for shard in "$@"; do
	shard_mode=$(head -n 1 "$shard/coverage.out")
	case "$shard_mode" in
		"mode: "*) ;;
		*)
			echo "$shard/coverage.out does not start with a mode line" >&2
			exit 1
			;;
	esac
	if [ -z "$mode" ]; then
		mode=$shard_mode
	elif [ "$shard_mode" != "$mode" ]; then
		echo "shard coverage modes differ: '$mode' and '$shard_mode' in $shard" >&2
		exit 1
	fi
done

profiles=
summaries=
for shard in "$@"; do
	profiles="$profiles $shard/coverage.out"
	summaries="$summaries $shard/go-coverage-summary.txt"
done

# shellcheck disable=SC2086 # The shard paths are word-split on purpose.
awk -v mode="$mode" '
	FNR == 1 { next }
	NF != 3 { printf "malformed profile line in %s: %s\n", FILENAME, $0 > "/dev/stderr"; failed = 1; exit 1 }
	{
		if (!($1 in count)) { order[++blocks] = $1; statements[$1] = $2 }
		else if (statements[$1] != $2) { printf "statement counts differ for %s\n", $1 > "/dev/stderr"; failed = 1; exit 1 }
		if (mode == "mode: set") { if ($3 > 0) count[$1] = 1; else if (!($1 in count)) count[$1] = 0 }
		else count[$1] += $3
	}
	END {
		if (failed) exit 1
		print mode
		for (i = 1; i <= blocks; i++) print order[i], statements[order[i]], count[order[i]]
	}
' $profiles >"$out_profile"

# shellcheck disable=SC2086 # The shard paths are word-split on purpose.
awk -v profile="$out_profile" '
	BEGIN {
		while ((getline line < profile) > 0) {
			if (line ~ /^mode: /) continue
			split(line, field, " ")
			package = field[1]
			sub(/:[^:]*$/, "", package)
			sub(/\/[^\/]*$/, "", package)
			total[package] += field[2]
			if (field[3] > 0) covered[package] += field[2]
		}
		close(profile)
	}
	{
		for (i = 1; i < NF; i++) {
			if ($(i + 1) != "coverage:") continue
			# go test prefixes a tested package with its status and
			# prints a package without tests on its own.
			package = ($1 == "ok" || $1 == "FAIL") ? $2 : $1
			if (package in seen) next
			seen[package] = 1
			if (package in total) printf "ok  \t%s\tcoverage: %.1f%% of statements\n", package, 100 * covered[package] / total[package]
			else print
			next
		}
	}
' $summaries >"$out_summary"
