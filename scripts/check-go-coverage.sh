#!/bin/sh

# Enforce the risk-based Go coverage policy from one race-enabled test run.
# The package summary is captured from `go test`; the aggregate is read from
# the profile so the two checks cannot silently report different test sets.
set -eu

profile=${1:-coverage.out}
summary=${2:-go-coverage-summary.txt}

if [ ! -s "$profile" ]; then
	echo "Go coverage profile is missing or empty: $profile" >&2
	exit 1
fi
if [ ! -f "$summary" ]; then
	echo "Go coverage summary is missing: $summary" >&2
	exit 1
fi

total=$(go tool cover -func="$profile" | awk '/^total:/ { print $3 }' | tr -d '%')
if [ -z "$total" ]; then
	echo "could not read aggregate Go coverage from $profile" >&2
	exit 1
fi

awk -v value="$total" 'BEGIN { if (value < 82) exit 1 }' || {
	echo "Go aggregate coverage ${total}% is below the required 82%" >&2
	exit 1
}

failures=0
packages_seen=0
while IFS='|' read -r package coverage; do
	[ -n "$package" ] || continue
	packages_seen=$((packages_seen + 1))
	threshold=80
	case "$package" in
		*/cmd/edgewatch) threshold=70 ;;
		*/internal/app|*/internal/web) threshold=75 ;;
		*/internal/store) threshold=78 ;;
	esac
	if awk -v value="$coverage" -v minimum="$threshold" 'BEGIN { exit !(value < minimum) }'; then
		echo "$package coverage ${coverage}% is below the required ${threshold}%" >&2
		failures=$((failures + 1))
	fi
	done <<EOF
$(awk '
/coverage: [0-9.]+% of statements/ {
		package = $2
		value = $0
		sub(/.*coverage: /, "", value)
		sub(/% of statements.*/, "", value)
		print package "|" value
}' "$summary")
EOF

if [ "$packages_seen" -eq 0 ]; then
	echo "no package coverage summaries found in $summary" >&2
	exit 1
fi
if [ "$failures" -ne 0 ]; then
	exit 1
fi

echo "Go coverage gates passed: aggregate ${total}%, ${packages_seen} production packages checked"
