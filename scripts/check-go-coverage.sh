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

# Derive the production package contract from the module instead of keeping a
# second hand-maintained list in this script. A newly added package therefore
# has to appear in the summary and meet its threshold before the gate passes.
required_packages=$(go list -f '{{if .GoFiles}}{{.ImportPath}}{{end}}' ./... 2>/dev/null | awk 'NF') || {
	echo "could not enumerate production Go packages" >&2
	exit 1
}
if [ -z "$required_packages" ]; then
	echo "production Go package inventory is empty" >&2
	exit 1
fi

while IFS= read -r package; do
	[ -n "$package" ] || continue
	coverage=$(awk -v wanted="$package" '
		{
			for (i = 1; i <= NF; i++) {
				if ($i != wanted) continue
				for (j = i + 1; j <= NF; j++) {
					if ($(j) == "coverage:") {
						value = $(j + 1)
						sub(/%$/, "", value)
						print value
						exit
					}
				}
			}
		}' "$summary")
	if [ -z "$coverage" ]; then
		echo "$package is missing from $summary" >&2
		failures=$((failures + 1))
		continue
	fi
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
$required_packages
EOF

required_count=$(printf '%s\n' "$required_packages" | awk 'NF { count++ } END { print count + 0 }')
if [ "$packages_seen" -ne "$required_count" ]; then
	echo "Go coverage summaries covered $packages_seen of $required_count required production packages" >&2
	failures=$((failures + 1))
fi
if [ "$failures" -ne 0 ]; then
	exit 1
fi

echo "Go coverage gates passed: aggregate ${total}%, ${packages_seen} production packages checked"
