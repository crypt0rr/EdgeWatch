#!/usr/bin/env bash

# Compare every `apk add` pin in the Dockerfile with the current package index
# of the Alpine branch that the pin's stage builds on. A stable Alpine branch
# keeps only the newest build of each package and removes the pinned build
# when it publishes an update. Image builds that reuse a cached layer keep
# passing, but the next build without a cache, such as the release build,
# fails. The build stages run on the build platform and the runtime stage on
# each target platform, so every pin must be in the x86_64 and the aarch64
# index, from the main or the community repository.
#
# Exit status: 0 when every pin is current, 1 when an index no longer has a
# pinned version, and 2 when the Dockerfile or an index cannot be read. Set
# ALPINE_MIRROR to read the indexes from another HTTPS mirror.
set -euo pipefail

if [[ $# -gt 1 ]]; then
  echo "usage: $0 [DOCKERFILE]" >&2
  exit 2
fi
dockerfile="${1:-Dockerfile}"
mirror="${ALPINE_MIRROR:-https://dl-cdn.alpinelinux.org/alpine}"
mirror="${mirror%/}"
architectures=(x86_64 aarch64)
repositories=(main community)
if [[ ! -f "$dockerfile" ]]; then
  echo "Dockerfile not found: $dockerfile" >&2
  exit 2
fi

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

# Print "BRANCH PACKAGE=VERSION" for each package of each `apk add`, after
# joining continuation lines and dropping comment and blank lines as Docker
# does. A stage takes its branch from an alpine:3.N base or an image tag
# ending in -alpine3.N, or from the earlier stage it builds on. An unpinned
# package, an apk option that can change the repository or the installed set,
# and a stage whose branch is unknown fail closed.
awk '
function fail(message) {
  print FILENAME ":" start ": " message > "/dev/stderr"
  failed = 1
  exit 2
}
function alpine_branch(image,    reference, tag, name, slash, colon, i) {
  reference = image
  sub(/@.*/, "", reference)
  if (tolower(reference) in stage_branch) return stage_branch[tolower(reference)]
  slash = 0
  for (i = length(reference); i > 0; i--) {
    if (substr(reference, i, 1) == "/") { slash = i; break }
  }
  colon = 0
  for (i = length(reference); i > slash; i--) {
    if (substr(reference, i, 1) == ":") { colon = i; break }
  }
  if (colon == 0) return ""
  tag = substr(reference, colon + 1)
  name = substr(reference, slash + 1, colon - slash - 1)
  if (match(tag, /(^|-)alpine3\.[0-9]+(\.[0-9]+)?$/)) {
    tag = substr(tag, RSTART, RLENGTH)
    sub(/^-?alpine/, "", tag)
  } else if (name != "alpine" || tag !~ /^3\.[0-9]+(\.[0-9]+)?$/) {
    return ""
  }
  if (tag ~ /^3\.[0-9]+\.[0-9]+$/) sub(/\.[0-9]+$/, "", tag)
  return tag
}
function instruction(text,    words, count, image, index_, word) {
  count = split(text, words, /[ \t]+/)
  if (count == 0) return
  word = toupper(words[1])
  if (word == "FROM") {
    index_ = 2
    while (index_ <= count && words[index_] ~ /^--/) index_++
    image = words[index_]
    branch = alpine_branch(image)
    if (index_ + 2 <= count && toupper(words[index_ + 1]) == "AS") {
      stage_branch[tolower(words[index_ + 2])] = branch
    }
    in_stage = 1
    return
  }
  if (word != "RUN") return
  for (index_ = 2; index_ < count; index_++) {
    if (words[index_] != "apk" || words[index_ + 1] != "add") continue
    if (!in_stage) fail("apk add before the first FROM")
    if (branch == "") fail("cannot tell the Alpine branch of the stage that runs apk add")
    packages = 0
    for (index_ += 2; index_ <= count; index_++) {
      word = words[index_]
      if (word ~ /^(&&|\|\||;|\|)/ || word ~ /^[0-9]*[<>]/) break
      if (word == "--no-cache") continue
      if (word ~ /^-/) fail("apk add option " word " is not supported by this check")
      if (word !~ /^[a-z0-9][a-z0-9._+-]*=[0-9][0-9A-Za-z.+~_-]*$/) {
        fail("apk package " word " must be pinned to a version")
      }
      print branch " " word
      packages++
    }
    if (packages == 0) fail("apk add installs no package")
  }
}
{
  sub(/\r$/, "")
  if (logical == "") start = FNR
  if ($0 ~ /^[ \t]*(#|$)/) next
  # Docker continues a line whose backslash only blanks follow.
  if ($0 ~ /\\[ \t]*$/) {
    sub(/\\[ \t]*$/, "")
    logical = logical $0 " "
    next
  }
  logical = logical $0
  sub(/^[ \t]+/, "", logical)
  sub(/[ \t]+$/, "", logical)
  instruction(logical)
  logical = ""
}
END {
  if (failed) exit 2
  if (logical != "") { sub(/^[ \t]+/, "", logical); sub(/[ \t]+$/, "", logical); instruction(logical) }
}
' "$dockerfile" | LC_ALL=C sort -u > "$workdir/pins" || exit 2
if [[ ! -s "$workdir/pins" ]]; then
  echo "$dockerfile has no apk add package" >&2
  exit 2
fi

stale=0
total=0
while read -r branch; do
  for architecture in "${architectures[@]}"; do
    index="$workdir/v$branch-$architecture"
    : > "$index"
    for repository in "${repositories[@]}"; do
      url="$mirror/v$branch/$repository/$architecture/APKINDEX.tar.gz"
      archive="$workdir/APKINDEX.tar.gz"
      if ! curl --fail --silent --show-error --location --proto '=https,file' --proto-redir '=https' \
          --retry 3 --max-time 120 --output "$archive" "$url"; then
        echo "could not download $url" >&2
        exit 2
      fi
      # Each record names its package on a P: line and its version on a V:
      # line, and a blank line ends it.
      if ! tar -xzOf "$archive" APKINDEX > "$workdir/APKINDEX" ||
          ! awk '/^P:/ { name = substr($0, 3) } /^V:/ { version = substr($0, 3) }
              /^$/ { if (name != "") print name "=" version; name = version = "" }
              END { if (name != "") print name "=" version }' "$workdir/APKINDEX" >> "$index"; then
        echo "could not read the package index at $url" >&2
        exit 2
      fi
    done
    if [[ ! -s "$index" ]]; then
      echo "the Alpine v$branch $architecture index lists no package" >&2
      exit 2
    fi
  done
  while read -r pin_branch pin; do
    [[ "$pin_branch" == "$branch" ]] || continue
    total=$((total + 1))
    package="${pin%%=*}"
    missing=""
    for architecture in "${architectures[@]}"; do
      index="$workdir/v$branch-$architecture"
      if grep -Fxq -- "$pin" "$index"; then
        continue
      fi
      current="$(grep -F -- "$package=" "$index" | awk -F= -v name="$package" '$1 == name { print $0 }' | paste -sd, - || true)"
      missing+="  $architecture: ${current:-no $package package}"$'\n'
    done
    if [[ -z "$missing" ]]; then
      echo "current: $pin (Alpine v$branch)"
    else
      stale=$((stale + 1))
      echo "stale: $pin is no longer in the Alpine v$branch index; it lists" >&2
      printf '%s' "$missing" >&2
    fi
  done < "$workdir/pins"
done < <(cut -d' ' -f1 "$workdir/pins" | LC_ALL=C sort -u)

if [[ "$stale" -gt 0 ]]; then
  echo "$stale of $total apk pins in $dockerfile are stale; update them to the listed versions" >&2
  exit 1
fi
echo "all $total apk pins in $dockerfile are current for ${architectures[*]}"
