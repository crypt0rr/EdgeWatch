#!/bin/sh
set -eu

image=${1:?usage: prepare-container-smoke-data.sh IMAGE DATA_DIRECTORY}
data_dir=${2:?usage: prepare-container-smoke-data.sh IMAGE DATA_DIRECTORY}

if [ ! -d "$data_dir" ]; then
  echo "container smoke data directory does not exist: $data_dir" >&2
  exit 2
fi

# Model a rootful Compose bind mount without relaxing permissions. In rootless
# Docker, container UID 0 maps to the invoking host user, so the same ownership
# operation gives the daemon the owner-only access it receives in production.
docker run --rm --read-only --tmpfs /tmp:size=16m,mode=1777 \
  --cap-drop ALL --cap-add CHOWN --security-opt no-new-privileges:true \
  --volume "$data_dir:/var/lib/edgewatch:rw" \
  --entrypoint /bin/sh "$image" \
  -ec 'chown 0:0 /var/lib/edgewatch && chmod 0750 /var/lib/edgewatch && test "$(stat -c %u:%g /var/lib/edgewatch)" = 0:0 && test "$(stat -c %a /var/lib/edgewatch)" = 750'
