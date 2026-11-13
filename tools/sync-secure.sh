#!/bin/sh
# Copy the secure-VBAN layer from the SDK (../SDK by default) into the hub package.
# The hub compiles these files as they are; do not edit them here, change the SDK and re-sync.
set -e
SDK=${1:-$(dirname "$0")/../sdk}
D=$(dirname "$0")/../package/vbanhub/src/secure
mkdir -p "$D/vban" "$D/monocypher"
cp "$SDK/src/vban_secure.c" "$SDK/src/vban_noise.c" "$D/"
cp "$SDK/src/vban/vban_secure.h" "$SDK/src/vban/vban_noise.h" "$SDK/src/vban/vban_proto.h" \
   "$SDK/src/vban/vban_config.h" "$D/vban/"
cp "$SDK/third_party/monocypher/monocypher.c" "$SDK/third_party/monocypher/monocypher.h" \
   "$SDK/third_party/monocypher/LICENCE.md" "$SDK/third_party/monocypher/VERSION" "$D/monocypher/"
( cd "$SDK" && git rev-parse --short HEAD 2>/dev/null || echo unknown ) > "$D/SDK_REVISION"
echo "synced from $SDK ($(cat "$D/SDK_REVISION"))"
