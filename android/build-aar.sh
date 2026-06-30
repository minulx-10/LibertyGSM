#!/usr/bin/env bash
# Build the shared Go core into android/app/libs/libgsm.aar.
#
# Prerequisites (one-time):
#   - Go 1.26.3+ and the Android NDK installed (Android Studio: SDK Manager -> NDK)
#   - export ANDROID_NDK_HOME=/path/to/ndk/<version>
#   - go install golang.org/x/mobile/cmd/gomobile@latest
#   - go install golang.org/x/mobile/cmd/gobind@latest
#   - gomobile init
#
# Then just run:  ./build-aar.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
TUNNEL_DIR="$HERE/../core-go/tunnel"
OUT="$HERE/app/libs/libgsm.aar"

mkdir -p "$HERE/app/libs"
echo "Building libgsm.aar from core-go/tunnel ..."
( cd "$TUNNEL_DIR" && gomobile bind -target=android -androidapi 21 -o "$OUT" . )
echo "OK -> $OUT"
echo "Now build the app in Android Studio (open the android/ folder)."
