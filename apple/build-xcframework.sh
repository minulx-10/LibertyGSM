#!/bin/sh
# Build the shared LibertyGSM Go core (core-go/tunnel) into an Apple xcframework.
#
# RUN ON macOS with Xcode + Go + gomobile installed:
#   go install golang.org/x/mobile/cmd/gomobile@latest
#   gomobile init
#
# Produces apple/LibGSM.xcframework, which the Xcode project links. The SAME
# package backs the Android .aar (android/build-aar.sh) — one core, two bindings.
set -e

here=$(cd "$(dirname "$0")" && pwd)
core="$here/../core-go/tunnel"
out="$here/LibGSM.xcframework"

export PATH="$PATH:$(go env GOPATH)/bin"

if ! command -v gomobile >/dev/null 2>&1; then
  echo "gomobile not found. Install it first:" >&2
  echo "  go install golang.org/x/mobile/cmd/gomobile@latest && gomobile init" >&2
  exit 1
fi

echo "Binding core-go/tunnel -> $out"
rm -rf "$out"
cd "$core"

# ios      = device (arm64) + simulator, macos = Catalyst-free macOS app.
# gomobile emits a single .xcframework covering all listed platforms.
gomobile bind \
  -target=ios,iossimulator,macos \
  -o "$out" \
  .

echo "Done: $out"
