#!/bin/bash
# Builds what is released for Apple silicon Macs: the `analyze-anything` command as a tar.gz and the desktop
# app as a DMG, both signed with a Developer ID certificate and notarized by Apple.
#
#   tools/release/macos.sh
#
# Needs in the environment: APPLE_ID, APPLE_TEAM_ID and APPLE_SPECIFIC_PASSWORD (an app-specific
# password for that Apple ID), and a "Developer ID Application" certificate of that team in the
# keychain. Writes into dist/release and prints the SHA-256 of each file. Nothing is uploaded.
set -euo pipefail
cd "$(dirname "$0")/../.."

: "${APPLE_ID:?set APPLE_ID}" "${APPLE_TEAM_ID:?set APPLE_TEAM_ID}" "${APPLE_SPECIFIC_PASSWORD:?set APPLE_SPECIFIC_PASSWORD}"
TARGET=aarch64-apple-darwin
VERSION=$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"]=="aa-cli"))')
IDENTITY=$(security find-identity -v -p codesigning | sed -n "s/.*\"\(Developer ID Application: .*(${APPLE_TEAM_ID})\)\".*/\1/p" | head -1)
[ -n "$IDENTITY" ] || { echo "no Developer ID Application certificate of team $APPLE_TEAM_ID in the keychain" >&2; exit 1; }
OUT=dist/release
rm -rf "$OUT"; mkdir -p "$OUT"
notarize() { xcrun notarytool submit "$1" --apple-id "$APPLE_ID" --team-id "$APPLE_TEAM_ID" --password "$APPLE_SPECIFIC_PASSWORD" --wait; }

echo "== analyze-anything $VERSION, the command"
rustup target add "$TARGET" >/dev/null
cargo build --release --locked --target "$TARGET" -p aa-cli
AA="target/$TARGET/release/analyze-anything"
"$AA" selftest >/dev/null
codesign --force --options runtime --timestamp --sign "$IDENTITY" "$AA"
codesign --verify --strict --verbose=2 "$AA"
NAME="analyze-anything-$VERSION-$TARGET"
rm -rf "$OUT/$NAME"; mkdir "$OUT/$NAME"
cp "$AA" README.md LICENSE NOTICE "$OUT/$NAME/"
# The short name, for those who unpack the archive by hand; Homebrew makes its own.
ln -s analyze-anything "$OUT/$NAME/aaaa"
# A program on its own cannot carry a notarization ticket; Apple records it and macOS asks.
(cd "$OUT" && ditto -c -k --keepParent "$NAME" "$NAME.zip")
notarize "$OUT/$NAME.zip"
rm "$OUT/$NAME.zip"
tar -C "$OUT" -czf "$OUT/$NAME.tar.gz" "$NAME"
rm -rf "$OUT/$NAME"

echo "== Analyze Anything $VERSION, the desktop app"
(cd apps/desktop && npm ci --no-audit --no-fund >/dev/null)
# Tauri signs with the hardened runtime, notarizes the app and staples the ticket to it.
(cd apps/desktop && APPLE_SIGNING_IDENTITY="$IDENTITY" APPLE_PASSWORD="$APPLE_SPECIFIC_PASSWORD" npx tauri build --target "$TARGET" --bundles app,dmg)
BUNDLE="target/$TARGET/release/bundle"
APP="$BUNDLE/macos/Analyze Anything.app"
DMG=$(ls "$BUNDLE"/dmg/*.dmg | head -1)
codesign --verify --deep --strict --verbose=2 "$APP"
xcrun stapler validate "$APP"
spctl --assess --type execute --verbose=2 "$APP"
# The disk image is what people download, so it carries its own ticket too.
notarize "$DMG"
xcrun stapler staple "$DMG"
spctl --assess --type open --context context:primary-signature --verbose=2 "$DMG"
cp "$DMG" "$OUT/Analyze-Anything-$VERSION-arm64.dmg"

echo "== done"
(cd "$OUT" && shasum -a 256 *)
