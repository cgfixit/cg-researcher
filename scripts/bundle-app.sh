#!/usr/bin/env bash
# Assemble and ad-hoc sign dist/cg-researcher.app from an aarch64-apple-darwin
# release binary, then zip it with ditto. Used by .github/workflows/release.yml
# and runnable locally on an Apple Silicon Mac:
#   cargo build --release --locked -p cg-researcher --target aarch64-apple-darwin
#   scripts/bundle-app.sh
# Ad-hoc signature is NOT Developer ID/notarization: downloaded copies are
# quarantined by Gatekeeper (right-click → Open, or xattr -d com.apple.quarantine).
set -euo pipefail
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin="${1:-$repo/target/aarch64-apple-darwin/release/cg-researcher}"
out="$repo/dist"
version="$(sed -n 's/^version = "\(.*\)"/\1/p' "$repo/Cargo.toml" | head -1)"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.]+)?$ ]] || { echo "bad version: $version" >&2; exit 1; }
[[ -x "$bin" ]] || { echo "missing binary: $bin" >&2; exit 1; }
lipo -verify_arch "$bin" arm64
app="$out/cg-researcher.app"
rm -rf "$app" "$out/cg-researcher-macos-arm64.app.zip"*
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
install -m 0755 "$bin" "$app/Contents/MacOS/cg-researcher"
sed "s/__VERSION__/$version/g" "$repo/packaging/macos/Info.plist" > "$app/Contents/Info.plist"
plutil -lint -s "$app/Contents/Info.plist"
cp "$repo/LICENSE" "$repo/README.md" "$repo/SECURITY.md" "$app/Contents/Resources/"
codesign --force --sign - --options runtime --timestamp=none \
  --identifier com.cgfixit.cg-researcher "$app"
codesign --verify --strict --deep "$app"
( cd "$out" && ditto -c -k --sequesterRsrc --keepParent cg-researcher.app cg-researcher-macos-arm64.app.zip \
  && shasum -a 256 cg-researcher-macos-arm64.app.zip > cg-researcher-macos-arm64.app.zip.sha256 )
cat "$out/cg-researcher-macos-arm64.app.zip.sha256"
