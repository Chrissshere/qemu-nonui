#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
root="$PWD"
build="$root/.build"
version=0.1.0
upstream="$build/LightTouchMac"
revision=5078f0a8f1aa86f512ca97a23aa4b3443a190845
python_sha=7a2384641584ab9984221fcb0fc9265df465922af71be71410529e2a9c3f0540
python_url=https://github.com/astral-sh/python-build-standalone/releases/download/20261110/cpython-3.13.18%2B20261110-aarch64-apple-darwin-install_only_stripped.tar.gz

if [[ "$(uname -m)" != arm64 ]]; then
    echo "Build NonUI on an Apple Silicon Mac." >&2
    exit 1
fi
mkdir -p "$build/downloads" dist

if [[ ! -d "$upstream/.git" ]]; then
    git -c advice.detachedHead=false clone --quiet --depth 1 --branch v1.0-2026.10.22 \
        https://github.com/samhenrigold/LightTouchMac.git "$upstream"
fi
if [[ "$(git -C "$upstream" rev-parse HEAD)" != "$revision" ]] || \
    [[ -n "$(git -C "$upstream" status --porcelain --untracked-files=no)" ]]; then
    echo "The cached Light Touch checkout differs from the pinned source." >&2
    exit 1
fi

python_archive="$build/downloads/python.tar.gz"
if [[ ! -f "$python_archive" ]]; then
    /usr/bin/curl -fLsS --retry 2 -o "$python_archive.tmp" "$python_url"
    mv "$python_archive.tmp" "$python_archive"
fi
printf '%s  %s\n' "$python_sha" "$python_archive" | /usr/bin/shasum -a 256 -c -

swift build --package-path storage --scratch-path "$build/storage" -c release \
    --disable-automatic-resolution --product RootBuilder
storage_bin="$(swift build --package-path storage --scratch-path "$build/storage" -c release --show-bin-path)"
stage="$(mktemp -d "$build/package.XXXXXX")"
trap 'rm -rf "$stage"' EXIT
bundle="$stage/NonUI.app/Contents"
resources="$bundle/Resources"
display="$bundle/Helpers/NonUI Display.app/Contents"
mkdir -p "$bundle/MacOS" "$display/MacOS" "$display/Resources" "$resources/runtime" "$resources/licenses"
icon_stage="$build/icons"
rm -rf "$icon_stage"
xcrun swift "$root/app/make-icon.swift" "$root/app/icon-source.png" "$icon_stage"
iconutil -c icns "$icon_stage/icon.iconset" -o "$icon_stage/AppIcon.icns"
for dest in "$resources" "$display/Resources"; do
    cp "$icon_stage/AppIcon.icns" "$icon_stage/AppIconLight.png" "$icon_stage/AppIconDark.png" "$dest/"
done
cp app/Info.plist "$bundle/Info.plist"
cp app/Display-Info.plist "$display/Info.plist"
cp app/nonui host-ready "$storage_bin/RootBuilder" "$resources/"
cp runtime/*.py "$resources/runtime/"
if /usr/bin/otool -L "$resources/RootBuilder" | /usr/bin/grep -q '@rpath/libswiftCompatibilitySpan.dylib'; then
    toolchain="$(cd "$(dirname "$(xcrun -f swiftc)")/.." && pwd)"
    support="$toolchain/lib/swift-6.2/macosx"
    cp "$support/libswiftCompatibilitySpan.dylib" "$resources/"
    if /usr/bin/otool -l "$resources/RootBuilder" | /usr/bin/grep -F "$support (" >/dev/null; then
        xcrun install_name_tool -delete_rpath "$support" "$resources/RootBuilder"
        /usr/bin/codesign --force --sign - "$resources/RootBuilder"
    fi
fi
cp LICENSE THIRD-PARTY.md "$resources/licenses/"
/usr/bin/tar -xzf "$python_archive" -C "$resources"

for dependency in "$build/storage/checkouts/"*; do
    name="$(basename "$dependency")"
    for notice in "$dependency"/LICENSE* "$dependency"/NOTICE*; do
        [[ -f "$notice" ]] || continue
        cp "$notice" "$resources/licenses/$name-$(basename "$notice")"
    done
done
cp "$build/storage/checkouts/Unrar.swift/Sources/Cunrar/license.txt" "$resources/licenses/UnRAR.txt"

xcrun swiftc -O -parse-as-library -target arm64-apple-macos15.0 \
    app/AppIcon.swift app/Importer.swift app/Logs.swift -o "$bundle/MacOS/NonUI"
xcrun swiftc -O -parse-as-library -target arm64-apple-macos15.0 \
    app/AppIcon.swift app/GuestPixels.swift app/Display.swift -o "$display/MacOS/NonUIDisplay"
xcrun clang -Wall -Wextra -Werror -O2 -arch arm64 -mmacosx-version-min=15.0 \
    native/runner.c -o "$resources/runner"
/usr/bin/codesign --force --sign - --entitlements native/entitlements.plist "$resources/runner"
/usr/bin/codesign --force --sign - "${display%/Contents}"
/usr/bin/codesign --force --sign - "$stage/NonUI.app"
/usr/bin/codesign --verify --strict --verbose=1 "$stage/NonUI.app"
/usr/bin/ditto -c -k --keepParent "$stage/NonUI.app" "$stage/NonUI-$version-macos-arm64.zip"

rm -rf "$root/dist/NonUI.app"
mv "$stage/NonUI.app" dist/
mv "$stage/NonUI-$version-macos-arm64.zip" dist/
(cd dist && /usr/bin/shasum -a 256 "NonUI-$version-macos-arm64.zip" > SHA256SUMS)
printf '%s\n' "$root/dist/NonUI.app" "$root/dist/NonUI-$version-macos-arm64.zip"
