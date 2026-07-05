#!/usr/bin/env bash
#
# Builds the Extension Guard Linux artifacts into release-linux/:
#   - guard               (CLI + systemd service + watchdog)
#   - extension-guard-status    (Wails status window)
#   - extension-ids.json  (config, copied next to the binaries)
#
# Run ON Linux: the Wails status UI links gtk/webkit, so it cannot be
# cross-compiled from Windows. The `guard` engine alone is pure Go and could be
# cross-compiled, but this script builds the full set.
#
# Prereqs (Debian/Ubuntu):
#   sudo apt install build-essential libgtk-3-dev libwebkit2gtk-4.1-dev
#   Go 1.25+ and:  go install github.com/wailsapp/wails/v2/cmd/wails@latest
#
# Usage:  bash build-linux.sh
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # repo root
release="$root/release-linux"

echo "== go test =="
go -C "$root" test ./...

echo "== go vet =="
go -C "$root" vet ./...

echo "== build guard =="
go -C "$root" build -ldflags "-s -w" -o guard ./cmd/guard

echo "== build status UI (wails) =="
( cd "$root/statusui" && wails build )

echo "== collect release artifacts =="
rm -rf "$release"
mkdir -p "$release"
cp "$root/guard" "$release/"
cp "$root/statusui/build/bin/extension-guard-status" "$release/"
cp "$root/extension-ids.json" "$release/"

echo
echo "Linux artifacts in $release :"
ls -1sh "$release"
echo
echo "Install with:  sudo installer/linux/install.sh"
echo "NOTE: these binaries are UNSIGNED."
