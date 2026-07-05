#!/usr/bin/env bash
#
# Installs Extension Guard on Linux: copies the binaries to /opt/extension-guard and
# registers + starts the systemd service. install-service prompts for the
# uninstall password (held by the parent / accountability partner).
#
# Build first:  bash build-linux.sh
# Then run:     sudo installer/linux/install.sh
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "This installer must run as root. Try: sudo $0" >&2
  exit 1
fi

src="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../release-linux" && pwd)"
dest=/opt/extension-guard

if [ ! -x "$src/guard" ]; then
  echo "Build artifacts not found in $src - run build-linux.sh first." >&2
  exit 1
fi

install -d "$dest"
install -m 0755 "$src/guard" "$dest/guard"
install -m 0755 "$src/extension-guard-status" "$dest/extension-guard-status"
install -m 0644 "$src/extension-ids.json" "$dest/extension-ids.json"

# Registers the systemd unit (Restart=always), enables boot start, sets the
# uninstall password, and starts the service (which applies the browser lock).
"$dest/guard" -config "$dest/extension-ids.json" install-service

echo
echo "Installed to $dest"
echo "Open the status window with: $dest/extension-guard-status"
