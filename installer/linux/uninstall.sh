#!/usr/bin/env bash
#
# Removes Extension Guard on Linux. uninstall-service prompts for the uninstall
# password, stops + removes the systemd unit, and lifts the browser lock.
#
# Run:  sudo installer/linux/uninstall.sh
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "This uninstaller must run as root. Try: sudo $0" >&2
  exit 1
fi

dest=/opt/extension-guard
if [ ! -x "$dest/guard" ]; then
  echo "Extension Guard does not appear to be installed at $dest." >&2
  exit 1
fi

"$dest/guard" -config "$dest/extension-ids.json" uninstall-service
rm -rf "$dest"
echo "Uninstalled."
