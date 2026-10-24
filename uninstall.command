#!/usr/bin/env bash
# Double-click uninstaller for macOS Finder (keeps data; run scripts/uninstall.sh --purge to delete it).
set -euo pipefail
cd "$(dirname "$0")"
./scripts/uninstall.sh "$@" || status=$?
echo; read -r -p "Press Return to close." _
exit "${status:-0}"
