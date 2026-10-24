#!/usr/bin/env bash
# Double-click installer for macOS Finder.
set -euo pipefail
cd "$(dirname "$0")"
./scripts/install.sh --with-netviewer "$@" || status=$?
echo; read -r -p "Press Return to close." _
exit "${status:-0}"
