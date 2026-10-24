#!/usr/bin/env bash
# cg-researcher uninstaller (macOS). Removes the launchd agent + binaries. Data (config, secrets,
# corpus, audit log) is kept unless --purge is given.
#   --purge   also delete ~/.cg-researcher and cg-researcher Keychain items (asks; --yes skips)
set -euo pipefail
purge=0; yes=0
for a in "$@"; do
  case "$a" in
    --purge) purge=1 ;;
    --yes) yes=1 ;;
    -h|--help) sed -n '2,5p' "$0"; exit 0 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done
CG_HOME="${CG_HOME:-$HOME/.cg-researcher}"

[[ "$(uname -s)" == "Darwin" ]] || { echo "cg-researcher's uninstaller targets macOS" >&2; exit 1; }
# Resolve aliases before removing even the binaries or launchd jobs.
if [[ -d "$CG_HOME" ]]; then
  CG_HOME="$(CDPATH='' cd -P -- "$CG_HOME" && pwd -P)"
  user_home="$(CDPATH='' cd -P -- "$HOME" && pwd -P)"
  case "$CG_HOME" in /) echo "refusing to uninstall from /" >&2; exit 1 ;; esac
  case "$user_home/" in
    "$CG_HOME/"*) echo "refusing to uninstall from home or its ancestor: $CG_HOME" >&2; exit 1 ;;
  esac
fi
LABEL="com.cgfixit.cg-researcher"
for l in com.cgfixit.cg-agent com.cgfixit.cg-agent.maintenance "$LABEL" "$LABEL.maintenance"; do
  launchctl bootout "gui/$(id -u)/$l" 2>/dev/null || true
  rm -f "$HOME/Library/LaunchAgents/$l.plist"
done
rm -rf "$HOME/Applications/CyClaw-Net-Viewer.app"
rm -f "$CG_HOME/bin/cg-researcher" "$CG_HOME/bin/netboard"
rmdir "$CG_HOME/bin" 2>/dev/null || true
echo "removed service and binaries"

if [[ "$purge" == 1 ]]; then
  [[ -d "$CG_HOME" ]] || { echo "nothing to purge"; exit 0; }
  if [[ "$yes" != 1 ]]; then
    read -r -p "Delete $CG_HOME and Keychain items (config, secrets, corpus, audit log)? type 'delete': " ans
    [[ "$ans" == "delete" ]] || { echo "kept $CG_HOME"; exit 0; }
  fi
  # Keychain items cg-researcher minted (service "cg-researcher"); delete-generic-password
  # takes no secret on argv. Bounded loop until none remain.
  for _ in $(seq 1 100); do security delete-generic-password -s cg-researcher >/dev/null 2>&1 || break; done
  # legacy service name from before the rename
  for _ in $(seq 1 100); do security delete-generic-password -s cg-agent >/dev/null 2>&1 || break; done
  rm -rf -- "$CG_HOME"
  echo "purged $CG_HOME"
else
  echo "kept data in $CG_HOME (use --purge to delete)"
fi
