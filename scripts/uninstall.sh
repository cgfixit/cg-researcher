#!/usr/bin/env bash
# cg-agent uninstaller (macOS). Removes the launchd agent + binaries. Data (config, secrets,
# corpus, audit log) is kept unless --purge is given.
#   --purge   also delete ~/.cg-agent and cg-agent Keychain items (asks; --yes skips)
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
CG_HOME="${CG_HOME:-$HOME/.cg-agent}"

[[ "$(uname -s)" == "Darwin" ]] || { echo "cg-agent's uninstaller targets macOS" >&2; exit 1; }
LABEL="com.cgfixit.cg-agent"
for l in "$LABEL" "$LABEL.maintenance"; do
  launchctl bootout "gui/$(id -u)/$l" 2>/dev/null || true
  rm -f "$HOME/Library/LaunchAgents/$l.plist"
done
rm -rf "$HOME/Applications/CyClaw-Net-Viewer.app"
rm -f "$CG_HOME/bin/cg-agent" "$CG_HOME/bin/netboard"
rmdir "$CG_HOME/bin" 2>/dev/null || true
echo "removed service and binaries"

if [[ "$purge" == 1 ]]; then
  [[ -d "$CG_HOME" ]] || { echo "nothing to purge"; exit 0; }
  case "$CG_HOME" in /|"$HOME"|"") echo "refusing to purge $CG_HOME" >&2; exit 1 ;; esac
  if [[ "$yes" != 1 ]]; then
    read -r -p "Delete $CG_HOME and Keychain items (config, secrets, corpus, audit log)? type 'delete': " ans
    [[ "$ans" == "delete" ]] || { echo "kept $CG_HOME"; exit 0; }
  fi
  # Keychain items cg-agent minted (service "cg-agent"); delete-generic-password
  # takes no secret on argv. Bounded loop until none remain.
  for _ in $(seq 1 100); do security delete-generic-password -s cg-agent >/dev/null 2>&1 || break; done
  rm -rf -- "$CG_HOME"
  echo "purged $CG_HOME"
else
  echo "kept data in $CG_HOME (use --purge to delete)"
fi
