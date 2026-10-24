#!/usr/bin/env bash
# cg-agent uninstaller. Removes service + binaries. Data (config, secrets,
# corpus, audit log) is kept unless --purge is given.
#   --purge   also delete ~/.cg-agent (asks for confirmation; --yes skips)
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

if [[ "$(uname -s)" == "Darwin" ]]; then
  launchctl bootout "gui/$(id -u)/com.cgfixit.cg-agent" 2>/dev/null || true
  rm -f "$HOME/Library/LaunchAgents/com.cgfixit.cg-agent.plist"
  rm -rf "$HOME/Applications/CyClaw-Net-Viewer.app"
  # Keychain items written by `cg-agent google-auth`
  security delete-generic-password -s cg-agent -a google_refresh_token >/dev/null 2>&1 || true
else
  if command -v systemctl >/dev/null 2>&1; then
    systemctl --user disable --now cg-agent.service 2>/dev/null || true
    rm -f "$HOME/.config/systemd/user/cg-agent.service"
    systemctl --user daemon-reload 2>/dev/null || true
  fi
fi
rm -f "$CG_HOME/bin/cg-agent" "$CG_HOME/bin/netboard"
rmdir "$CG_HOME/bin" 2>/dev/null || true
echo "removed service and binaries"

if [[ "$purge" == 1 ]]; then
  [[ -d "$CG_HOME" ]] || { echo "nothing to purge"; exit 0; }
  case "$CG_HOME" in /|"$HOME"|"") echo "refusing to purge $CG_HOME" >&2; exit 1 ;; esac
  if [[ "$yes" != 1 ]]; then
    read -r -p "Delete $CG_HOME (config, secrets, corpus, audit log)? type 'delete': " ans
    [[ "$ans" == "delete" ]] || { echo "kept $CG_HOME"; exit 0; }
  fi
  rm -rf -- "$CG_HOME"
  echo "purged $CG_HOME"
else
  echo "kept data in $CG_HOME (use --purge to delete)"
fi
