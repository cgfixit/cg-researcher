#!/usr/bin/env bash
# cg-agent installer for macOS 14+ (Apple Silicon or Intel). Builds from source
# with --locked, ad-hoc code-signs with the hardened runtime, installs to
# ~/.cg-agent/bin and runs `cg-agent init`. Never uses sudo.
#   --with-netviewer   also build CyClaw-Net-Viewer at a pinned commit
#   --service          install + load a per-user launchd agent (com.cgfixit.cg-agent)
#   --maintenance      install a daily 03:15 launchd job running `cg-agent maintain`
#   --print-plist      print the service plist and exit (used by CI to lint it)
#   --print-maintenance-plist  print the maintenance plist and exit
set -euo pipefail
umask 077

LABEL="com.cgfixit.cg-agent"
MLABEL="com.cgfixit.cg-agent.maintenance"
NETVIEWER_REPO="https://github.com/cgfixit/CyClaw-Net-Viewer.git"
NETVIEWER_COMMIT="30871d83d37e2450516f5d689ad2e9d6a8e15045"
NETVIEWER_TOOLCHAIN="1.85.0"

with_netviewer=0
service=0
maintenance=0
print_plist=0
print_mplist=0
for a in "$@"; do
  case "$a" in
    --with-netviewer) with_netviewer=1 ;;
    --service) service=1 ;;
    --maintenance) maintenance=1 ;;
    --print-plist) print_plist=1 ;;
    --print-maintenance-plist) print_mplist=1 ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CG_HOME="${CG_HOME:-$HOME/.cg-agent}"
bin_dir="$CG_HOME/bin"
plist="$HOME/Library/LaunchAgents/$LABEL.plist"
mplist="$HOME/Library/LaunchAgents/$MLABEL.plist"

xml_escape() { local s="$1"; s="${s//&/&amp;}"; s="${s//</&lt;}"; s="${s//>/&gt;}"; printf '%s' "$s"; }

render_plist() {
  local b h
  b="$(xml_escape "$bin_dir/cg-agent")"
  h="$(xml_escape "$CG_HOME")"
  cat <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array><string>$b</string><string>--home</string><string>$h</string><string>serve</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ThrottleInterval</key><integer>30</integer>
  <key>ProcessType</key><string>Background</string>
  <key>LimitLoadToSessionType</key><string>Aqua</string>
  <key>Umask</key><integer>63</integer>
  <key>EnvironmentVariables</key>
  <dict><key>PATH</key><string>/usr/bin:/bin:/usr/sbin:/sbin</string></dict>
  <key>StandardOutPath</key><string>/dev/null</string>
  <key>StandardErrorPath</key><string>$h/logs/serve.stderr.log</string>
</dict>
</plist>
PLIST
}

# Daily health check. launchd's StartCalendarInterval also fires a missed run
# after wake, unlike cron, which is why this is launchd and not crontab.
render_maintenance_plist() {
  local b h
  b="$(xml_escape "$bin_dir/cg-agent")"
  h="$(xml_escape "$CG_HOME")"
  cat <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$MLABEL</string>
  <key>ProgramArguments</key>
  <array><string>$b</string><string>--home</string><string>$h</string><string>maintain</string></array>
  <key>StartCalendarInterval</key>
  <dict><key>Hour</key><integer>3</integer><key>Minute</key><integer>15</integer></dict>
  <key>RunAtLoad</key><false/>
  <key>ProcessType</key><string>Background</string>
  <key>LowPriorityIO</key><true/>
  <key>Nice</key><integer>10</integer>
  <key>Umask</key><integer>63</integer>
  <key>EnvironmentVariables</key>
  <dict><key>PATH</key><string>/usr/bin:/bin:/usr/sbin:/sbin</string></dict>
  <key>StandardOutPath</key><string>$h/logs/maintenance.log</string>
  <key>StandardErrorPath</key><string>$h/logs/maintenance.log</string>
</dict>
</plist>
PLIST
}

load_agent() { # label plist-path renderer
  local label="$1" path="$2" renderer="$3"
  mkdir -p "$(dirname "$path")"
  "$renderer" > "$path.tmp"
  plutil -lint -s "$path.tmp"
  chmod 600 "$path.tmp"
  mv -f "$path.tmp" "$path"
  launchctl bootout "gui/$(id -u)/$label" 2>/dev/null || true
  launchctl bootstrap "gui/$(id -u)" "$path"
  launchctl print "gui/$(id -u)/$label" >/dev/null
}

if [[ "$print_plist" == 1 ]]; then render_plist; exit 0; fi
if [[ "$print_mplist" == 1 ]]; then render_maintenance_plist; exit 0; fi

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "cg-agent targets macOS. On other systems build manually: cargo build --release --locked -p cg-agent" >&2
  exit 1
fi
major="$(sw_vers -productVersion | cut -d. -f1)"
if (( major < 14 )); then echo "macOS 14 (Sonoma) or newer required; found $(sw_vers -productVersion)" >&2; exit 1; fi
xcode-select -p >/dev/null 2>&1 || { echo "Xcode Command Line Tools required: xcode-select --install" >&2; exit 1; }
command -v cargo >/dev/null 2>&1 || { echo "cargo not found: install rustup from https://rustup.rs" >&2; exit 1; }

echo "==> building cg-agent for $(uname -m) (release, --locked)"
( cd "$repo" && cargo build --release --locked -p cg-agent )
mkdir -p "$bin_dir" "$CG_HOME/logs"
chmod 700 "$CG_HOME" "$bin_dir" "$CG_HOME/logs"
install -m 0755 "$repo/target/release/cg-agent" "$bin_dir/cg-agent"
# Ad-hoc signature + hardened runtime: stable enough for Gatekeeper/AMFI on the
# building Mac, but NOT a Developer ID. Each rebuild changes the code identity,
# so Keychain items show a one-time "Always Allow" prompt after upgrades.
codesign --force --sign - --options runtime --identifier "$LABEL" "$bin_dir/cg-agent"
codesign --verify --strict "$bin_dir/cg-agent"
"$bin_dir/cg-agent" --home "$CG_HOME" init

if [[ "$with_netviewer" == 1 ]]; then
  command -v rustup >/dev/null 2>&1 || { echo "rustup required for Net-Viewer's pinned toolchain" >&2; exit 1; }
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' EXIT
  echo "==> CyClaw-Net-Viewer @ ${NETVIEWER_COMMIT:0:12}"
  git -c advice.detachedHead=false clone --quiet --filter=blob:none "$NETVIEWER_REPO" "$work/nv"
  git -C "$work/nv" -c advice.detachedHead=false checkout --quiet "$NETVIEWER_COMMIT"
  got="$(git -C "$work/nv" rev-parse HEAD)"
  [[ "$got" == "$NETVIEWER_COMMIT" ]] || { echo "pinned commit mismatch: $got" >&2; exit 1; }
  rustup toolchain install "$NETVIEWER_TOOLCHAIN" --profile minimal >/dev/null
  ( cd "$work/nv" && cargo "+$NETVIEWER_TOOLCHAIN" build --release --locked )
  install -m 0755 "$work/nv/target/release/netboard" "$bin_dir/netboard"
  codesign --force --sign - --options runtime "$bin_dir/netboard"
  if [[ -x "$work/nv/scripts/make-app.sh" ]]; then
    ( cd "$work/nv" && ./scripts/make-app.sh ) && {
      mkdir -p "$HOME/Applications"
      rm -rf "$HOME/Applications/CyClaw-Net-Viewer.app"
      cp -R "$work/nv/dist/CyClaw-Net-Viewer.app" "$HOME/Applications/"
      echo "    installed ~/Applications/CyClaw-Net-Viewer.app"
    }
  fi
  echo "    netboard CLI: $bin_dir/netboard  (enable connectors.netconnect.include_connections to expose it as a tool)"
fi

if [[ "$service" == 1 ]]; then
  load_agent "$LABEL" "$plist" render_plist
  echo "==> launchd agent loaded ($LABEL); logs: $CG_HOME/logs/serve.stderr.log"
fi
if [[ "$maintenance" == 1 ]]; then
  load_agent "$MLABEL" "$mplist" render_maintenance_plist
  echo "==> daily maintenance at 03:15 ($MLABEL); log: $CG_HOME/logs/maintenance.log"
fi

cat <<MSG

cg-agent installed: $bin_dir/cg-agent
  config   $CG_HOME/cg.toml   (all connectors ship disabled)
  corpus   $CG_HOME/corpus    then: cg-agent index
  chat     $bin_dir/cg-agent chat
  check    $bin_dir/cg-agent selftest
  web UI   $bin_dir/cg-agent ui        (with \`cg-agent serve\` or --service running)
Add to PATH:  export PATH="$bin_dir:\$PATH"
MSG
