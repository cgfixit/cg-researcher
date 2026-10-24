#!/usr/bin/env bash
# cg-agent installer (macOS / Linux). Builds from source with --locked,
# installs to ~/.cg-agent/bin, runs `cg-agent init`. Never uses sudo.
#   --with-netviewer   macOS: build CyClaw-Net-Viewer at a pinned commit
#   --service          install a launchd agent (macOS) / systemd user unit (Linux)
set -euo pipefail
umask 077

NETVIEWER_REPO="https://github.com/cgfixit/CyClaw-Net-Viewer.git"
NETVIEWER_COMMIT="30871d83d37e2450516f5d689ad2e9d6a8e15045"
NETVIEWER_TOOLCHAIN="1.85.0"

with_netviewer=0
service=0
for a in "$@"; do
  case "$a" in
    --with-netviewer) with_netviewer=1 ;;
    --service) service=1 ;;
    -h|--help) sed -n '2,6p' "$0"; exit 0 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CG_HOME="${CG_HOME:-$HOME/.cg-agent}"
bin_dir="$CG_HOME/bin"
os="$(uname -s)"

command -v cargo >/dev/null 2>&1 || { echo "cargo not found: install rustup from https://rustup.rs" >&2; exit 1; }

echo "==> building cg-agent (release, --locked)"
( cd "$repo" && cargo build --release --locked -p cg-agent )
mkdir -p "$bin_dir"
chmod 700 "$CG_HOME" "$bin_dir"
install -m 0755 "$repo/target/release/cg-agent" "$bin_dir/cg-agent"
"$bin_dir/cg-agent" --home "$CG_HOME" init

if [[ "$with_netviewer" == 1 ]]; then
  if [[ "$os" != "Darwin" ]]; then
    echo "==> skipping CyClaw-Net-Viewer (macOS only)"
  else
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
fi

if [[ "$service" == 1 ]]; then
  if [[ "$os" == "Darwin" ]]; then
    plist="$HOME/Library/LaunchAgents/com.cgfixit.cg-agent.plist"
    mkdir -p "$(dirname "$plist")"
    cat > "$plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.cgfixit.cg-agent</string>
  <key>ProgramArguments</key><array>
    <string>$bin_dir/cg-agent</string><string>--home</string><string>$CG_HOME</string><string>serve</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ThrottleInterval</key><integer>30</integer>
  <key>StandardErrorPath</key><string>$CG_HOME/logs/serve.stderr.log</string>
  <key>StandardOutPath</key><string>/dev/null</string>
  <key>ProcessType</key><string>Background</string>
</dict></plist>
PLIST
    chmod 600 "$plist"
    launchctl bootout "gui/$(id -u)/com.cgfixit.cg-agent" 2>/dev/null || true
    launchctl bootstrap "gui/$(id -u)" "$plist"
    echo "==> launchd agent loaded (com.cgfixit.cg-agent)"
  else
    unit="$HOME/.config/systemd/user/cg-agent.service"
    mkdir -p "$(dirname "$unit")"
    cat > "$unit" <<UNIT
[Unit]
Description=cg-agent (loopback API + gateways)
After=network-online.target

[Service]
ExecStart=$bin_dir/cg-agent --home $CG_HOME serve
Restart=on-failure
RestartSec=30
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$CG_HOME
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LockPersonality=yes
UMask=0077

[Install]
WantedBy=default.target
UNIT
    systemctl --user daemon-reload
    systemctl --user enable --now cg-agent.service
    echo "==> systemd user unit enabled (cg-agent.service)"
  fi
fi

cat <<MSG

cg-agent installed: $bin_dir/cg-agent
  config   $CG_HOME/cg.toml   (all connectors ship disabled)
  corpus   $CG_HOME/corpus    then: cg-agent index
  chat     $bin_dir/cg-agent chat
  check    $bin_dir/cg-agent selftest
Add to PATH:  export PATH="$bin_dir:\$PATH"
MSG
