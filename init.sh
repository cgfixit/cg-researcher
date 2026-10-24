#!/usr/bin/env bash
# Developer bootstrap: pinned toolchain, locked deps, full local gate
# (fmt, clippy -D warnings, tests), then `cg-researcher init` into $CG_HOME.
set -euo pipefail
cd "$(dirname "$0")"
command -v rustup >/dev/null 2>&1 || { echo "install rustup: https://rustup.rs" >&2; exit 1; }
rustup show active-toolchain >/dev/null   # installs the channel from rust-toolchain.toml
cargo fetch --locked
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo run --locked -q -p cg-researcher -- init
echo "ok. next: cargo run -p cg-researcher -- selftest"
