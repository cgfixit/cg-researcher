---
name: verify
description: Run the cg-researcher local gate (fmt, clippy -D warnings, shellcheck, deny, selftest) before committing or opening a PR. Use after any code, script or workflow change, or when asked to check, lint or validate the repo.
---

# verify

Lint first, then exercise the real binary. Run the full test suite only when asked, or when a change touches logic the lints cannot judge (CI runs it on every PR anyway).

1. Format and lint, exactly as CI does:
   ```bash
   cargo fmt --all --check
   cargo clippy --workspace --all-targets --locked -- -D warnings
   ```
   `unwrap_used` warns and CI uses `-D warnings`, so no `unwrap()` outside tests.
2. Scripts, if any `*.sh` or `*.command` changed (CI shellchecks `scripts/*.sh e2e/*.sh install.command uninstall.command init.sh`):
   ```bash
   shellcheck scripts/*.sh e2e/*.sh install.command uninstall.command init.sh
   bash -n scripts/install.sh && ./scripts/install.sh --print-plist | plutil -lint -   # plutil is macOS only
   ```
3. Dependencies, if any `Cargo.toml` or `Cargo.lock` changed: `cargo deny check` (the `bans` section enforces the no-telemetry rule I2) and keep `--locked` working.
4. Run it, in a throwaway home so `~/.cg-researcher` is untouched:
   ```bash
   H="$(mktemp -d)"; cargo run -q -p cg-researcher -- --home "$H" init && cargo run -q -p cg-researcher -- --home "$H" selftest && cargo run -q -p cg-researcher -- --home "$H" audit verify
   ```
   For UI changes also start the mock model (`cargo run -p cg-researcher --example mock_llm`) and `serve --no-gateways`, as `e2e/start-server.sh` does.
5. Report what ran and what did not. Nothing here exercises Keychain, launchd or the installer on a Mac, so say so when a change touches them.
