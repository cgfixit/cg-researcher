---
name: verify
description: Run the cg-researcher local gate (fmt, clippy -D warnings, shellcheck, deny, selftest) before committing or opening a PR. Use after any code, script or workflow change, or when asked to check, lint or validate the repo.
---

# verify

Lint first, then exercise the real binary. Run the full test suite only when asked, or when a change touches logic the lints cannot judge (CI runs it on every PR anyway).

1. The lint gate, which is exactly what CI's `lint` job runs on an Apple Silicon runner:
   ```bash
   scripts/lint.sh            # hygiene, cargo fmt, clippy -D warnings, shellcheck, actionlint, zizmor, plutil (macOS)
   scripts/lint.sh --fast     # same without clippy, while iterating
   ```
   `unwrap_used` warns and CI uses `-D warnings`, so no `unwrap()` outside tests. Read the `skip:` lines: on a machine without `shellcheck` or `actionlint` the script still exits 0, and a skipped linter is an unverified step, not a pass (`brew install shellcheck actionlint zizmor` on a Mac). Under `CI=1` a missing linter is a hard failure.
2. Scripts and workflows, if any `*.sh`, `*.command` or `.github/workflows/*.yml` changed: step 1 covers them when the linters are present. Without them, at least `bash -n` every touched script and `./scripts/install.sh --print-plist | plutil -lint -` on a Mac.
3. Dependencies, if any `Cargo.toml`, `Cargo.lock` or `deny.toml` changed, exactly as `audit.yml` runs it:
   ```bash
   cargo metadata --format-version 1 --locked >/dev/null   # the lock still matches the manifests
   cargo deny check advisories bans licenses sources        # `bans` enforces the no-telemetry rule I2
   ```
   Versions live once, in `[workspace.dependencies]` in the root `Cargo.toml`; a crate manifest only says `name.workspace = true` plus its own `features`. A missing `cargo-deny` binary is a missing check, not a pass: `cargo install cargo-deny --locked` first. Never add an advisory ignore to silence a finding a bump introduced; fix the version. `fuzz/` has its own lock (not a workspace member, nightly only); keep its versions equal to the workspace lock.
4. Run it, in a throwaway home so `~/.cg-researcher` is untouched:
   ```bash
   H="$(mktemp -d)"; cargo run -q -p cg-researcher -- --home "$H" init && cargo run -q -p cg-researcher -- --home "$H" selftest && cargo run -q -p cg-researcher -- --home "$H" audit verify
   ```
   For UI changes also start the mock model (`cargo run -p cg-researcher --example mock_llm`) and `serve --no-gateways`, as `e2e/start-server.sh` does.
5. Report what ran and what did not, with exit codes. Never pipe a pass/fail command into `grep` or `tail` without checking its own exit status. Nothing here exercises Keychain, launchd or the installer on a Mac, so say so when a change touches them.

Related: `run-cg-researcher` for a full mock-model run with `serve` and the UI; `invariants-check` and `config-guard` when the diff touches a gate, the audit log, the sanitizer, the HTTP guard or `config/cg.toml`.
