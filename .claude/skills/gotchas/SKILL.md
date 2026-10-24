---
name: gotchas
description: Session-tested traps for working on cg-researcher - things that hang, fail for the wrong reason, or look green for the wrong reason. Load before installing, verifying, running the mock model, touching CI or release workflows, bumping dependencies, or when a check passes suspiciously fast.
---

# gotchas

Only what `CLAUDE.md` and `INVARIANTS.md` do not already say: the "looks green for the wrong reason" list. Every entry names the symptom, the wrong fix, the right fix and where the evidence is. Add an entry only for something that was actually hit; speculation goes nowhere.

## 1. A Rosetta shell builds an x86_64 binary on an Apple Silicon Mac

- **Symptom:** `install.sh` or `cargo build` succeeds, `rustc -vV` says `host: x86_64-apple-darwin`, the binary runs under Rosetta, and on macOS 27 it would not run at all.
- **Wrong fix:** `--target aarch64-apple-darwin` on the command line and move on; the next `cargo` call forgets it.
- **Right fix:** `install.sh` refuses when `sysctl.proc_translated` is 1; re-run from a native shell (`arch -arm64 zsh`) and use a native arm64 rustup. Check `rustc -vV` before trusting any Mac build.
- **Evidence:** the Rosetta guard in `scripts/install.sh`; README prerequisites.

## 2. Homebrew `rust` ignores `rust-toolchain.toml`

- **Symptom:** clippy or the build fails on edition 2024 or on a lint that 1.99.1 knows, or `init.sh` exits with "install rustup".
- **Wrong fix:** Relax the edition, lower `rust-version`, or add `#[allow]`.
- **Right fix:** Only rustup honors the pin. `install.sh` refuses `rustc` older than 1.90; `brew uninstall rust` and install rustup, then `rustup show active-toolchain` installs 1.99.1 automatically.
- **Evidence:** the Rust-version guard in `scripts/install.sh`; `init.sh`.

## 3. Port 11434 is Ollama's port, and the mock uses it

- **Symptom:** `run-cg-researcher` or the Playwright suite "passes" with real, non-deterministic answers, or the mock fails to bind, or the suite times out on `webServer`.
- **Wrong fix:** Raise the timeout, or point tests at the real Ollama.
- **Right fix:** Stop Ollama (or LM Studio on 1234) before running the mock; `reuseExistingServer` is deliberately `false` in `e2e/playwright.config.mjs`, so an existing listener is an error, not a convenience. Same for `serve` on 8797: a `/health` that answers before you started anything is someone else's process, possibly the launchd agent.
- **Evidence:** `e2e/playwright.config.mjs`, `e2e/start-server.sh`, `crates/cg-researcher/examples/mock_llm.rs`.

## 4. A check that fails in two seconds with `runner_id: 0` did not run

- **Symptom:** Every check on a PR fails within the same two seconds of being created, the job shows `runner_id: 0`, and the log download returns 404. Nothing ran; that is an account-level Actions block (billing or a disabled workflow), not thirteen simultaneous real failures. This happened to this account once; the macOS matrix has run green on `main` since (see the ci.yml run list).
- **Wrong fix:** Assume green, start "fixing" the red checks, or claim the installer and Keychain code are CI-verified from the YAML alone.
- **Right fix:** Read the run, not the badge. Anything in `install.sh`, `keychain.rs`, the launchd plists, `bundle-app.sh` or `packaging/` is unverified until a Mac or the macOS runner has actually executed it on your commit. Linux verification does not transfer, and `install-smoke` runs on push and schedule only, never on a PR.
- **Evidence:** README "Status"; `CLAUDE.md` installer note; `ci.yml` `install-smoke` `if:`.

## 5. `macos-latest` is not macOS 27

- **Symptom:** Someone reads the CI matrix as covering Golden Gate.
- **Wrong fix:** Add a `macos-27` runner label that does not exist; the job queues forever.
- **Right fix:** `macos-latest` is macOS 26 arm64 today and moves to 27 only when GitHub flips the label. The matrix comment in `ci.yml` says so; keep it accurate when the label moves.
- **Evidence:** `.github/workflows/ci.yml` matrix comment; `actions/runner-images`.

## 6. The Intel tarball has a sunset date, not a removal

- **Symptom:** The `universal` release job prints a warning about the Intel sunset and someone deletes the job early, or ignores it after the date.
- **Right fix:** The warning fires from `INTEL_SUNSET` in `release.yml` (read the date there). Before that date, leave the job; after it, remove the `universal` job and the README line about the universal tarball in one change.
- **Evidence:** `.github/workflows/release.yml`, step "Intel artifact sunset check".

## 7. `cargo metadata --locked` prints the whole graph on success

- **Symptom:** A verification command that chains `cargo metadata ... || cargo metadata ...` floods the terminal with a megabyte of JSON and the real result is lost.
- **Right fix:** `cargo metadata --format-version 1 --locked >/dev/null && echo LOCK-OK`. Check the exit status, never grep the output for a pass.
- **Evidence:** `verify` skill step 3.

## 8. `cargo deny` is not installed by default, and a missing checker is not a pass

- **Symptom:** `cargo deny check` prints "no such command" and a pipeline that ends in `| tail` reports exit 0.
- **Wrong fix:** Skip it because CI will run it.
- **Right fix:** `cargo install cargo-deny --locked`, then run the exact CI command `cargo deny check advisories bans licenses sources`. The `multiple-versions = "warn"` tree it prints is noise; the last line is the verdict.
- **Evidence:** `.github/workflows/audit.yml`; `deny.toml`.

## 9. Dependency versions are declared once

- **Symptom:** A bump in one crate's `Cargo.toml` does not build, or `cargo metadata --locked` fails with "lock file needs to be updated".
- **Wrong fix:** Add a version to the crate manifest, or hand-edit `Cargo.lock`.
- **Right fix:** Versions live only in `[workspace.dependencies]` in the root `Cargo.toml`; crates say `name.workspace = true` and add features. After a deliberate bump, `cargo update -p <crate>` regenerates the lock; then `cargo deny`, and keep `fuzz/Cargo.lock` on the same versions.
- **Evidence:** root `Cargo.toml`; `verify` skill step 3.

## 9b. `rust-toolchain.toml` wins over the nightly you installed for fuzzing

- **Symptom:** In CI, `cargo fuzz` fails with "the option `Z` is only accepted on the nightly compiler" even though the job installed a nightly.
- **Wrong fix:** Remove the stable pin, or run `rustup default nightly` on the runner.
- **Right fix:** The pin applies to every `cargo` invocation in the tree; rustup picks it over the installed nightly. `fuzz.yml` sets `RUSTUP_TOOLCHAIN` to its pinned nightly as a job env (read the date there, not here). Locally, `cargo +nightly fuzz run <target>` does the same per command.
- **Evidence:** `.github/workflows/fuzz.yml` job env .

## 9c. `scripts/lint.sh` exits 0 with linters missing, except under `CI`

- **Symptom:** "lint: ok" on a box without `shellcheck` or `actionlint`; the same tree fails CI's `lint` job.
- **Right fix:** Read the `skip:` lines. A skipped linter is unverified, not passed. `brew install shellcheck actionlint zizmor` on a Mac; the sandbox has none of them.
- **Evidence:** `need()` in `scripts/lint.sh`; `.github/workflows/lint.yml` installs sha256-verified arm64 binaries.

## 10. Test counts go stale the moment they are written down

- **Symptom:** A doc quotes a test count that no longer matches; the Keychain test is `#[ignore]` off macOS and is only counted when run with `-- --ignored` on a Mac, and two more tests are `cfg`-gated.
- **Right fix:** Quote the numbers from the `cargo test --workspace --locked` output (`passed`, `ignored`) of the run you are describing, and name the commit; never carry a number forward. The Playwright suite is nine specs (`e2e/ui.spec.mjs` six, `e2e/stream.spec.mjs` three) in two browsers, so "18" is a run count, not a spec count.
- **Evidence:** `cargo test` summary lines; `grep -c '^test(' e2e/*.spec.mjs`.

## 11. Branch names and the default branch

- **Symptom:** `git fetch origin main` says "couldn't find remote ref", or a local branch literally named `origin/main` shadows the remote-tracking ref and every `git` command does something surprising.
- **Right fix:** The default branch is `main` now (it was `cg/main`). Never create a local branch whose name starts with `origin/`. After the remote is repaired, `git fetch --prune` and re-track. Push human branches as `cg/<topic>`; agent sessions use their driver prefix (`claude/`, `codex/`, ...) per `.github/PULL_REQUEST_TEMPLATE.md`.
- **Evidence:** `CLAUDE.md` default-branch line; `.github/workflows/*.yml` `branches: ["main"]`.

## 12. GitHub rejects pushes with a private email

- **Symptom:** `push declined due to email privacy restrictions`.
- **Right fix:** Author and commit with the noreply identity the existing history uses (`git log -1 --format='%an <%ae>'`), not a real mailbox. Do not disable the privacy setting to make a push work.

## 13. Never comment `@codex review` without the operator's approval

- **Symptom:** A push does not re-trigger the external review; the fixes to review findings are the diffs most worth a second look and go unreviewed.
- **Right fix:** Tell the operator the fixes are unreviewed and let them decide. The rule is in `CLAUDE.md` and is not negotiable from inside a session.

## Related skills

`verify` for the local gate; `run-cg-researcher` before claiming a change works; `invariants-check` and `config-guard` for gate, audit, sanitizer, HTTP guard and config diffs. None of them is push or merge authorization.
