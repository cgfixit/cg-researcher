# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`cg-researcher` (formerly `cg-agent`): a local-first research assistant in Rust. RAG over a notes corpus, a loopback OpenAI-compatible model (Ollama / LM Studio / llama.cpp / vLLM), and an optional, triple-gated external model (Claude / Grok). The product target is Apple Silicon (arm64) on macOS 14+, including macOS 27 "Golden Gate" (Apple silicon only, last release with Rosetta). CI covers macOS 15 and `macos-latest` (macOS 26 today; it becomes 27 when GitHub flips the label). Intel is best-effort and only on macOS 26 or older. Linux builds and passes tests but is best-effort (no Keychain, no launchd, installer refuses to run).

The default branch is `main`. CI, Dependabot and the workflows in `.github/` target it.

## Commands

Toolchain is pinned in `rust-toolchain.toml` (1.99.1, edition 2024); rustup installs it automatically.

```bash
./init.sh                                   # full local gate + `cg-researcher init` into $CG_HOME
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo test -p cg-core --locked <name>       # single test (substring match), e.g. `agent::tests::topology_`
cargo test -p cg-core --locked keychain -- --ignored   # Keychain test (macOS only, needs a throwaway keychain)
cargo run -p cg-researcher -- selftest      # runtime self-check; also: chat, serve, index, audit verify, maintain
cargo deny check bans                       # enforces the no-telemetry dependency bans (deny.toml)
cargo llvm-cov --workspace --locked --summary-only --fail-under-lines 70   # CI coverage floor
```

- The data dir is `$CG_HOME` or `~/.cg-researcher`; override per invocation with `--home <dir>` (use a throwaway dir when experimenting).
- Fuzzing (`fuzz/`, nightly + `cargo-fuzz`): targets `attachments` and `sanitizer`.
- Browser e2e (`e2e/`, Playwright Chromium + WebKit): needs the mock model (`cargo run -p cg-researcher --example mock_llm`, listens on 127.0.0.1:11434), then `cd e2e && npm ci --ignore-scripts && npx playwright test`. `e2e/start-server.sh` builds a throwaway home and runs `serve --no-gateways`.
- Shell scripts are shellchecked in CI (`scripts/*.sh e2e/*.sh *.command init.sh`).

## How to verify work here

Lint first, then run the real binary. Reach for the test suite last.

1. **Lint, always**: `scripts/lint.sh` (add `--fast` to skip clippy while iterating). It is written for macOS (bash 3.2, BSD userland) and is what CI's `lint` job runs on an Apple Silicon runner, so a clean local run predicts a clean CI run. It covers repo hygiene (below), `cargo fmt`, `clippy -D warnings`, `shellcheck`, `actionlint`, `zizmor` when installed, and `plutil` on macOS. Install the linters once with `brew install shellcheck actionlint zizmor`. Any change under `.github/` or to a shell script gets `actionlint` and `shellcheck` before it is committed, not after CI fails.
2. **Run the code instead of the test suite** while developing: build and exercise the binary against a throwaway home, and watch what it actually does.
   ```bash
   H="$(mktemp -d)"
   cargo run -q -p cg-researcher -- --home "$H" init
   cargo run -q -p cg-researcher -- --home "$H" selftest
   cargo run -q -p cg-researcher -- --home "$H" audit verify
   # UI / server work: `cargo run -p cg-researcher --example mock_llm` in one shell, then
   # cargo run -q -p cg-researcher -- --home "$H" serve --no-gateways   and curl / open the UI
   ```
   Prefer a `cargo run` or a short script that reproduces the behavior over writing or running a test for it. Run `cargo test` only when asked, when a change touches logic the lints and a live run cannot judge (graph routing, gates, sanitizer, audit chain), or just before opening a PR. CI runs the full suite on macOS on every PR anyway.
3. **macOS is the target**. Anything written to run locally (scripts, Makefile-style helpers, CI steps that mirror local commands) must work on a stock Mac: `/bin/bash` 3.2 (no associative arrays, `mapfile`, `${var,,}`), BSD `sed`/`stat`/`date`, `shasum -a 256` not `sha256sum`. Keychain, launchd and the installer can only be exercised on a Mac or the macOS CI jobs; say so when a change touches them and the sandbox is Linux.

## Repo hygiene (privacy)

Nothing from a data directory ever enters git. `scripts/lint.sh --hygiene` enforces this and CI runs it on every push; `.gitignore` carries the patterns.

- Never track: a `--home` or `~/.cg-researcher` / `.cg-agent` tree or its parts (`secrets/`, `logs/`, `state/`, `corpus/`, `index/`, `ui-settings.toml`, `*.pb`, `*.sqlite3`), any log file, key material or encrypted blobs (`*.key`, `*.enc`, `*.pem`, `*.p12`, `*.gpg`, `*.keychain-db`, `*.mobileprovision`), `.env*` except `.env.example`, `.DS_Store`, `node_modules`, Playwright reports, fuzz corpora, `.claude/settings.local.json`.
- When experimenting, pass `--home "$(mktemp -d)"` or set `CG_HOME` outside the repo. Do not create a data dir inside the checkout.
- Secrets in config are references only (`env:` / `op://` / `keychain:` / `file:`), never values (`crates/cg-core/src/secrets.rs`). If a real key or token ever lands in a commit, rotate it; a force-push does not un-leak it. `gitleaks` scans every push and the full history weekly; extend `.gitleaks.toml` only for exact public test fixtures.
- Old or rotated keys: delete them from the data dir (`secrets/`) and the Keychain, do not park them in the repo, `docs/`, or `security/`.
- `security/` holds audit deliverables (report, SARIF, diff), not credentials or scan logs.

Lints: `unsafe_code = "forbid"` workspace-wide; `clippy::unwrap_used` warns, `dbg_macro` denies. Clippy runs with `-D warnings`, so avoid `unwrap()` in non-test code.

`scripts/install.sh` needs Xcode CLT and a native arm64 rustup (it rejects Rosetta shells and Rust older than 1.90). Nothing in this sandbox can run it, so changes to it, Keychain code or the launchd plists are unverified until a Mac or the macOS CI runs them.

Repo skills in `.claude/skills/`: `verify` (local gate, lint first), `invariants-check` (diff vs `INVARIANTS.md`), `optimizer` (measure-first perf and size work that must not weaken an invariant).

## Architecture

Cargo workspace, five crates (`crates/*`):

- **`cg-graph`**: small LangGraph-style `StateGraph` / `CompiledGraph` (nodes, routers, a single entry and a single sink). Generic; no policy.
- **`cg-core`**: everything policy-bearing: `agent.rs` (builds the graph and all node logic), `config`, `rag` (SQLite FTS5 + embeddings), `llm` and `external` clients, `sanitizer` (injection scanning), `egress` (host-pinned HTTPS), `sandbox` (child-process env clearing), `secrets` / `keychain`, `settings` (UI overlay whitelist), `tune` (autotune), `attachments`, `tools`.
- **`cg-audit`**: protobuf audit records (`proto/`, compiled in `build.rs`), HMAC-SHA256 chained, signed head, cross-process append lock. Queries and senders are stored only as keyed fingerprints.
- **`cg-connectors`**: Telegram, SMS, Gmail, Gcal, web search, 1Password, netconnect. Exposed as trait objects behind the tool gate.
- **`cg-researcher`**: the binary. `main.rs` (CLI), `runtime.rs` (`run_turn`), `serve.rs` (axum-style loopback API + embedded web UI from `ui/`), `chat.rs`, `tests.rs`.

**The graph is the policy.** Every turn starts at `retrieve` and ends at `audit_logger`:

```
retrieve → guardrail_input → route_by_score → local_llm ⇄ tool_gate → tool_exec
                                            → user_gate → local_llm | external_fallback | pause
→ guardrail_output → audit_logger → END
```

Two gates matter most:
- `user_gate`: may this turn leave the machine? The external client is constructed only in `Agent::new` (one construction site) when `app.mode = "hybrid"` and `external.enabled`; the third gate is per-query consent. Pausing is not a blocked thread: the graph ends with `needs_confirm = true` and the client re-sends with `confirm_online`. External models never get tools and their output marks the turn **tainted**.
- `tool_gate`: per call, args must parse, tool must be offered to the origin (remote origins get read-only `remote_ok` tools), writes auto-approve only if `tools.auto_approve_writes` AND not tainted AND local origin; otherwise the `Confirmer` is asked. Denied calls return `DENIED: <reason>` to the model as the tool result.

`INVARIANTS.md` (I1–I8) lists the security rules and the exact tests that enforce each one. Read it before touching the graph, gates, audit, sanitizer, UI/HTTP guard or crate dependencies. Per its own rule, change an invariant only with a test and a `SECURITY.md` note. Notable structural ones:
- I6: `cg-core` must never depend on `cg-connectors` (checked by `core_never_depends_on_connectors`).
- I2: no telemetry; child processes use `sandbox::clean_command`; `deny.toml` bans telemetry crates.
- I8: server answers only loopback `Host` headers, refuses cross-origin, strict no-inline CSP; UI settings changes limited to a whitelist (`settings::check_overlay`), and relaxing any `[external.rules]` needs ack plus a `policy_relaxed` audit record.
- Model URL and HTTP bind must be loopback (`Config::validate`); all connector HTTP goes through `Egress` (host-pinned, HTTPS-only, no redirects, no proxy).

Config: defaults in `config/cg.toml`; UI overrides layer on top via `~/.cg-researcher/ui-settings.toml`. Docs: `docs/user-guide.md`, `docs/feature.md`, `SECURITY.md`.
