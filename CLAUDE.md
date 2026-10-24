# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`cg-researcher` (formerly `cg-agent`): a local-first research assistant in Rust. RAG over a notes corpus, a loopback OpenAI-compatible model (Ollama / LM Studio / llama.cpp / vLLM), and an optional, triple-gated external model (Claude / Grok). The product target is Apple Silicon (arm64) on macOS 14+, including macOS 27 "Golden Gate" (Apple silicon only, last release with Rosetta). CI covers macOS 15 and `macos-latest` (macOS 26 today; it becomes 27 when GitHub flips the label). Intel is best-effort and only on macOS 26 or older. Linux builds and passes tests but is best-effort (no Keychain, no launchd, installer refuses to run).

The default branch is `main`. CI, Dependabot and the workflows in `.github/` target it.

## Commands

Toolchain is pinned in `rust-toolchain.toml` (1.99.1, edition 2024, MSRV 1.90); rustup installs it automatically. Every external crate version is declared once in `[workspace.dependencies]` (root `Cargo.toml`); crate manifests inherit with `name.workspace = true` and add only `features`. Bump a version there, never in a crate, and keep `cargo metadata --locked` passing.

```bash
./init.sh                                   # full local gate + `cg-researcher init` into $CG_HOME
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo test -p cg-core --locked <name>       # single test (substring match), e.g. `agent::tests::topology_`
cargo test -p cg-core --locked keychain -- --ignored   # Keychain test (macOS only, needs a throwaway keychain)
cargo run -p cg-researcher -- selftest      # runtime self-check; also: chat, serve, index, audit verify, maintain
cargo deny check advisories bans licenses sources   # what audit.yml runs; `bans` is the no-telemetry rule (deny.toml)
cargo llvm-cov --workspace --locked --summary-only --fail-under-lines 70   # CI coverage floor
```

- The data dir is `$CG_HOME` or `~/.cg-researcher`; override per invocation with `--home <dir>` (use a throwaway dir when experimenting).
- Fuzzing (`fuzz/`, nightly + `cargo-fuzz`): targets `attachments` and `sanitizer`.
- Browser e2e (`e2e/`, Playwright Chromium + WebKit): needs the mock model (`cargo run -p cg-researcher --example mock_llm`, listens on 127.0.0.1:11434), then `cd e2e && npm ci --ignore-scripts && npx playwright test`. `e2e/start-server.sh` builds a throwaway home and runs `serve --no-gateways`.
- Shell scripts are shellchecked in CI (`scripts/*.sh e2e/*.sh *.command init.sh`).

Lints: `unsafe_code = "forbid"` workspace-wide; `clippy::unwrap_used` warns, `dbg_macro` denies. Clippy runs with `-D warnings`, so avoid `unwrap()` in non-test code.

`scripts/install.sh` needs Xcode CLT and a native arm64 rustup (it rejects Rosetta shells and Rust older than 1.90). Nothing in this sandbox can run it, so changes to it, Keychain code or the launchd plists are unverified until a Mac or the macOS CI runs them.

Repo skills in `.claude/skills/` (index in `.claude/skills/README.md`): `verify` (local gate, lint first), `invariants-check` (diff vs `INVARIANTS.md`), `config-guard` (shipped `config/cg.toml` still fail-closed), `run-cg-researcher` (real binary against the mock model in a throwaway home), `optimizer` (measure-first perf and size work that must not weaken an invariant), `gotchas` (session-tested traps; load before install, CI, release or dependency work). `.claude/settings.json` pre-approves the `cargo` gate commands, the repo scripts and read-only `git`/`rg`; anything else prompts, so do not work around a prompt. Lint first, then run the changed code; the full suite is CI's job. Never comment `@codex review` on a PR without the operator's approval.

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
