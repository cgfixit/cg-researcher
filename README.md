# CG LOCAL RESEARCHER

A local-first research assistant: RAG over your own notes, a loopback model
(Ollama / LM Studio / llama.cpp / vLLM), and an optional, triple-gated external
model. Every turn starts at `retrieve` and ends at `audit_logger`. The graph is
the policy (`cg-graph` is a small LangGraph-style `StateGraph`; there is no
maintained Rust LangGraph).

Docs: [user guide](docs/user-guide.md) · [features](docs/feature.md) · [security](SECURITY.md) ·
[invariants](INVARIANTS.md). Formerly `cg-agent`; see the user
guide for the one-time migration.

## Quickstart

```bash
./init.sh                       # dev: pinned toolchain, fmt, clippy -D warnings, tests, init
./scripts/install.sh            # or install: release build → ~/.cg-researcher/bin/cg-researcher
#   --with-netviewer  (macOS) also builds CyClaw-Net-Viewer at a pinned commit
#   --service         per-user launchd agent (com.cgfixit.cg-researcher)
#   --maintenance     daily 03:15 launchd health check (com.cgfixit.cg-researcher.maintenance)
ollama pull qwen3.8:27b-mlx-cg && ollama pull gemma4-26b-a4b:ud-q4_k_xl-cg && ollama pull all-minilm
cp ~/notes/*.md ~/.cg-researcher/corpus/ && cg-researcher index
cg-researcher chat                   # /attach ./diagram.png   /attach ./spec.docx
cg-researcher selftest
cg-researcher ui                     # local web UI (needs serve / --service running)
```

cg-researcher targets **Apple Silicon (arm64) Macs on macOS 14 (Sonoma) or newer**, including macOS 27
"Golden Gate", which is Apple silicon only. CI runs the Mac jobs on macOS 15 and `macos-latest` (macOS 26 today, Golden Gate once GitHub moves the label); Golden Gate uses the same
arm64 binary. Intel builds (`--target x86_64-apple-darwin`) are best-effort and
only possible on macOS 26 or older, because Golden Gate does not run on Intel Macs.
Linux builds and passes the test suite, but it is best-effort: no Keychain, no launchd, and the installer refuses to run.

Prerequisites for `install.sh`: Xcode Command Line Tools (`xcode-select --install`) and a native arm64
[rustup](https://rustup.rs) (not Homebrew `rust`; `rust-toolchain.toml` pins 1.99.1 and only rustup honors it).
The installer refuses to run from a Rosetta shell, so it never builds an x86_64 binary by accident
(`rustc -vV` should report `host: aarch64-apple-darwin`).

macOS Finder users can double-click `install.command` / `uninstall.command`. Tagged releases also
publish a draft **Apple Silicon `cg-researcher.app`** (ad-hoc signed, not notarized) plus a universal
CLI tarball; build the app locally with `scripts/bundle-app.sh`.
`scripts/uninstall.sh` keeps your data; `--purge` deletes `~/.cg-researcher` after you type `delete`.

## Local models

Any OpenAI-compatible server on loopback: Ollama (`:11434/v1`), LM Studio (`:1234/v1`),
llama.cpp `llama-server` / `mlx_lm.server` (`:8080/v1`), vLLM. Non-loopback model URLs are
refused unless `llm.allow_non_loopback = true`. Defaults: `llm.model = "qwen3.8:27b-mlx-cg"` (text generation) and `llm.vision_model = "gemma4-26b-a4b:ud-q4_k_xl-cg"`
(multimodal, for PNG attachments). Set `llm.vision_model` to any VLM (for example
`qwen2.5vl:7b`) to let PNG attachments reach a model. Set it to `""` and PNGs are validated and
stripped, then not sent.

## Commands

| command | what it does |
|---|---|
| `init` | owner-only `~/.cg-researcher`, default config, audit key, API key, SMS PIN |
| `chat` | CLI turn loop; the only origin that can approve writes interactively |
| `serve` | `127.0.0.1:8797` API (`/health`, `/query`, `/query/stream`, `/tools`, `/api/*`) + web UI + enabled gateways |
| `ui [--print]` | mint a single-use pairing code and open `http://127.0.0.1:8797/#p=…` |
| `maintain` | selftest + audit-chain verify, recorded in the audit log; non-zero exit on failure |
| `gateways` | Telegram / SMS only |
| `index` | rebuild the RAG index from the corpus (.md .txt .docx); a running `serve` picks it up live |
| `app` | what `cg-researcher.app` runs: init if needed, start or reuse `serve`, open the UI |
| `audit verify` / `audit tail -n 20` | check the protobuf audit chain + signed head / show recent records |
| `google-auth` | loopback PKCE consent for Gmail / Calendar (least-privilege scopes) |
| `netviewer [--cli]` | open CyClaw-Net-Viewer.app or print its numeric socket snapshot |

```bash
curl -s 127.0.0.1:8797/query -H "authorization: Bearer $(cat ~/.cg-researcher/secrets/api.key)" \
  -H 'content-type: application/json' -d '{"query":"what is in my notes about X?"}'
```

## Graph and gates

```
retrieve → guardrail_input ─┬─ route_by_score ─┬─ local_llm ⇄ tool_gate → tool_exec
                            │                  └─ user_gate ─┬─ local_llm
                            │                                ├─ external_fallback (Claude / Grok, 3 gates, no tools)
                            │                                └─ (pause: ask the human)
                            └──────────────── guardrail_output → audit_logger → END
```

Ten nodes, four routers, one entry (`retrieve`), one sink (`audit_logger`). Two of the
nodes are gates, and they answer different questions.

### `user_gate` — may this turn leave the machine?

Reached only when `route_by_score` finds no confident local match (or the operator sent
`/ext` / `prefer_external`). It is gate 3 of 3 for the external model; gates 1 and 2
(`app.mode = "hybrid"` and `external.enabled`) decide whether an external client is even
constructed, and `Agent::new` is the only construction site.

| external client | origin may consent | `confirm_online` | result |
|---|---|---|---|
| none (gates 1+2 closed) | — | — | `local_llm` |
| built | **no** (SMS always; Telegram unless `allow_telegram`) | — | `local_llm` |
| built | yes | `true` (or `prefer_external`) | `external_fallback` |
| built | yes | `false` | `local_llm` |
| built | yes | unset | **pause** → `audit_logger` |

The pause is not a blocked thread. The graph ends with `needs_confirm = true` and the
client re-sends the same query with `confirm_online` set; nothing is checkpointed and no
model is called in between. External models never receive tools, and their output marks
the turn **tainted**.

### `tool_gate` — may each requested tool call run?

Reached whenever `local_llm` returns tool calls. It is inside the bounded
`local_llm ⇄ tool_gate → tool_exec` cycle (`max_tool_iterations`). For every call:

1. Arguments must parse as a JSON object, else `denied`.
2. The tool must be in the list **offered for this origin** (remote origins get read-only,
   `remote_ok` tools), else `denied`. Offering is done by topology, not by prompt.
3. `Effect::Read` → `allowed`.
4. `Effect::Write` → `allowed` only if `tools.auto_approve_writes` **and** the turn is not
   tainted **and** the origin is local. Otherwise the `Confirmer` is asked with a
   human-readable summary (suffixed `[turn contains untrusted content]` when tainted) and
   the call becomes `confirmed` or `declined`. Remote channels cannot confirm.

Denied and declined calls are not dropped: `tool_exec` returns `DENIED: <reason>` to the
model as the tool result, so the model can explain instead of hallucinating success. Tool
output from `untrusted_output` connectors is sanitized, wrapped in `<untrusted>`, and
taints the turn, which removes auto-approval from any later write in the same turn.
Every decision is written to the audit chain with the args stored as HMAC fingerprints.

## External models (Anthropic Claude, xAI Grok)

Off by default. Three gates, all required (I3): `app.mode = "hybrid"`, `external.enabled = true`,
and consent on **each** query (CLI `y`, the UI's "External" button, `/ext <question>` in chat, or
`"prefer_external": true` on `/query`). SMS can never consent; Telegram can only if
`external.rules.allow_telegram` is on.

- Keys live in the macOS Keychain (`keychain:cg-researcher/anthropic_api_key`, `…/xai_api_key`); paste them
  in the UI's Keys tab. Prefixes are checked (`sk-ant-`, `xai-`) and no endpoint ever returns a key.
- Hosts are pinned: `api.anthropic.com`, `api.x.ai` or `us.api.x.ai`. Anthropic uses `/v1/messages`;
  xAI uses `/v1/chat/completions` (not the Responses API, which stores prompts for 30 days by default).
- External models **never** get tools. Their output marks the turn tainted, so later writes need human approval.
- `[external.rules]` all ship closed: local RAG context, attachment text and images stay on the
  machine; calls are budgeted (20/hour, 100/day); output is capped at 2048 tokens. The outbound query
  and context are redacted and capped at 24,000 chars. Loosening a rule in the UI shows a confirmation
  and writes `policy_relaxed` to the audit log.
- **Autotune** runs on every model switch. Local: Ollama `/api/show` or LM Studio `/api/v0/models`
  gives the context length and vision/tool capability. External: the provider's model-metadata
  endpoint, falling back to a built-in table. It derives max_tokens, temperature ceiling, RAG top_k and
  a context-character budget, and records `model_tuned` in the audit log.

## Web UI

`cg-researcher ui` asks the running server for a one-time pairing code (API key required, 120 s TTL,
single use). It then opens the browser on a URL whose `#fragment` carries the code: browsers never send
fragments to servers, and the page wipes it from history. The page swaps the code for a 12-hour
session token kept in `sessionStorage`. Tabs: Chat (local / auto / external), Models (switch +
autotune), Rules, Keys, Status (graph, budgets, audit verify). The UI is compiled into the binary and
has no CDN or remote assets. It runs under a strict CSP (`default-src 'none'`, no inline script). The
server answers only `Host: 127.0.0.1|localhost|[::1]` (DNS-rebinding guard) and refuses
cross-origin requests. Settings changes are limited to a whitelist (model, rules, provider, keys).
Chat answers from the local model stream in as they are generated (`POST /query/stream`,
server-sent events). Each streamed piece has already been through the output guard (secret
redaction, link defanging, `<think>` stripping), and text is held back at a word boundary so a
secret split across tokens never reaches the page half-written. The `final` event carries the
authoritative answer, which replaces the streamed text. External-model answers and the CLI are not
streamed.
The UI cannot change bind address, loopback rules, connectors or write approval. Overrides go to
`~/.cg-researcher/ui-settings.toml` (0600), layered over `cg.toml`.

## Scheduled jobs

| what | schedule | where |
|---|---|---|
| `cg-researcher maintain` (selftest + audit verify) | daily 03:15 local | launchd `com.cgfixit.cg-researcher.maintenance` via `install.sh --maintenance` |
| CI on macOS (build, test, Keychain, install smoke) | Mon 07:41 UTC | `.github/workflows/ci.yml` |
| gitleaks full-history rescan | Mon 05:23 UTC | `.github/workflows/gitleaks.yml` |
| actionlint + zizmor + shellcheck | Mon 05:29 UTC | `.github/workflows/workflow-lint.yml` |
| cargo-audit + cargo-deny | Mon 06:17 UTC | `.github/workflows/audit.yml` |
| fuzz attachments + sanitizer (15 min each) | Tue 04:47 UTC | `.github/workflows/fuzz.yml` |

On every push and PR: `scripts/lint.sh` on an Apple Silicon runner (`lint.yml`: hygiene, fmt, clippy,
shellcheck, actionlint, plutil). On every PR: browser end-to-end tests of the web UI in Chromium and WebKit (`ui-e2e.yml`, against a
real `serve` and a Rust mock model), line coverage with a 70% floor (`coverage.yml`), and a 2-minute
fuzz run when attachment, sanitizer or secret code changes. Locally:
`cargo build -p cg-researcher --bins --examples && (cd e2e && npm ci && npx playwright install --only-shell chromium webkit && npx playwright test)`
and `cargo +nightly fuzz run attachments`.

launchd is preferred on macOS because it runs a missed job after wake. If you prefer cron anyway:

```cron
15 3 * * * $HOME/.cg-researcher/bin/cg-researcher --home $HOME/.cg-researcher maintain >> $HOME/.cg-researcher/logs/maintenance.log 2>&1
```

Appending is safe while `serve` is running: writers take an advisory lock on `audit.pb.lock` and resync from
the verified tail, so the chain never forks.

## Retrieval

One owner-only SQLite file (`~/.cg-researcher/index/rag.sqlite3`): **FTS5 BM25** for keywords and
**exact cosine** over unit-normalized embeddings, fused with RRF (k = 60) as in CyClaw. Vectors are
scanned in RAM by a vectorizable Rust loop: fine to ~1M chunks, no ANN index, no vector server, no
SQLite extension, no `unsafe`. Hostile FTS5 syntax in a question is quoted away. Changing
`embed_model` needs `cg-researcher index` (a dimension mismatch falls back to keyword-only, with a warning).

## Connectors (all `enabled = false` by default)

| connector | tools / role | effect | notes |
|---|---|---|---|
| `web_search` | `web_search` | read, untrusted | SerpAPI. Public google.com only if **no key** and `allow_public_google = true`; never a fallback after a key rejection or quota hit |
| `netconnect` | `net_neighbors`, `net_connections` | read | ARP cache via fixed `/usr/sbin` paths; RFC1918 CIDR allowlist; `net_connections` uses bundled CyClaw-Net-Viewer (macOS) |
| `telegram` | inbound gateway | — | long-poll, private DMs, numeric user-id allowlist, optional 6-digit confirm codes |
| `sms` | inbound gateway | — | Twilio polling (no webhook), E.164 allowlist **+ PIN**, lockout, deletes processed inbound messages |
| `gmail` | `gmail_search`, `gmail_read`, `gmail_create_draft`, `gmail_send` | read untrusted / write | single recipient, header-injection-proof MIME |
| `gcal` | `gcal_list_events`, `gcal_create_event` | read untrusted / write | no attendees field (cannot invite third parties) |
| `onepassword` | `onepassword_search` | read | `op item list` metadata only, and never `op item get` |

Adding a connector means one module with `async fn build(&Ctx) -> Parts` plus one line in `REGISTRY`
(`crates/cg-connectors/src/lib.rs`).

## Layout

```
crates/cg-graph       StateGraph / conditional edges / bounded invoke
crates/cg-audit       protobuf (prost + protox, no protoc) HMAC-SHA256 chained log
crates/cg-core        config, policy graph, RAG, model clients, egress, sanitizer, secrets
crates/cg-connectors  everything that talks to a third party
crates/cg-researcher  the binary (clap, axum, embedded UI from crates/cg-researcher/ui)
config/cg.toml        shipped defaults, copied by `init`; every gate closed
packaging/macos       Info.plist for the .app bundle
scripts/              lint.sh (the lint gate), install.sh, uninstall.sh, bundle-app.sh
e2e/                  Playwright specs (Chromium + WebKit) against serve + the mock model
fuzz/                 cargo-fuzz targets (attachments, sanitizer); own Cargo.lock, nightly only
.claude/              Claude Code settings and repo skills (see Development)
```

## Dependencies and toolchain

| file | pins |
|---|---|
| `rust-toolchain.toml` | Rust **1.99.1** with `rustfmt` + `clippy` (rustup only; Homebrew `rust` ignores it) |
| `Cargo.toml` | edition 2024, `rust-version = "1.90"` (MSRV, checked by CI), `resolver = "3"`; every external crate version lives once in `[workspace.dependencies]` and the crates inherit it with `name.workspace = true` plus their own `features` |
| `Cargo.lock` | committed; everything runs `--locked` (CI, `init.sh`, `install.sh`) |
| `deny.toml` | license allowlist, crates.io only, `wildcards = "deny"`, and the I2 bans (`opentelemetry*`, `sentry`, `posthog-rs`, `openssl-sys`, `native-tls`); `cargo deny check advisories bans licenses sources` is the CI command |
| `fuzz/Cargo.toml` + `fuzz/Cargo.lock` | separate package (not a workspace member), pinned nightly in `fuzz.yml`; its resolved versions match the workspace lock |
| `e2e/package.json` + `package-lock.json` | `@playwright/test` 1.64.1 only; `npm ci --ignore-scripts` |
| `.github/workflows/*.yml` | all actions pinned by SHA; the same `dtolnay/rust-toolchain` SHA and `1.99.1` everywhere, `1.90` for the MSRV job |

HTTP is `reqwest` on rustls (no OpenSSL, no `native-tls`, enforced by `deny.toml`); SQLite is `rusqlite` with the bundled engine and FTS5; the audit log is `prost` with `protox`, so no `protoc` is needed; macOS Keychain goes through `security-framework` (macOS-only target dependency). Changing a version means editing the root `Cargo.toml` once, then `cargo metadata --locked` must still pass or the lock needs a deliberate `cargo update -p <crate>`.

## Development

`CLAUDE.md` is the contributor manual (commands, lints, architecture, the gate rules). `INVARIANTS.md` I1-I8
lists each security rule with the test that fails if it breaks; a change to one needs a test and a `SECURITY.md` note.
`.claude/skills/` holds the repo skills, usable from Claude Code as `/<name>` or as plain checklists:

| skill | purpose |
|---|---|
| `verify` | the local gate: `scripts/lint.sh` (hygiene, fmt, clippy `-D warnings`, shellcheck, actionlint, plutil), `cargo deny`, then `init` / `selftest` / `audit verify` in a throwaway home |
| `invariants-check` | maps a diff to I1-I8 and the tests that cover each |
| `config-guard` | asserts `config/cg.toml` still ships fail-closed (offline, external off, connectors off, loopback, quoted booleans refused, UI overlay whitelist) |
| `run-cg-researcher` | runs the real binary against the mock model: throwaway home, index, `serve`, `/query`, UI pairing, Playwright, audit verify |
| `optimizer` | measure-first performance and size work that must not weaken a guard |
| `gotchas` | session-tested traps: Rosetta shells, Homebrew rust, port 11434 vs Ollama, unrun macOS CI, `macos-latest` vs 27, lock and deny handling |

Lint first (`scripts/lint.sh`, the same script CI's `lint` job runs on an Apple Silicon runner; `--hygiene`
alone checks that no data dir, log, key or encrypted blob is tracked), then run the code; the full suite is
CI's job. The lints are strict: `unsafe_code = "forbid"`, `clippy::unwrap_used` warns under `-D warnings`,
`dbg_macro` denies.

## Status

Verified in this repo's sandbox on Linux x86_64. That covers 131 unit and mock-HTTP tests (graph, audit,
connectors, external providers via a loopback mock, the UI/HTTP security surface) plus one Keychain test
that is `#[ignore]` off macOS, clippy `-D warnings` on 1.99.1, an MSRV 1.90 check, `cargo deny`
(advisories, bans, licenses, sources), and an end-to-end smoke with the mock model: `init`, `index`,
`selftest` (10-node graph), `serve`, `/query` with sources, the DNS-rebinding (421) and missing-bearer (401)
refusals, UI pairing, `audit verify`. Earlier passes also covered three concurrent `maintain` runs, a
headless-browser pass over every tab, the six Playwright specs in Chromium and WebKit, 60 s fuzz runs per
target (~3.2M inputs, no crashes), 74% line coverage, and the `.app` launch path. **Not yet run on a Mac**:
the macOS CI matrix (macos-15 / macos-latest, Keychain, launchd, installer) is written but GitHub Actions
has not executed it on this account. Windows is unsupported. Real Anthropic/xAI/Telegram/Twilio/Google/SerpAPI
accounts were not exercised.

See [SECURITY.md](SECURITY.md) and [INVARIANTS.md](INVARIANTS.md).
