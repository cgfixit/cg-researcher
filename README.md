# cg-researcher

```
retrieve → guardrail_input ─┬─ route_by_score ─┬─ local_llm ⇄ tool_gate → tool_exec
                            │                  └─ user_gate ─┬─ local_llm
                            │                                ├─ external_fallback (Claude / Grok, 3 gates, no tools)
                            │                                └─ (pause: ask the human)
                            └──────────────── guardrail_output → audit_logger → END
```

Every path starts at `retrieve` and ends at `audit_logger`. The graph is the policy
(`cg-graph` is a small LangGraph-style `StateGraph`; there is no maintained Rust LangGraph).

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
ollama pull qwen3:8b && ollama pull all-minilm
cp ~/notes/*.md ~/.cg-researcher/corpus/ && cg-researcher index
cg-researcher chat                   # /attach ./diagram.png   /attach ./spec.docx
cg-researcher selftest
cg-researcher ui                     # local web UI (needs serve / --service running)
```

cg-researcher is built for **macOS 14+** (Apple Silicon first, Intel via `--target x86_64-apple-darwin`).
Linux builds and passes the test suite, but it is best-effort: no Keychain, no launchd, and the installer refuses to run.

macOS Finder users can double-click `install.command` / `uninstall.command`. Tagged releases also
publish a draft **Apple Silicon `cg-researcher.app`** (ad-hoc signed, not notarized) plus a universal
CLI tarball; build the app locally with `scripts/bundle-app.sh`.
`scripts/uninstall.sh` keeps your data; `--purge` deletes `~/.cg-researcher` after you type `delete`.

## Local models

Any OpenAI-compatible server on loopback: Ollama (`:11434/v1`), LM Studio (`:1234/v1`),
llama.cpp `llama-server` / `mlx_lm.server` (`:8080/v1`), vLLM. Non-loopback model URLs are
refused unless `llm.allow_non_loopback = true`. Set `llm.vision_model` to a VLM (for example
`qwen2.5vl:7b`) to let PNG attachments reach a model. Without it, PNGs are validated and
stripped, then not sent.

## Commands

| command | what it does |
|---|---|
| `init` | owner-only `~/.cg-researcher`, default config, audit key, API key, SMS PIN |
| `chat` | CLI turn loop; the only origin that can approve writes interactively |
| `serve` | `127.0.0.1:8797` API (`/health`, `/query`, `/tools`, `/api/*`) + web UI + enabled gateways |
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
autotune), Rules, Keys, Status (flow-ordered graph, budgets, audit verify, "Reindex corpus"). The UI is compiled into the binary and
has no CDN or remote assets. It runs under a strict CSP (`default-src 'none'`, no inline script). The
server answers only `Host: 127.0.0.1|localhost|[::1]` (DNS-rebinding guard) and refuses
cross-origin requests. Settings changes are limited to a whitelist (model, rules, provider, keys).
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
crates/cg-researcher  the binary (clap, axum, embedded UI)
packaging/macos       Info.plist for the .app bundle
```

## Status

Verified in this repo's sandbox on Linux x86_64. That covers 114 unit and mock-HTTP tests (graph, audit,
connectors, external providers via a loopback mock, the UI/HTTP security surface), clippy `-D warnings`
on 1.99.1, an MSRV 1.90 check, and an end-to-end smoke with `serve`, three concurrent `maintain` runs, UI
pairing, a headless-browser pass over every tab, and the `.app` launch path. **Not yet run on a Mac**: the macOS CI matrix
(macos-15 / macos-26, Keychain, launchd, installer) is written but GitHub Actions has not executed it
on this account. Windows is unsupported. Real Anthropic/xAI/Telegram/Twilio/Google/SerpAPI accounts
were not exercised.

See [SECURITY.md](SECURITY.md) and [INVARIANTS.md](INVARIANTS.md).
