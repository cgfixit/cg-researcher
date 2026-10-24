# User guide

cg-researcher is a local-first research agent for one person on one Mac (Apple Silicon, macOS 14+ including
macOS 27 Golden Gate, which has no Intel support). It answers from your own files with a local model, and reaches out only through connectors
you enable.

## Install

| option | how | notes |
|---|---|---|
| From source (supported) | `./scripts/install.sh` or double-click `install.command` | Needs Xcode CLT + a native arm64 rustup (not Homebrew `rust`); refuses to run under Rosetta. Builds `--locked`, ad-hoc signs, installs `~/.cg-researcher/bin/cg-researcher`. |
| As a background service | `./scripts/install.sh --service --maintenance` | launchd `com.cgfixit.cg-researcher` (serve) + `.maintenance` (daily 03:15 health check). |
| App bundle | download `cg-researcher-macos-arm64.app.zip` from a release, check `shasum -a 256 -c`, unzip to `/Applications` | Ad-hoc signed, **not notarized**: first launch needs right-click → Open. Double-click starts a server (or reuses the launchd one) and opens the UI. |

Upgrading from the old `cg-agent` name: `install.sh` moves `~/.cg-agent` to `~/.cg-researcher` and
retires the old launchd jobs. Re-save API keys once (Keychain items can't be renamed without reading
them), then run `cg-researcher index`.

## First run

```bash
cg-researcher init                         # owner-only home, config, audit key, API key, SMS PIN
ollama pull qwen3.8:27b-mlx-cg && ollama pull gemma4-26b-a4b:ud-q4_k_xl-cg && ollama pull all-minilm
cp ~/notes/*.md ~/.cg-researcher/corpus/
cg-researcher index                        # FTS5 + embeddings into rag.sqlite3
cg-researcher selftest
```

Any OpenAI-compatible server on loopback works: set `[llm] base_url` and `model` in
`~/.cg-researcher/cg.toml` (LM Studio `:1234/v1`, llama-server or mlx_lm.server `:8080/v1`). For PNG
attachments to reach a model, set `llm.vision_model` (default `gemma4-26b-a4b:ud-q4_k_xl-cg`; `""` disables).

## Everyday use

- `cg-researcher chat`: `/attach <file>` (.png .docx .md .txt), `/ext <q>` asks the external model, `/clear`, `/quit`.
- `cg-researcher ui`: opens the web UI (pairs with a single-use code). Tabs: Chat, Models, Rules, Keys, Status.
  Chat shows the corpus folder and chunk count, a "Thinking… Ns" timer until the first words arrive,
  then the local model's answer streaming in ("Running tools…" while it calls a tool), source chips, a Copy button
  and New chat (clears the page only; nothing is stored). Status → Reindex corpus does the same as
  `cg-researcher index` without leaving the browser. If the server restarts, the page says "Session
  ended"; run `cg-researcher ui` again.
- `cg-researcher index`: re-run after adding or changing files, or after changing `embed_model`. A running server
  picks up the new index without a restart. The UI button calls `POST /api/reindex` (authenticated).
- HTTP: `POST 127.0.0.1:8797/query` with `Authorization: Bearer $(cat ~/.cg-researcher/secrets/api.key)`.
  `POST /query/stream` takes the same body and returns server-sent events: `delta` `{"text":…}`
  (guarded, provisional), `reset` (discard provisional text; a tool round started), then one `final`
  (same JSON as `/query`) or `error`. Only local-model text streams; the turn finishes and is audited
  even if the client disconnects. Example: `curl -N 127.0.0.1:8797/query/stream -H "authorization: Bearer $(cat ~/.cg-researcher/secrets/api.key)" -H 'content-type: application/json' -d '{"query":"…"}'`.

How answers are chosen: retrieval scores the question against your corpus (keyword + semantic). A
confident match goes to the local model with the retrieved context. A weak match asks you whether
to answer anyway locally, use the external model (if enabled), or stop.

## External models (optional)

1. `app.mode = "hybrid"` and `external.enabled = true` (both in `cg.toml` or the UI).
2. Paste the key in UI → Keys (stored in the Keychain as `cg-researcher/anthropic_api_key` or `cg-researcher/xai_api_key`).
3. Consent per query (CLI `y`, UI "External", `/ext`).

`external.model` must belong to `external.provider` (`claude-*` for anthropic, `grok-*` for xai) or be
empty for the provider default. A mismatch is refused when `cg.toml` loads and by the UI (HTTP 400),
so a provider switch can't silently keep the other vendor's model id.

Rules (`[external.rules]`) ship closed: no local context, attachments or images leave the machine.
Each loosening asks for confirmation and is written to the audit log.

## Connectors

All start off. Enable one in `cg.toml`, provide its secret reference (`env:NAME`,
`keychain:cg-researcher/NAME` or `file:NAME` under `secrets/`), then `cg-researcher selftest`.
Gmail and Calendar also need `cg-researcher google-auth`. Telegram and SMS need a non-empty allowlist or they
refuse to start; SMS also needs the PIN from `secrets/sms_pin`.

## Maintenance and audit

- `cg-researcher maintain`: selftest + audit-chain check, recorded in the log (the launchd job runs it daily).
- `cg-researcher audit verify` / `cg-researcher audit tail -n 20`.
- Logs: stderr (launchd: `~/.cg-researcher/logs/*.log`, 0600). The audit log is protobuf + HMAC chain; it stores
  fingerprints, not your queries.

## Uninstall

`./scripts/uninstall.sh` (or `uninstall.command`) removes the binaries and launchd jobs and keeps your data.
`--purge` also deletes `~/.cg-researcher` and the Keychain items (including legacy `cg-agent` ones) after you type `delete`.

## Troubleshooting

| symptom | fix |
|---|---|
| "cannot reach 127.0.0.1:8797" | start `cg-researcher serve`, or install with `--service` |
| Keychain "Always Allow" prompt after upgrading | expected: ad-hoc signatures change per build |
| "app is damaged / can't be opened" | Gatekeeper quarantine on an unnotarized download: right-click → Open, or `xattr -dr com.apple.quarantine cg-researcher.app` after checking the SHA-256 |
| answers ignore your notes | `cg-researcher index`; if you changed `embed_model`, the log says the vector size changed, so reindex |
| "query embedding has N dims, index has M" | same: reindex after switching embedding model |
| remote message ignored | sender not in the allowlist (by design, silent) |
