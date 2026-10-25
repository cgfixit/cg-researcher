# Features

Status: **done** = implemented with tests; **partial** = works with stated limits; **not started** = listed
intent only, no code or config slot. "Verified" says where it has actually run: `L` = Linux sandbox
tests/smoke, `CI` = GitHub's macOS runners (macos-15, macos-latest; a runner, not a daily-use Mac), `M` = on
an operator's Mac, `R` = against the real third-party service. Nothing is `M` or `R` yet.

| area | feature | status | verified |
|---|---|---|---|
| Core | 10-node policy graph (retrieve → … → audit_logger) | done | L |
| Core | Local models over OpenAI-compatible loopback (Ollama, LM Studio, llama.cpp, MLX, vLLM) | done | L (mock) |
| Core | Autotune on every model switch (context, max_tokens, top_k) | done | L (mock) |
| RAG | SQLite FTS5 BM25 + exact cosine, RRF fusion, single 0600 file | done | L |
| RAG | Live reload of a rebuilt index in a running server | done | L |
| RAG | Corpus .md .txt .docx (zip-bomb limits) | done | L |
| Chat | Attachments .png (re-encoded, metadata stripped) .docx .md .txt | done | L |
| External | Anthropic Claude / xAI Grok, triple-gated, no tools, rules + budgets, model id must match provider | done | L (mock) |
| UI | Loopback web UI, pairing code, strict CSP, settings whitelist, in-browser reindex, mobile layout | done | L (headless Chromium) |
| UI | Streaming local answers (SSE `/query/stream`, guarded per chunk, `/query` fallback) | done; external + CLI not streamed | L (Chromium + WebKit, mock model) |
| Audit | Protobuf HMAC-chained log, signed head, cross-process lock | done | L |
| CI | UI e2e (Playwright Chromium + WebKit, incl. streaming frames), cargo-fuzz (attachments, sanitizer, stream), llvm-cov floor 70% | done; runs in Actions | L |
| CI | Daily `nightly-YYYYMMDD-<sha>` prerelease (`.app` + universal CLI) when `main` moved without a tag or a release run; 09:07 Eastern | done; `release.yml` `gate` job, no run yet | — |
| Connectors | Web search: SerpAPI, opt-in public Google | done | L (mock) |
| Connectors | netconnect (ARP, RFC1918 allowlist) + Net-Viewer sockets | partial (macOS paths) | L |
| Connectors | Telegram gateway (numeric allowlist, private chats) | done | L (mock) |
| Connectors | SMS via Twilio (E.164 allowlist + PIN, polling) | done; number is paid (~$1+/mo) | L (mock) |
| Connectors | Gmail search/read/draft/send (single recipient, human-approved) | done | L (mock) |
| Connectors | Google Calendar list/create (no attendees) | done | L (mock) |
| Connectors | 1Password metadata search (`op item list` only) | done | L (mock) |
| Connectors | Discord / WhatsApp / voice | not started | — |
| macOS | Keychain secrets | done | L (compiled), CI (throwaway keychain round trip) |
| macOS | launchd service + daily maintenance job | done | CI (`install-smoke`, push/schedule only) |
| macOS | install/uninstall `.sh` + `.command`, legacy `~/.cg-agent` migration | done | shellcheck |
| macOS | Apple Silicon `.app` bundle, ad-hoc signed, public release on a `v*` tag | done; not notarized | L (launch path), CI (release.yml build) |
| Dropped | Long-term memory (semantic/episodic/procedural) | removed by request (interesting. it wasnt but this was surprisingly good for perplexity  | — |
