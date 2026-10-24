---
name: run-cg-researcher
description: Build and run cg-researcher end to end on this machine with the deterministic mock model - init a throwaway home, index a corpus, serve, hit the loopback API, open or script the web UI, and smoke-test the result. Use when asked to run, start, launch, demo, screenshot or verify the app, or to confirm a change works in the real binary rather than in unit tests.
---

# run-cg-researcher

Run the real binary against the mock model so the result is repeatable and never touches `~/.cg-researcher`. Everything here is loopback-only and needs no model weights. This is the same setup the browser tests use (`e2e/playwright.config.mjs` and `e2e/start-server.sh`).

## Rules

- Always pass `--home "$H"` with a throwaway directory. Never run `init` or `index` against the default home while verifying a change.
- One server per home. `serve` binds `127.0.0.1:8797`; if `/health` already answers before you start, that is someone else's process (a launchd agent or an earlier run), not your build. Stop your own process when done, and never kill one you did not start.
- The mock listens on `127.0.0.1:11434`, which is also Ollama's port. If Ollama is running on this Mac, stop it first or you will test against a real model and get non-deterministic answers.
- Use `serve --no-gateways` so no Telegram or SMS polling starts.
- The API key lives at `$H/secrets/api.key`; use it as a bearer token. Never paste it into a URL or a commit.

## 1. Build

```bash
cargo build --locked -p cg-researcher --bins --examples
BIN=target/debug/cg-researcher
MOCK=target/debug/examples/mock_llm
```

## 2. Throwaway home, corpus, index

```bash
H="$(mktemp -d)"
"$BIN" --home "$H" init
mkdir -p "$H/corpus" && printf '# Veeam immutability\nHardened Linux repositories keep backups immutable.\n' > "$H/corpus/veeam.md"
if curl -fs 127.0.0.1:11434/v1/models >/dev/null 2>&1; then echo "port 11434 is taken (Ollama?): stop it first" >&2; exit 1; fi
"$MOCK" 127.0.0.1:11434 &  MOCK_PID=$!
until curl -fs 127.0.0.1:11434/v1/models >/dev/null; do kill -0 "$MOCK_PID" || { echo "mock died" >&2; exit 1; }; sleep 0.2; done
"$BIN" --home "$H" index
"$BIN" --home "$H" selftest
```

`selftest` checks config, graph topology, connectors, egress pinning and the local model; `index` embeds through the mock (16-dim vectors), so the RAG path is real even though the answers are canned.

## 3. Serve and query

```bash
"$BIN" --home "$H" serve --no-gateways &  SERVE_PID=$!
until curl -fs 127.0.0.1:8797/health >/dev/null; do sleep 0.2; done
KEY="$(cat "$H/secrets/api.key")"
curl -s 127.0.0.1:8797/query -H "authorization: Bearer $KEY" -H 'content-type: application/json' \
  -d '{"query":"what do my notes say about immutability?"}'
```

Expect a JSON answer that starts with `MOCK ANSWER:` and a `sources` list naming `veeam.md`. A request containing `SLOW` makes the mock wait two seconds (for busy-state checks). Streaming is `POST /query/stream` (server-sent events).

Negative probes worth one line each when the change touches the HTTP surface (I8):

```bash
curl -s -o /dev/null -w '%{http_code}\n' 127.0.0.1:8797/health -H 'Host: evil.example'          # expect 421 (DNS-rebinding guard)
curl -s -o /dev/null -w '%{http_code}\n' 127.0.0.1:8797/query -H 'content-type: application/json' -d '{}'   # expect 401 without the bearer
```

## 4. Web UI

```bash
"$BIN" --home "$H" ui --print     # prints http://127.0.0.1:8797/#p=<single-use code>, 120 s TTL
```

Open it in a browser, or run the Playwright suite instead, which starts its own mock and server (stop yours first, or they fight over the ports):

```bash
cd e2e && npm ci --ignore-scripts && npx playwright install --only-shell chromium webkit && npx playwright test
```

The suite is six specs run in Chromium and WebKit. In this repo's Linux sandbox, Chromium and Playwright are preinstalled; do not run `playwright install` there.

## 5. Audit and teardown

```bash
"$BIN" --home "$H" audit verify
"$BIN" --home "$H" audit tail -n 5
kill "$SERVE_PID" "$MOCK_PID"
rm -rf "$H"
```

`audit verify` must report the chain OK after the turns above; every `/query` appends a record.

## 6. Report

State what ran (commands, exit codes, the answer text), and what did not: nothing here exercises Keychain, launchd, `install.sh`, the `.app` bundle or a real model. Those need a Mac. If a step failed, paste the error; a run that "mostly worked" is a failed run.
