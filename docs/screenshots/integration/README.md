# Combined PR verification — 2026-10-24

No product regression was found in the paths exercised below. This is a cumulative
build and runtime check, beyond the earlier pairwise merge checks. The evidence
commit adds documentation and captures; it does not change the tested runtime.

## Exact candidate

| Input | Revision |
| --- | --- |
| Latest fetched main, including merged #28/#29/#32 | `3a764b4b807f5fd7220eaf1fee7d46ca4cfec148` |
| #27 full Gmail previews | `32e8717ddf86b839e8490c784c343afdee281111` |
| #30 TLS hardening | `35884ff788192d248a698d86ce0721b32113bb9d` |
| #31 authenticated pairing and Protected context | `c28f23c97620c3bf76c2217e18e853cd52a908b9` |
| Local composite commit | `d679e4ea11104e2b5d27b6ccae8b046fad8fca0f` |
| Composite tree | `3c0fff6a67633e88db7e752bbc8431087250183d` |

The local integration branch was not merged into main or published as another PR.
Its reproducible inputs and hashes are also in [manifest.json](manifest.json).

```sh
git switch --detach 3a764b4b807f5fd7220eaf1fee7d46ca4cfec148
git merge --no-ff --no-edit 32e8717ddf86b839e8490c784c343afdee281111
git merge --no-ff --no-edit 35884ff788192d248a698d86ce0721b32113bb9d
git merge --no-ff --no-edit c28f23c97620c3bf76c2217e18e853cd52a908b9
git rev-parse 'HEAD^{tree}'
```

Use a disposable checkout for those commands. The resulting file tree is the
identity to compare; newly created merge commit timestamps may differ.

Pinned Rust 1.99.1 built the binary and examples in a fresh, integration-specific
Cargo target. Debug binary SHA-256:
`4ed401fefdcecfb15f6d8b97e2a79b6bffab6de136977da13d97fadaa0e32669`.
The run used an isolated application home and loopback port 19217. Generation
used real Ollama at `http://127.0.0.1:11434/v1`, model `qwen3.8:27b-mlx-cg`,
digest `c4472360741adbd8757713b465fb169f2af2927cd6756998f9b8f33652330196`.
No mock model generated these acceptance answers.

## Executed checks

| Path | Result |
| --- | --- |
| Build and lint | Binary/examples build, scoped clippy for core/connectors/researcher with `-D warnings`, formatting, JS syntax, actionlint and ShellCheck passed. |
| Focused security regressions | 14 passed: 6 egress/TLS checks, 2 automatic-write checks, full Gmail preview, 2 pairing checks, impostor refusal, wildcard-address mapping and settings whitelist/acknowledgement. These were rerun on the combined tree. |
| Runtime selftest | Config, ten-node graph, closed external client, connectors, pinned egress, audit chain and actual local-model reachability passed. |
| In-app browser + real Ollama | Authenticated pairing/fragment scrubbing, corpus answer, Protected context tooltip, duplicate-Enter draft preservation, copying the answer, New chat, autotune, reindex, policy save, key validation, injection guard and restart invalidation passed. No captured browser warning/error logs. |
| Policy persistence | Tightened hourly budget 20 → 19; cancelled relaxation left 19 on disk; accepted restoration persisted 20 and emitted `policy_relaxed`. External payload permissions stayed closed. |
| Running HTTP guards | Unauthenticated 401, foreign Host 421, foreign Origin 403. Attempts to set `external.tls_roots` or `tools.auto_approve_writes` through the UI API returned 400. Strict CSP was present. Home/config/key modes were 0700/0600/0600. |
| Actual CLI attachment | Real Qwen read the synthetic review and returned SILVER-MOON-9317, 73 minutes, and the next action. CLI status used protected context. |
| Native Safari + real Ollama | The actual bundled `app` command paired with the existing listener. Safari returned two hours/37 days from the corpus. A file selected with Safari's native picker then produced SILVER-MOON-9317, 73 minutes and the attachment's next action. |
| Local app packaging | `bundle-app.sh` assembled and ad-hoc signed an arm64 debug app; codesign/lipo checks and ditto ZIP extraction/reverification passed. Listener PID was unchanged across `app` launch. This is not Developer ID/notarized release acceptance. |
| Merged uninstall fix | Actual script under stubbed destructive commands passed safe/unsafe aliases, relative home + CDPATH, unrelated-data preservation and absolute plist arguments using Bash 3.2. No real service, Keychain item or user data was removed. |
| Merged archive/workflow fixes | Actual tar creation/extraction, manual binary installation and isolated init passed using the combined arm64 debug binary. Native Mach-O fixtures accepted both universal slices and rejected missing x86_64. These fixtures are not a universal release binary build. |
| Audit | Chain verified with 23 records at the final audit check after browser, native and CLI paths; the earlier status capture shows the chain at 17 records. |

The shell sandbox initially prevented LaunchServices from opening the local URL
(-10661). The unchanged app command succeeded through authorized access. The
in-app browser's file chooser did not deliver a selection; the native Safari
picker successfully exercised the actual browser attachment path. Neither issue
required weakening product authentication, TLS or approval controls.

## Seven captures from the combined binary

All images below are actual in-app-browser captures of the combined candidate,
visually inspected before publication. Only synthetic corpus content is shown.
Native Safari acceptance is recorded above; its unrelated tabs were not uploaded.

![Real combined Qwen answer with Protected context and copied answer](01-live-qwen-chat.png)

![Combined local model and completed autotune](02-model-settings.png)

![Policy saved with external payload permissions closed](03-policy-controls.png)

![Invalid synthetic key rejected before storage](04-key-validation.png)

![Combined health, graph and verified audit chain](05-status-audit.png)

![Injection attempt refused before model execution](06-injection-guard.png)

![Old session rejected after the combined server restarts](07-session-expired.png)

## Limits

- `all-minilm` is not installed: index/reindex produced one chunk and zero
  embeddings. Retrieval success here is keyword-only, not semantic acceptance.
- Autotune shows the model's advertised 262,144-token ceiling; Ollama's loaded
  context was 32,768. Vision inference was not exercised.
- A separate disposable home enabled public Google search. The combined CLI and
  real Qwen reached the actual tool, which returned CAPTCHA/consent refusal.
  No successful search URL was claimed. SerpAPI credentials were absent.
- Live Anthropic/xAI, Gmail/Calendar/Telegram/SMS/1Password credentials, actual
  external write effects, real Keychain mutation, launchd install/purge,
  Gatekeeper/quarantine and a release-optimized universal build were not tested.
- Hosted CI remains separate. Current PR checks had an account billing/spending
  block; local success does not turn those failed/cancelled/skipped jobs into passes.

The local ad-hoc ZIP hash was
`84bd80ecba52cf6ea2290b7607f6cd339fa577cec1a87cde486f86e246835c22`.
It identifies a local debug acceptance artifact, not a published release.
