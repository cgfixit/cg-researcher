---
name: config-guard
description: Statically check that config/cg.toml (and any config or settings code change) still ships fail-closed - offline mode, external model off, every connector disabled, write auto-approval off, loopback-only model URL and bind, quoted booleans refused, UI overlay whitelist intact. Use before merging a change to config/cg.toml, config.rs, settings.rs, or the shipped defaults, or when asked to check the config.
---

# config-guard

One question: does the shipped configuration still honor the contracts the running system assumes? This is not a graph or gate review (that is `invariants-check`). Config is the single source of every tunable, and the fail-closed defaults are load-bearing for I3, I7 and I8.

The checker is the Rust test suite, not a hand parser. A filter that matches zero tests is not evidence. Reading TOML and saying it "looks closed" is not evidence either.

## Contracts

| id | severity | contract | locked by |
|---|---|---|---|
| C1 | FAIL | `app.mode = "offline"` and `external.enabled = false` in the shipped file (gates 1 and 2 of I3 closed) | `config::tests::shipped_config_parses_and_keeps_safe_defaults`, `defaults_are_offline_and_loopback` |
| C2 | FAIL | Every `[connectors.*]` table ships `enabled = false`; an enabled connector with an empty allowlist is a startup error, never "allow everyone" | `shipped_config_parses_and_keeps_safe_defaults`, `telegram::tests::*`, `sms::tests::pin_allowlist_and_lockout` |
| C3 | FAIL | `tools.auto_approve_writes = false`, `tools.remote_origins_read_only = true` | `defaults_are_offline_and_loopback`, `agent::tests::remote_origins_are_never_offered_write_tools` |
| C4 | FAIL | All `[external.rules]` ship closed: `send_local_context`, `allow_attachment_text`, `allow_images`, `allow_telegram` false; budgets and caps inside the ranges `Config::validate` enforces | `defaults_are_offline_and_loopback`, `Config::validate` |
| C5 | FAIL | `llm.base_url` and `server.host` are loopback; `allow_non_loopback` is false; non-loopback is refused at load (the only overrides are that key and the `CG_ALLOW_NON_LOOPBACK_BIND=1` environment variable, both documented in SECURITY.md and neither settable from the UI) | `non_loopback_llm_is_refused_by_default`, `Config::validate` |
| C6 | FAIL | Quoted booleans (`"true"`) and unknown keys are rejected, so a typo cannot silently open a gate | `quoted_bool_and_unknown_keys_are_refused` (`deny_unknown_fields` on every config struct) |
| C7 | FAIL | `external.model` must match `external.provider` (`claude-*` for anthropic, `grok-*` for xai); `xai_region` is `global` or `us` | `external_model_must_match_provider`, `Config::validate` |
| C8 | FAIL | Secrets are references only (`env:`, `op://`, `keychain:`, `file:`); no inline key in `cg.toml` or in `ui-settings.toml` | `secrets` tests, `settings_require_auth_whitelist_and_ack_for_relaxations` |
| C9 | FAIL | The UI overlay can change only whitelisted keys (model, rules, provider, keys); bind address, loopback rules, connectors and write approval are unreachable from the UI; relaxing a rule needs an ack and writes `policy_relaxed` (I8) | `settings::tests::overlay_cannot_touch_dangerous_keys`, `relaxations_are_detected`, `cg-researcher::tests::settings_require_auth_whitelist_and_ack_for_relaxations` |
| C10 | WARN | Comments in `cg.toml` still describe the actual default (for example the `max_calls_per_hour` numbers and the triple-gate note); `README.md` and `docs/user-guide.md` quote the same values | grep, see below |

## Run

```bash
cargo test -p cg-core --locked config::tests
cargo test -p cg-core --locked settings::tests
cargo test -p cg-researcher --locked settings_require_auth_whitelist_and_ack_for_relaxations
cargo run -q -p cg-researcher --locked -- --home "$(mktemp -d)" init   # the shipped file must load and validate
```

Then diff-read `config/cg.toml` for accidental quoted booleans, a flipped `enabled`, or a non-loopback URL, and grep every value you touched in the docs:

```bash
git diff main...HEAD -- config/cg.toml crates/cg-core/src/config.rs crates/cg-core/src/settings.rs
grep -n 'enabled = ' config/cg.toml
grep -rn '<the value you changed>' README.md docs/ SECURITY.md
```

## Interpret

1. **Broken contract**: fix the TOML, or the code if code is the truth and the TOML drifted. Re-run until green. Never delete or loosen the assertion.
2. **Deliberate re-tune**: the same change set must update the `cg.toml` comment, `INVARIANTS.md` if an invariant row is affected, and `SECURITY.md` (the file requires a note for any invariant change). WARN rows exist so that re-tunes are conscious.
3. **New config key**: it needs a default that keeps the gate closed, `deny_unknown_fields` must still hold, and if the UI may set it, it must be added to the overlay whitelist deliberately, with a test.

## Report

```text
Config Guard: PASS | FAIL
Evidence: <test names and results, init exit code>
Contracts: <one line per C1-C10>
Re-tune: <none | list, with the SECURITY.md note>
Verdict: safe to merge | fix required: ...
```

## Guardrails

- Report-oriented. Do not edit config only to silence a check without an authorized change.
- Never open a shipped gate to make a convenience path green.
- Pair with `invariants-check` when the change also touches the graph, gates, audit, sanitizer or the HTTP guard.
- A skill run is not merge or push authorization.
