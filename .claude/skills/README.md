# .claude/skills

Claude Code skills, one `SKILL.md` per folder, invoked as `/<folder>` or loaded by the model when the description matches. Loading a skill grants no push, merge or release authority; `CLAUDE.md` and `INVARIANTS.md` stay the contract.

Truth order when a skill and a document disagree: code > `config/cg.toml` > `INVARIANTS.md` > `CLAUDE.md` > `README.md` > the skill.

| skill | use it when | writes to the tree |
|---|---|---|
| [`verify/`](verify/SKILL.md) | before any commit or PR: fmt, clippy `-D warnings`, shellcheck, `cargo deny`, then `init` / `selftest` / `audit verify` in a throwaway home | no |
| [`invariants-check/`](invariants-check/SKILL.md) | the diff touches the graph, gates, audit log, sanitizer, HTTP/UI guard, external-model code, connectors or Cargo dependencies; maps files to I1-I8 and names the test for each | no (may add a test) |
| [`config-guard/`](config-guard/SKILL.md) | `config/cg.toml`, `config.rs` or `settings.rs` changed; asserts the shipped defaults are still fail-closed (offline, external off, connectors off, loopback, quoted booleans refused, overlay whitelist) | no |
| [`run-cg-researcher/`](run-cg-researcher/SKILL.md) | you need the real binary running: mock model, throwaway home, `serve`, `/query`, UI pairing, Playwright, audit verify | no (throwaway `--home` only) |
| [`optimizer/`](optimizer/SKILL.md) | asked to speed up, shrink or profile; measure first, one change at a time, never through a guard | yes |
| [`gotchas/`](gotchas/SKILL.md) | before install, verify, the mock model, CI or release work, or when a check passes suspiciously fast; the "looks green for the wrong reason" list | no |

Typical order for a code change: `run-cg-researcher` or the unit test that covers it, then `invariants-check` and `config-guard` if their triggers apply, then `verify` last.

Reference: the layout and tone follow the skills in `cgfixit/CG-agent-harness` (`.claude/skills/`), adapted to this repo's crates, gates and tests. Nothing here is a runtime plugin; the binary does not read this directory.
