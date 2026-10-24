# .claude

Claude Code project configuration. The instructions loaded every session are the root [CLAUDE.md](../CLAUDE.md); nothing in this folder grants authority beyond it.

- [`settings.json`](settings.json): pre-approves the `cargo` commands the local gate uses, the repo scripts, and read-only `git` / `rg` queries. Anything else prompts; do not work around a prompt.
- [`skills/`](skills/README.md): one `SKILL.md` per folder, invoked as `/<folder>`: `verify`, `invariants-check`, `config-guard`, `run-cg-researcher`, `optimizer`.

There is no `SessionStart` hook. The toolchain comes from `rust-toolchain.toml` through rustup, and `cargo fetch --locked` is enough to prime a fresh checkout.
