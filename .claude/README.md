# .claude

Claude Code project configuration. The instructions loaded every session are the root [CLAUDE.md](../CLAUDE.md); nothing in this folder grants authority beyond it.

- [`settings.json`](settings.json): pre-approves the `cargo` commands the local gate uses, `init.sh`, `scripts/lint.sh`, and `git status` / `diff` / `log` (the install, uninstall and bundle scripts are deliberately not pre-approved). `cargo run` is deliberately not pre-approved (a prefix rule cannot force a throwaway `--home`) and `rg` is not either (`--pre` runs commands); anything else prompts; do not work around a prompt.
- [`skills/`](skills/README.md): one `SKILL.md` per folder, invoked as `/<folder>`: `verify`, `invariants-check`, `config-guard`, `run-cg-researcher`, `optimizer`, `gotchas`.

There is no `SessionStart` hook. The toolchain comes from `rust-toolchain.toml` through rustup, and `cargo fetch --locked` is enough to prime a fresh checkout.
