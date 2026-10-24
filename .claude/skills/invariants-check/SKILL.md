---
name: invariants-check
description: Check a change against INVARIANTS.md (I1-I8) before it is committed. Use when touching the graph, gates, audit log, sanitizer, HTTP/UI guard, external-model code, connectors, config validation, or Cargo dependencies.
---

# invariants-check

`INVARIANTS.md` is the contract: each row names the rule, the code that enforces it and the test that fails if it breaks. A change that weakens one is a bug, not a trade-off.

1. Read `INVARIANTS.md` and `git diff main...HEAD` (or the working tree diff).
2. Map each touched file to the invariants it can affect:
   - `crates/cg-core/src/agent.rs`, `cg-graph`: I1 (`retrieve` entry, everything ends at `audit_logger`), I3 (external model gates, one construction site in `Agent::new`), I7 (remote origins, tainted turns).
   - `sandbox.rs`, any `Command` use, `deny.toml`, new dependencies: I2 (no telemetry, cleared child env). Never add a crate from the `deny.toml` bans, or `openssl-sys` / `native-tls`.
   - `crates/cg-audit`: I4 (HMAC chain, signed head, no plaintext queries or senders).
   - `sanitizer.rs`, `attachments.rs`, retrieval and tool-output paths: I5.
   - `cg-core/Cargo.toml`: I6, core must never depend on `cg-connectors`.
   - `serve.rs`, `settings.rs`, `config.rs`, `ui/`: I8 (loopback Host only, no cross-origin, no inline script, whitelisted settings, audited relaxations) and the loopback checks in `Config::validate`.
3. For each affected invariant, name the existing test that covers the change and run it by name, for example `cargo test -p cg-core --locked topology_`. If the change adds a code path the tests do not reach, add a test.
4. A change that alters an invariant's wording or behavior needs a test and a `SECURITY.md` note (the file says so). Update the table row too.
5. Output: one line per affected invariant, `I# held / changed / not covered`, plus the test that proves it. Call out anything you could not verify.
