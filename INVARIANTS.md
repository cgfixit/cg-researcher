# Invariants

Each invariant names the CyClaw rule it ports and the test that would fail if it broke.
Change one only with a test and a SECURITY.md note.

| id | invariant | CyClaw origin | enforced by | test |
|---|---|---|---|---|
| I1 | `retrieve` is the unconditional entry; every path ends at `audit_logger` | Rules 1, 3 | `cg-core/src/agent.rs` graph + `CompiledGraph::sink` | `agent::tests::topology_entry_is_retrieve_and_everything_converges_on_audit`, `cg-graph` tests |
| I2 | No telemetry: no telemetry SDK linked; every child process gets a cleared env + kill-switch vars; logs to stderr only | telemetry kill-switch | `sandbox::clean_command`, `deny.toml` bans, `init_logging` | `sandbox::tests::child_env_is_cleared_and_killswitched`, `cargo deny check bans` |
| I3 | External model is triple-gated: `mode = hybrid` AND `external.enabled` (client constructed only then, crate-private constructor) AND per-query consent; SMS can never consent | Rule 2 | `Agent::new`, `user_gate`, `runtime::run_turn` | `agent::tests::external_client_requires_hybrid_and_enabled`, `…has_exactly_one_construction_site`, `low_score_in_hybrid_pauses_without_calling_any_model`, `sms::tests::first_poll_primes_without_replay` |
| I4 | Audit records are protobuf, HMAC-SHA256 chained, keyed by a 0600 key; queries/senders stored only as keyed fingerprints | Rules 3, 7 | `cg-audit` | `cg-audit` tests, `agent::tests::audit_chain_verifies_and_stores_no_plaintext`, `audit verify` |
| I5 | Injection scanning on input, retrieved chunks, tool output, attachments and the soul file (every load, which tightens CyClaw Rule 5) | Rules 4, 5 | `sanitizer`, `guardrail_input`, `Agent::new` | `sanitizer` tests, `agent::tests::injection_is_blocked_before_any_model_call` |
| I6 | Core never depends on connectors; connectors are trait objects behind the tool gate | Rule 9 | Cargo graph | `cg-agent::tests::core_never_depends_on_connectors` |
| I7 | Remote origins (Telegram, SMS) need a non-empty allowlist (fail loud), get read tools only, and cannot approve writes; tainted turns never auto-approve writes | new | `tool_gate`, gateway `build` | `telegram::tests::*`, `sms::tests::pin_allowlist_and_lockout`, `agent::tests::remote_origins_are_never_offered_write_tools`, `auto_approve_never_applies_to_tainted_turns` |

Also: model URL and HTTP bind must be loopback (`Config::validate`); all connector HTTP goes through
a host-pinned, HTTPS-only, no-redirect, no-proxy `Egress`; the API key is compared in constant time.
