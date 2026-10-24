# Invariants

Each invariant names the CyClaw rule it ports and the test that would fail if it broke.
Change one only with a test and a SECURITY.md note.

| id | invariant | CyClaw origin | enforced by | test |
|---|---|---|---|---|
| I1 | `retrieve` is the unconditional entry; every path ends at `audit_logger` | Rules 1, 3 | `cg-core/src/agent.rs` graph + `CompiledGraph::sink` | `agent::tests::topology_entry_is_retrieve_and_everything_converges_on_audit`, `cg-graph` tests |
| I2 | No telemetry: no telemetry SDK linked; every child process gets a cleared env + kill-switch vars; logs to stderr only | telemetry kill-switch | `sandbox::clean_command`, `deny.toml` bans, `init_logging` | `sandbox::tests::child_env_is_cleared_and_killswitched`, `cargo deny check bans` |
| I3 | External model (Anthropic or xAI) is triple-gated: `mode = hybrid` AND `external.enabled` (client constructed only then, one crate-private constructor, pinned hosts) AND per-query consent (`prefer_external` from CLI/HTTP/UI counts; SMS never; Telegram only with `rules.allow_telegram`). It never gets tools, its output taints the turn, and the outbound payload is redacted, budgeted and rule-gated | Rule 2 | `Agent::new`, `user_gate`, `outbound`, `external_fallback`, `runtime::run_turn` | `agent::tests::external_client_requires_hybrid_and_enabled`, `…has_exactly_one_construction_site`, `prefer_external_is_consent_from_local_origins_only`, `telegram_consent_needs_the_allow_telegram_rule`, `outbound_query_is_redacted_and_capped`, `local_context_is_sent_only_when_the_rule_allows`, `exhausted_budget_never_calls_the_provider` |
| I4 | Audit records are protobuf, HMAC-SHA256 chained, keyed by a 0600 key, with a signed head against tail truncation and a cross-process append lock; queries/senders stored only as keyed fingerprints | Rules 3, 7 | `cg-audit` | `cg-audit` tests (incl. `two_writers_on_one_log_keep_a_single_chain`, `whole_record_tail_truncation_is_detected_by_head`), `agent::tests::audit_chain_verifies_and_stores_no_plaintext`, `audit verify` |
| I5 | Injection scanning on input, retrieved chunks, tool output, attachments and the soul file (every load, which tightens CyClaw Rule 5) | Rules 4, 5 | `sanitizer`, `guardrail_input`, `Agent::new` | `sanitizer` tests, `agent::tests::injection_is_blocked_before_any_model_call` |
| I6 | Core never depends on connectors; connectors are trait objects behind the tool gate | Rule 9 | Cargo graph | `cg-researcher::tests::core_never_depends_on_connectors` |
| I7 | Remote origins (Telegram, SMS) need a non-empty allowlist (fail loud), get read tools only, and cannot approve writes; tainted turns never auto-approve writes | new | `tool_gate`, gateway `build` | `telegram::tests::*`, `sms::tests::pin_allowlist_and_lockout`, `agent::tests::remote_origins_are_never_offered_write_tools`, `auto_approve_never_applies_to_tainted_turns` |
| I8 | The UI/HTTP surface answers only loopback Host headers, refuses cross-origin requests, serves a no-inline CSP, can change only whitelisted settings, and needs explicit acknowledgement plus an audit record to relax any rule | new | `serve::guard`, `settings::check_overlay`, `settings::relaxations` | `cg-researcher::tests::host_and_origin_checks_block_dns_rebinding`, `every_response_carries_strict_security_headers`, `settings_require_auth_whitelist_and_ack_for_relaxations`, `ui_assets_have_no_inline_script_or_html_injection_sinks` |

Also: `unsafe_code = "forbid"` across the workspace and no SQLite extensions, so memory safety
outside SQLite rests on the compiler. FTS5 queries are built only from quoted tokenizer terms
(`rag::tests::fts_query_neutralizes_fts5_syntax`); the index file is 0600 and the serving
connection is `query_only` (`rag::tests::running_retriever_sees_a_rebuild_from_another_connection`).
Model URL and HTTP bind must be loopback (`Config::validate`); all connector HTTP goes through
a host-pinned, HTTPS-only, no-redirect, no-proxy `Egress`; the API key is compared in constant time.
