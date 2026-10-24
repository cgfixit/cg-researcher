# cg-researcher supply-chain and security audit

Date: 2026-10-24. Target: `cgfixit/cg-researcher`, branch `cg/main`, `Cargo.lock` with 311 packages.

## Bottom line

- **0 known vulnerabilities and 0 RustSec warnings.** Two independent databases agree: RustSec through cargo-audit, and OSV through osv-scanner.
- **No banned crates.** Telemetry SDKs, OpenSSL and native-tls are all absent, and cargo-deny enforces this in CI.
- The only open items are 7 accepted risks, listed below. None of them is a CVE.
- **RAG engine decision:** sqlite-vec was vendored, reviewed and then **removed**. Retrieval is SQLite FTS5 + exact in-RAM cosine in safe Rust, so the C attack surface stays at SQLite alone and no new crates were added (lockfile unchanged at 311 packages).

Caveat: a clean scan only means nothing known is present today. It does not show the code is free of vulnerabilities. Reachability analysis was skipped because there were no findings to analyse.

## Scanner matrix

| Tool | Version | Result |
|---|---|---|
| cargo-audit (RustSec) | 0.22.2 | 0 vulns, 0 warnings (unmaintained/yanked/unsound) |
| osv-scanner | 2.7.0 | 0 vulns across 311 packages |
| cargo-deny | 0.20.2 | advisories ok, bans ok, licenses ok, sources ok; warnings for duplicate versions only (foldhash ×2, hashbrown ×3, syn ×2) |
| clippy `-D warnings` | toolchain 1.99.1 | clean (workspace, all targets); MSRV 1.90.0 `cargo check --all-targets --locked` passes |
| zizmor (GH Actions) | 1.31.1 | 0 findings across 5 workflows, incl. the new `.app` release job |
| actionlint | 1.7.12 | clean |
| shellcheck | distro | clean on all `.sh` / `.command` (incl. `scripts/bundle-app.sh`) |
| gitleaks | 8.30.1 (sha256-verified) | clean on full history and working tree; one public Telegram-docs example token in a sanitizer test is allowlisted by exact match AND path (a canary in the same file is still caught) |

## Hardening applied (see `hardened.diff`)

- Workspace-wide `unsafe_code = "forbid"`, clippy `unwrap_used = warn` and `dbg_macro = deny`.
- Every crate has `publish = false`, so an internal crate name can never be published by accident and dependency-confused.
- Rust MSRV pinned at 1.90, with toolchain 1.99.1 pinned via `rust-toolchain.toml`. CI uses `--locked` everywhere.
- `deny.toml`:
  - only the crates.io registry is allowed, and unknown git sources are denied
  - wildcard version requirements are denied
  - yanked crates are denied
  - licenses must come from an allowlist
  - `opentelemetry*`, `sentry`, `posthog-rs`, `openssl-sys` and `native-tls` are banned (invariant I2)
- TLS uses rustls only.
- Every GitHub Action is pinned to a full commit SHA.
- Downloaded binaries (actionlint, gitleaks) are checked against their sha256.
- Workflows use top-level `permissions: contents: read` and set `persist-credentials: false` on checkout.
- Dependabot has a 7-day cooldown.
- `deny.toml` license allowlist trimmed to licenses actually present (BSD-2-Clause removed).
- Release: `contents: write` only on the publish job, draft-only, checksums re-verified before upload; `id-token`/`attestations: write` only on the `.app` job, used only when the repo is public; no cache in release jobs (no cache poisoning).
- FTS5 queries are built from quoted tokens only (user text can't inject FTS5 operators); the serving connection is `PRAGMA query_only`.

## Accepted risks

| ID | Issue | Why accepted / mitigation |
|---|---|---|
| CG-ACC-001 | A same-user attacker holding `audit.key` can truncate the log and forge a matching head | **Narrowed.** A signed head (`audit.pb.head`) now catches tail deletion by anyone without the key. Defeating a key holder needs an off-host anchor. |
| CG-ACC-003 | Duplicate transitive crate versions | No advisories. The cost is binary size and build time only. |
| CG-ACC-005 | No checksum was published for the cargo-audit 0.22.2 release binary used in the local scan | CI builds cargo-audit from crates.io with `--locked` and does not use that binary. |
| CG-ACC-006 | Ad-hoc code signing means Keychain shows an "Always Allow" prompt after each rebuild | There is no Developer ID or notarization. The prompt is a nuisance, not a bypass. |
| CG-ACC-007 | The external-call budget lives in memory and resets when the process restarts | Restarting needs local access. Provider-side spend limits are the backstop. |
| CG-ACC-009 | The `.app` and release binaries are ad-hoc signed, not notarized | Gatekeeper quarantines downloads. SHA-256 is published; provenance attestation turns on once the repo is public. Source install stays the supported path. |
| CG-ACC-008 | Anyone holding the API key can mint UI pairing codes, and sessions are memory-only | Same-user tool by design. The key file is 0600, and codes are single-use with a 120 s TTL. |

Resolved since the previous report:
- **CG-ACC-002:** the Keychain write no longer passes the secret on argv; it uses `security-framework` 3.7.0 in-process.
- **CG-ACC-004:** an oversized body now returns 413, and a test covers it.
- **New (fixed):** concurrent writers (`serve` + `chat` + scheduled `maintain`) could fork the audit chain. Appends now take an advisory lock on `audit.pb.lock` and resync from the verified tail. Covered by a 6-writer test and a live smoke with 3 concurrent processes plus `serve`.

## Evaluated and rejected: sqlite-vec 0.1.9

Vendored at upstream tag v0.1.9 (sha256 `ba081a47…fd85`) and built with `SQLITE_VEC_OMIT_FS`, then removed. The reasons:
- It is pre-1.0 C (~10k lines) and would have been the workspace's only `unsafe` FFI.
- It has a history of memory-safety bugs. [GHSA-vrcx-gx3g-j3h8 / CVE-2024-46488](https://github.com/advisories/GHSA-vrcx-gx3g-j3h8) is a heap overflow in npy parsing, fixed in 0.1.3; `OMIT_FS` would have compiled that code out.
- Review found `sqlite3_vec_init` writes `*pzErrMsg` without a null check.
- `vec0` is brute-force KNN, so it offers no speed advantage over the in-RAM scan at personal-corpus scale.

Revisit only if the corpus exceeds about 1M chunks, and at that point compare it against an ANN index.

## Not covered

- No fuzzing.
- No `cargo-geiger` count of unsafe code in dependencies; `forbid(unsafe_code)` covers first-party crates only.
- No SBOM was produced. `cargo cyclonedx` would be the next step.
- Not built or run on macOS or Windows. The macOS CI matrix (`macos-15` / `macos-26`) exists but has not run, because GitHub Actions billing is blocked on this account.

Raw machine-readable output is in `findings.json` and `findings.sarif`. The SARIF file can be uploaded with `github/codeql-action/upload-sarif`.
