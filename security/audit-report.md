# cg-agent supply-chain and security audit

Date: 2026-10-24. Target: `cgfixit/cg-agent`, branch `cg/main`, `Cargo.lock` with 311 packages.

## Bottom line

- **0 known vulnerabilities and 0 RustSec warnings.** Two independent databases agree: RustSec through cargo-audit, and OSV through osv-scanner.
- **No banned crates.** Telemetry SDKs, OpenSSL and native-tls are all absent, and cargo-deny enforces this in CI.
- The only open items are 5 accepted risks, listed below. None of them is a CVE.

Caveat: a clean scan only means nothing known is present today. It does not show the code is free of vulnerabilities. Reachability analysis was skipped because there were no findings to analyse.

## Scanner matrix

| Tool | Version | Result |
|---|---|---|
| cargo-audit (RustSec) | 0.22.2 | 0 vulns, 0 warnings (unmaintained/yanked/unsound) |
| osv-scanner | 2.7.0 | 0 vulns across 311 packages |
| cargo-deny | 0.20.2 | advisories ok, bans ok, licenses ok, sources ok; warnings for duplicate versions only (foldhash ×2, hashbrown ×3, syn ×2) |
| clippy `-D warnings` | toolchain 1.99.1 | clean (workspace, all targets); MSRV 1.90.0 `cargo check --all-targets --locked` passes |
| zizmor (GH Actions) | 1.31.1 | 0 findings; pedantic mode gives 3 help-level concurrency-limit notes |
| actionlint | 1.7.12 | clean |
| shellcheck | distro | clean on all `.sh` / `.command` |

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

## Accepted risks

| ID | Issue | Why accepted / mitigation |
|---|---|---|
| CG-ACC-001 | Deleting whole records from the end of the audit log goes undetected | The hash chain catches byte flips, reordering and mid-frame truncation; all three were verified in the e2e run. To also catch tail deletion, store the head hash somewhere external. |
| CG-ACC-002 | On macOS, `security add-generic-password -w` puts the secret on argv | Only the same user can see it, and only while `store` runs. This fits the single-operator model. Reads go through stdout. |
| CG-ACC-003 | Duplicate transitive crate versions | No advisories. The cost is binary size and build time only. |
| CG-ACC-004 | An oversized body returns 400 instead of 413 | The limit itself is still enforced. Only the status code is wrong. |
| CG-ACC-005 | No checksum was published for the cargo-audit 0.22.2 release binary used in the local scan | CI builds cargo-audit from crates.io with `--locked` and does not use that binary. |

## Not covered

- No fuzzing.
- No `cargo-geiger` count of unsafe code in dependencies; `forbid(unsafe_code)` covers first-party crates only.
- No SBOM was produced. `cargo cyclonedx` would be the next step.
- Not built or run on macOS or Windows. macOS CI exists (`macos-15`) but has not run yet.

Raw machine-readable output is in `findings.json` and `findings.sarif`. The SARIF file can be uploaded with `github/codeql-action/upload-sarif`.
