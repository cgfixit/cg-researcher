<!--
Baseline: cgfixit/CyClaw and cgfixit/CG-agent-harness PR templates, adapted to
cg-researcher. GitHub discovers this file in .github/, not .github/workflows/.
Keep every section. Replace prompts with evidence; use N/A plus a reason where
appropriate. Never tick a check you skipped. The checker validates structure,
not the truth of a security claim, scan result, or release attestation.
Branch / title / integration policy:
- Base is main, NOT cg/main and NOT another feature branch. No stacked bases.
  The repository's default branch was renamed to main; do not restore the old name.
- Agent heads use the actual driver: claude/, codex/, grok/, kimi/, copilot/,
  perplexity/, cyclaw/ (or CyClaw/), or agent/ only if the driver is unknown.
  Human cg/, fix/, feat/, docs/, security/, infra/, hotfix/, release/, and
  dependency-bot branches are also supported. Use a short kebab-case feature.
  There are no tracked branch-name hooks here; do not claim otherwise.
- Title: [prefix] - Short descriptive sentence. Prefixes: invariant, governance,
  security, graph, rag, model, connectors, ui, macos, release, infra, fix, feat,
  refactor, test, docs, deps. Choose what the diff actually does.
- Prefer a draft until a human reviews the evidence; prefer squash-and-merge.
  Record command + exit code + tested SHA, failures, skips, and residual risk.
- Truth order: source/Cargo graph and shipped config/cg.toml, then INVARIANTS.md,
  SECURITY.md and CLAUDE.md, then README.md/docs. Flag contradictions.
-->
## Proposed changes
<!-- Explain the whole diff against main, not just the first commit. Name files,
functions/settings, intended behavior, deliberate non-goals, and related issues. -->
## McLuhan Tetrad
<!-- Analyze this change as a medium. Four simultaneous effects (not sequential).
Replace prompts with evidence from the diff. Use N/A + reason where none apply. -->
- **Enhances**: <!-- What capability, process, or signal does this amplify? -->
- **Obsolesces**: <!-- What prior practice, tool, path, or default does this push aside? -->
- **Retrieves**: <!-- What earlier pattern, constraint, or safeguard does this revive? -->
- **Reverses into**: <!-- When pushed to extreme (overuse, scale, edge cases, misconfig), what does this flip into? -->
## Invariant / Governance Impact
<!-- Name applicable IDs and explain before -> after with test evidence. For a
non-runtime diff, say none affected and name the guarantees left unchanged.
These are cg-researcher's EIGHT invariants, not the harness's process boundary:
I1: retrieve is the entry; every path converges on audit_logger (cg-core/agent.rs,
    cg-graph). Preserve the bounded model/tool loop and denied-call results.
I2: no telemetry; cleared child env/kill-switches; stderr logs; deny.toml bans.
I3: external model needs hybrid + external.enabled + per-query origin-authorized
    consent; no tools, tainted output, redaction, rules, budgets and pinned hosts.
I4: protobuf HMAC-SHA256 audit chain, 0600 key, signed head and append lock;
    queries/senders/tool args remain keyed fingerprints, not plaintext.
I5: scan input, RAG chunks, tool output, attachments and soul at every load.
I6: cg-core never depends on cg-connectors; connectors are trait objects behind
    tool_gate. This is crate/dependency isolation, NOT a child-process boundary.
I7: Telegram/SMS fail closed without allowlists; remote tools read-only, remote
    origins cannot approve writes, tainted turns never auto-approve writes.
I8: loopback Host/Origin guards, bearer/pairing/session auth, no-inline CSP,
    whitelisted settings, explicit acknowledgement + audit for rule relaxations.
Also check quoted FTS5 terms, query_only reads, owner-only files, shipped loopback
model/bind defaults and explicit allow_non_loopback overrides, no SQLite
extensions, unsafe_code=forbid, pinned HTTPS Egress with no redirects/proxy.
A deliberate invariant change requires a regression test and SECURITY.md note.
Do not weaken shipped defaults to make a test pass. -->
## Types of changes
<!-- Tick all applicable types. A template or workflow is infrastructure, not a
runtime feature. Security/dependency/CI work is not docs-only. -->
- [ ] Bugfix
- [ ] New feature
- [ ] Breaking change / migration
- [ ] Security / privacy / vulnerability remediation
- [ ] Invariant / governance
- [ ] Dependencies / supply chain
- [ ] Graph / RAG / model routing
- [ ] Connectors / gateways / write approval
- [ ] UI / HTTP / settings
- [ ] macOS install / launchd / packaging / release
- [ ] CI / infrastructure / templates
- [ ] Refactor / tests
- [ ] Documentation
## Benefits / why
<!-- Concrete operator/maintainer benefit. Explain local/offline behavior and
whether credentials, network traffic, cost, disk format, or permissions change. -->
## Risks to monitor
<!-- Residual risks; exact failure signal (test/log/audit event); skipped/failed
checks and why. Call out migration/data-loss risks and real-provider/macOS gaps.
Rollback: revert the squash commit on main; describe additional data/schema,
config, launchd or credential recovery when reverting code alone is insufficient.
Never enable external access, auto-approval, or broad egress as a workaround. -->
## Security / secvulnscan
<!-- Required even for CI/docs: say what changed or N/A with a reason. Record
scanner version, tested SHA, command, exit code, findings and dispositions.
Current jobs: supply-chain (audit.yml), gitleaks, workflow-lint, secvulnscan.
Fresh scans, not the historical security/audit-report.md, support a clean claim.
Run applicable steps with installed, pinned tools (no customer/provider secrets):
  cargo audit --deny warnings
  cargo deny check advisories bans licenses sources
  osv-scanner scan source --lockfile Cargo.lock --lockfile fuzz/Cargo.lock --lockfile e2e/package-lock.json --no-call-analysis=rust --no-resolve
  gitleaks git --redact --exit-code 1 .
  gitleaks dir --redact --exit-code 1 .
  actionlint
  zizmor --offline .github/workflows
  shellcheck scripts/*.sh e2e/*.sh install.command uninstall.command init.sh
CI ignores repository OSV suppression config and requests all vulnerability
results. Reviewed exceptions require an explicit policy change, not a hidden
osv-scanner.toml override. OSV queries disclose dependency names/versions; never
send operator corpus/keys.
Rust call analysis stays OFF because it can execute build scripts. --no-resolve
avoids manifest dependency resolution. All three tracked lockfiles are required.
Full-history gitleaks needs an unshallow clone. The dir scan covers uncommitted
changes; .gitignore exclusions still apply. Missing tools, API failures, stale
DBs and resource exhaustion are NOT clean results. Record advisory IDs,
reachability, fix/compensating control, and owner/expiry for any exception.
Security review: injection/taint + origin/write gates; external consent/egress;
audit tampering/concurrency; secrets/Keychain; UI auth/CSP; dependency/CI trust.
CI metadata checking is not a trust boundary: branch protection/review must
protect its workflow and script from being weakened in the same PR.
Do not paste corpus text, mail, keys, SMS PINs, pairing codes, or raw tokens. -->
## Checklist
<!-- Tick only completed items on the recorded SHA. Leave skipped/inapplicable
rows open and explain them. Green CI is not proof of live provider behavior. -->
- [ ] Read INVARIANTS.md, SECURITY.md, CLAUDE.md and relevant source/config
- [ ] Explained invariant impact with evidence (or justified no runtime impact)
- [ ] `cargo fmt --all --check` passed
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings` passed
- [ ] `cargo test --workspace --locked` passed
- [ ] Security / secvulnscan results, findings and skips recorded
- [ ] Relevant browser tests, coverage and fuzz results recorded (or N/A with reason)
- [ ] No new mandatory online model, telemetry, exposed bind, or open write default
- [ ] Relevant docs/config/migration notes updated, or not needed with a reason
- [ ] `node --test scripts/check-pr-template.test.cjs` passed for template/checker changes
- [ ] PR body checked with the shared local checker using the actual title/base/diff
<!-- Local preflight (Node 20+; no npm install or GitHub token required):
  git diff --name-only -z origin/main...HEAD | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.stringify(s.split("\0").filter(Boolean))))' > /tmp/pr-files.json
  node scripts/check-pr-template.cjs --body /path/to/body.md --title '[infra] - Example change' --base main --branch <actual-head> --files /tmp/pr-files.json
For renames, include both old and new paths (or GitHub file objects with
previous_filename). --files [] deliberately asserts no runtime files changed.
UI changes: cargo build --locked -p cg-researcher --bins --examples; then in e2e/:
  npm ci --ignore-scripts --no-audit --no-fund
  npx playwright install --with-deps --only-shell chromium webkit
  npx playwright test
Record Chromium/WebKit results; WebKit is not native Safari/macOS verification.
Coverage: existing coverage.yml enforces 70% lines; record result and tested SHA.
Parser/guard changes: existing fuzz.yml targets attachments, sanitizer and stream;
record each target, duration, seeds/artifacts, and crash results. A bounded run is not
proof that no bugs exist. Do not claim these jobs executed from their YAML alone. -->
## macOS Apple Silicon / release
<!-- Write N/A + reason if packaging/runtime/install behavior is untouched.
Otherwise record what actually ran on macOS and attach CI run/artifact links.
Linux validation is not macOS, Keychain, launchd, or Gatekeeper validation.
Existing ci.yml: macos-15 + macos-26 build/test, throwaway-Keychain tests,
x86_64-apple-darwin cross-check, MSRV 1.90. Install smoke runs on push/manual/
schedule, NOT PR events. Record a manual run on this branch when needed.
Apple Silicon release steps on an arm64 Mac (macOS 14+ target):
  uname -m                     # must be arm64
  MACOSX_DEPLOYMENT_TARGET=14.0 cargo build --release --locked -p cg-researcher --target aarch64-apple-darwin
  bash scripts/bundle-app.sh
  plutil -lint dist/cg-researcher.app/Contents/Info.plist
  lipo -verify_arch dist/cg-researcher.app/Contents/MacOS/cg-researcher arm64
  codesign --verify --strict --deep dist/cg-researcher.app
  (cd dist && shasum -a 256 -c cg-researcher-macos-arm64.app.zip.sha256)
Use a disposable home to test --version, init, selftest and audit verify; verify
0700 home/0600 config, loopback health, 401 auth, 421 Host, 403 Origin and CSP.
Exercise throwaway Keychain, launchd service + maintenance, installer/uninstaller
and purge ONLY in an isolated test account/home, never against operator data.
Round-trip unzip with ditto and re-check signature; smoke app/UI pairing,
server reuse and no duplicate listener. Record model/network-dependent skips.
release.yml already builds the arm64 app + universal CLI and publishes them; do not duplicate that build.
A manual `gh workflow run release.yml --ref <this-branch>` with no inputs publishes an unreviewed
`nightly-YYYYMMDD-<sha7>` prerelease for that SHA (not Latest). It is not an artifact-only build.
Re-running a SHA whose auto release already has the app and CLI assets skips the rebuild instead of failing.
Dispatch a branch only when you intend to publish that tip.
Check the universal CLI has arm64 AND x86_64 slices, signatures and SHA-256.
Before a HUMAN creates a v* tag: reconcile Cargo workspace version, rendered
Info.plist version and tag, inspect artifacts/checksums and current CI/security.
A `v*` tag push publishes a public GitHub Release immediately (not a draft). Manual dispatch and the
daily schedule publish prereleases and do not move GitHub Latest.
Verify public-repository app provenance with `gh attestation verify <zip> --repo cgfixit/cg-researcher`.
Ad-hoc signing is NOT Developer ID or notarization; document Gatekeeper
quarantine and Keychain identity/rebuild prompts honestly. No tag/publish/signing
credentials in PR CI. Release evidence must include artifact and workflow URLs. -->
## Further comments
<!-- Evidence table: command/check | tested SHA | exit/result | artifact/log link.
Name targeted regression tests and what they prove, plus what they do not prove.
List skipped commands with reasons. Record branch head and main base SHAs;
a committed test run may reference the tree-equivalent parent SHA, but say so.
For core changes include before/after invariant notes and compensating controls.
For rule/schema changes include config/data migration and non-code rollback. -->
## Suggested merge order of open PRs
<!-- List real open PRs: PR/status, Impact, Action (three short lines per PR).
Chronological unless dependencies justify otherwise. If alone, write
"independent, only open PR". Use Unverified when no trial merge was run.
Safe = clean trial merge against the named main SHA (NOT proof of green CI).
Dirty = conflicts; Blocked = failed checks, dependencies or not-ready draft.
Record trial merge date + base SHA + command/result, or explicitly "trial merge
not run" and why. Never mark Safe from GitHub's mergeability label alone.
Use a clean disposable worktree for git merge --no-commit --no-ff <head>, then
abort only if MERGE_HEAD exists; never disturb a contributor's working tree.
Recheck after main moves. Rebase only your own branch; a shared branch needs
coordination. Force-with-lease requires owner approval; never force main. -->
## ELI5
<!-- Keep this the LAST heading. Plain but technical: what was missing, what the
whole diff changes (including later commits), files/functions/settings involved,
what could break and the exact detection signal, what was tested vs reasoned,
and rollback. No marketing, no softened gates, no fabricated execution claims.
Replace the timestamp below with a real Eastern time; leave nothing after it. -->
Last updated: YYYY-MM-DD HH:MM ET
