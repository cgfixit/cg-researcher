#!/usr/bin/env bash
# Local lint gate for cg-researcher. Written for macOS (the product target: /bin/bash 3.2,
# BSD userland) and also runs on Linux. Lints only: no test suite, no network, no writes
# outside target/. CI runs the same script (.github/workflows/lint.yml, macOS runner).
#
#   scripts/lint.sh              everything below
#   scripts/lint.sh --fast       skip cargo clippy (fmt, scripts, workflows, hygiene only)
#   scripts/lint.sh --hygiene    only the tracked-file / .gitignore checks
#
# Sections: hygiene (no data dirs, logs, keys or .enc blobs tracked; .gitignore sane),
# cargo fmt + clippy -D warnings, cargo deny (when installed), shellcheck, actionlint, zizmor (optional), plutil (macOS).
# A missing shellcheck or actionlint is a hard failure under CI and a warning with the brew
# hint elsewhere. cargo deny and zizmor are skipped when absent, even under CI: lint.yml does
# not install them; audit.yml and workflow-lint.yml run both on Linux for every PR.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

fast=0
hygiene_only=0
for a in "$@"; do
  case "$a" in
    --fast) fast=1 ;;
    --hygiene) hygiene_only=1 ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done

fail=0
section() { printf '\n==> %s\n' "$*"; }
bad() { printf 'FAIL: %s\n' "$*" >&2; fail=1; }
indent() { while IFS= read -r l; do printf '  %s\n' "$l"; done <<<"$1"; }
need() { # tool brew-formula
  if command -v "$1" >/dev/null 2>&1; then return 0; fi
  if [[ -n "${CI:-}" ]]; then bad "$1 not installed (CI requires it)"; else
    printf 'skip: %s not installed (brew install %s)\n' "$1" "$2"; fi
  return 1
}

# ---------------------------------------------------------------- hygiene
section "hygiene: nothing private is tracked"
# Data-directory layout (crates/cg-core/src/paths.rs), key material, logs, encrypted blobs.
# Patterns are anchored to whole paths so src files like secrets.rs / paths.rs stay allowed.
# state/, corpus/ and index/ are generic names, so like .gitignore they only count at the
# repo root (a data dir rooted at the checkout); a nested docs/index/ or src/state/ is fine.
private_re='^(state|corpus|index)/|(^|/)(secrets|logs|\.cg-researcher|\.cg-agent|node_modules|target|playwright-report|test-results)/|\.(enc|key|pem|p12|pfx|der|jks|keystore|gpg|pgp|mobileprovision|provisionprofile|keychain|keychain-db|token|secret|log|pb|pb\.head|pb\.lock|sqlite3|sqlite3-journal|sqlite3-wal|sqlite3-shm|db)$|(^|/)(\.env(\..*)?|\.netrc|id_rsa.*|id_ed25519.*|ui-settings\.toml|sms_pin|secrets\.(json|toml|yaml|yml|env)|\.DS_Store)$'
# Public test fixtures (a sample .db for RAG, a DER public cert for egress pinning) are the one
# exception, matching the negations in .gitignore. Keys stay banned there (.key/.pem/.p12 not carved out).
fixture_re='^crates/[^/]+/tests/fixtures/[^/]+\.(db|der)$'
tracked_private="$(git ls-files | grep -E "$private_re" | grep -vE '(^|/)\.env\.example$' | grep -vE "$fixture_re" || true)"
if [[ -n "$tracked_private" ]]; then
  bad "private or generated files are tracked:"; indent "$tracked_private" >&2
else echo "ok: no data dirs, logs, keys or encrypted blobs tracked"; fi

ignored_tracked="$(git ls-files -i -c --exclude-standard || true)"
if [[ -n "$ignored_tracked" ]]; then
  bad "tracked files that .gitignore says to ignore (git rm --cached them, or fix the pattern):"
  indent "$ignored_tracked" >&2
else echo "ok: no tracked file is also ignored"; fi

# Sentinels that must be ignored wherever they appear (a --home inside the repo, a stray key).
for s in secrets/api.key secrets/audit.key x/secrets/sms_pin sms_pin logs/serve.stderr.log logs/audit.pb \
         logs/audit.pb.head logs/audit.pb.lock index/rag.sqlite3 index/rag.sqlite3-wal secrets.toml \
         ui-settings.toml .cg-researcher/cg.toml cgh/cg.toml \
         a.enc a.key a.pem a.p12 a.log .env .env.local .DS_Store e2e/node_modules/x \
         fuzz/corpus/x fuzz/artifacts/x target/x dist/x .claude/settings.local.json; do
  git check-ignore -q "$s" || bad ".gitignore does not cover: $s"
done
# Negative sentinels: patterns must not be so broad they hide legitimate files.
for s in crates/cg-core/tests/fixtures/sample.db crates/cg-core/tests/fixtures/pin.der docs/summary.txt; do
  if git check-ignore -q "$s"; then bad ".gitignore wrongly ignores: $s"; fi
done
for s in summary.txt x.db x.der state/x.db; do
  git check-ignore -q "$s" || bad ".gitignore does not cover: $s"
done
# gitignore has no trailing comments (git treats "pattern  # note" as a literal pattern).
if grep -nE '^[^#[:space:]].*[[:space:]]#' .gitignore; then bad ".gitignore has trailing comments"; fi
echo "ok: .gitignore sentinels"
# The staged-additions net below uses only private_re, so it must catch the same sentinels
# (cg.toml and settings.local.json are legitimately tracked elsewhere and stay out of it).
for s in secrets/api.key logs/audit.pb logs/audit.pb.head logs/audit.pb.lock index/rag.sqlite3 \
         index/rag.sqlite3-wal x/secrets/sms_pin sms_pin secrets.toml ui-settings.toml a.enc a.log .env; do
  printf '%s\n' "$s" | grep -qE "$private_re" || bad "hygiene regex does not match: $s"
done
echo "ok: hygiene regex covers the sentinels"

# Large blobs do not belong here either (models, corpora, databases).
big="$(git ls-files -z | xargs -0 wc -c 2>/dev/null | awk '$1 > 1048576 && $2 != "total" {print $2" ("$1" bytes)"}')"
if [[ -n "$big" ]]; then bad "tracked files over 1 MiB:"; printf '  %s\n' "$big" >&2; fi

# Staged or working-tree additions get the same scan, so a bad `git add` is caught before commit.
staged_private="$(git diff --cached --name-only --diff-filter=A | grep -E "$private_re" | grep -vE "$fixture_re" || true)"
[[ -z "$staged_private" ]] || { bad "staged for commit:"; indent "$staged_private" >&2; }

if [[ "$hygiene_only" == 1 ]]; then [[ "$fail" == 0 ]]; exit; fi

# ---------------------------------------------------------------- rust
section "cargo fmt"
cargo fmt --all --check || bad "cargo fmt --all --check"
if [[ "$fast" == 0 ]]; then
  section "cargo clippy -D warnings"
  cargo clippy --workspace --all-targets --locked -- -D warnings || bad "clippy"
fi

# ---------------------------------------------------------------- supply chain
# Same deny.toml audit.yml enforces. `bans` is the I2 no-telemetry gate; #13 passed this
# script and still turned main red on it (path deps without a version vs wildcards = "deny").
# advisories needs the online RustSec DB, so it stays in audit.yml only.
section "cargo deny (bans licenses sources)"
if command -v cargo-deny >/dev/null 2>&1; then
  cargo deny --log-level error check bans licenses sources || bad "cargo deny check bans licenses sources (see deny.toml)"
else
  echo "skip: cargo-deny not installed (cargo install --locked cargo-deny; audit.yml runs it in CI)"
fi

# ---------------------------------------------------------------- shell
section "shellcheck"
if need shellcheck shellcheck; then
  # Same set CI lints, plus this script and the e2e helper.
  shellcheck scripts/*.sh e2e/*.sh install.command uninstall.command init.sh || bad "shellcheck"
fi
for f in scripts/*.sh e2e/*.sh install.command uninstall.command init.sh; do
  bash -n "$f" || bad "bash -n $f"
done

# ---------------------------------------------------------------- workflows
section "actionlint"
if need actionlint actionlint; then
  actionlint -color || bad "actionlint"
fi
section "zizmor (optional)"
if command -v zizmor >/dev/null 2>&1; then
  zizmor --offline .github/workflows || bad "zizmor"
elif command -v pipx >/dev/null 2>&1 && [[ -n "${LINT_ZIZMOR:-${CI:-}}" ]]; then
  pipx run zizmor==1.31.1 --offline .github/workflows || bad "zizmor"
else
  echo "skip: zizmor not installed (brew install zizmor; CI runs it on Linux in workflow-lint)"
fi

# ---------------------------------------------------------------- macOS plists
if [[ "$(uname -s)" == Darwin ]]; then
  section "plutil"
  plutil -lint packaging/macos/Info.plist || bad "Info.plist"
  ./scripts/install.sh --print-plist | plutil -lint -s - || bad "launchd plist"
  ./scripts/install.sh --print-maintenance-plist | plutil -lint -s - || bad "maintenance plist"
else
  echo; echo "note: not macOS, plutil checks skipped (CI runs them on macos-15)"
fi

echo
if [[ "$fail" == 0 ]]; then echo "lint: ok"; else echo "lint: FAILED" >&2; exit 1; fi
