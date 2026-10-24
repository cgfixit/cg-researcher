#!/usr/bin/env bash
# Fresh throwaway home -> init -> one-file corpus -> index -> serve (no
# gateways). Used by e2e/playwright.config.mjs; expects the mock model on
# 127.0.0.1:11434 (`cargo run -p cg-researcher --example mock_llm`).
set -euo pipefail
: "${CG_BIN:?path to the cg-researcher binary}"
: "${CG_E2E_HOME:?throwaway data directory}"
rm -rf "$CG_E2E_HOME"
"$CG_BIN" --home "$CG_E2E_HOME" init >/dev/null
# The default 60 req/min is a global budget shared by every endpoint, pairing
# included; two browser projects running 12 tests back to back spend it in
# under a minute and the later pairings get 429 ("not paired" in the UI).
sed 's/^rate_limit_per_min = .*/rate_limit_per_min = 600/' "$CG_E2E_HOME/cg.toml" > "$CG_E2E_HOME/cg.toml.tmp"
mv "$CG_E2E_HOME/cg.toml.tmp" "$CG_E2E_HOME/cg.toml"
grep -q '^rate_limit_per_min = 600$' "$CG_E2E_HOME/cg.toml"
mkdir -p "$CG_E2E_HOME/corpus"
cat > "$CG_E2E_HOME/corpus/veeam.md" <<'MD'
# Veeam immutability
Hardened Linux repositories keep backups immutable for the configured number of days,
which protects backups from ransomware that gains admin rights on the backup server.
MD
"$CG_BIN" --home "$CG_E2E_HOME" index >/dev/null
exec "$CG_BIN" --home "$CG_E2E_HOME" serve --no-gateways
