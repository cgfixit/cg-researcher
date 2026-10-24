#!/usr/bin/env bash
# Fresh throwaway home -> init -> one-file corpus -> index -> serve (no
# gateways). Used by e2e/playwright.config.mjs; expects the mock model on
# 127.0.0.1:11434 (`cargo run -p cg-researcher --example mock_llm`).
set -euo pipefail
: "${CG_BIN:?path to the cg-researcher binary}"
: "${CG_E2E_HOME:?throwaway data directory}"
rm -rf "$CG_E2E_HOME"
"$CG_BIN" --home "$CG_E2E_HOME" init >/dev/null
mkdir -p "$CG_E2E_HOME/corpus"
cat > "$CG_E2E_HOME/corpus/veeam.md" <<'MD'
# Veeam immutability
Hardened Linux repositories keep backups immutable for the configured number of days,
which protects backups from ransomware that gains admin rights on the backup server.
MD
"$CG_BIN" --home "$CG_E2E_HOME" index >/dev/null
exec "$CG_BIN" --home "$CG_E2E_HOME" serve --no-gateways
