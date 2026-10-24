---
name: optimizer
description: Measure and improve cg-researcher performance, binary size or build time without weakening a security invariant. Use when asked to optimize, speed up, profile, shrink or reduce latency, memory or build time.
---

# optimizer

Measure first. Do not change code on a guess, and do not quote a speedup you did not measure. There are no benchmarks in this repo, so write the measurement before the optimization.

## Ground rules
- A faster path that skips a guard is a regression. Do not drop or batch away: the output guard re-run during streaming, sanitizer passes (I5), audit appends or `fsync`/locking (I4), the egress host pinning, or constant-time key comparison. Run the `invariants-check` skill on any diff that touches those areas.
- The release profile is already tuned (`lto = "thin"`, `codegen-units = 1`, `strip`, `panic = "abort"`); do not re-tune it without a size or time number to justify it.
- `unsafe_code = "forbid"` workspace-wide, so no unsafe fast paths. No new telemetry or profiling crates in the shipped binary (I2); use dev-only tooling.

## Where the time and size actually are
- Retrieval (`crates/cg-core/src/rag.rs`): FTS5 BM25 plus an exact cosine scan over all f32 vectors held in RAM, fused with RRF. Cost grows linearly with chunk count. Index rebuild (`cg-researcher index`) is dominated by embedding calls to the local model.
- Local model round trips and streaming (`llm.rs`, `serve.rs`): usually the dominant latency. Check the model server before the Rust.
- Sanitizer and redaction (`sanitizer.rs`): regex-heavy, runs on input, chunks, tool output and every streamed answer.
- Build: `cargo build --release --locked -p cg-researcher` (thin LTO, one codegen unit, so it is the slowest CI job). Dependency count affects both build time and binary size; `cargo tree -p cg-researcher --duplicates` shows duplicate versions (`deny.toml` has `multiple-versions = "warn"`).

## Procedure
1. State the target (latency, memory, size or build time) and capture a baseline in a scratch directory (a throwaway `--home`, a fixed corpus, the mock model `cargo run -p cg-researcher --example mock_llm` for repeatable runs; `run-cg-researcher` has the full setup).
   - Size: `cargo build --release --locked -p cg-researcher && ls -l target/release/cg-researcher`
   - Time: `time` around `cg-researcher index` or a fixed `/query`; repeat at least 5 runs and report the spread.
   - Memory: `/usr/bin/time -l` on macOS (`-v` on Linux).
   - Optional, only if installed: `cargo bloat --release`, `hyperfine`, `cargo flamegraph`. On macOS, Instruments or `sample` work without extra installs.
2. Find the hot spot with a profile, not by reading code.
3. Make one change, re-measure with the same procedure, keep it only if the number moves beyond the noise.
4. Run the `verify` skill, then `invariants-check` if a guarded path was touched.
5. Report: baseline, result, method, machine (note Apple Silicon vs the Linux sandbox; numbers do not transfer between them), and anything left unmeasured.
