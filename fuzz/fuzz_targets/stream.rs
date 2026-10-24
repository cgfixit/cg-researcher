//! Streaming answers: the SSE parser and the per-chunk output guard.
//!
//! * `SseChat` is chunking-invariant: feeding a body in arbitrary pieces gives
//!   the same outcome (error / content / model / tool calls / deltas) as
//!   feeding it whole, and never yields more than 32 tool calls. A network
//!   that splits a line, a UTF-8 sequence or a `data:` prefix cannot change
//!   what the agent sees.
//! * `StreamGuard` never puts on screen, even transiently: a registered secret
//!   value (one containing spaces, so the whitespace cut alone cannot hide
//!   it), a complete secret shape (`redact` is a no-op on everything shown),
//!   or text from inside a `<think>` block. Shown text stays within the
//!   character cap.
//!
//! Not asserted: query strings inside a not-yet-closed markdown link can show
//! briefly before `defang_output_links` rewrites the link and stops the
//! stream. The UI renders answers as plain text (never fetched, never
//! clickable), and a bare URL with the same query passes the final guard
//! anyway, so that is not an exfiltration channel.
//!
//! Input layout: `[chunk seed, flags, position seed, body...]`.
#![no_main]

use cg_core::llm::SseChat;
use cg_core::sanitizer::redact;
use cg_core::stream::{StreamEvent, StreamGuard};
use libfuzzer_sys::fuzz_target;

const SECRET: &str = "hunter2 horse battery staple";
const THINK_MARK: &str = "QZTHINKMARK";

/// Deterministic chunk sizes (1..=17 bytes) from a seed.
fn sizes(seed: u8) -> impl Iterator<Item = usize> {
    let mut x = u32::from(seed) | 1;
    std::iter::repeat_with(move || {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        ((x >> 16) % 17 + 1) as usize
    })
}

#[derive(Debug, PartialEq)]
struct SseOutcome {
    result: String,
    deltas: String,
}

fn run_sse<'a>(pieces: impl Iterator<Item = &'a [u8]>) -> SseOutcome {
    let mut acc = SseChat::default();
    let mut deltas = String::new();
    let mut err = None;
    for p in pieces {
        match acc.feed(p, &mut |t: &str| deltas.push_str(t)) {
            Ok(true) => break,
            Ok(false) => {}
            Err(e) => {
                err = Some(format!("{e:?}"));
                break;
            }
        }
    }
    let result = match err {
        Some(e) => format!("feed error {e}"),
        None => match acc.finish() {
            Ok(r) => {
                assert!(r.tool_calls.len() <= 32);
                let calls: Vec<_> = r
                    .tool_calls
                    .iter()
                    .map(|c| (c.id.as_str(), c.name.as_str(), c.arguments.as_str()))
                    .collect();
                format!("ok {:?} {:?} {calls:?}", r.content, r.model)
            }
            Err(e) => format!("finish error {e:?}"),
        },
    };
    SseOutcome { result, deltas }
}

fn split_bytes(b: &[u8], seed: u8) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut i = 0;
    for n in sizes(seed) {
        if i >= b.len() {
            break;
        }
        let j = (i + n).min(b.len());
        out.push(&b[i..j]);
        i = j;
    }
    out
}

/// Split on char boundaries, roughly `sizes(seed)` bytes per token.
fn split_text(s: &str, seed: u8) -> Vec<&str> {
    let mut out = Vec::new();
    let mut i = 0;
    for n in sizes(seed) {
        if i >= s.len() {
            break;
        }
        let mut j = (i + n).min(s.len());
        while !s.is_char_boundary(j) {
            j += 1;
        }
        out.push(&s[i..j]);
        i = j;
    }
    out
}

fn floor_boundary(s: &str, mut i: usize) -> usize {
    i = i.min(s.len());
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fuzz_target!(|data: &[u8]| {
    let [seed, flags, pos, body @ ..] = data else {
        return;
    };

    // 1. SSE parser: whole vs. chunked.
    let whole = run_sse(std::iter::once(body));
    let chunked = run_sse(split_bytes(body, *seed).into_iter());
    assert_eq!(whole, chunked, "SSE outcome depends on chunking");

    // 2. Stream guard over model text built from the same bytes.
    let base = String::from_utf8_lossy(body);
    if base.contains(THINK_MARK) || base.contains("hunter2") {
        return; // keep the markers unambiguous
    }
    let mut text = base.into_owned();
    let at = floor_boundary(&text, usize::from(*pos) * text.len() / 256);
    if flags & 1 != 0 {
        text.insert_str(at, &format!(" {SECRET} "));
    }
    if flags & 2 != 0 {
        let at = floor_boundary(&text, text.len() / 2);
        let close = if flags & 16 != 0 { "" } else { "</think>" };
        text.insert_str(at, &format!("<think>{THINK_MARK} private{close}"));
    }
    cg_core::secrets::redactor().register(SECRET);

    let max_chars = if flags & 8 != 0 { 40 } else { 24_000 };
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let mut g = StreamGuard::new(tx, max_chars);
    let tokens = split_text(&text, *seed);
    if flags & 4 != 0 {
        // A tool-call round: part of one reply, then `reset`, then a whole
        // new reply (the agent resets only between model calls).
        for t in &tokens[..tokens.len() / 2] {
            g.push(t);
        }
        g.reset();
    }
    for t in &tokens {
        g.push(t);
    }
    drop(g);

    // Rebuild what the UI shows: deltas append, reset clears.
    let mut shown = String::new();
    let check = |s: &str| {
        assert!(!s.contains(SECRET), "registered secret streamed: {s:?}");
        assert!(!s.contains(THINK_MARK), "thinking streamed: {s:?}");
        assert_eq!(redact(s), s, "secret shape streamed: {s:?}");
        assert!(s.chars().count() <= max_chars, "cap exceeded");
    };
    while let Ok(ev) = rx.try_recv() {
        match ev {
            StreamEvent::Delta(d) => {
                shown.push_str(&d);
                check(&shown);
            }
            StreamEvent::Reset => shown.clear(),
        }
    }
});
