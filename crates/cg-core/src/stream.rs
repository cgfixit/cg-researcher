//! Guarded token streaming for the local model.
//!
//! Streamed text is provisional and never bypasses the output guardrail:
//! every emitted delta is a prefix of `guard_output_text(strip_thinking(raw))`
//! for the raw text received so far, cut back to the last whitespace (so a
//! secret-shaped word is only shown once it is complete and has been
//! redacted) and further back past any tail that could be the start of a
//! registered secret value. If guarding ever rewrites text already emitted
//! (e.g. a markdown link is defanged after its text was shown), streaming
//! stops and the client waits for the final answer, which is authoritative
//! and replaces the provisional text.

use tokio::sync::mpsc::UnboundedSender;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamEvent {
    /// Guarded text to append.
    Delta(String),
    /// Discard provisional text (the model switched to tool calls).
    Reset,
}

pub type StreamSink = UnboundedSender<StreamEvent>;

/// Re-guard after this many new bytes (or a newline). Bounds the O(n^2)
/// cost of re-running the guard over the whole buffer.
const RECHECK_BYTES: usize = 24;

pub struct StreamGuard {
    tx: StreamSink,
    raw: String,
    emitted: String,
    checked_len: usize,
    max_chars: usize,
    stopped: bool,
}

impl StreamGuard {
    pub fn new(tx: StreamSink, max_chars: usize) -> Self {
        Self {
            tx,
            raw: String::new(),
            emitted: String::new(),
            checked_len: 0,
            max_chars,
            stopped: false,
        }
    }

    pub fn push(&mut self, delta: &str) {
        if self.stopped || delta.is_empty() {
            return;
        }
        self.raw.push_str(delta);
        // `max_chars` below counts only text safe to show; an unclosed
        // <think> block or one endless word keeps that empty, so cap the raw
        // buffer too (4 bytes per char) instead of re-guarding up to the SSE cap.
        if self.raw.len() > self.max_chars.saturating_mul(4) {
            self.stopped = true;
            return;
        }
        if self.raw.len() < self.checked_len + RECHECK_BYTES && !delta.contains('\n') {
            return;
        }
        self.checked_len = self.raw.len();
        let visible = crate::llm::strip_thinking(&self.raw);
        let (guarded, _) = crate::sanitizer::guard_output_text(&visible);
        let safe = committed(&guarded);
        if !safe.starts_with(self.emitted.as_str()) {
            self.stopped = true; // guard rewrote shown text: wait for the final answer
            return;
        }
        if safe.chars().count() > self.max_chars {
            self.stopped = true;
            return;
        }
        if safe.len() > self.emitted.len() {
            let d = safe[self.emitted.len()..].to_string();
            if self.tx.send(StreamEvent::Delta(d)).is_err() {
                self.stopped = true; // client went away
                return;
            }
            self.emitted = safe.to_string();
        }
    }

    pub fn reset(&mut self) {
        self.raw.clear();
        self.emitted.clear();
        self.checked_len = 0;
        if self.tx.send(StreamEvent::Reset).is_err() {
            self.stopped = true;
        }
    }
}

/// The part of guarded text that is safe to show now: up to and including the
/// last whitespace, minus any tail that could begin a registered secret.
fn committed(g: &str) -> &str {
    let cut = g
        .char_indices()
        .rev()
        .find(|(_, c)| c.is_whitespace())
        .map(|(i, c)| i + c.len_utf8())
        .unwrap_or(0);
    let p = &g[..cut];
    let hold = crate::secrets::redactor().pending_prefix_len(p);
    &p[..p.len() - hold]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hidden_text_cannot_keep_the_guard_running() {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let mut g = StreamGuard::new(tx, 100);
        g.push("<think>");
        for _ in 0..100 {
            g.push("thinking-without-end ");
        }
        assert!(g.stopped && g.raw.len() <= 400 + 32);
    }

    fn run(chunks: &[&str]) -> (String, Vec<StreamEvent>) {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut g = StreamGuard::new(tx, 24_000);
        for c in chunks {
            g.push(c);
        }
        drop(g);
        let mut ev = Vec::new();
        while let Ok(e) = rx.try_recv() {
            ev.push(e);
        }
        let text = ev
            .iter()
            .filter_map(|e| match e {
                StreamEvent::Delta(d) => Some(d.as_str()),
                StreamEvent::Reset => None,
            })
            .collect();
        (text, ev)
    }

    /// Split into single characters: the worst case for a streamer.
    fn chars(s: &str) -> Vec<String> {
        s.chars().map(String::from).collect()
    }

    #[test]
    fn plain_text_streams_as_a_prefix_of_the_final_answer() {
        let full = "Immutable backups resist ransomware.\nUse hardened repositories and test restores often. ";
        let parts = chars(full);
        let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
        let (shown, _) = run(&refs);
        assert!(!shown.is_empty());
        assert!(full.starts_with(&shown), "{shown:?}");
    }

    #[test]
    fn secret_shapes_split_across_tokens_never_leak() {
        let key = "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345";
        let bot = "1234567890:AAbbCCddEEffGGhhIIjjKKllMMnnOOppQQr";
        let full = format!(
            "Here is the key {key} and Bearer abc.def-123 plus api_key = s3cr3tvalue and {bot} done. And more words follow here.\n"
        );
        let parts = chars(&full);
        let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
        let (shown, _) = run(&refs);
        for bad in [
            "sk-ant-api03",
            "ABCDEFGHIJ",
            "abc.def-123",
            "s3cr3tvalue",
            "AAbbCCdd",
        ] {
            assert!(!shown.contains(bad), "leaked {bad}: {shown:?}");
        }
    }

    #[test]
    fn registered_secret_values_are_held_back_until_complete() {
        // A value with spaces defeats the whitespace cut; the prefix holdback
        // must cover it.
        crate::secrets::redactor().register("hunter2 horse battery staple");
        let full = "the passphrase is hunter2 horse battery staple ok and that is all of it.\n";
        let parts = chars(full);
        let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
        let (shown, _) = run(&refs);
        assert!(!shown.contains("hunter2"), "{shown:?}");
        assert!(!shown.contains("horse battery"), "{shown:?}");
    }

    #[test]
    fn thinking_blocks_are_never_streamed() {
        let full = "<think>secret plan about the user and more private reasoning</think>The answer is 42 and that is final.\n";
        let parts = chars(full);
        let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
        let (shown, _) = run(&refs);
        assert!(
            !shown.contains("secret plan") && !shown.contains("think"),
            "{shown:?}"
        );
        assert!(shown.starts_with("The answer"), "{shown:?}");
    }

    #[test]
    fn defanged_link_after_shown_text_stops_the_stream() {
        let full = "See [the docs now please and thanks](https://e.example/?q=leak) for more information on this topic.\n";
        let parts = chars(full);
        let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
        let (shown, _) = run(&refs);
        assert!(!shown.contains("leak"), "{shown:?}");
        assert!(full.starts_with(&shown), "provisional text stays a prefix");
    }

    #[test]
    fn reset_is_forwarded_and_clears_state() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut g = StreamGuard::new(tx, 24_000);
        g.push("calling a tool now with some words to cross the recheck threshold\n");
        g.reset();
        g.push("final words after the tool ran, long enough to flush a delta\n");
        let mut ev = Vec::new();
        while let Ok(e) = rx.try_recv() {
            ev.push(e);
        }
        let r = ev
            .iter()
            .position(|e| *e == StreamEvent::Reset)
            .expect("reset");
        assert!(r > 0 && r + 1 < ev.len(), "{ev:?}");
    }
}
