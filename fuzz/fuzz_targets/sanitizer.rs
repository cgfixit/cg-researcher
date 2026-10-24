//! Input/output guards on arbitrary UTF-8.
//! * `sanitize_untrusted` output cannot open or close an `<untrusted>`
//!   wrapper and carries no bidi override;
//! * `defang_output_links` leaves nothing to defang (no surviving markdown
//!   image or query-carrying link: those are zero-click exfil channels);
//! * `redact` leaves nothing to redact.
#![no_main]

use cg_core::sanitizer::{check_input, defang_output_links, redact, sanitize_untrusted};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|text: &str| {
    let _ = check_input(text, 8192);

    let (clean, _) = sanitize_untrusted(text);
    assert!(!clean.contains("<untrusted") && !clean.contains("</untrusted"));
    assert!(!clean.contains('\u{202E}'));

    let (out, _) = defang_output_links(text);
    let (again, n) = defang_output_links(&out);
    assert_eq!(n, 0, "defang left something behind: {out:?}");
    assert_eq!(again, out);

    let r = redact(text);
    assert_eq!(redact(&r), r, "redaction is not a fixed point");
});
