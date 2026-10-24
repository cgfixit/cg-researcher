//! Attachment parsing (PNG / DOCX / Markdown / text) on arbitrary bytes.
//! Beyond "no panic", checks the properties the agent relies on:
//! * a sanitized PNG contains only rendering chunks (no tEXt/zTXt/iTXt/eXIf
//!   metadata reaches a model) and sanitizing it again changes nothing;
//! * extracted text respects `max_text_chars`;
//! * the display name never carries a path separator or control character.
#![no_main]

use base64::Engine;
use cg_core::attachments::{Kind, parse, sanitize_png};
use cg_core::config::AttachmentConfig;
use libfuzzer_sys::fuzz_target;

const KEEP: &[&[u8; 4]] = &[
    b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"gAMA", b"cHRM", b"sRGB", b"iCCP",
];

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let name = match sel % 5 {
        0 => "notes.md",
        1 => "log.txt",
        2 => "report.docx",
        3 => "image.png",
        _ => "../../etc/\u{7}evil\\name.md",
    };
    let lim = AttachmentConfig {
        max_bytes: 1 << 20,
        max_text_chars: 4096,
        max_image_side: 512,
        max_per_turn: 4,
    };
    // Selector 3 steers past the signature and IHDR checks so the fuzzer
    // spends its time in the chunk walker instead of rediscovering PNG magic.
    let steered;
    let rest = if sel % 5 == 3 {
        let mut v =
            b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR\0\0\0\x01\0\0\0\x01\x08\x06\0\0\0\0\0\0\0".to_vec();
        v.extend_from_slice(rest);
        steered = v;
        &steered[..]
    } else {
        rest
    };
    let Ok(a) = parse(name, rest, &lim) else {
        return;
    };
    assert!(!a.name.contains(['/', '\\']) && !a.name.chars().any(char::is_control));
    if let Some(t) = &a.text {
        assert!(t.chars().count() <= lim.max_text_chars);
    }
    if a.kind == Kind::Png {
        let b64 = a.png_base64.as_deref().expect("png output");
        let png = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .expect("valid base64");
        let mut i = 8;
        while i + 12 <= png.len() {
            let len = u32::from_be_bytes([png[i], png[i + 1], png[i + 2], png[i + 3]]) as usize;
            let ty = [png[i + 4], png[i + 5], png[i + 6], png[i + 7]];
            assert!(KEEP.iter().any(|k| **k == ty), "kept chunk {ty:?}");
            i += 12 + len;
        }
        assert_eq!(i, png.len(), "output ends exactly after IEND");
        assert_eq!(
            sanitize_png(&png, lim.max_image_side).as_deref(),
            Ok(&png[..])
        );
    }
});
