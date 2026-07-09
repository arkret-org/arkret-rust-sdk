#![no_main]

//! Fuzz the opaque sync-cursor decoder (`arkret_core::cursor::Cursor::decode`).
//!
//! `Cursor::decode` parses a fully untrusted `ck:cursor:` token (Base64URL body
//! wrapping canonical JSON) and enforces size, version, handle, timestamp and
//! TTL bounds. It MUST fail closed with `Err` on any malformed / oversized /
//! non-canonical / expired token and never panic.

use arkret_core::cursor::Cursor;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Exercise both the raw-bytes and the `ck:cursor:`-prefixed shapes so the
    // fuzzer reaches the Base64URL + canonical-JSON + validation path, not just
    // the prefix rejection.
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = Cursor::decode(text);
        let prefixed = format!("ak:cursor:{text}");
        let _ = Cursor::decode(&prefixed);
    }
});
