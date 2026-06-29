#![no_main]

//! Fuzz the canonical-JSON parsing / validation surface
//! (`cokret_core::canonical`). These functions consume fully untrusted bytes
//! (wire envelopes, signing inputs) and MUST never panic — only return
//! `Err` — on malformed, over-long, deeply-nested or non-canonical input.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Strict canonical-form validation: rejects duplicate keys, floats,
    // out-of-range integers, BOMs, non-NFC strings, etc. Must not panic.
    let _ = cokret_core::canonical::validate_canonical_bytes(data);

    // Lenient parse into a `serde_json::Value`. Must not panic on adversarial
    // nesting / encoding.
    let _ = cokret_core::canonical::parse_canonical_json(data);

    // Round-trip: if it parses as UTF-8 JSON, re-canonicalizing must also be
    // panic-free.
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
            let _ = cokret_core::canonical::canonical_json_bytes(&value);
        }
    }
});
