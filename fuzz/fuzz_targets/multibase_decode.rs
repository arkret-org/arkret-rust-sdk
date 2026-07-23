#![no_main]

//! Fuzz the multibase / multicodec decoders
//! (`arkret_canonical::multibase::decode_multibase_base58btc`,
//! `arkret_canonical::multibase::decode_ed25519_multibase`,
//! `arkret_canonical::multibase::decode_multicodec_varint`).
//!
//! These decode attacker-controlled key material out of DID documents and
//! verification methods. They MUST reject malformed base58, truncated varints,
//! wrong multicodec prefixes and short key bytes with `Err`/`None`, never
//! panicking or over-reading.

use arkret_canonical::multibase::{
    decode_ed25519_multibase, decode_multibase_base58btc, decode_multicodec_varint,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Byte-oriented varint decoder takes raw bytes directly.
    let _ = decode_multicodec_varint(data);

    // The multibase decoders take a `str`; feed the UTF-8 view when valid.
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = decode_multibase_base58btc(text);
        let _ = decode_ed25519_multibase(text);
    }
});
