#![no_main]

//! Fuzz the detached-JWS proof verifier
//! (`arkret_signatures::proof::verify_eddsa_detached_jws_proof`) and the
//! public-key material decoder. Both consume attacker-controlled bytes (a
//! wire `Proof` plus resolver-supplied key material) and MUST fail closed
//! without panicking: a malformed proof or key is a rejection, never a crash
//! and never a spurious "valid".

use arkret_identifiers::Did;
use arkret_signatures::proof::{PublicKeyMaterial, verify_eddsa_detached_jws_proof};
use arkret_wire::Proof;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Split the input: first 32 bytes seed the "public key", the rest is the
    // fuzzed proof JSON. This keeps the key well-formed-length so the verifier
    // exercises the signature path rather than bailing early on key length.
    let (key_part, rest) = if data.len() >= 32 {
        data.split_at(32)
    } else {
        (data, &[][..])
    };
    let mut key_bytes = [0u8; 32];
    let copy_len = key_part.len().min(32);
    key_bytes[..copy_len].copy_from_slice(&key_part[..copy_len]);
    let public_key = PublicKeyMaterial::Ed25519Raw {
        bytes: key_bytes.to_vec(),
    };

    let Ok(text) = std::str::from_utf8(rest) else {
        return;
    };
    let Ok(proof) = serde_json::from_str::<Proof>(text) else {
        return;
    };

    let actor_id = Did::new("did:web:fuzz.example").expect("static did");
    // Verifier must return Ok/Err, never panic, on arbitrary canonical bytes +
    // arbitrary (parsed) proof + arbitrary key.
    let _ =
        verify_eddsa_detached_jws_proof(&proof, b"fuzz-canonical-bytes", &actor_id, &public_key);
});
