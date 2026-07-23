#![no_main]

//! Fuzz the hand-written deterministic-CBOR reader for the MLS governance
//! binding extension
//! (`arkret_models_crypto::MlsGovernanceBindingPayload::from_deterministic_cbor`).
//!
//! This reader consumes attacker-controlled MLS GroupContext extension bytes
//! and has hand-rolled bounds / depth / item-count caps (SDK-ROB fixes). It
//! MUST never panic, never over-allocate, and never loop unbounded on
//! malformed, truncated, deeply-nested or array/map-bomb CBOR — only return
//! `Err`. This target locks those caps against regression.

use arkret_models_crypto::MlsGovernanceBindingPayload;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = MlsGovernanceBindingPayload::from_deterministic_cbor(data);
});
