//! Three-tier cross-signing key records and the stateless device chain verifier.

use arkret_canonical::binding_contexts;
use arkret_models_identity::CrossSigningPublish;
use arkret_wire::{DeviceId, Did};
use serde::{Deserialize, Serialize};

use crate::device::DeviceTrustState;
use crate::errors::Result;

/// Round 4 (spec a77b995) — canonical cell_subject for the CAS-register
/// guarding `ak.cross_signing.publish`. The wire form is the tuple
/// `(principal_id, expected_previous_generation)` rendered as
/// `<did>|<expected_previous_generation>` (the `|` is reserved in DID
/// method-specific-ids by the round-4 DID regex tightening, so the boundary
/// is unambiguous). Reducer uses this as the lattice cell key so concurrent
/// publishes resolve via CAS rather than signature-order races.
pub fn cross_signing_publish_cell_subject(
    principal_id: &Did,
    expected_previous_generation: u64,
) -> String {
    format!("{}|{}", principal_id.as_str(), expected_previous_generation)
}

/// Per-device binding signed by SSK and embedded in `ak.device.authorize`
/// (spec §5.2 `content.cross_signing_binding`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceTrustBinding {
    pub verification_method: String,
    pub alg: String,
    pub ssk_generation: u64,
    pub signature: String,
}

impl DeviceTrustBinding {
    /// Canonical signing input for `ak.device-trust-bind-v1`.
    ///
    /// Covers the full device trust record per `device-lifecycle.md` §5.2:
    /// verify key, HPKE sealing key and the canonical algorithm set. The
    /// `algorithms` slice is sorted (UTF-8 bytewise) and deduplicated before
    /// entering the transcript, so producer and verifier always agree on the
    /// canonical array.
    pub fn canonical_input(
        principal_id: &Did,
        device_id: &DeviceId,
        device_public_key: &str,
        hpke_key: &str,
        algorithms: &[String],
        ssk_generation: u64,
    ) -> Result<Vec<u8>> {
        canonical_device_trust_binding_input(
            principal_id,
            device_id,
            device_public_key,
            hpke_key,
            algorithms,
            ssk_generation,
        )
    }
}

/// Verifier outcome for a single device's trust chain (spec §5.2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceTrustChainOutcome {
    /// Verified end-to-end: PSK / SSK / device binding all valid at the
    /// currently accepted generation.
    CrossSigned,
    /// Cross-signing has been reset since this device was authorized; the
    /// chain references an older SSK generation. The caller MUST treat the
    /// device as `needs_reverification` until a new binding lands.
    NeedsReverification,
    /// `cross_signing_binding.ssk_generation` is ahead of the accepted
    /// publish — caller MUST trigger a control-stream re-sync.
    AwaitingPublish,
    /// No cross-signing binding is present.
    Unverified,
    /// Cryptographic check failed.
    Invalid,
}

fn canonical_device_trust_binding_input(
    principal_id: &Did,
    device_id: &DeviceId,
    device_public_key: &str,
    hpke_key: &str,
    algorithms: &[String],
    ssk_generation: u64,
) -> Result<Vec<u8>> {
    // §5.2: algorithms MUST be UTF-8 bytewise ascending and deduplicated
    // before entering the signing input.
    let mut canonical_algorithms = algorithms.to_vec();
    canonical_algorithms.sort_unstable();
    canonical_algorithms.dedup();
    let body = serde_json::json!({
        "principal_id": principal_id.as_str(),
        "device_id": device_id.as_str(),
        "device_public_key": device_public_key,
        "hpke_key": hpke_key,
        "algorithms": canonical_algorithms,
        "ssk_generation": ssk_generation,
    });
    let mut out = binding_contexts::DEVICE_TRUST_BIND_PREFIX.to_vec();
    out.extend_from_slice(&arkret_canonical::canonical::canonical_json_bytes(&body)?);
    Ok(out)
}

/// Stateless Tier-2 device cross-signing chain verifier
/// (`crypto-media/device-lifecycle.md` §5.2.1 steps 3 + 5 / §8.3 steps 2–3).
///
/// This is **pure cryptography**: no DID resolution and no network. Steps 1–2
/// of §5.2.1 (DID-anchoring the PSK into the principal's current control set)
/// are the caller's responsibility — the caller resolves the principal DID,
/// confirms `publish.principal_signing_key` equals the DID-resolved key
/// byte-for-byte, and passes the **already-anchored PSK** in via
/// `anchored_psk`. This primitive then:
///
///   * (a) verifies `publish.self_signing_key.binding.signature` with the anchored PSK over the
///     §5.1 self-signing canonical input (PSK→SSK);
///   * (b) compares `binding.ssk_generation` to `publish.generation`: equal ⇒ continue, less ⇒
///     [`DeviceTrustState::NeedsReverification`], greater ⇒ [`DeviceTrustState::Unverified`];
///   * (c) when generations match, verifies `binding.signature` with the published SSK public key
///     over the §5.2 `ak.device-trust-bind-v1` canonical input (SSK→device).
///
/// `device_public_key` is the bare multibase Ed25519 key the directory exposes
/// (the inner key of the directory `device_signing_key` did:key); it enters
/// the device-binding canonical input verbatim, closing "the key the directory
/// gave us ⇔ the key the SSK cross-signed" (§8.3 step 5).
///
/// The canonical signing inputs come from the **same** constructors used
/// everywhere else in the ecosystem — [`CrossSigningPublish::self_signing_binding_input`]
/// and [`DeviceTrustBinding::canonical_input`] — so soland's
/// `check_device_cross_signing_binding` and this client-side primitive sign and
/// verify byte-identical bytes.
pub struct DeviceCrossSigningChainVerification<'a> {
    pub publish: &'a CrossSigningPublish,
    pub binding: &'a DeviceTrustBinding,
    pub principal_id: &'a Did,
    pub device_id: &'a DeviceId,
    pub device_public_key: &'a str,
    pub hpke_key: &'a str,
    pub algorithms: &'a [String],
    pub anchored_psk: &'a arkret_signatures::PublicKeyMaterial,
}

/// Returns [`DeviceTrustState`]. Malformed key material / decode failures map to
/// [`DeviceTrustState::Unverified`] (fail-closed), never `Ok(CrossSigned)`.
pub fn verify_device_cross_signing_chain(
    input: DeviceCrossSigningChainVerification<'_>,
) -> DeviceTrustState {
    let DeviceCrossSigningChainVerification {
        publish,
        binding,
        principal_id,
        device_id,
        device_public_key,
        hpke_key,
        algorithms,
        anchored_psk,
    } = input;
    // Signature-domain integrity: every key record and binding on the chain
    // declares an `alg`, and this verifier only implements Ed25519. Any other
    // declared algorithm MUST fail closed instead of being silently verified
    // as Ed25519 (a declared `ML-DSA-65` binding must never pass because its
    // carried key happens to decode as 32 bytes).
    const EDDSA_ALG: &str = "EdDSA";
    if publish.principal_signing_key.alg.as_str() != EDDSA_ALG
        || publish.self_signing_key.alg.as_str() != EDDSA_ALG
        || publish.self_signing_key.binding.alg.as_str() != EDDSA_ALG
        || binding.alg != EDDSA_ALG
    {
        return DeviceTrustState::Unverified;
    }
    // (a) PSK→SSK: the anchored PSK MUST sign the published SSK record over
    // the §5.1 self-signing canonical input.
    let Ok(ssk_input) = publish.self_signing_binding_input() else {
        return DeviceTrustState::Unverified;
    };
    if !arkret_signatures::verify_detached_ed25519_signature(
        anchored_psk,
        &ssk_input,
        &publish.self_signing_key.binding.signature,
    ) {
        return DeviceTrustState::Unverified;
    }

    // (b) generation comparison (§5.2.1 step 5).
    match binding.ssk_generation.cmp(&publish.generation.get()) {
        std::cmp::Ordering::Less => return DeviceTrustState::NeedsReverification,
        std::cmp::Ordering::Greater => return DeviceTrustState::Unverified,
        std::cmp::Ordering::Equal => {}
    }

    // (c) SSK→device: the published SSK public key MUST sign the device
    // binding over the §5.2 ak.device-trust-bind-v1 canonical input.
    let ssk_key = arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
        value: publish.self_signing_key.public_key.as_str().to_owned(),
    };
    let Ok(device_input) = DeviceTrustBinding::canonical_input(
        principal_id,
        device_id,
        device_public_key,
        hpke_key,
        algorithms,
        binding.ssk_generation,
    ) else {
        return DeviceTrustState::Unverified;
    };
    if !arkret_signatures::verify_detached_ed25519_signature(
        &ssk_key,
        &device_input,
        &binding.signature,
    ) {
        return DeviceTrustState::Unverified;
    }

    DeviceTrustState::CrossSigned
}
