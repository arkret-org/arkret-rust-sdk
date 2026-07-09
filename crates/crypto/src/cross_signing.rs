//! Three-tier cross-signing key records, publish/reset content, and the
//! stateless device cross-signing chain verifier.

use chrono::{DateTime, Utc};
use cokret_core::{DeviceId, Did, Error, Result, binding_contexts};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::device::DeviceTrustState;
use crate::errors::{
    MAX_ALGORITHM_NAME_LEN, MAX_DEVICE_QUORUM_SIGNATURES, MAX_IDENTIFIER_LEN, MAX_KEY_FIELD_LEN,
    MAX_REASON_LEN, validate_max_length, validate_nonempty_key,
};

/// Three-tier cross-signing key kinds — see `crypto-media/device-lifecycle.md` §5.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossSigningKeyKind {
    /// DID-control-rooted principal signing key. Rotation MUST enter DID
    /// method history / key log.
    PrincipalSigning,
    /// Signs the principal's own devices (`ck.device.authorize` bindings).
    SelfSigning,
    /// Signs other principals' identity keys to express manual trust.
    UserSigning,
}

/// Public key record used inside `ck.cross_signing.publish.v1` content.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossSigningKeyRecord {
    /// Verification method id, e.g. `did:webvh:...#cx_self_signing_v1`.
    pub kid: String,
    /// Signature algorithm; defaults to `EdDSA` for v1 core.
    pub alg: String,
    /// Multibase-encoded public key (or whatever `key_format` declares).
    pub public_key: String,
    /// Encoding used for `public_key`; v1 core defaults to `multibase`.
    #[serde(default = "default_key_format")]
    pub key_format: String,
}

fn default_key_format() -> String {
    "multibase".to_owned()
}

/// Signature binding produced by the principal signing key (PSK) over a
/// subordinate `self_signing` / `user_signing` record.
///
/// Canonical signing input (spec §5.1):
///
/// ```text
/// "ck-cross-signing-bind-v1\n"
///   + canonical_json({
///       "principal_id": <did>,
///       "subordinate_key_kind": "self_signing" | "user_signing",
///       "subordinate_kid": <kid>,
///       "subordinate_alg": <alg>,
///       "subordinate_public_key": <public_key>,
///       "generation": <generation>
///     })
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossSigningBinding {
    pub verification_method: String,
    pub alg: String,
    pub signature: String,
}

/// `ck.cross_signing.publish.v1` content (spec §5.1).
///
/// Round 4 (2026-05-20, spec a77b995) — wire-breaking: adds required
/// `expected_previous_generation` so the reducer can run a CAS check
/// `(principal_id, expected_previous_generation == current)` before the
/// signature is verified. The CAS cell key is the tuple
/// `(principal_id, expected_previous_generation)` (see
/// [`cross_signing_publish_cell_subject`]). Reducer behaviour: reject with
/// `cas_conflict` when `expected_previous_generation != current_generation`
/// or `generation != current_generation + 1`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossSigningPublishContent {
    pub principal_id: Did,
    /// Round 4 (spec a77b995) — REQUIRED deployment-scope trust domain.
    /// Mixed into the canonical `ck-cross-signing-bind-v1` signing input
    /// so a publish from deployment A cannot be replayed into deployment
    /// B. MUST match the receiver's accepted trust domain.
    pub trust_domain: cokret_core::TypedTrustDomainId,
    pub principal_signing_key: CrossSigningKeyRecord,
    pub self_signing_key: SignedCrossSigningKey,
    pub user_signing_key: SignedCrossSigningKey,
    /// Round 4 (spec a77b995) — CAS guard: MUST equal the current accepted
    /// generation. 0 for the very first publish, otherwise the prior
    /// accepted generation. Reducer compares this against state BEFORE
    /// verifying signatures.
    pub expected_previous_generation: u64,
    /// Monotonic counter; MUST equal previous accepted generation + 1 when
    /// this publish follows a reset, or 1 for the very first publish.
    pub generation: u64,
    pub issued_at: DateTime<Utc>,
}

/// Round 4 (spec a77b995) — canonical cell_subject for the CAS-register
/// guarding `ck.cross_signing.publish`. The wire form is the tuple
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

/// SSK / USK record carrying its PSK binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedCrossSigningKey {
    #[serde(flatten)]
    pub key: CrossSigningKeyRecord,
    pub binding: CrossSigningBinding,
}

impl CrossSigningPublishContent {
    pub fn validate_structure(&self) -> Result<()> {
        if self.principal_signing_key.kid.trim().is_empty()
            || self.self_signing_key.key.kid.trim().is_empty()
            || self.user_signing_key.key.kid.trim().is_empty()
        {
            return Err(Error::Protocol(
                "cross-signing publish requires non-empty kids".to_owned(),
            ));
        }
        if self.self_signing_key.key.public_key == self.user_signing_key.key.public_key {
            return Err(Error::Protocol(
                "cross-signing publish requires distinct SSK and USK public keys".to_owned(),
            ));
        }
        if self.generation == 0 {
            return Err(Error::Protocol(
                "cross-signing publish generation must be ≥ 1".to_owned(),
            ));
        }
        // Bindings must reference the published PSK kid.
        if self.self_signing_key.binding.verification_method != self.principal_signing_key.kid {
            return Err(Error::Protocol(
                "self_signing_key binding must reference the published PSK kid".to_owned(),
            ));
        }
        if self.user_signing_key.binding.verification_method != self.principal_signing_key.kid {
            return Err(Error::Protocol(
                "user_signing_key binding must reference the published PSK kid".to_owned(),
            ));
        }
        Ok(())
    }

    /// Canonical JSON bytes signed by PSK for the `self_signing_key` binding.
    pub fn self_signing_binding_input(&self) -> Result<Vec<u8>> {
        canonical_cross_signing_binding_input(
            &self.principal_id,
            &self.trust_domain,
            CrossSigningKeyKind::SelfSigning,
            &self.self_signing_key.key,
            self.generation,
        )
    }

    /// Canonical JSON bytes signed by PSK for the `user_signing_key` binding.
    pub fn user_signing_binding_input(&self) -> Result<Vec<u8>> {
        canonical_cross_signing_binding_input(
            &self.principal_id,
            &self.trust_domain,
            CrossSigningKeyKind::UserSigning,
            &self.user_signing_key.key,
            self.generation,
        )
    }
}

/// `ck.cross_signing.reset.v1` content (spec §14.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossSigningResetContent {
    pub principal_id: Did,
    /// Deployment-scope trust domain — enters the reset proof transcript so a
    /// proof cannot be replayed across deployments (spec §14.1).
    pub trust_domain: cokret_core::TypedTrustDomainId,
    /// Typed event_id of the enclosing Event Envelope; bound into the transcript
    /// so the same proof bytes cannot be wrapped into a different Event shell.
    pub reset_event_id: String,
    pub previous_generation: u64,
    pub new_generation: u64,
    #[serde(rename = "reset_reason_code")]
    pub reset_reason: String,
    pub proof: CrossSigningResetProof,
    pub issued_at: DateTime<Utc>,
}

/// High-risk proof for a cross-signing reset.
///
/// Round C47 (spec e10b6ad): `cross-signing-reset.schema.json` moved from an
/// open `additionalProperties: true` object to a strict `oneOf` discriminator
/// with per-variant `required` fields. Every variant now carries `alg`; the
/// signing key is identified by `verification_method` (DID URL); the
/// recovery-unlock variant uses `recovery_secret_ref` + `unlock_commitment`;
/// the device-quorum variant carries a `threshold` int and per-signature
/// `verification_method` / `alg`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CrossSigningResetProof {
    /// Signature from the principal's current DID control key.
    PrincipalSigning {
        verification_method: String,
        alg: String,
        signature: String,
    },
    /// Unlock of secret storage with the recovery key.
    RecoveryUnlock {
        recovery_session_id: String,
        recovery_secret_ref: String,
        unlock_commitment: String,
        alg: String,
        signature: String,
    },
    /// Quorum of already-verified devices.
    DeviceQuorum {
        threshold: u32,
        signatures: Vec<DeviceQuorumSignature>,
    },
    /// Signature from a recovery service declared in the principal's DID document.
    TrustedRecoveryService {
        service_did: Did,
        verification_method: String,
        alg: String,
        signature: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        attestation_ref: Option<String>,
    },
}

/// One device's signature contribution in a `device_quorum`
/// cross-signing-reset proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceQuorumSignature {
    /// Quorum-contributing device.
    pub device_id: DeviceId,
    /// DID URL / verification-method identifying the signing key.
    pub verification_method: String,
    /// Signature algorithm (e.g. `EdDSA`).
    pub alg: String,
    /// Detached signature bytes (multibase / base64).
    pub signature: String,
}

impl CrossSigningResetContent {
    pub fn validate_structure(&self) -> Result<()> {
        if self.new_generation != self.previous_generation + 1 {
            return Err(Error::Protocol(
                "cross-signing reset new_generation must equal previous_generation + 1".to_owned(),
            ));
        }
        validate_nonempty_key("cross-signing reset reset_reason", &self.reset_reason)?;
        validate_max_length(
            "cross-signing reset reset_reason",
            &self.reset_reason,
            MAX_REASON_LEN,
        )?;
        match &self.proof {
            CrossSigningResetProof::DeviceQuorum {
                threshold,
                signatures,
            } => {
                if signatures.is_empty() {
                    return Err(Error::Protocol(
                        "device_quorum reset proof requires at least one signature".to_owned(),
                    ));
                }
                if *threshold == 0 {
                    return Err(Error::Protocol(
                        "device_quorum reset proof requires threshold >= 1".to_owned(),
                    ));
                }
                if signatures.len() > MAX_DEVICE_QUORUM_SIGNATURES {
                    return Err(Error::Protocol(format!(
                        "device_quorum reset proof signatures count {} exceeds {}",
                        signatures.len(),
                        MAX_DEVICE_QUORUM_SIGNATURES
                    )));
                }
                // SDK-COR-04: a quorum that ships fewer signatures than its own
                // declared threshold is internally contradictory; reject early
                // (the authoritative count + signature verification still
                // happens reducer/server-side).
                if (signatures.len() as u64) < u64::from(*threshold) {
                    return Err(Error::Protocol(format!(
                        "device_quorum reset proof has {} signature(s) below declared threshold {}",
                        signatures.len(),
                        threshold
                    )));
                }
                for sig in signatures {
                    validate_nonempty_key(
                        "device_quorum verification_method",
                        &sig.verification_method,
                    )?;
                    validate_max_length(
                        "device_quorum verification_method",
                        &sig.verification_method,
                        MAX_IDENTIFIER_LEN,
                    )?;
                    validate_nonempty_key("device_quorum alg", &sig.alg)?;
                    validate_max_length("device_quorum alg", &sig.alg, MAX_ALGORITHM_NAME_LEN)?;
                    validate_nonempty_key("device_quorum signature", &sig.signature)?;
                    validate_max_length(
                        "device_quorum signature",
                        &sig.signature,
                        MAX_KEY_FIELD_LEN,
                    )?;
                }
            }
            CrossSigningResetProof::PrincipalSigning {
                verification_method,
                alg,
                signature,
            }
            | CrossSigningResetProof::TrustedRecoveryService {
                verification_method,
                alg,
                signature,
                ..
            } => {
                if verification_method.trim().is_empty()
                    || alg.trim().is_empty()
                    || signature.trim().is_empty()
                {
                    return Err(Error::Protocol(
                        "reset proof requires verification_method + alg + signature".to_owned(),
                    ));
                }
                validate_max_length(
                    "reset proof verification_method",
                    verification_method,
                    MAX_IDENTIFIER_LEN,
                )?;
                validate_max_length("reset proof alg", alg, MAX_ALGORITHM_NAME_LEN)?;
                validate_max_length("reset proof signature", signature, MAX_KEY_FIELD_LEN)?;
            }
            CrossSigningResetProof::RecoveryUnlock {
                recovery_session_id,
                recovery_secret_ref,
                unlock_commitment,
                alg,
                signature,
            } => {
                if recovery_session_id.trim().is_empty()
                    || recovery_secret_ref.trim().is_empty()
                    || unlock_commitment.trim().is_empty()
                    || alg.trim().is_empty()
                    || signature.trim().is_empty()
                {
                    return Err(Error::Protocol(
                        "recovery_unlock proof requires recovery_session_id + recovery_secret_ref + unlock_commitment + alg + signature".to_owned(),
                    ));
                }
                validate_max_length(
                    "recovery_unlock recovery_session_id",
                    recovery_session_id,
                    MAX_IDENTIFIER_LEN,
                )?;
                validate_max_length(
                    "recovery_unlock recovery_secret_ref",
                    recovery_secret_ref,
                    MAX_IDENTIFIER_LEN,
                )?;
                validate_max_length(
                    "recovery_unlock unlock_commitment",
                    unlock_commitment,
                    MAX_KEY_FIELD_LEN,
                )?;
                validate_max_length("recovery_unlock alg", alg, MAX_ALGORITHM_NAME_LEN)?;
                validate_max_length("recovery_unlock signature", signature, MAX_KEY_FIELD_LEN)?;
            }
        }
        Ok(())
    }

    fn reset_proof_kind(&self) -> &'static str {
        match &self.proof {
            CrossSigningResetProof::PrincipalSigning { .. } => "principal_signing",
            CrossSigningResetProof::RecoveryUnlock { .. } => "recovery_unlock",
            CrossSigningResetProof::DeviceQuorum { .. } => "device_quorum",
            CrossSigningResetProof::TrustedRecoveryService { .. } => "trusted_recovery_service",
        }
    }

    fn reset_proof_body(&self, include_unlock_commitment: bool) -> Value {
        match &self.proof {
            CrossSigningResetProof::PrincipalSigning {
                verification_method,
                alg,
                ..
            } => serde_json::json!({
                "verification_method": verification_method,
                "alg": alg,
            }),
            CrossSigningResetProof::RecoveryUnlock {
                recovery_session_id,
                recovery_secret_ref,
                unlock_commitment,
                alg,
                ..
            } => {
                let mut body = serde_json::json!({
                    "recovery_session_id": recovery_session_id,
                    "recovery_secret_ref": recovery_secret_ref,
                    "alg": alg,
                });
                if include_unlock_commitment && let Some(object) = body.as_object_mut() {
                    object.insert(
                        "unlock_commitment".to_owned(),
                        Value::String(unlock_commitment.clone()),
                    );
                }
                body
            }
            CrossSigningResetProof::DeviceQuorum {
                threshold,
                signatures,
            } => {
                let signatures = signatures
                    .iter()
                    .map(|signature| {
                        serde_json::json!({
                            "device_id": signature.device_id.as_str(),
                            "verification_method": signature.verification_method,
                            "alg": signature.alg,
                        })
                    })
                    .collect::<Vec<_>>();
                serde_json::json!({
                    "threshold": threshold,
                    "signatures": signatures,
                })
            }
            CrossSigningResetProof::TrustedRecoveryService {
                service_did,
                verification_method,
                alg,
                attestation_ref,
                ..
            } => {
                let mut body = serde_json::json!({
                    "service_did": service_did.as_str(),
                    "verification_method": verification_method,
                    "alg": alg,
                });
                if let Some(attestation_ref) = attestation_ref
                    && let Some(object) = body.as_object_mut()
                {
                    object.insert(
                        "attestation_ref".to_owned(),
                        Value::String(attestation_ref.clone()),
                    );
                }
                body
            }
        }
    }

    fn reset_signing_body(&self, include_unlock_commitment: bool) -> Value {
        serde_json::json!({
            "trust_domain": self.trust_domain.as_str(),
            "reset_event_id": self.reset_event_id,
            "principal_id": self.principal_id.as_str(),
            "previous_generation": self.previous_generation,
            "new_generation": self.new_generation,
            "reset_reason_code": self.reset_reason,
            "issued_at": self.issued_at,
            "proof_kind": self.reset_proof_kind(),
            "proof_body": self.reset_proof_body(include_unlock_commitment),
        })
    }

    /// Canonical signing input for a `ck.cross_signing.reset` proof
    /// (`ck-cross-signing-reset-v1`, spec crypto-media/device-lifecycle.md §14.1).
    ///
    /// Binds the reset's principal + generation transition + reason + issued
    /// time + proof family/body so the proof cannot be replayed onto a different
    /// reset or another proof shell.
    pub fn reset_signing_input(&self) -> Result<Vec<u8>> {
        let mut out = binding_contexts::CROSS_SIGNING_RESET_PREFIX.to_vec();
        out.extend_from_slice(&cokret_core::canonical::canonical_json_bytes(
            &self.reset_signing_body(true),
        )?);
        Ok(out)
    }

    /// Canonical JSON bytes used inside the public `recovery_unlock`
    /// commitment. This mirrors the reset signing body, except the proof body
    /// excludes both `signature` and `unlock_commitment` to avoid self-reference.
    pub fn recovery_unlock_binding_input(&self) -> Result<Vec<u8>> {
        cokret_core::canonical::canonical_json_bytes(&self.reset_signing_body(false))
    }

    /// Expected `recovery_unlock.unlock_commitment` for this reset payload.
    ///
    /// Wire form is `sha256:<lowercase_hex>` over:
    /// `ck-cross-signing-reset-unlock-binding-v1\n || recovery_secret_ref ||
    /// recovery_unlock_binding_input`.
    pub fn recovery_unlock_commitment(&self) -> Result<String> {
        let CrossSigningResetProof::RecoveryUnlock {
            recovery_secret_ref,
            ..
        } = &self.proof
        else {
            return Err(Error::Protocol(
                "recovery_unlock_commitment requires recovery_unlock proof".to_owned(),
            ));
        };
        let binding_input = self.recovery_unlock_binding_input()?;
        Ok(cokret_core::canonical::sha256_digest_from_slices(&[
            binding_contexts::CROSS_SIGNING_RESET_UNLOCK_BINDING_PREFIX,
            recovery_secret_ref.as_bytes(),
            &binding_input,
        ]))
    }
}

/// Per-device binding signed by SSK and embedded in `ck.device.authorize`
/// (spec §5.2 `content.cross_signing_binding`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceTrustBinding {
    pub verification_method: String,
    pub alg: String,
    pub ssk_generation: u64,
    pub signature: String,
}

impl DeviceTrustBinding {
    /// Canonical signing input for `ck-device-trust-bind-v1`.
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

/// Bootstrap binding for the first-device inception path (spec §5.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceBootstrapBinding {
    pub kind: String,
    pub did_method_evidence_ref: String,
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
    /// Legitimate bootstrap path (`§5.3 bootstrap_binding` present and no
    /// prior publish accepted).
    Bootstrap,
    /// No cross-signing binding present and bootstrap is not allowed.
    Unverified,
    /// Cryptographic check failed.
    Invalid,
}

fn canonical_cross_signing_binding_input(
    principal_id: &Did,
    trust_domain: &cokret_core::TypedTrustDomainId,
    subordinate_kind: CrossSigningKeyKind,
    subordinate: &CrossSigningKeyRecord,
    generation: u64,
) -> Result<Vec<u8>> {
    let kind_str = match subordinate_kind {
        CrossSigningKeyKind::SelfSigning => "self_signing",
        CrossSigningKeyKind::UserSigning => "user_signing",
        CrossSigningKeyKind::PrincipalSigning => {
            return Err(Error::Protocol(
                "principal_signing key is not a subordinate binding target".to_owned(),
            ));
        }
    };
    let body = serde_json::json!({
        "principal_id": principal_id.as_str(),
        "trust_domain": trust_domain.as_str(),
        "subordinate_key_kind": kind_str,
        "subordinate_kid": subordinate.kid,
        "subordinate_alg": subordinate.alg,
        "subordinate_public_key": subordinate.public_key,
        "generation": generation,
    });
    let mut out = binding_contexts::CROSS_SIGNING_BIND_PREFIX.to_vec();
    out.extend_from_slice(&cokret_core::canonical::canonical_json_bytes(&body)?);
    Ok(out)
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
    out.extend_from_slice(&cokret_core::canonical::canonical_json_bytes(&body)?);
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
///     over the §5.2 `ck-device-trust-bind-v1` canonical input (SSK→device).
///
/// `device_public_key` is the bare multibase Ed25519 key the directory exposes
/// (the inner key of the directory `device_signing_key` did:key); it enters
/// the device-binding canonical input verbatim, closing "the key the directory
/// gave us ⇔ the key the SSK cross-signed" (§8.3 step 5).
///
/// The canonical signing inputs come from the **same** constructors used
/// everywhere else in the ecosystem — [`CrossSigningPublishContent::self_signing_binding_input`]
/// and [`DeviceTrustBinding::canonical_input`] — so soland's
/// `check_device_cross_signing_binding` and this client-side primitive sign and
/// verify byte-identical bytes.
pub struct DeviceCrossSigningChainVerification<'a> {
    pub publish: &'a CrossSigningPublishContent,
    pub binding: &'a DeviceTrustBinding,
    pub principal_id: &'a Did,
    pub device_id: &'a DeviceId,
    pub device_public_key: &'a str,
    pub hpke_key: &'a str,
    pub algorithms: &'a [String],
    pub anchored_psk: &'a cokret_signatures::PublicKeyMaterial,
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
    if publish.principal_signing_key.alg != EDDSA_ALG
        || publish.self_signing_key.key.alg != EDDSA_ALG
        || publish.self_signing_key.binding.alg != EDDSA_ALG
        || binding.alg != EDDSA_ALG
    {
        return DeviceTrustState::Unverified;
    }
    // (a) PSK→SSK: the anchored PSK MUST sign the published SSK record over
    // the §5.1 self-signing canonical input.
    let Ok(ssk_input) = publish.self_signing_binding_input() else {
        return DeviceTrustState::Unverified;
    };
    if !cokret_signatures::verify_detached_ed25519_signature(
        anchored_psk,
        &ssk_input,
        &publish.self_signing_key.binding.signature,
    ) {
        return DeviceTrustState::Unverified;
    }

    // (b) generation comparison (§5.2.1 step 5).
    match binding.ssk_generation.cmp(&publish.generation) {
        std::cmp::Ordering::Less => return DeviceTrustState::NeedsReverification,
        std::cmp::Ordering::Greater => return DeviceTrustState::Unverified,
        std::cmp::Ordering::Equal => {}
    }

    // (c) SSK→device: the published SSK public key MUST sign the device
    // binding over the §5.2 ck-device-trust-bind-v1 canonical input.
    let ssk_key = cokret_signatures::PublicKeyMaterial::Ed25519Multibase {
        value: publish.self_signing_key.key.public_key.clone(),
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
    if !cokret_signatures::verify_detached_ed25519_signature(
        &ssk_key,
        &device_input,
        &binding.signature,
    ) {
        return DeviceTrustState::Unverified;
    }

    DeviceTrustState::CrossSigned
}
