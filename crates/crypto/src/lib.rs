//! Protocol crypto machine contracts.
//!
//! ## Feature flags
//!
//! * `backup` — pulls in the [`backup`] module, which provides client-side Argon2id KDF,
//!   XChaCha20-Poly1305 AEAD, a recovery-key codec, and a typed [`cokret_core::KeyBackup`] envelope
//!   builder (spec: `crypto-media/key-management.md` §7). When the feature is off, the bare types
//!   crate stays free of heavyweight crypto deps.

#[cfg(feature = "backup")]
pub mod backup;

use std::collections::{BTreeMap, VecDeque};

use chrono::{DateTime, Utc};
use cokret_core::{
    BlobRef, DeviceId, Did, EncryptedPayload, EncryptedPayloadScheme, Error, EventId, Hash,
    RealmId, Result,
};
pub use cokret_signatures::{DetachedSignature, DetachedSignatureBinding, DetachedVerifier};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Typed crypto-machine validation errors.
///
/// Round 2 (post-improve): introduced so call sites can branch on the
/// specific validation failure (bounds vs replay vs key mismatch)
/// instead of inspecting the free-form `Error::Protocol` string. The
/// `From<CryptoError> for cokret_core::Error` impl below preserves
/// the existing wire surface — every `CryptoError` still renders as
/// `Error::Protocol(<message>)` for callers that haven't migrated.
///
/// New code SHOULD return `CryptoError` directly; bridge to
/// `cokret_core::Error` only at the protocol-boundary using `?` or
/// `Into::into`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CryptoError {
    /// Generic validation failure with a free-form message. Prefer one
    /// of the typed variants when the failure has structure.
    #[error("crypto validation failed: {0}")]
    Validation(String),
    /// Two values that should be identical (e.g. a binding's
    /// `verification_method` and the PSK kid it references) disagreed.
    #[error("crypto key mismatch")]
    KeyMismatch,
    /// A message-index / generation / nonce that should be strictly
    /// monotonic was observed at or below the high-water mark.
    #[error("crypto replay detected")]
    ReplayDetected,
    /// A string or collection field exceeded its declared maximum.
    #[error("crypto bound exceeded for {field}: limit {limit}")]
    BoundsExceeded {
        /// Name of the field that overflowed.
        field: String,
        /// The maximum the field is allowed to take.
        limit: usize,
    },
}

impl From<CryptoError> for Error {
    fn from(err: CryptoError) -> Self {
        // Preserve the v1 wire surface — every typed crypto error still
        // renders as `Error::Protocol(<message>)` for callers that
        // haven't migrated to matching on `CryptoError` directly.
        Self::Protocol(err.to_string())
    }
}

/// Common validation entry-point implemented by every crypto-machine
/// payload that has structural invariants beyond what `serde` can
/// enforce. Round 2 — introduced as a typed counterpart to the ad-hoc
/// inherent `validate()` methods so callers can dispatch generically.
pub trait Validate {
    /// Round-trippable validation. Returns the first failure as a typed
    /// [`CryptoError`].
    fn validate(&self) -> std::result::Result<(), CryptoError>;
}

/// Discriminator for the request variants the crypto-machine plan
/// queue dispatches on. One variant per `CryptoMachineRequestBody` arm.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CryptoMachineRequestKind {
    /// `ck.keys.upload_device_keys` — publish this device's keys.
    UploadDeviceKeys,
    /// `ck.keys.query_device_keys` — fetch peers' keys.
    QueryDeviceKeys,
    /// `ck.keys.claim_one_time_keys` — claim peers' one-time keys.
    ClaimOneTimeKeys,
    /// `ck.event.encrypt` — encrypt an event into a Realm session.
    EncryptEvent,
    /// `ck.event.decrypt` — decrypt a received encrypted event.
    DecryptEvent,
    /// `ck.keys.share_room_key` — distribute a Realm session key.
    ShareRoomKey,
    /// `ck.keys.request_room_key` — request a missing session key.
    RequestRoomKey,
    /// `ck.keys.backup_secrets` — push to secret backup storage.
    BackupSecrets,
    /// `ck.keys.restore_secrets` — pull from secret backup storage.
    RestoreSecrets,
}

/// Per-device public key bundle published via
/// `ck.keys.upload_device_keys`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeviceKeyBundle {
    pub user_id: Did,
    pub device_id: DeviceId,
    pub signing_key: String,
    pub identity_key: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub algorithms: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signatures: Vec<DetachedSignature>,
}

impl DeviceKeyBundle {
    pub fn validate(&self) -> Result<()> {
        validate_nonempty_key("signing_key", &self.signing_key)?;
        validate_nonempty_key("identity_key", &self.identity_key)?;
        validate_max_length("signing_key", &self.signing_key, MAX_KEY_FIELD_LEN)?;
        validate_max_length("identity_key", &self.identity_key, MAX_KEY_FIELD_LEN)?;
        if self.algorithms.len() > MAX_ALGORITHMS_PER_BUNDLE {
            return Err(Error::Protocol(format!(
                "device key bundle algorithms count {} exceeds {}",
                self.algorithms.len(),
                MAX_ALGORITHMS_PER_BUNDLE
            )));
        }
        for (name, value) in &self.algorithms {
            validate_max_length("algorithm name", name, MAX_ALGORITHM_NAME_LEN)?;
            validate_max_length("algorithm value", value, MAX_ALGORITHM_VALUE_LEN)?;
        }
        Ok(())
    }
}

/// Maximum length (bytes) for serialized device/cross-signing public keys and
/// signature values. 4 KiB comfortably covers any RFC-defined public key /
/// signature format the v1 crypto suite emits.
pub const MAX_KEY_FIELD_LEN: usize = 4096;

/// Maximum length (bytes) for short identifier strings (kid, algorithm,
/// reason codes, transaction ids).
pub const MAX_IDENTIFIER_LEN: usize = 256;

/// Maximum length (bytes) for a free-form reason or label string.
pub const MAX_REASON_LEN: usize = 1024;

/// Maximum length (bytes) for an algorithm-name map key (e.g. `ed25519`).
pub const MAX_ALGORITHM_NAME_LEN: usize = 64;

/// Maximum length (bytes) for an algorithm-map value (parameter string).
pub const MAX_ALGORITHM_VALUE_LEN: usize = 256;

/// Maximum number of algorithm entries inside a single `DeviceKeyBundle`.
pub const MAX_ALGORITHMS_PER_BUNDLE: usize = 32;

/// Maximum number of one-time keys a single `OneTimeKeyClaim` may request.
/// Protects the server claim path from unbounded per-claim allocation.
pub const MAX_ONE_TIME_KEY_CLAIM_COUNT: u32 = 1000;

/// Maximum number of verification-method names attached to a single
/// `DeviceVerificationFlow`.
pub const MAX_VERIFICATION_METHODS: usize = 32;

/// Maximum number of device-quorum signatures attached to a single
/// `CrossSigningResetProof::DeviceQuorum`.
pub const MAX_DEVICE_QUORUM_SIGNATURES: usize = 256;

/// Helper: reject empty / whitespace-only key strings with a uniform error.
fn validate_nonempty_key(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(Error::Protocol(format!("{field} must not be empty")));
    }
    Ok(())
}

/// Helper: reject string fields above a per-field byte ceiling.
fn validate_max_length(field: &str, value: &str, max: usize) -> Result<()> {
    if value.len() > max {
        return Err(Error::Protocol(format!(
            "{field} length {} exceeds {}",
            value.len(),
            max
        )));
    }
    Ok(())
}

/// Per-device cross-signing trust verdict tracked alongside the
/// device-key bundle in `CryptoStoreBinding::device_trust`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceTrustState {
    /// No verification path is yet established.
    Unverified,
    /// User has marked the device trusted on this client only.
    LocallyTrusted,
    /// Device key is signed by the principal's SSK.
    CrossSigned,
    /// Verified end-to-end (cross-signed plus an interactive verification).
    Verified,
    /// After a cross-signing reset (spec §14.2), trust state drops here and
    /// the device must be re-verified before it can be treated as
    /// `cross_signed` or `verified` again.
    NeedsReverification,
    Blocked,
}

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
    #[serde(rename = "reset_reason_code", alias = "reset_reason")]
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
                recovery_secret_ref,
                unlock_commitment,
                alg,
                signature,
            } => {
                if recovery_secret_ref.trim().is_empty()
                    || unlock_commitment.trim().is_empty()
                    || alg.trim().is_empty()
                    || signature.trim().is_empty()
                {
                    return Err(Error::Protocol(
                        "recovery_unlock proof requires recovery_secret_ref + unlock_commitment + alg + signature".to_owned(),
                    ));
                }
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

    /// Canonical signing input for a `ck.cross_signing.reset` proof
    /// (`ck-cross-signing-reset-v1`, spec crypto-media/device-lifecycle.md §14.1).
    ///
    /// Binds the reset's principal + generation transition + reason so the proof
    /// cannot be replayed onto a different reset. Both the proving client and the
    /// verifying receiver MUST reconstruct this byte-identically.
    pub fn reset_signing_input(&self) -> Result<Vec<u8>> {
        let body = serde_json::json!({
            "principal_id": self.principal_id.as_str(),
            "trust_domain": self.trust_domain.as_str(),
            "reset_event_id": self.reset_event_id,
            "previous_generation": self.previous_generation,
            "new_generation": self.new_generation,
            "reset_reason": self.reset_reason,
        });
        let mut out = b"ck-cross-signing-reset-v1\n".to_vec();
        out.extend_from_slice(&cokret_core::canonical::canonical_json_bytes(&body)?);
        Ok(out)
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
    pub fn canonical_input(
        principal_id: &Did,
        device_id: &DeviceId,
        device_public_key: &str,
        ssk_generation: u64,
    ) -> Result<Vec<u8>> {
        canonical_device_trust_binding_input(
            principal_id,
            device_id,
            device_public_key,
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
    let mut out = b"ck-cross-signing-bind-v1\n".to_vec();
    out.extend_from_slice(&cokret_core::canonical::canonical_json_bytes(&body)?);
    Ok(out)
}

fn canonical_device_trust_binding_input(
    principal_id: &Did,
    device_id: &DeviceId,
    device_public_key: &str,
    ssk_generation: u64,
) -> Result<Vec<u8>> {
    let body = serde_json::json!({
        "principal_id": principal_id.as_str(),
        "device_id": device_id.as_str(),
        "device_public_key": device_public_key,
        "ssk_generation": ssk_generation,
    });
    let mut out = b"ck-device-trust-bind-v1\n".to_vec();
    out.extend_from_slice(&cokret_core::canonical::canonical_json_bytes(&body)?);
    Ok(out)
}

/// Interactive verification-flow state machine
/// (`ck.device.verification.v1`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFlowState {
    /// Initial state — request sent, awaiting peer ready.
    Requested,
    /// Peer accepted; negotiation can start.
    Ready,
    /// SAS (short-authentication-string) leg started.
    SasStarted,
    /// QR-code leg scanned.
    QrScanned,
    /// Verification completed successfully.
    Done,
    /// Either party cancelled.
    Cancelled,
    /// Window expired before completion.
    TimedOut,
}

/// Active interactive-verification flow between two of the principal's
/// own devices (or a peer and a verifier).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceVerificationFlow {
    pub transaction_id: String,
    pub user_id: Did,
    pub from_device: DeviceId,
    pub to_device: DeviceId,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
    pub state: VerificationFlowState,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

impl DeviceVerificationFlow {
    pub fn validate(&self) -> Result<()> {
        validate_nonempty_key("verification transaction id", &self.transaction_id)?;
        validate_max_length(
            "verification transaction id",
            &self.transaction_id,
            MAX_IDENTIFIER_LEN,
        )?;
        if self.from_device == self.to_device {
            return Err(Error::Protocol(
                "verification requires two distinct devices".to_owned(),
            ));
        }
        if self.methods.len() > MAX_VERIFICATION_METHODS {
            return Err(Error::Protocol(format!(
                "verification methods count {} exceeds {}",
                self.methods.len(),
                MAX_VERIFICATION_METHODS
            )));
        }
        for method in &self.methods {
            validate_nonempty_key("verification method", method)?;
            validate_max_length("verification method", method, MAX_IDENTIFIER_LEN)?;
        }
        Ok(())
    }

    pub fn advance(&mut self, next: VerificationFlowState) -> Result<()> {
        let allowed = matches!(
            (self.state, next),
            (
                VerificationFlowState::Requested,
                VerificationFlowState::Ready
            ) | (
                VerificationFlowState::Ready,
                VerificationFlowState::SasStarted
            ) | (
                VerificationFlowState::Ready,
                VerificationFlowState::QrScanned
            ) | (
                VerificationFlowState::SasStarted,
                VerificationFlowState::Done
            ) | (
                VerificationFlowState::QrScanned,
                VerificationFlowState::Done
            ) | (_, VerificationFlowState::Cancelled)
                | (_, VerificationFlowState::TimedOut)
        );
        if allowed {
            self.state = next;
            Ok(())
        } else {
            Err(Error::Protocol(format!(
                "invalid verification transition from {:?} to {:?}",
                self.state, next
            )))
        }
    }
}

/// Lifecycle state of a Realm E2EE session key tracked locally.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CryptoSessionState {
    /// Session keys received but no message decrypted yet.
    Pending,
    /// In active use for inbound / outbound payloads.
    Active,
    /// Sender deliberately withheld the key (see `UnableToDecryptReason::Withheld`).
    Withheld,
    /// Session age / message count exceeded its rotation budget.
    Expired,
    /// Session was revoked (e.g. on device removal).
    Revoked,
}

/// Local record of a single Realm session — key id, sender device key,
/// algorithm, current state and replay watermark.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoSessionRecord {
    pub realm_id: RealmId,
    pub session_id: String,
    pub sender_key: String,
    pub algorithm: String,
    pub state: CryptoSessionState,
    pub created_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_index_high_watermark: Option<u64>,
}

impl CryptoSessionRecord {
    pub fn validate(&self) -> Result<()> {
        if self.session_id.trim().is_empty()
            || self.sender_key.trim().is_empty()
            || self.algorithm.trim().is_empty()
        {
            return Err(Error::Protocol(
                "crypto session requires id, sender key and algorithm".to_owned(),
            ));
        }
        validate_max_length("crypto session id", &self.session_id, MAX_IDENTIFIER_LEN)?;
        validate_max_length(
            "crypto session sender_key",
            &self.sender_key,
            MAX_KEY_FIELD_LEN,
        )?;
        validate_max_length(
            "crypto session algorithm",
            &self.algorithm,
            MAX_ALGORITHM_NAME_LEN,
        )?;
        Ok(())
    }

    pub fn accept_message_index(&mut self, index: u64, now: DateTime<Utc>) -> Result<()> {
        if self
            .message_index_high_watermark
            .is_some_and(|seen| index <= seen)
        {
            return Err(Error::Protocol(
                "encrypted session replay detected".to_owned(),
            ));
        }
        self.message_index_high_watermark = Some(index);
        self.last_used_at = now;
        Ok(())
    }
}

/// Sender-explicit refusal to share a Realm session key with this
/// device (e.g. via `m.blacklisted` or recipient-not-trusted).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithheldKeyRecord {
    /// Realm the withheld session belongs to.
    pub realm_id: RealmId,
    /// Session that the sender refused to share.
    pub session_id: String,
    /// Sending principal.
    pub sender: Did,
    /// Wire `code` (e.g. `m.blacklisted`).
    pub code: String,
    /// Mapped `UnableToDecryptReason` for renderer convenience.
    pub reason: UnableToDecryptReason,
    /// Time the withheld notice was observed locally.
    pub received_at: DateTime<Utc>,
}

/// Inbound device-to-device secret-gossip request body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretGossipRequestBody {
    pub request_id: String,
    pub name: String,
    pub requesting_device: DeviceId,
    pub recipient_device: DeviceId,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

impl SecretGossipRequestBody {
    pub fn validate(&self) -> Result<()> {
        validate_nonempty_key("secret gossip request_id", &self.request_id)?;
        validate_max_length(
            "secret gossip request_id",
            &self.request_id,
            MAX_IDENTIFIER_LEN,
        )?;
        validate_nonempty_key("secret gossip name", &self.name)?;
        validate_max_length("secret gossip name", &self.name, MAX_IDENTIFIER_LEN)?;
        if self.requesting_device == self.recipient_device {
            return Err(Error::Protocol(
                "secret gossip request requires distinct devices".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Request to claim `count` one-time keys for a (user, device) pair on a
/// specific algorithm.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OneTimeKeyClaim {
    /// Target principal.
    pub user_id: Did,
    /// Target device.
    pub device_id: DeviceId,
    /// One-time key algorithm (e.g. `signed_curve25519`).
    pub algorithm: String,
    /// How many keys to claim in this batch.
    pub count: u32,
}

impl OneTimeKeyClaim {
    pub fn validate(&self) -> Result<()> {
        validate_nonempty_key("one-time key algorithm", &self.algorithm)?;
        validate_max_length(
            "one-time key algorithm",
            &self.algorithm,
            MAX_ALGORITHM_NAME_LEN,
        )?;
        if self.count == 0 {
            return Err(Error::Protocol(
                "one-time key claim count must be non-zero".to_owned(),
            ));
        }
        if self.count > MAX_ONE_TIME_KEY_CLAIM_COUNT {
            return Err(Error::Protocol(format!(
                "one-time key claim count {} exceeds {}",
                self.count, MAX_ONE_TIME_KEY_CLAIM_COUNT
            )));
        }
        Ok(())
    }
}

/// Lifecycle state of the principal's secret-storage backup.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretBackupState {
    /// Backup not configured.
    Disabled,
    /// Backup active and accepting writes.
    Enabled,
    /// Mid-rotation to a new recovery key / public key.
    Rotating,
    /// Restore in progress from a recovery key.
    Recovering,
}

/// Public descriptor of the principal's secret-storage backup
/// (`ck.schema.key_backup.v1`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretBackupDescriptor {
    pub backup_id: String,
    pub state: SecretBackupState,
    pub algorithm: String,
    pub public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_recovery_at: Option<DateTime<Utc>>,
}

impl SecretBackupDescriptor {
    pub fn validate(&self) -> Result<()> {
        if self.backup_id.trim().is_empty()
            || self.algorithm.trim().is_empty()
            || self.public_key.trim().is_empty()
        {
            return Err(Error::Protocol(
                "secret backup descriptor requires id, algorithm and public key".to_owned(),
            ));
        }
        validate_max_length("secret backup id", &self.backup_id, MAX_IDENTIFIER_LEN)?;
        validate_max_length(
            "secret backup algorithm",
            &self.algorithm,
            MAX_ALGORITHM_NAME_LEN,
        )?;
        validate_max_length(
            "secret backup public_key",
            &self.public_key,
            MAX_KEY_FIELD_LEN,
        )?;
        Ok(())
    }
}

/// Discrete phase in a key's lifecycle journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyLifecyclePhase {
    /// Material generated locally.
    Created,
    /// Public half published to the server.
    Uploaded,
    /// One-time key claimed by a peer.
    Claimed,
    /// Session key shared via `share_room_key`.
    Shared,
    /// Replaced as part of a rotation cadence.
    Rotated,
    /// Captured into secret backup.
    BackedUp,
    /// Restored from secret backup.
    Recovered,
    /// Revoked / blacklisted.
    Revoked,
}

/// Lifecycle-journal row emitted whenever a key transitions phases.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyLifecycleEvent {
    /// Stable reference identifying the key (kid / session id / backup id).
    pub key_ref: String,
    /// Phase the key moved into.
    pub phase: KeyLifecyclePhase,
    /// Principal that performed the transition.
    pub actor: Did,
    /// Device that performed the transition.
    pub device_id: DeviceId,
    /// Wall-clock time of the transition.
    pub occurred_at: DateTime<Utc>,
    /// Free-form reason / context string.
    pub reason: String,
}

/// Decryption metadata bound to an encrypted media blob.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaEncryptionInfo {
    pub blob_ref: BlobRef,
    pub scheme: EncryptedPayloadScheme,
    pub key_ref: String,
    pub plaintext_sha256: Hash,
    pub ciphertext_sha256: Hash,
}

impl MediaEncryptionInfo {
    pub fn validate_plaintext(&self, plaintext: &[u8]) -> Result<()> {
        let actual = Hash::new(sha256_prefixed(plaintext))?;
        if actual == self.plaintext_sha256 {
            Ok(())
        } else {
            Err(Error::Protocol(
                "encrypted media plaintext digest mismatch".to_owned(),
            ))
        }
    }
}

/// Classification of why an encrypted event failed to decrypt locally.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnableToDecryptReason {
    /// No session key recorded for the session id.
    NoSession,
    /// Sender DID is not known to the local store.
    UnknownSender,
    /// Sender device key is not known to the local store.
    UnknownDevice,
    /// Olm/Megolm message-index key is missing.
    MissingMegolmKey,
    /// Ciphertext failed MAC / shape validation.
    BadCiphertext,
    /// Sender withheld the session key (`m.withheld`).
    Withheld,
}

/// Inbound record kept on the local store when an encrypted event
/// could not be decrypted; renderers display it as a placeholder until
/// retry succeeds.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UnableToDecryptRecord {
    pub event_id: EventId,
    pub realm_id: RealmId,
    pub sender: Did,
    pub reason: UnableToDecryptReason,
    pub encrypted_content: EncryptedPayload,
    pub first_seen_at: DateTime<Utc>,
}

/// Request body the crypto-machine plan queue dispatches on. Each
/// variant corresponds 1:1 with a [`CryptoMachineRequestKind`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CryptoMachineRequestBody {
    UploadDeviceKeys(DeviceKeyBundle),
    QueryDeviceKeys {
        users: Vec<Did>,
    },
    ClaimOneTimeKeys(Vec<OneTimeKeyClaim>),
    EncryptEvent {
        realm_id: RealmId,
        event_kind: String,
        content: Value,
    },
    DecryptEvent {
        event_id: EventId,
        payload: EncryptedPayload,
    },
    /// Matrix/MIMI compat name. The v1 concept is sharing a Realm
    /// E2EE session key — the `ShareRoomKey` variant name maps to the
    /// `ck.keys.room_key` interop device-message kind.
    ShareRoomKey {
        realm_id: RealmId,
        session_id: String,
        recipients: Vec<DeviceId>,
    },
    /// Matrix/MIMI compat name. Requests a Realm E2EE session key
    /// re-share from peers; maps to the interop `ck.keys.room_key`
    /// device-message kind.
    RequestRoomKey {
        event_id: EventId,
        realm_id: RealmId,
        session_id: String,
        requesting_device_id: DeviceId,
    },
    BackupSecrets(SecretBackupDescriptor),
    RestoreSecrets {
        backup_id: String,
    },
}

impl CryptoMachineRequestBody {
    pub fn kind(&self) -> CryptoMachineRequestKind {
        match self {
            Self::UploadDeviceKeys(_) => CryptoMachineRequestKind::UploadDeviceKeys,
            Self::QueryDeviceKeys { .. } => CryptoMachineRequestKind::QueryDeviceKeys,
            Self::ClaimOneTimeKeys(_) => CryptoMachineRequestKind::ClaimOneTimeKeys,
            Self::EncryptEvent { .. } => CryptoMachineRequestKind::EncryptEvent,
            Self::DecryptEvent { .. } => CryptoMachineRequestKind::DecryptEvent,
            Self::ShareRoomKey { .. } => CryptoMachineRequestKind::ShareRoomKey,
            Self::RequestRoomKey { .. } => CryptoMachineRequestKind::RequestRoomKey,
            Self::BackupSecrets(_) => CryptoMachineRequestKind::BackupSecrets,
            Self::RestoreSecrets { .. } => CryptoMachineRequestKind::RestoreSecrets,
        }
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::UploadDeviceKeys(bundle) => bundle.validate(),
            Self::QueryDeviceKeys { users } if users.is_empty() => Err(Error::Protocol(
                "device-key query must include users".to_owned(),
            )),
            Self::ClaimOneTimeKeys(claims) if claims.is_empty() => Err(Error::Protocol(
                "one-time key claim must include requests".to_owned(),
            )),
            Self::ClaimOneTimeKeys(claims) => {
                for claim in claims {
                    claim.validate()?;
                }
                Ok(())
            }
            Self::EncryptEvent { event_kind, .. } if event_kind.trim().is_empty() => Err(
                Error::Protocol("encrypt event request must include event kind".to_owned()),
            ),
            Self::ShareRoomKey {
                session_id,
                recipients,
                ..
            } => {
                if session_id.trim().is_empty() || recipients.is_empty() {
                    Err(Error::Protocol(
                        "share room key request requires session id and recipients".to_owned(),
                    ))
                } else {
                    Ok(())
                }
            }
            Self::RequestRoomKey { session_id, .. } if session_id.trim().is_empty() => Err(
                Error::Protocol("room key request requires session id".to_owned()),
            ),
            Self::BackupSecrets(descriptor) => descriptor.validate(),
            Self::RestoreSecrets { backup_id } if backup_id.trim().is_empty() => Err(
                Error::Protocol("restore request must include backup id".to_owned()),
            ),
            _ => Ok(()),
        }
    }
}

/// Response body the crypto-machine plan returns once a request is
/// processed (or queued for processing).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum CryptoMachineResponseBody {
    /// Request accepted and queued for asynchronous processing.
    Queued {
        request_id: String,
        kind: CryptoMachineRequestKind,
    },
    /// `UploadDeviceKeys` accepted.
    DeviceKeysUploaded { device_id: DeviceId },
    /// `QueryDeviceKeys` result set.
    DeviceKeys(Vec<DeviceKeyBundle>),
    /// `ClaimOneTimeKeys` result set (one per claimed device).
    OneTimeKeysClaimed(Vec<DeviceKeyBundle>),
    /// `EncryptEvent` produced this payload.
    Encrypted(EncryptedPayload),
    /// `DecryptEvent` resolved to this plaintext value.
    Decrypted(Value),
    /// `DecryptEvent` could not decrypt — caller should display a placeholder.
    UnableToDecrypt(UnableToDecryptRecord),
    /// `ShareRoomKey` fanned out to this many recipients.
    RoomKeyShared {
        realm_id: RealmId,
        session_id: String,
        recipients: usize,
    },
    /// `RequestRoomKey` was emitted on the wire.
    RoomKeyRequested {
        event_id: EventId,
        session_id: String,
    },
    /// `BackupSecrets` flushed this descriptor to storage.
    BackupReady(SecretBackupDescriptor),
    /// `RestoreSecrets` pulled the named backup and recovered this many secrets.
    Restored {
        backup_id: String,
        recovered_secrets: usize,
    },
}

/// In-memory FIFO queue of pending crypto-machine requests.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CryptoMachinePlan {
    queue: VecDeque<(String, CryptoMachineRequestBody)>,
}

impl CryptoMachinePlan {
    pub fn push(
        &mut self,
        request_id: impl Into<String>,
        request: CryptoMachineRequestBody,
    ) -> Result<CryptoMachineResponseBody> {
        request.validate()?;
        let request_id = request_id.into();
        if request_id.trim().is_empty() {
            return Err(Error::Protocol(
                "crypto request id must not be empty".to_owned(),
            ));
        }
        let kind = request.kind();
        self.queue.push_back((request_id.clone(), request));
        Ok(CryptoMachineResponseBody::Queued { request_id, kind })
    }

    pub fn pop(&mut self) -> Option<(String, CryptoMachineRequestBody)> {
        self.queue.pop_front()
    }

    pub fn pending_len(&self) -> usize {
        self.queue.len()
    }

    pub fn pending_kinds(&self) -> Vec<CryptoMachineRequestKind> {
        self.queue
            .iter()
            .map(|(_, request)| request.kind())
            .collect()
    }
}

/// Aggregate local cache of every per-device crypto fact this client
/// has observed (device keys, trust verdicts, verification flows,
/// sessions, secret backup, withheld notices, UTD records, lifecycle
/// journal).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CryptoStoreBinding {
    pub device_keys: BTreeMap<DeviceId, DeviceKeyBundle>,
    pub device_trust: BTreeMap<DeviceId, DeviceTrustState>,
    pub verification_flows: BTreeMap<String, DeviceVerificationFlow>,
    pub sessions: BTreeMap<String, CryptoSessionRecord>,
    pub backup: Option<SecretBackupDescriptor>,
    pub withheld_keys: BTreeMap<String, WithheldKeyRecord>,
    pub unable_to_decrypt: BTreeMap<EventId, UnableToDecryptRecord>,
    pub lifecycle: Vec<KeyLifecycleEvent>,
}

impl CryptoStoreBinding {
    pub fn record_device_keys(&mut self, bundle: DeviceKeyBundle) -> Result<()> {
        bundle.validate()?;
        self.device_keys.insert(bundle.device_id.clone(), bundle);
        Ok(())
    }

    pub fn set_device_trust(&mut self, device_id: DeviceId, trust: DeviceTrustState) {
        self.device_trust.insert(device_id, trust);
    }

    pub fn record_verification_flow(&mut self, flow: DeviceVerificationFlow) -> Result<()> {
        flow.validate()?;
        self.verification_flows
            .insert(flow.transaction_id.clone(), flow);
        Ok(())
    }

    pub fn record_session(&mut self, session: CryptoSessionRecord) -> Result<()> {
        session.validate()?;
        self.sessions
            .insert(session_key(&session.realm_id, &session.session_id), session);
        Ok(())
    }

    pub fn session_mut(
        &mut self,
        realm_id: &RealmId,
        session_id: &str,
    ) -> Option<&mut CryptoSessionRecord> {
        self.sessions.get_mut(&session_key(realm_id, session_id))
    }

    pub fn record_withheld_key(&mut self, record: WithheldKeyRecord) {
        self.withheld_keys
            .insert(session_key(&record.realm_id, &record.session_id), record);
    }

    pub fn record_unable_to_decrypt(&mut self, record: UnableToDecryptRecord) {
        self.unable_to_decrypt
            .insert(record.event_id.clone(), record);
    }
}

pub(crate) fn session_key(realm_id: &RealmId, session_id: &str) -> String {
    format!("{}|{}", realm_id.as_str(), session_id)
}

// ── Round-2 typed `Validate` trait impls ────────────────────────────────
//
// These implementations mirror the existing inherent `validate()`
// methods (when present) but return the typed `CryptoError` instead of
// `cokret_core::Error::Protocol`. The inherent methods stay for
// backward compatibility; new call sites should prefer the trait form
// (`<T as Validate>::validate(&value)`).

impl Validate for DeviceVerificationFlow {
    fn validate(&self) -> std::result::Result<(), CryptoError> {
        if self.transaction_id.trim().is_empty() {
            return Err(CryptoError::Validation(
                "verification transaction id must not be empty".to_owned(),
            ));
        }
        if self.transaction_id.len() > MAX_IDENTIFIER_LEN {
            return Err(CryptoError::BoundsExceeded {
                field: "verification transaction id".to_owned(),
                limit: MAX_IDENTIFIER_LEN,
            });
        }
        if self.from_device == self.to_device {
            return Err(CryptoError::Validation(
                "verification requires two distinct devices".to_owned(),
            ));
        }
        if self.methods.len() > MAX_VERIFICATION_METHODS {
            return Err(CryptoError::BoundsExceeded {
                field: "verification methods".to_owned(),
                limit: MAX_VERIFICATION_METHODS,
            });
        }
        for method in &self.methods {
            if method.trim().is_empty() {
                return Err(CryptoError::Validation(
                    "verification method must not be empty".to_owned(),
                ));
            }
            if method.len() > MAX_IDENTIFIER_LEN {
                return Err(CryptoError::BoundsExceeded {
                    field: "verification method".to_owned(),
                    limit: MAX_IDENTIFIER_LEN,
                });
            }
        }
        Ok(())
    }
}

impl Validate for WithheldKeyRecord {
    fn validate(&self) -> std::result::Result<(), CryptoError> {
        if self.session_id.trim().is_empty() {
            return Err(CryptoError::Validation(
                "withheld key record requires session id".to_owned(),
            ));
        }
        if self.session_id.len() > MAX_IDENTIFIER_LEN {
            return Err(CryptoError::BoundsExceeded {
                field: "withheld session id".to_owned(),
                limit: MAX_IDENTIFIER_LEN,
            });
        }
        if self.code.trim().is_empty() {
            return Err(CryptoError::Validation(
                "withheld key record requires wire code".to_owned(),
            ));
        }
        if self.code.len() > MAX_IDENTIFIER_LEN {
            return Err(CryptoError::BoundsExceeded {
                field: "withheld code".to_owned(),
                limit: MAX_IDENTIFIER_LEN,
            });
        }
        Ok(())
    }
}

impl Validate for KeyLifecycleEvent {
    fn validate(&self) -> std::result::Result<(), CryptoError> {
        if self.key_ref.trim().is_empty() {
            return Err(CryptoError::Validation(
                "key lifecycle event requires key_ref".to_owned(),
            ));
        }
        if self.key_ref.len() > MAX_IDENTIFIER_LEN {
            return Err(CryptoError::BoundsExceeded {
                field: "key lifecycle key_ref".to_owned(),
                limit: MAX_IDENTIFIER_LEN,
            });
        }
        if self.reason.len() > MAX_REASON_LEN {
            return Err(CryptoError::BoundsExceeded {
                field: "key lifecycle reason".to_owned(),
                limit: MAX_REASON_LEN,
            });
        }
        Ok(())
    }
}

pub(crate) fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{}", base16_lower(&Sha256::digest(bytes)))
}

pub(crate) fn base16_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:web:{name}.example")).unwrap()
    }

    fn device() -> DeviceId {
        DeviceId::new("ck:device:01904100-0000-7000-8000-000000000001").unwrap()
    }

    #[test]
    fn crypto_machine_plan_validates_and_orders_requests() {
        let mut plan = CryptoMachinePlan::default();
        let queued = plan
            .push(
                "r1",
                CryptoMachineRequestBody::QueryDeviceKeys {
                    users: vec![did("alice")],
                },
            )
            .unwrap();
        assert_eq!(
            queued,
            CryptoMachineResponseBody::Queued {
                request_id: "r1".to_owned(),
                kind: CryptoMachineRequestKind::QueryDeviceKeys
            }
        );
        assert_eq!(
            plan.pending_kinds(),
            vec![CryptoMachineRequestKind::QueryDeviceKeys]
        );
        assert!(matches!(
            plan.push(
                "bad",
                CryptoMachineRequestBody::QueryDeviceKeys { users: Vec::new() }
            ),
            Err(Error::Protocol(_))
        ));
        plan.push(
            "share",
            CryptoMachineRequestBody::ShareRoomKey {
                realm_id: RealmId::new("ck:realm:01904100-0000-7000-8000-6c355fb9dada").unwrap(),
                session_id: "sess1".to_owned(),
                recipients: vec![device()],
            },
        )
        .unwrap();
        assert_eq!(
            plan.pending_kinds(),
            vec![
                CryptoMachineRequestKind::QueryDeviceKeys,
                CryptoMachineRequestKind::ShareRoomKey
            ]
        );
    }

    #[test]
    fn store_binding_records_device_keys_and_unable_to_decrypt() {
        let mut binding = CryptoStoreBinding::default();
        let bundle = DeviceKeyBundle {
            user_id: did("alice"),
            device_id: device(),
            signing_key: "ed25519:abc".to_owned(),
            identity_key: "curve25519:def".to_owned(),
            algorithms: BTreeMap::new(),
            signatures: Vec::new(),
        };
        binding.record_device_keys(bundle).unwrap();
        assert_eq!(binding.device_keys.len(), 1);

        let payload = EncryptedPayload {
            scheme: EncryptedPayloadScheme::MlsRfc9420,
            group_id: "group".to_owned(),
            epoch: 1,
            content_type: "application/json".to_owned(),
            ciphertext: "abc".to_owned(),
            aad: None,
            payload_digest: Hash::new(sha256_prefixed(b"abc")).unwrap(),
            key_ref: None,
        };
        binding.record_unable_to_decrypt(UnableToDecryptRecord {
            event_id: EventId::new("ck:event:01904100-0000-7000-8000-4e7fda181f9f").unwrap(),
            realm_id: RealmId::new("ck:realm:01904100-0000-7000-8000-6c355fb9dada").unwrap(),
            sender: did("alice"),
            reason: UnableToDecryptReason::NoSession,
            encrypted_content: payload,
            first_seen_at: Utc::now(),
        });
        assert_eq!(binding.unable_to_decrypt.len(), 1);
    }

    #[test]
    fn verification_session_and_withheld_key_state_are_tracked() {
        let mut binding = CryptoStoreBinding::default();
        let mut flow = DeviceVerificationFlow {
            transaction_id: "verif1".to_owned(),
            user_id: did("alice"),
            from_device: DeviceId::new("ck:device:01904100-0000-7000-8000-000000000001").unwrap(),
            to_device: DeviceId::new("ck:device:01904100-0000-7000-8000-000000000004").unwrap(),
            methods: vec!["sas".to_owned(), "qr".to_owned()],
            state: VerificationFlowState::Requested,
            created_at: Utc::now(),
            expires_at: None,
        };
        flow.advance(VerificationFlowState::Ready).unwrap();
        flow.advance(VerificationFlowState::SasStarted).unwrap();
        flow.advance(VerificationFlowState::Done).unwrap();
        binding.record_verification_flow(flow).unwrap();
        binding.set_device_trust(
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000004").unwrap(),
            DeviceTrustState::Verified,
        );
        assert_eq!(
            binding
                .device_trust
                .get(&DeviceId::new("ck:device:01904100-0000-7000-8000-000000000004").unwrap()),
            Some(&DeviceTrustState::Verified)
        );

        let realm_id = RealmId::new("ck:realm:01904100-0000-7000-8000-6c355fb9dada").unwrap();
        binding
            .record_session(CryptoSessionRecord {
                realm_id: realm_id.clone(),
                session_id: "sess1".to_owned(),
                sender_key: "curve25519:def".to_owned(),
                algorithm: "ck.mls.v1".to_owned(),
                state: CryptoSessionState::Active,
                created_at: Utc::now(),
                last_used_at: Utc::now(),
                message_index_high_watermark: None,
            })
            .unwrap();
        let session = binding.session_mut(&realm_id, "sess1").unwrap();
        session.accept_message_index(7, Utc::now()).unwrap();
        assert!(matches!(
            session.accept_message_index(7, Utc::now()),
            Err(Error::Protocol(_))
        ));

        binding.record_withheld_key(WithheldKeyRecord {
            realm_id,
            session_id: "sess1".to_owned(),
            sender: did("alice"),
            code: "m.blacklisted".to_owned(),
            reason: UnableToDecryptReason::Withheld,
            received_at: Utc::now(),
        });
        assert_eq!(binding.withheld_keys.len(), 1);
    }

    #[test]
    fn media_encryption_info_validates_plaintext_digest() {
        let plaintext = b"hello media";
        let info = MediaEncryptionInfo {
            blob_ref: BlobRef::from_bytes(plaintext),
            scheme: EncryptedPayloadScheme::MlsRfc9420,
            key_ref: "media-key-1".to_owned(),
            plaintext_sha256: Hash::new(sha256_prefixed(plaintext)).unwrap(),
            ciphertext_sha256: Hash::new(sha256_prefixed(b"ciphertext")).unwrap(),
        };
        info.validate_plaintext(plaintext).unwrap();
        assert!(matches!(
            info.validate_plaintext(b"changed"),
            Err(Error::Protocol(_))
        ));
    }

    // ── Round-2 typed Validate trait coverage ───────────────────────

    #[test]
    fn typed_validate_rejects_invalid_device_verification_flow() {
        let mut flow = DeviceVerificationFlow {
            transaction_id: String::new(),
            user_id: did("alice"),
            from_device: DeviceId::new("ck:device:01904100-0000-7000-8000-000000000001").unwrap(),
            to_device: DeviceId::new("ck:device:01904100-0000-7000-8000-000000000002").unwrap(),
            methods: Vec::new(),
            state: VerificationFlowState::Requested,
            created_at: Utc::now(),
            expires_at: None,
        };

        // Empty transaction id.
        assert!(matches!(
            <DeviceVerificationFlow as Validate>::validate(&flow),
            Err(CryptoError::Validation(_))
        ));

        // Same device on both sides.
        flow.transaction_id = "tx".to_owned();
        flow.to_device = flow.from_device.clone();
        assert!(matches!(
            <DeviceVerificationFlow as Validate>::validate(&flow),
            Err(CryptoError::Validation(_))
        ));

        // Too many methods → BoundsExceeded.
        flow.to_device = DeviceId::new("ck:device:01904100-0000-7000-8000-000000000002").unwrap();
        flow.methods = (0..(MAX_VERIFICATION_METHODS + 1))
            .map(|i| format!("m{i}"))
            .collect();
        let err = <DeviceVerificationFlow as Validate>::validate(&flow).unwrap_err();
        assert!(
            matches!(err, CryptoError::BoundsExceeded { ref field, limit }
            if field == "verification methods" && limit == MAX_VERIFICATION_METHODS)
        );
    }

    #[test]
    fn typed_validate_rejects_invalid_withheld_key_record() {
        let realm_id = RealmId::new("ck:realm:01904100-0000-7000-8000-6c355fb9dada").unwrap();
        let mut record = WithheldKeyRecord {
            realm_id,
            session_id: String::new(),
            sender: did("alice"),
            code: "m.blacklisted".to_owned(),
            reason: UnableToDecryptReason::Withheld,
            received_at: Utc::now(),
        };
        assert!(matches!(
            <WithheldKeyRecord as Validate>::validate(&record),
            Err(CryptoError::Validation(_))
        ));

        record.session_id = "sess1".to_owned();
        record.code = String::new();
        assert!(matches!(
            <WithheldKeyRecord as Validate>::validate(&record),
            Err(CryptoError::Validation(_))
        ));

        record.code = "x".repeat(MAX_IDENTIFIER_LEN + 1);
        let err = <WithheldKeyRecord as Validate>::validate(&record).unwrap_err();
        assert!(matches!(err, CryptoError::BoundsExceeded { ref field, .. }
            if field == "withheld code"));
    }

    #[test]
    fn typed_validate_rejects_invalid_key_lifecycle_event() {
        let mut ev = KeyLifecycleEvent {
            key_ref: String::new(),
            phase: KeyLifecyclePhase::Created,
            actor: did("alice"),
            device_id: device(),
            occurred_at: Utc::now(),
            reason: "init".to_owned(),
        };
        assert!(matches!(
            <KeyLifecycleEvent as Validate>::validate(&ev),
            Err(CryptoError::Validation(_))
        ));

        ev.key_ref = "kid".to_owned();
        ev.reason = "r".repeat(MAX_REASON_LEN + 1);
        let err = <KeyLifecycleEvent as Validate>::validate(&ev).unwrap_err();
        assert!(matches!(err, CryptoError::BoundsExceeded { ref field, .. }
            if field == "key lifecycle reason"));
    }

    #[test]
    fn crypto_error_converts_to_core_protocol_error() {
        // Backward-compat: every CryptoError still renders to
        // Error::Protocol so callers that have not migrated keep
        // seeing the same shape.
        let core_err: Error = CryptoError::ReplayDetected.into();
        assert!(matches!(core_err, Error::Protocol(_)));

        let core_err: Error = CryptoError::BoundsExceeded {
            field: "field".to_owned(),
            limit: 10,
        }
        .into();
        if let Error::Protocol(message) = core_err {
            assert!(message.contains("field"));
            assert!(message.contains("10"));
        } else {
            panic!("expected Error::Protocol");
        }
    }

    // ── Round-3 hardening tests ─────────────────────────────────────

    /// Deterministic LCG so the property test is reproducible without
    /// pulling in `proptest` / `quickcheck` as deps. Seeded inputs are
    /// always the same and any failure is easy to repro by rerunning.
    fn xorshift_next(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    fn make_session() -> CryptoSessionRecord {
        CryptoSessionRecord {
            realm_id: RealmId::new("ck:realm:01904100-0000-7000-8000-6c355fb9dada").unwrap(),
            session_id: "sess-prop".to_owned(),
            sender_key: "curve25519:def".to_owned(),
            algorithm: "ck.mls.v1".to_owned(),
            state: CryptoSessionState::Active,
            created_at: Utc::now(),
            last_used_at: Utc::now(),
            message_index_high_watermark: None,
        }
    }

    /// Property: for any strictly increasing sequence of indices, every
    /// `accept_message_index` call succeeds; for any index ≤ the running
    /// high-water mark, the call must reject with `Error::Protocol`.
    #[test]
    fn message_index_monotonicity_property() {
        const RUNS: usize = 64;
        const STEPS: usize = 32;
        let mut state: u64 = 0xC0FFEE_u64;
        let now = Utc::now();

        for run in 0..RUNS {
            let mut session = make_session();
            let mut high: u64 = 0;
            let mut saw_increase = false;
            for _ in 0..STEPS {
                // Pick a random *delta* up to 1024. delta == 0 must be
                // rejected as replay; delta > 0 must be accepted and
                // advance the watermark.
                let delta = xorshift_next(&mut state) % 1024;
                let candidate = high.saturating_add(delta);
                let res = session.accept_message_index(candidate, now);
                if delta == 0 && session.message_index_high_watermark.is_some() {
                    assert!(
                        matches!(res, Err(Error::Protocol(_))),
                        "run {run}: replay at index {candidate} (high={high}) must reject"
                    );
                } else if candidate == 0
                    && high == 0
                    && session.message_index_high_watermark.is_none()
                {
                    // Very first call at index 0 is accepted (no prior watermark).
                    res.unwrap();
                    high = candidate;
                    saw_increase = true;
                } else if delta > 0 {
                    res.unwrap();
                    high = candidate;
                    saw_increase = true;
                    assert_eq!(session.message_index_high_watermark, Some(high));
                }
            }
            // Sanity: most runs must observe at least one accepted step.
            assert!(saw_increase || RUNS > 1);
        }
    }

    /// Wraparound: u64::MAX is accepted as a one-off, but every following
    /// candidate (including u64::MAX itself) must reject. This documents
    /// the contract that the watermark is sticky at the top of the range
    /// — callers MUST rotate the session before they can submit more.
    #[test]
    fn message_index_wraparound_at_u64_max() {
        let mut session = make_session();
        let now = Utc::now();
        session.accept_message_index(u64::MAX, now).unwrap();
        // Every subsequent index (including u64::MAX) must reject.
        assert!(matches!(
            session.accept_message_index(u64::MAX, now),
            Err(Error::Protocol(_))
        ));
        assert!(matches!(
            session.accept_message_index(0, now),
            Err(Error::Protocol(_))
        ));
        assert!(matches!(
            session.accept_message_index(u64::MAX - 1, now),
            Err(Error::Protocol(_))
        ));
        // Watermark stays pinned.
        assert_eq!(session.message_index_high_watermark, Some(u64::MAX));
    }

    /// `CrossSigningResetProof::DeviceQuorum { threshold: 0, .. }` must
    /// be rejected even when the signatures vector is non-empty.
    #[test]
    fn reset_signing_input_is_stable_and_binds_replay_fields() {
        let content = CrossSigningResetContent {
            principal_id: did("alice"),
            trust_domain: cokret_core::TypedTrustDomainId::new("ck:trust_domain:example.net")
                .unwrap(),
            reset_event_id: "ck:event:01964137-0000-7000-8000-0000000000aa".to_owned(),
            previous_generation: 1,
            new_generation: 2,
            reset_reason: "lost phone".to_owned(),
            proof: CrossSigningResetProof::PrincipalSigning {
                verification_method: "did:web:alice.example#psk".to_owned(),
                alg: "EdDSA".to_owned(),
                signature: "AAAA".to_owned(),
            },
            issued_at: Utc::now(),
        };
        let base = content.reset_signing_input().unwrap();
        assert!(base.starts_with(b"ck-cross-signing-reset-v1\n"));
        // Deterministic.
        assert_eq!(base, content.reset_signing_input().unwrap());
        // Generation transition is bound.
        let mut gen_changed = content.clone();
        gen_changed.previous_generation = 2;
        gen_changed.new_generation = 3;
        assert_ne!(base, gen_changed.reset_signing_input().unwrap());
        // trust_domain is bound (cross-deployment replay protection).
        let mut domain_changed = content.clone();
        domain_changed.trust_domain =
            cokret_core::TypedTrustDomainId::new("ck:trust_domain:other.net").unwrap();
        assert_ne!(base, domain_changed.reset_signing_input().unwrap());
        // reset_event_id is bound (event-shell replay protection).
        let mut event_changed = content.clone();
        event_changed.reset_event_id = "ck:event:01964137-0000-7000-8000-0000000000bb".to_owned();
        assert_ne!(base, event_changed.reset_signing_input().unwrap());
    }

    #[test]
    fn cross_signing_reset_proof_threshold_zero_rejected() {
        let content = CrossSigningResetContent {
            principal_id: did("alice"),
            trust_domain: cokret_core::TypedTrustDomainId::new("ck:trust_domain:example.net")
                .unwrap(),
            reset_event_id: "ck:event:01964137-0000-7000-8000-0000000000aa".to_owned(),
            previous_generation: 1,
            new_generation: 2,
            reset_reason: "lost phone".to_owned(),
            proof: CrossSigningResetProof::DeviceQuorum {
                threshold: 0,
                signatures: vec![DeviceQuorumSignature {
                    device_id: device(),
                    verification_method: "did:web:alice.example#dev1".to_owned(),
                    alg: "EdDSA".to_owned(),
                    signature: "AAAA".to_owned(),
                }],
            },
            issued_at: Utc::now(),
        };
        let err = content.validate_structure().unwrap_err();
        if let Error::Protocol(message) = err {
            assert!(
                message.contains("threshold >= 1"),
                "unexpected message: {message}"
            );
        } else {
            panic!("expected Error::Protocol");
        }
    }

    /// `PrincipalSigning` / `TrustedRecoveryService` / `RecoveryUnlock`:
    /// blank kid/alg/signature strings must all be rejected.
    #[test]
    fn cross_signing_reset_proof_rejects_malformed_kid_alg() {
        // PrincipalSigning with whitespace-only `verification_method`.
        let blank_verification_method = CrossSigningResetContent {
            principal_id: did("alice"),
            trust_domain: cokret_core::TypedTrustDomainId::new("ck:trust_domain:example.net")
                .unwrap(),
            reset_event_id: "ck:event:01964137-0000-7000-8000-0000000000aa".to_owned(),
            previous_generation: 1,
            new_generation: 2,
            reset_reason: "rot".to_owned(),
            proof: CrossSigningResetProof::PrincipalSigning {
                verification_method: "   ".to_owned(),
                alg: "EdDSA".to_owned(),
                signature: "sig".to_owned(),
            },
            issued_at: Utc::now(),
        };
        assert!(matches!(
            blank_verification_method.validate_structure(),
            Err(Error::Protocol(_))
        ));

        // PrincipalSigning with empty `alg`.
        let blank_alg = CrossSigningResetContent {
            proof: CrossSigningResetProof::PrincipalSigning {
                verification_method: "did:web:a.example#k1".to_owned(),
                alg: String::new(),
                signature: "sig".to_owned(),
            },
            ..blank_verification_method.clone()
        };
        assert!(matches!(
            blank_alg.validate_structure(),
            Err(Error::Protocol(_))
        ));

        // RecoveryUnlock with blank `unlock_commitment` is rejected.
        let blank_unlock = CrossSigningResetContent {
            proof: CrossSigningResetProof::RecoveryUnlock {
                recovery_secret_ref: "ref".to_owned(),
                unlock_commitment: "  ".to_owned(),
                alg: "EdDSA".to_owned(),
                signature: "sig".to_owned(),
            },
            ..blank_verification_method.clone()
        };
        assert!(matches!(
            blank_unlock.validate_structure(),
            Err(Error::Protocol(_))
        ));

        // device_quorum with one signature whose `alg` is empty.
        let bad_quorum = CrossSigningResetContent {
            proof: CrossSigningResetProof::DeviceQuorum {
                threshold: 1,
                signatures: vec![DeviceQuorumSignature {
                    device_id: device(),
                    verification_method: "did:web:a.example#d".to_owned(),
                    alg: String::new(),
                    signature: "AAAA".to_owned(),
                }],
            },
            ..blank_verification_method
        };
        assert!(matches!(
            bad_quorum.validate_structure(),
            Err(Error::Protocol(_))
        ));
    }

    /// `CrossSigningResetProof::DeviceQuorum`: an over-long `alg` string
    /// must be rejected as bounds-exceeded, not silently accepted.
    #[test]
    fn cross_signing_reset_proof_oversized_alg_rejected() {
        let content = CrossSigningResetContent {
            principal_id: did("alice"),
            trust_domain: cokret_core::TypedTrustDomainId::new("ck:trust_domain:example.net")
                .unwrap(),
            reset_event_id: "ck:event:01964137-0000-7000-8000-0000000000aa".to_owned(),
            previous_generation: 1,
            new_generation: 2,
            reset_reason: "rot".to_owned(),
            proof: CrossSigningResetProof::DeviceQuorum {
                threshold: 1,
                signatures: vec![DeviceQuorumSignature {
                    device_id: device(),
                    verification_method: "did:web:a.example#d".to_owned(),
                    alg: "X".repeat(MAX_ALGORITHM_NAME_LEN + 1),
                    signature: "AAAA".to_owned(),
                }],
            },
            issued_at: Utc::now(),
        };
        let err = content.validate_structure().unwrap_err();
        assert!(matches!(err, Error::Protocol(_)));
    }

    /// Recording an `UnableToDecryptRecord` with a `BadCiphertext`
    /// reason: the binding accepts it but the encrypted payload is
    /// observable (the renderer needs it to show a placeholder) and
    /// later inserts under the same event id MUST overwrite.
    #[test]
    fn unable_to_decrypt_path_bad_ciphertext() {
        let mut binding = CryptoStoreBinding::default();
        let event_id = EventId::new("ck:event:01904100-0000-7000-8000-4e7fda181f9f").unwrap();
        let realm_id = RealmId::new("ck:realm:01904100-0000-7000-8000-6c355fb9dada").unwrap();
        let payload = EncryptedPayload {
            scheme: EncryptedPayloadScheme::MlsRfc9420,
            group_id: "group".to_owned(),
            epoch: 1,
            content_type: "application/json".to_owned(),
            // intentionally non-decryptable: empty ciphertext + mismatched digest
            ciphertext: String::new(),
            aad: None,
            payload_digest: Hash::new(sha256_prefixed(b"not-the-ciphertext")).unwrap(),
            key_ref: None,
        };
        let record = UnableToDecryptRecord {
            event_id: event_id.clone(),
            realm_id: realm_id.clone(),
            sender: did("alice"),
            reason: UnableToDecryptReason::BadCiphertext,
            encrypted_content: payload.clone(),
            first_seen_at: Utc::now(),
        };
        binding.record_unable_to_decrypt(record);
        assert_eq!(binding.unable_to_decrypt.len(), 1);
        let stored = binding.unable_to_decrypt.get(&event_id).unwrap();
        assert_eq!(stored.reason, UnableToDecryptReason::BadCiphertext);
        assert!(stored.encrypted_content.ciphertext.is_empty());

        // Recording again with NoSession overwrites the prior entry —
        // the keyed event id is stable so the second observation wins.
        binding.record_unable_to_decrypt(UnableToDecryptRecord {
            event_id: event_id.clone(),
            realm_id,
            sender: did("alice"),
            reason: UnableToDecryptReason::NoSession,
            encrypted_content: payload,
            first_seen_at: Utc::now(),
        });
        assert_eq!(binding.unable_to_decrypt.len(), 1);
        assert_eq!(
            binding.unable_to_decrypt.get(&event_id).unwrap().reason,
            UnableToDecryptReason::NoSession
        );
    }
}
