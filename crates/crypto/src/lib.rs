//! Protocol crypto machine contracts.
//!
//! ## Feature flags
//!
//! * `backup` — pulls in the [`backup`] module, which provides
//!   client-side Argon2id KDF, XChaCha20-Poly1305 AEAD, a recovery-key
//!   codec, and a typed [`contrix_core::KeyBackup`] envelope builder
//!   (spec: `crypto-media/key-management.md` §7). When the feature is
//!   off, the bare types crate stays free of heavyweight crypto deps.

#[cfg(feature = "backup")]
pub mod backup;

use std::collections::{BTreeMap, VecDeque};

use chrono::{DateTime, Utc};
use contrix_core::{
    BlobRef, DeviceId, Did, EncryptedPayload, EncryptedPayloadScheme, Error, EventId, Hash, Result,
    SpaceId,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub use contrix_signatures::{DetachedSignature, DetachedSignatureBinding, DetachedVerifier};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CryptoMachineRequestKind {
    UploadDeviceKeys,
    QueryDeviceKeys,
    ClaimOneTimeKeys,
    EncryptEvent,
    DecryptEvent,
    ShareRoomKey,
    RequestRoomKey,
    BackupSecrets,
    RestoreSecrets,
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceTrustState {
    Unverified,
    LocallyTrusted,
    CrossSigned,
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
    /// Signs the principal's own devices (`cx.device.authorize` bindings).
    SelfSigning,
    /// Signs other principals' identity keys to express manual trust.
    UserSigning,
}

/// Public key record used inside `cx.cross_signing.publish.v1` content.
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
/// "cx-cross-signing-bind-v1\n"
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
    pub signed_by: String,
    pub alg: String,
    pub signature: String,
}

/// `cx.cross_signing.publish.v1` content (spec §5.1).
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
    /// Mixed into the canonical `cx-cross-signing-bind-v1` signing input
    /// so a publish from deployment A cannot be replayed into deployment
    /// B. MUST match the receiver's accepted trust domain.
    pub trust_domain: contrix_core::TypedTrustDomainId,
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
/// guarding `cx.cross_signing.publish`. The wire form is the tuple
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
            return Err(Error::Protocol("cross-signing publish generation must be ≥ 1".to_owned()));
        }
        // Bindings must reference the published PSK kid.
        if self.self_signing_key.binding.signed_by != self.principal_signing_key.kid {
            return Err(Error::Protocol(
                "self_signing_key binding must reference the published PSK kid".to_owned(),
            ));
        }
        if self.user_signing_key.binding.signed_by != self.principal_signing_key.kid {
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

/// `cx.cross_signing.reset.v1` content (spec §14.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossSigningResetContent {
    pub principal_id: Did,
    pub previous_generation: u64,
    pub new_generation: u64,
    pub reset_reason: String,
    pub proof: CrossSigningResetProof,
    pub issued_at: DateTime<Utc>,
}

/// High-risk proof for a cross-signing reset.
///
/// Round C47 (spec e10b6ad): `cross-signing-reset.schema.json` moved from an
/// open `additionalProperties: true` object to a strict `oneOf` discriminator
/// with per-variant `required` fields. Every variant now carries `alg`; the
/// `verification_method` field is renamed to `signed_by` (DID URL); the
/// recovery-unlock variant uses `recovery_secret_ref` + `unlock_commitment`;
/// the device-quorum variant gains a `threshold` int and per-signature
/// `signed_by` / `alg`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CrossSigningResetProof {
    /// Signature from the principal's current DID control key.
    PrincipalSigning { signed_by: String, alg: String, signature: String },
    /// Unlock of secret storage with the recovery key.
    RecoveryUnlock {
        recovery_secret_ref: String,
        unlock_commitment: String,
        alg: String,
        signature: String,
    },
    /// Quorum of already-verified devices.
    DeviceQuorum { threshold: u32, signatures: Vec<DeviceQuorumSignature> },
    /// Signature from a recovery service declared in the principal's DID document.
    TrustedRecoveryService {
        service_did: Did,
        signed_by: String,
        alg: String,
        signature: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        attestation_ref: Option<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceQuorumSignature {
    pub device_id: DeviceId,
    pub signed_by: String,
    pub alg: String,
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
            CrossSigningResetProof::DeviceQuorum { threshold, signatures } => {
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
                    validate_nonempty_key("device_quorum signed_by", &sig.signed_by)?;
                    validate_max_length(
                        "device_quorum signed_by",
                        &sig.signed_by,
                        MAX_IDENTIFIER_LEN,
                    )?;
                    validate_nonempty_key("device_quorum alg", &sig.alg)?;
                    validate_max_length(
                        "device_quorum alg",
                        &sig.alg,
                        MAX_ALGORITHM_NAME_LEN,
                    )?;
                    validate_nonempty_key("device_quorum signature", &sig.signature)?;
                    validate_max_length(
                        "device_quorum signature",
                        &sig.signature,
                        MAX_KEY_FIELD_LEN,
                    )?;
                }
            }
            CrossSigningResetProof::PrincipalSigning { signed_by, alg, signature }
            | CrossSigningResetProof::TrustedRecoveryService {
                signed_by, alg, signature, ..
            } => {
                if signed_by.trim().is_empty()
                    || alg.trim().is_empty()
                    || signature.trim().is_empty()
                {
                    return Err(Error::Protocol(
                        "reset proof requires signed_by + alg + signature".to_owned(),
                    ));
                }
                validate_max_length("reset proof signed_by", signed_by, MAX_IDENTIFIER_LEN)?;
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
                validate_max_length(
                    "recovery_unlock alg",
                    alg,
                    MAX_ALGORITHM_NAME_LEN,
                )?;
                validate_max_length(
                    "recovery_unlock signature",
                    signature,
                    MAX_KEY_FIELD_LEN,
                )?;
            }
        }
        Ok(())
    }
}

/// Per-device binding signed by SSK and embedded in `cx.device.authorize`
/// (spec §5.2 `content.cross_signing_binding`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceTrustBinding {
    pub signed_by: String,
    pub alg: String,
    pub ssk_generation: u64,
    pub signature: String,
}

impl DeviceTrustBinding {
    /// Canonical signing input for `cx-device-trust-bind-v1`.
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
    trust_domain: &contrix_core::TypedTrustDomainId,
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
    let mut out = b"cx-cross-signing-bind-v1\n".to_vec();
    out.extend_from_slice(&contrix_core::canonical::canonical_json_bytes(&body)?);
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
    let mut out = b"cx-device-trust-bind-v1\n".to_vec();
    out.extend_from_slice(&contrix_core::canonical::canonical_json_bytes(&body)?);
    Ok(out)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFlowState {
    Requested,
    Ready,
    SasStarted,
    QrScanned,
    Done,
    Cancelled,
    TimedOut,
}

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
            return Err(Error::Protocol("verification requires two distinct devices".to_owned()));
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
            (VerificationFlowState::Requested, VerificationFlowState::Ready)
                | (VerificationFlowState::Ready, VerificationFlowState::SasStarted)
                | (VerificationFlowState::Ready, VerificationFlowState::QrScanned)
                | (VerificationFlowState::SasStarted, VerificationFlowState::Done)
                | (VerificationFlowState::QrScanned, VerificationFlowState::Done)
                | (_, VerificationFlowState::Cancelled)
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CryptoSessionState {
    Pending,
    Active,
    Withheld,
    Expired,
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoSessionRecord {
    pub space_id: SpaceId,
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
        validate_max_length("crypto session sender_key", &self.sender_key, MAX_KEY_FIELD_LEN)?;
        validate_max_length(
            "crypto session algorithm",
            &self.algorithm,
            MAX_ALGORITHM_NAME_LEN,
        )?;
        Ok(())
    }

    pub fn accept_message_index(&mut self, index: u64, now: DateTime<Utc>) -> Result<()> {
        if self.message_index_high_watermark.is_some_and(|seen| index <= seen) {
            return Err(Error::Protocol("encrypted session replay detected".to_owned()));
        }
        self.message_index_high_watermark = Some(index);
        self.last_used_at = now;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithheldKeyRecord {
    pub space_id: SpaceId,
    pub session_id: String,
    pub sender: Did,
    pub code: String,
    pub reason: UnableToDecryptReason,
    pub received_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretGossipReqBody {
    pub request_id: String,
    pub name: String,
    pub requesting_device: DeviceId,
    pub recipient_device: DeviceId,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

impl SecretGossipReqBody {
    pub fn validate(&self) -> Result<()> {
        validate_nonempty_key("secret gossip request_id", &self.request_id)?;
        validate_max_length("secret gossip request_id", &self.request_id, MAX_IDENTIFIER_LEN)?;
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OneTimeKeyClaim {
    pub user_id: Did,
    pub device_id: DeviceId,
    pub algorithm: String,
    pub count: u32,
}

impl OneTimeKeyClaim {
    pub fn validate(&self) -> Result<()> {
        validate_nonempty_key("one-time key algorithm", &self.algorithm)?;
        validate_max_length("one-time key algorithm", &self.algorithm, MAX_ALGORITHM_NAME_LEN)?;
        if self.count == 0 {
            return Err(Error::Protocol("one-time key claim count must be non-zero".to_owned()));
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretBackupState {
    Disabled,
    Enabled,
    Rotating,
    Recovering,
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyLifecyclePhase {
    Created,
    Uploaded,
    Claimed,
    Shared,
    Rotated,
    BackedUp,
    Recovered,
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyLifecycleEvent {
    pub key_ref: String,
    pub phase: KeyLifecyclePhase,
    pub actor: Did,
    pub device_id: DeviceId,
    pub occurred_at: DateTime<Utc>,
    pub reason: String,
}

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
            Err(Error::Protocol("encrypted media plaintext digest mismatch".to_owned()))
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnableToDecryptReason {
    NoSession,
    UnknownSender,
    UnknownDevice,
    MissingMegolmKey,
    BadCiphertext,
    Withheld,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UnableToDecryptRecord {
    pub event_id: EventId,
    pub space_id: SpaceId,
    pub sender: Did,
    pub reason: UnableToDecryptReason,
    pub encrypted_payload: EncryptedPayload,
    pub first_seen_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CryptoMachineReqBody {
    UploadDeviceKeys(DeviceKeyBundle),
    QueryDeviceKeys {
        users: Vec<Did>,
    },
    ClaimOneTimeKeys(Vec<OneTimeKeyClaim>),
    EncryptEvent {
        space_id: SpaceId,
        event_kind: String,
        content: Value,
    },
    DecryptEvent {
        event_id: EventId,
        payload: EncryptedPayload,
    },
    /// Matrix/MIMI compat name. The v1 concept is sharing a Space
    /// E2EE session key — the `ShareRoomKey` variant name maps to the
    /// `cx.keys.room_key` interop device-message kind.
    ShareRoomKey {
        space_id: SpaceId,
        session_id: String,
        recipients: Vec<DeviceId>,
    },
    /// Matrix/MIMI compat name. Requests a Space E2EE session key
    /// re-share from peers; maps to the interop `cx.keys.room_key`
    /// device-message kind.
    RequestRoomKey {
        event_id: EventId,
        space_id: SpaceId,
        session_id: String,
        requesting_device_id: DeviceId,
    },
    BackupSecrets(SecretBackupDescriptor),
    RestoreSecrets {
        backup_id: String,
    },
}

impl CryptoMachineReqBody {
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
            Self::QueryDeviceKeys { users } if users.is_empty() => {
                Err(Error::Protocol("device-key query must include users".to_owned()))
            }
            Self::ClaimOneTimeKeys(claims) if claims.is_empty() => {
                Err(Error::Protocol("one-time key claim must include requests".to_owned()))
            }
            Self::ClaimOneTimeKeys(claims) => {
                for claim in claims {
                    claim.validate()?;
                }
                Ok(())
            }
            Self::EncryptEvent { event_kind, .. } if event_kind.trim().is_empty() => {
                Err(Error::Protocol("encrypt event request must include event kind".to_owned()))
            }
            Self::ShareRoomKey { session_id, recipients, .. } => {
                if session_id.trim().is_empty() || recipients.is_empty() {
                    Err(Error::Protocol(
                        "share room key request requires session id and recipients".to_owned(),
                    ))
                } else {
                    Ok(())
                }
            }
            Self::RequestRoomKey { session_id, .. } if session_id.trim().is_empty() => {
                Err(Error::Protocol("room key request requires session id".to_owned()))
            }
            Self::BackupSecrets(descriptor) => descriptor.validate(),
            Self::RestoreSecrets { backup_id } if backup_id.trim().is_empty() => {
                Err(Error::Protocol("restore request must include backup id".to_owned()))
            }
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum CryptoMachineResBody {
    Queued { request_id: String, kind: CryptoMachineRequestKind },
    DeviceKeysUploaded { device_id: DeviceId },
    DeviceKeys(Vec<DeviceKeyBundle>),
    OneTimeKeysClaimed(Vec<DeviceKeyBundle>),
    Encrypted(EncryptedPayload),
    Decrypted(Value),
    UnableToDecrypt(UnableToDecryptRecord),
    RoomKeyShared { space_id: SpaceId, session_id: String, recipients: usize },
    RoomKeyRequested { event_id: EventId, session_id: String },
    BackupReady(SecretBackupDescriptor),
    Restored { backup_id: String, recovered_secrets: usize },
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CryptoMachinePlan {
    queue: VecDeque<(String, CryptoMachineReqBody)>,
}

impl CryptoMachinePlan {
    pub fn push(
        &mut self,
        request_id: impl Into<String>,
        request: CryptoMachineReqBody,
    ) -> Result<CryptoMachineResBody> {
        request.validate()?;
        let request_id = request_id.into();
        if request_id.trim().is_empty() {
            return Err(Error::Protocol("crypto request id must not be empty".to_owned()));
        }
        let kind = request.kind();
        self.queue.push_back((request_id.clone(), request));
        Ok(CryptoMachineResBody::Queued { request_id, kind })
    }

    pub fn pop(&mut self) -> Option<(String, CryptoMachineReqBody)> {
        self.queue.pop_front()
    }

    pub fn pending_len(&self) -> usize {
        self.queue.len()
    }

    pub fn pending_kinds(&self) -> Vec<CryptoMachineRequestKind> {
        self.queue.iter().map(|(_, request)| request.kind()).collect()
    }
}

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
        self.verification_flows.insert(flow.transaction_id.clone(), flow);
        Ok(())
    }

    pub fn record_session(&mut self, session: CryptoSessionRecord) -> Result<()> {
        session.validate()?;
        self.sessions.insert(session_key(&session.space_id, &session.session_id), session);
        Ok(())
    }

    pub fn session_mut(
        &mut self,
        space_id: &SpaceId,
        session_id: &str,
    ) -> Option<&mut CryptoSessionRecord> {
        self.sessions.get_mut(&session_key(space_id, session_id))
    }

    pub fn record_withheld_key(&mut self, record: WithheldKeyRecord) {
        self.withheld_keys.insert(session_key(&record.space_id, &record.session_id), record);
    }

    pub fn record_unable_to_decrypt(&mut self, record: UnableToDecryptRecord) {
        self.unable_to_decrypt.insert(record.event_id.clone(), record);
    }
}

pub(crate) fn session_key(space_id: &SpaceId, session_id: &str) -> String {
    format!("{}|{}", space_id.as_str(), session_id)
}

#[allow(dead_code)] // Retained as a crate-internal utility for future callers.
pub(crate) fn encrypted_payload_digest(payload: &EncryptedPayload) -> Result<Hash> {
    let bytes = contrix_core::canonical::canonical_json_bytes(payload)?;
    Hash::new(sha256_prefixed(&bytes)).map_err(Into::into)
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
        DeviceId::new("cx:device:01904100-0000-7000-8000-000000000001").unwrap()
    }

    #[test]
    fn crypto_machine_plan_validates_and_orders_requests() {
        let mut plan = CryptoMachinePlan::default();
        let queued = plan
            .push("r1", CryptoMachineReqBody::QueryDeviceKeys { users: vec![did("alice")] })
            .unwrap();
        assert_eq!(
            queued,
            CryptoMachineResBody::Queued {
                request_id: "r1".to_owned(),
                kind: CryptoMachineRequestKind::QueryDeviceKeys
            }
        );
        assert_eq!(plan.pending_kinds(), vec![CryptoMachineRequestKind::QueryDeviceKeys]);
        assert!(matches!(
            plan.push("bad", CryptoMachineReqBody::QueryDeviceKeys { users: Vec::new() }),
            Err(Error::Protocol(_))
        ));
        plan.push(
            "share",
            CryptoMachineReqBody::ShareRoomKey {
                space_id: SpaceId::new("cx:space:01904100-0000-7000-8000-6c355fb9dada").unwrap(),
                session_id: "sess1".to_owned(),
                recipients: vec![device()],
            },
        )
        .unwrap();
        assert_eq!(
            plan.pending_kinds(),
            vec![CryptoMachineRequestKind::QueryDeviceKeys, CryptoMachineRequestKind::ShareRoomKey]
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
            event_id: EventId::new("cx:event:01904100-0000-7000-8000-4e7fda181f9f").unwrap(),
            space_id: SpaceId::new("cx:space:01904100-0000-7000-8000-6c355fb9dada").unwrap(),
            sender: did("alice"),
            reason: UnableToDecryptReason::NoSession,
            encrypted_payload: payload,
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
            from_device: DeviceId::new("cx:device:01904100-0000-7000-8000-000000000001").unwrap(),
            to_device: DeviceId::new("cx:device:01904100-0000-7000-8000-000000000004").unwrap(),
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
            DeviceId::new("cx:device:01904100-0000-7000-8000-000000000004").unwrap(),
            DeviceTrustState::Verified,
        );
        assert_eq!(
            binding
                .device_trust
                .get(&DeviceId::new("cx:device:01904100-0000-7000-8000-000000000004").unwrap()),
            Some(&DeviceTrustState::Verified)
        );

        let space_id = SpaceId::new("cx:space:01904100-0000-7000-8000-6c355fb9dada").unwrap();
        binding
            .record_session(CryptoSessionRecord {
                space_id: space_id.clone(),
                session_id: "sess1".to_owned(),
                sender_key: "curve25519:def".to_owned(),
                algorithm: "cx.mls.v1".to_owned(),
                state: CryptoSessionState::Active,
                created_at: Utc::now(),
                last_used_at: Utc::now(),
                message_index_high_watermark: None,
            })
            .unwrap();
        let session = binding.session_mut(&space_id, "sess1").unwrap();
        session.accept_message_index(7, Utc::now()).unwrap();
        assert!(matches!(session.accept_message_index(7, Utc::now()), Err(Error::Protocol(_))));

        binding.record_withheld_key(WithheldKeyRecord {
            space_id,
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
        assert!(matches!(info.validate_plaintext(b"changed"), Err(Error::Protocol(_))));
    }
}
