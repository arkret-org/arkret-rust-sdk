//! Operation draft facade retained by `arkret-core`.
//!
//! The SDK-local drafting layer (`Operation`, `OperationEnvelope`, the
//! registry-backed builder, `CausalRef`, rank interval arithmetic) migrated
//! to `arkret-event-draft`; the MLS transport envelope wire shapes migrated
//! to `arkret_models_crypto::mls_envelopes` (their draft binding is the
//! [`MlsEnvelopeOperationExt`] extension trait on the event-draft side).
//! This module keeps the re-export panel plus the encrypted-payload and
//! KeyPackage record shapes that still bind core-resident types.

pub use arkret_event_draft::{
    CausalRef, ContainerRebalanceAssignment, MlsEnvelopeOperationExt, Operation, OperationEnvelope,
    OperationEnvelopeBuilder, OperationEventConversion, OperationSignature,
    container_rebalance_assignments, rank_between, rank_exhausted,
};
pub use arkret_models_collaboration::governance::grant_constraint::*;
pub use arkret_models_collaboration::governance::operation_wire::*;
pub use arkret_models_collaboration::objects::read_receipts::*;
pub use arkret_models_crypto::mls_envelopes::{
    MlsAppStateRef, MlsCommitEnvelope, MlsProposalEnvelope, MlsWelcomeEnvelope,
};

use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EncryptedPayload {
    pub scheme: EncryptedPayloadScheme,
    pub group_id: String,
    pub epoch: u64,
    pub content_type: String,
    pub ciphertext: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub aad: Option<EncryptedEnvelopeAad>,
    pub payload_digest: Hash,
    /// Reference to the key material that decrypts `ciphertext`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ref: Option<KeyRefObject>,
}

/// Typed `key_ref` per `media-and-blob.md` §encrypted-payload (B-22).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct KeyRefObject {
    pub algorithm: String,
    pub group_state_ref: String,
}

impl KeyRefObject {
    /// Build an MLS-RFC9420 typed `key_ref` from a group id and epoch.
    pub fn mls_rfc9420(group_id: impl Into<String>, epoch: u64) -> Self {
        Self {
            algorithm: EncryptedPayloadScheme::MlsRfc9420.as_str().to_owned(),
            group_state_ref: format!("{}:{}", group_id.into(), epoch),
        }
    }

    /// Build an MLS-EXPORTER-AEAD typed `key_ref` (§2.10) from a group id and
    /// epoch. The `algorithm` token `MLS-EXPORTER-AEAD` is bound by the
    /// `encrypted-envelope.schema.json` if/then to `scheme=mls-exporter-aead-v1`.
    pub fn mls_exporter_aead(group_id: impl Into<String>, epoch: u64) -> Self {
        Self {
            algorithm: "MLS-EXPORTER-AEAD".to_owned(),
            group_state_ref: format!("{}:{}", group_id.into(), epoch),
        }
    }
}

impl EncryptedPayload {
    pub fn mls_payload_digest(
        epoch: u64,
        content_type: &str,
        aad: Option<&EncryptedEnvelopeAad>,
        ciphertext_bytes: &[u8],
    ) -> Result<Hash> {
        Self::payload_digest_for_scheme(
            EncryptedPayloadScheme::MlsRfc9420,
            epoch,
            content_type,
            aad,
            ciphertext_bytes,
        )
    }

    /// §2.3.3 content payload digest, parameterized by `scheme`. The digest binds
    /// the `scheme` token into the metadata (`encryption` field) so a payload
    /// authored under `mls-exporter-aead-v1` (§2.10) and one under `mls-rfc9420`
    /// never collide, and the receiver's verification is scheme-bound.
    /// `ciphertext_bytes` are the raw decoded ciphertext bytes (for
    /// `mls-exporter-aead-v1` that is the `nonce || AEAD_ct` blob).
    pub fn payload_digest_for_scheme(
        scheme: EncryptedPayloadScheme,
        epoch: u64,
        content_type: &str,
        aad: Option<&EncryptedEnvelopeAad>,
        ciphertext_bytes: &[u8],
    ) -> Result<Hash> {
        let metadata = EncryptedPayloadDigestMetadata {
            content_type,
            encryption: scheme.as_str(),
            epoch,
            aad,
        };
        let mut input = canonical::canonical_json_bytes(&metadata)?;
        input.extend_from_slice(ciphertext_bytes);
        Ok(Hash::new(canonical::sha256_digest(&input))?)
    }

    pub fn verify_mls_payload_digest(&self, ciphertext_bytes: &[u8]) -> Result<()> {
        let expected = Self::payload_digest_for_scheme(
            self.scheme.clone(),
            self.epoch,
            &self.content_type,
            self.aad.as_ref(),
            ciphertext_bytes,
        )?;
        if expected == self.payload_digest {
            Ok(())
        } else {
            Err(Error::Protocol(
                "encrypted payload digest mismatch".to_owned(),
            ))
        }
    }

    /// Validate that the key reference, when present, is usable for lookup.
    pub fn validate_key_ref(&self) -> Result<()> {
        if let Some(key_ref) = &self.key_ref
            && key_ref.algorithm.trim().is_empty()
        {
            return Err(Error::Protocol(
                "key_ref.algorithm must not be empty".to_owned(),
            ));
        }
        if let Some(key_ref) = &self.key_ref
            && key_ref.group_state_ref.trim().is_empty()
        {
            return Err(Error::Protocol(
                "key_ref.group_state_ref must not be empty".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct EncryptedPayloadDigestMetadata<'a> {
    pub content_type: &'a str,
    pub encryption: &'a str,
    pub epoch: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aad: Option<&'a EncryptedEnvelopeAad>,
}

pub use arkret_models_collaboration::events_payloads::list_message_mimi_mls::MlsKeyPackageState;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MlsKeyPackageRecord {
    /// Globally unique identifier (`ak:mls:kp:<uuid>`, RFC 9562 UUIDv7).
    pub keypackage_id: String,
    pub principal_id: Did,
    pub device_id: DeviceId,
    /// MLS KeyPackage material (base64url).
    pub key_package: String,
    /// Canonical hash of `key_package`.
    pub keypackage_ref: Hash,
    pub cipher_suites: Vec<String>,
    /// Content / MLS profile capabilities (e.g. `mimi.content.v1`).
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Lifecycle state.
    #[serde(default)]
    pub state: MlsKeyPackageState,
    /// Bound `claim_id` once `state = claimed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_id: Option<String>,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_signature: Option<Proof>,
    /// Whether this is a reusable last-resort KeyPackage. Last-resort
    /// KeyPackages are NOT consumed on claim (the server keeps them
    /// claimable), so a member is always (re-)addable even after its
    /// single-use KeyPackages are exhausted. The init-key forward-secrecy
    /// trade-off is the standard MLS last-resort guarantee. The KeyPackage
    /// material MUST itself carry the OpenMLS `last_resort` extension (built
    /// via `mark_as_last_resort`) so the holder retains the init private key
    /// across repeated Welcome processing.
    #[serde(default)]
    pub last_resort: bool,
}

impl MlsKeyPackageRecord {
    /// Schema id for `ak.mls.keypackage` events / records.
    pub const SCHEMA: &'static str = "ak.schema.mls_keypackage.v1";

    /// Whether the record is currently usable for a Welcome.
    pub fn is_usable(&self) -> bool {
        !matches!(
            self.state,
            MlsKeyPackageState::Revoked
                | MlsKeyPackageState::Consumed
                | MlsKeyPackageState::Expired
        )
    }
}
