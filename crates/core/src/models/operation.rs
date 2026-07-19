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
pub use arkret_models_collaboration::events_payloads::list_message_mimi_mls::MlsKeyPackageState;
pub use arkret_models_collaboration::governance::grant_constraint::*;
pub use arkret_models_collaboration::governance::operation_wire::*;
pub use arkret_models_collaboration::objects::read_receipts::*;
// `EncryptedPayload` / `KeyRefObject` and the scheme-bound payload-digest
// helpers moved to `arkret_models_crypto::encrypted_envelope` so the crypto
// machine can consume them without the core facade.
pub use arkret_models_crypto::encrypted_envelope::{EncryptedPayload, KeyRefObject};
pub use arkret_models_crypto::mls_envelopes::{
    MlsAppStateRef, MlsCommitEnvelope, MlsProposalEnvelope, MlsWelcomeEnvelope,
};

use super::*;

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
