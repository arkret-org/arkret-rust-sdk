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
// `EncryptedPayload` / `KeyRefObject` and the scheme-bound payload-digest
// helpers moved to `arkret_models_crypto::encrypted_envelope` so the crypto
// machine can consume them without the core facade.
pub use arkret_models_crypto::encrypted_envelope::{EncryptedPayload, KeyRefObject};
pub use arkret_models_crypto::mls_envelopes::{
    MlsAppStateRef, MlsCommitEnvelope, MlsProposalEnvelope, MlsWelcomeEnvelope,
};
// `MlsKeyPackageRecord` moved to `arkret_models_crypto::mls_records` so the MLS
// behavior layer can consume it without the core facade. Re-exported here to
// keep the `arkret_core::MlsKeyPackageRecord` path stable. (`MlsKeyPackageState`
// also moved there but already reaches the core root through the
// `list_message_mimi_mls` re-export glob in `event_payload`.)
pub use arkret_models_crypto::mls_records::MlsKeyPackageRecord;
