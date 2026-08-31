//! Arkret v1 collaboration domain models.
//!
//! Trunk crate of the model family: governance, collaboration objects,
//! event payloads, and sync/federation frames, organized as semantic
//! module directories. Phase 1A seeded the governance module with the
//! receive-policy, audit, and plaintext-classification wire shapes;
//! phase 1B-c2 lands the governance domain (realm governance, circle,
//! invite addressing, moderation, and grant constraints)
//! plus the first event-payload faces migrated from the `arkret` umbrella.

pub mod account_lifecycle;
pub mod agent_operations;
pub use arkret_models_identity::agent_signer_evidence;
pub mod call_signal;
pub mod contact_operations;
pub mod direct_conversation_ops;
pub mod event_query;
pub mod event_sync;
pub mod events_payloads;
pub mod federation;
pub mod governance;
pub mod governance_dependencies;
pub mod governance_payloads;
pub mod history_key;
pub mod http_bodies;
mod internal_prelude;
pub mod mls_group_state_material;
pub mod object_lifecycle;
pub mod objects;
pub mod prepared_event_draft;
pub mod principal_operations;
pub mod resolved_state;
pub mod seal_transparency;
pub mod session_grant_bodies;
pub mod sidecar_operations;
pub mod signal_message_stream;
pub mod signal_plaintext;
pub mod sync_frames;

pub use events_payloads::{
    RealmOrganizationAuthorization, RealmOrganizationControlScope, RealmOrganizationIssuerRole,
    RealmOrganizationPayload, RealmOrganizationRelationship, RealmOrganizationStatus,
    SignatureMaterial, realm_organization_statement_signing_bytes,
};
pub use governance::audit::{AccessKind, AuditPolicyAccessPayload};
pub use prepared_event_draft::PreparedEventDraft;
pub use resolved_state::ResolvedStateEvent;

macro_rules! string_marker {
    ($name:ident, $variant:ident, $wire:literal) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
        #[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
        pub enum $name {
            #[serde(rename = $wire)]
            $variant,
        }
    };
}

pub(crate) use string_marker;
