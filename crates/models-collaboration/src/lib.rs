//! Arkret v1 collaboration domain models.
//!
//! Trunk crate of the model family: governance, collaboration objects,
//! event payloads, and sync frames, organized as semantic
//! module directories. Phase 1A seeded the governance module with the
//! receive-policy, audit, and plaintext-classification wire shapes;
//! phase 1B-c2 lands the governance domain (realm governance, circle,
//! invite addressing, moderation, and grant constraints)
//! plus the first event-payload faces migrated from the `arkret` umbrella.

pub mod account_lifecycle;
pub mod account_operations;
pub mod account_status;
pub mod account_subscribe_projections;
pub mod actor_profile_resolution;
pub mod agent_operations;
pub mod agent_scope;
pub mod agent_sidecar;
pub mod applet_installation_authority;
pub mod authority_commit;
pub mod call_signal;
pub mod consent_operations;
pub mod contact_operations;
pub mod device_messages;
pub mod device_pairing;
pub mod direct_conversation;
pub mod event_query;
pub mod event_sync;
pub mod events_payloads;
pub mod governance;
pub mod governance_payloads;
mod internal_prelude;
pub mod message_authoring;
pub mod mimi_operations;
pub mod mls_group_state_material;
pub mod object_lifecycle;
pub mod objects;
pub mod prepared_event_draft;
pub mod principal_operations;
mod serde_absence;
pub mod session_grant_bodies;
pub mod session_grants;
pub mod sidecar_operations;
pub mod signal_message_stream;
pub mod signal_operations;
pub mod signal_plaintext;
pub mod strand_watch_operations;
pub mod sync_frames;

pub use events_payloads::{
    RealmOrganizationAuthorization, RealmOrganizationControlScope, RealmOrganizationIssuerRole,
    RealmOrganizationPayload, RealmOrganizationRelationship, RealmOrganizationStatus,
    SignatureMaterial, realm_organization_statement_signing_bytes,
};
pub use governance::audit::{AccessKind, AuditPolicyAccessPayload};
pub use prepared_event_draft::PreparedEventDraft;

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
