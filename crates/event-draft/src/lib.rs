//! Arkret v1 client-side event drafting.
//!
//! Owner of the SDK-local drafting layer that sits *in front of* the wire
//! Event Envelope: typed Event drafts, the local MLS scheduler draft,
//! local reducer projections and MLS scheduler records, the event-draft kind
//! registry, LexoRank-style rank interval arithmetic, and
//! the strand create/tracks-update payload builders. None of these shapes
//! are Arkret v1 wire facts — they materialize into signed [`Event`]s
//! (owned by `arkret-wire`) before touching network, sync, or reducers.
//!
//! [`Event`]: arkret_wire::Event

mod accountability;
mod agent;
mod applet;
mod calendar;
mod event_intent;
mod event_payload;
mod ghost_profile;
mod metadata_send_gate;
mod operation;
mod payloads;
mod rank;
mod registry;
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub mod test_support;
mod typed_event_draft;

pub use accountability::accountability_grant_intent;
pub use agent::{
    AgentLifecycleState, build_agent_deactivate_intent, build_agent_key_authorize_intent,
    build_agent_key_revoke_intent, build_agent_pause_intent, build_agent_resume_intent,
};
pub use applet::AppletBridgeErrorBuilder;
pub use calendar::{RsvpAuthoring, RsvpResponseBranch};
pub use event_intent::EventIntent;
pub use event_payload::{
    EVENT_PAYLOAD_BINDINGS, EventPayloadBinding, EventPayloadExt, EventSpec, MessageEventPayload,
    validate_event_payload,
};
pub use ghost_profile::GhostActorProfileRequest;
pub use metadata_send_gate::{EventMetadataSendGate, EventMetadataSendGateExt};
pub use operation::{
    LocalOperationDraft, LocalOperationSpec, MlsEnvelopeOperationExt, ProjectedEventOperation,
    ProjectionContext, local_operation_spec,
};
pub use payloads::StrandCreateObject;
pub use rank::{rank_between, rank_exhausted};
pub use registry::{
    EventDraftKindConformanceVector, EventDraftKindRegistry, EventDraftKindSpec,
    EventDraftKindValidation, event_draft_kind_conformance_vectors,
};
pub use typed_event_draft::{
    EventAuthoringContext, ExtensionPayloadValidator, TypedEventDraft, ValidatedExtensionPayload,
};

/// Result alias for this crate's fallible drafting operations.
pub type Result<T> = std::result::Result<T, EventDraftError>;

/// Errors surfaced while drafting, validating, or materializing operations.
#[derive(Debug, thiserror::Error)]
pub enum EventDraftError {
    /// Spec-level violation carrying the reason message verbatim.
    #[error("{0}")]
    Protocol(String),

    #[error(transparent)]
    Wire(#[from] arkret_wire::WireError),

    #[error(transparent)]
    Canonical(#[from] arkret_canonical::CanonicalError),

    #[error(transparent)]
    Identifier(#[from] arkret_identifiers::IdentifierError),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
