//! Arkret v1 client-side event drafting.
//!
//! Owner of the SDK-local drafting layer that sits *in front of* the wire
//! Event Envelope: the local [`Operation`] draft record, the
//! [`OperationEnvelope`] + registry-backed [`OperationEnvelopeBuilder`],
//! the draft-to-event conversion ([`OperationEventConversion`]), the
//! event-draft kind registry, LexoRank-style rank interval arithmetic, and
//! the strand create/tracks-update payload builders. None of these shapes
//! are Arkret v1 wire facts — they materialize into signed [`Event`]s
//! (owned by `arkret-wire`) before touching network, sync, or reducers.
//!
//! [`Event`]: arkret_wire::Event

mod accountability;
mod agent;
mod applet;
mod calendar;
mod device;
mod event_payload;
mod ghost_profile;
mod operation;
pub mod operations;
mod payloads;
mod rank;
mod registry;

pub use accountability::accountability_grant_event;
pub use agent::{
    agent_key_authorize_effects, agent_key_revoke_effects, build_agent_deactivate_event,
    build_agent_key_authorize_event, build_agent_key_revoke_event, build_agent_pause_event,
    build_agent_resume_event,
};
pub use applet::AppletBridgeErrorBuilder;
pub use calendar::{RsvpAuthoring, RsvpResponseBranch};
pub use device::{build_cross_signing_publish_event_at, build_device_authorize_event_at};
pub use event_payload::{EventPayloadExt, MessageEventPayload};
pub use ghost_profile::GhostActorProfileRequest;
pub use operation::{
    CausalRef, MlsEnvelopeOperationExt, MlsWelcomeTargetExt, Operation, OperationEnvelope,
    OperationEnvelopeBuilder, OperationEventConversion, OperationSignature,
};
pub use payloads::{StrandCreateObject, StrandTracksUpdatePayload};
pub use rank::{
    ContainerRebalanceAssignment, container_rebalance_assignments, rank_between, rank_exhausted,
};
pub use registry::{
    EventDraftKindConformanceVector, EventDraftKindRegistry, EventDraftKindSpec,
    EventDraftKindValidation, event_draft_kind_conformance_vectors, required_fields_for_event_kind,
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
