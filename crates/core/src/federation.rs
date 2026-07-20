//! Arkret federation wire contracts and shared helpers.
//!
//! The pure federation frame shapes live in `arkret-models-collaboration`
//! (`federation::frames`); the transaction envelope, in-memory
//! replay-protection store, and delta batch (which bind
//! `arkret_event_draft::Operation` and `FederationTransactionRequestBody`)
//! live in `arkret-event-draft` (`federation`). Both are re-exported here
//! for path stability.

pub use arkret_event_draft::federation::{
    DEFAULT_FEDERATION_REPLAY_CAPACITY, DEFAULT_FEDERATION_REPLAY_TTL_SECS, FederationDeltaBatch,
    FederationTransactionEnvelope, MemoryFederationReplayStore,
};
pub use arkret_models_collaboration::federation::frames::{
    FederationBackfillAuthorization, FederationBackfillOutcome, FederationBackfillQuery,
    FederationEventAuthOutcome, FederationEventAuthQuery, FederationMediaOutcome,
    FederationMediaRequestBody, FederationQuarantineKind, FederationQuarantineRecord,
    FederationReplayDecision, FederationReplayRecord, HttpMessageSignatureInput,
    ServiceEndpointDescriptor, VerifyActorChallenge, VerifyActorChallengeSignature,
    WellKnownArkretServer,
};

pub use crate::HttpMessageSignature;
