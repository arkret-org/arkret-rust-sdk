//! Producer-side builders for Arkret bootstrap Events.
//!
//! Bootstrap produces content-bound Events which a producer signs. The current
//! governance Station validates those immutable Events and appends one
//! [`arkret_wire::RealmCommit`] per Event to the appropriate independent Realm,
//! Circle, or Sidecar stream.

mod agent;
mod agent_provision;
mod self_principal;
#[cfg(test)]
mod tests;

pub use agent::{
    AgentPcrCreateEventInput, AgentPcrCreatePayloadInput, build_agent_pcr_create,
    build_agent_pcr_create_payload,
};
pub use agent_provision::{AgentProvisionIntentOptions, build_agent_provision_intent};
pub use self_principal::{
    SelfPrincipalPcrCreateInput, build_pcr_genesis_unit, build_self_principal_pcr_create,
    validate_self_principal_pcr_create,
};

pub const DID_INCEPTION_REF_ROLE: &str = "did_inception";

/// Author a bootstrap Event whose kind and payload type are one type-level
/// fact; the payload is validated through its SDK binding before signing.
fn author_event<K: arkret_event_draft::EventSpec>(
    scope_ref: arkret_wire::ScopeRef,
    actor_id: arkret_wire::ActorId,
    executed_by: Option<arkret_wire::ActorId>,
    authorization_ref: Option<arkret_wire::AuthorizationRef>,
    created_at: chrono::DateTime<chrono::Utc>,
    semantic_refs: Vec<arkret_wire::SemanticRef>,
    payload: K::Payload,
) -> arkret_wire::Result<arkret_wire::AuthoredEvent> {
    let mut draft = arkret_event_draft::TypedEventDraft::<K>::new(scope_ref, actor_id, payload)
        .map_err(draft_error)?
        .with_semantic_refs(semantic_refs);
    if let Some(executed_by) = executed_by {
        draft = draft.with_executed_by(executed_by);
    }
    if let Some(authorization_ref) = authorization_ref {
        draft = draft.with_authorization_ref(authorization_ref);
    }
    draft
        .author_with_digest_suite(created_at, arkret_canonical::DigestSuite::Sha256)
        .map_err(draft_error)
}

fn draft_error(error: arkret_event_draft::EventDraftError) -> arkret_wire::WireError {
    match error {
        arkret_event_draft::EventDraftError::Wire(error) => error,
        other => arkret_wire::WireError::Protocol(other.to_string()),
    }
}
