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

#[allow(clippy::too_many_arguments)]
fn author_event(
    kind: arkret_wire::EventKind,
    scope_ref: arkret_wire::ScopeRef,
    actor_id: arkret_wire::ActorId,
    executed_by: Option<arkret_wire::ActorId>,
    authorization_ref: Option<arkret_wire::AuthorizationRef>,
    created_at: chrono::DateTime<chrono::Utc>,
    semantic_refs: Vec<arkret_wire::SemanticRef>,
    payload: serde_json::Value,
) -> arkret_wire::Result<arkret_wire::AuthoredEvent> {
    let serde_json::Value::Object(payload) = payload else {
        return Err(arkret_wire::WireError::Protocol(
            "bootstrap Event payload must serialize as an object".to_owned(),
        ));
    };
    let placeholder =
        arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0; 32]);
    let realm_id = scope_ref
        .realm_id_opt()
        .cloned()
        .unwrap_or_else(|| arkret_wire::RealmId::from_event_id(&placeholder));
    arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        arkret_wire::Event {
            event_id: placeholder,
            kind,
            realm_id,
            scope_ref,
            actor_id,
            executed_by,
            authorization_ref,
            applet_id: None,
            external_ref: None,
            created_at: arkret_canonical::normalize_timestamp_canonical(created_at),
            semantic_refs,
            payload: payload.into_iter().collect(),
            producer_proof: None,
        },
        arkret_canonical::DigestSuite::Sha256,
    )
}
