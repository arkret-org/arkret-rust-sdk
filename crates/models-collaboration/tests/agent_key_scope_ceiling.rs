use arkret_models_collaboration::agent_scope::agent_key_scope_within_provision;
use arkret_models_collaboration::events_payloads::agent::AgentKeyScope;
use arkret_wire::{EventId, RealmId};
use serde_json::json;

#[test]
fn key_ceiling_preserves_content_boundary_and_mandatory_controller_review() {
    let realm = RealmId::from_event_id(&EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [11; 32],
    ));
    let outside = RealmId::from_event_id(&EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [12; 32],
    ));
    let ceiling: AgentKeyScope = serde_json::from_value(json!({
        "actions":["ak.event.read","ak.message.create"],
        "resources":[{"kind":"realm","realm_id":realm}],
        "constraints":[{"constraint_kind":"claim_based","constraint_subkind":"approval","effect":"allow","controller_approval_required":true}]
    })).unwrap();
    let mut narrowed = ceiling.clone();
    narrowed.actions = vec!["ak.event.read".to_owned()];
    assert!(agent_key_scope_within_provision(&ceiling, &narrowed));
    narrowed.resources =
        serde_json::from_value(json!([{"kind":"strand","realm_id":realm,
            "resource_ref":arkret_wire::StrandId::from_event_id(&EventId::from_digest(arkret_canonical::DigestSuite::Sha256,[14;32])).as_str()}])).unwrap();
    assert!(agent_key_scope_within_provision(&ceiling, &narrowed));
    narrowed.resources =
        serde_json::from_value(json!([{"kind":"realm","realm_id":outside}])).unwrap();
    assert!(!agent_key_scope_within_provision(&ceiling, &narrowed));
    narrowed = ceiling.clone();
    narrowed.constraints.clear();
    assert!(!agent_key_scope_within_provision(&ceiling, &narrowed));
    narrowed = ceiling.clone();
    narrowed.actions.push("ak.capability.grant".to_owned());
    assert!(!agent_key_scope_within_provision(&ceiling, &narrowed));
}

#[test]
fn operation_selection_does_not_become_an_implicit_content_ceiling() {
    let ceiling: AgentKeyScope = serde_json::from_value(json!({
        "actions":["ak.event.read"],
        "resources":[{"kind":"operation","operation":"ak.self.committed_event.read.scan.v1"}]
    }))
    .unwrap();
    let mut child = ceiling.clone();
    child.resources = serde_json::from_value(json!([{"kind":"realm","realm_id":RealmId::from_event_id(&EventId::from_digest(arkret_canonical::DigestSuite::Sha256,[13;32]))}])).unwrap();
    assert!(agent_key_scope_within_provision(&ceiling, &child));
    child.resources = serde_json::from_value(
        json!([{"kind":"operation","operation":"ak.self.committed_event.stream.subscribe.v1"}]),
    )
    .unwrap();
    assert!(!agent_key_scope_within_provision(&ceiling, &child));
    child.resources.clear();
    assert!(!agent_key_scope_within_provision(&ceiling, &child));
}
