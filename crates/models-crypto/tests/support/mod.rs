use arkret_models_crypto::{ContentContext, EncryptedEnvelope, EventContentMaterial};
use arkret_schema_conformance::spec_json_artifact;
use arkret_wire::ScopeRef;
use serde_json::Value;

pub fn fixture() -> Value {
    spec_json_artifact("fixtures/content-history-fixture.json").unwrap()
}

pub fn sender_domain() -> String {
    String::from_utf8(
        arkret_canonical::canonical_json_bytes(
            &fixture()["kat"]["content_context"]["producer"]["actor_id"],
        )
        .unwrap(),
    )
    .unwrap()
}

pub fn material(
    envelope: &EncryptedEnvelope,
    scope: &ScopeRef,
    kind: &str,
) -> EventContentMaterial {
    let f = fixture();
    let mut context: ContentContext =
        serde_json::from_value(f["kat"]["content_context"].clone()).unwrap();
    let data = serde_json::to_value(envelope).unwrap();
    context.root_context.effective_scope = scope.clone();
    context.root_context.epoch = envelope.encryption_context.epoch();
    context.root_context.group_state_ref = envelope.encryption_context.group_state_ref().clone();
    context.root_ref =
        serde_json::from_value(data["encryption_context"]["root_ref"].clone()).unwrap();
    context.content_key_salt = data["encryption_context"]["content_key_salt"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut outer = f["kat"]["outer_event"].clone();
    outer["scope_ref"] = serde_json::to_value(scope).unwrap();
    outer["kind"] = Value::String(kind.to_owned());
    if let Some(realm) = scope.realm_id_opt() {
        outer["realm_id"] = serde_json::to_value(realm).unwrap();
    }
    EventContentMaterial {
        content_context: context,
        outer_event: outer,
        key_commitment: serde_json::from_value(
            data["encryption_context"]["key_commitment"].clone(),
        )
        .unwrap(),
        protection: serde_json::from_value(data["encryption_context"]["protection"].clone())
            .unwrap(),
    }
}
