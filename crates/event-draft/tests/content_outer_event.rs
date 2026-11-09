//! Frozen outer bytes, not native source or content-backup durability proofs.

use arkret_event_draft::TypedEventDraft;
use arkret_models_collaboration::events_payloads::{ContentBlock, MessageCreatePayload};
use arkret_models_crypto::EventContentMaterial;
use arkret_wire::{
    AccountId, ActorId, DidCoreId, Event, EventId, RealmId, ScopeRef, StrandId, event_spec,
};
use chrono::{TimeZone as _, Utc};
use serde_json::json;

#[test]
fn encryption_only_draft_rejects_identity_changes_and_installs_only_a_valid_typed_payload() {
    let fixture =
        arkret_schema_conformance::spec_json_artifact("fixtures/content-history-fixture.json")
            .unwrap();
    let outer = &fixture["kat"]["outer_event"];
    let scope: ScopeRef = serde_json::from_value(outer["scope_ref"].clone()).unwrap();
    let actor: ActorId = serde_json::from_value(outer["actor_id"].clone()).unwrap();
    let at = "2026-11-09T01:02:03.000Z".parse().unwrap();
    let draft = || {
        arkret_event_draft::EventContentDraft::<event_spec::MessageCreate>::new(
            scope.clone(),
            actor.clone(),
            at,
        )
        .unwrap()
    };
    assert!(
        draft()
            .with_prepared_outer(
                draft()
                    .intent()
                    .clone()
                    .with_created_at(at + chrono::Duration::seconds(1))
            )
            .is_err()
    );
    let other = ActorId::account(AccountId::new(
        DidCoreId::new("ak:did_core:web:other.example").unwrap(),
        DidCoreId::new("ak:did_core:web:station.example").unwrap(),
    ));
    let different = arkret_event_draft::EventContentDraft::<event_spec::MessageCreate>::new(
        scope.clone(),
        other,
        at,
    )
    .unwrap();
    assert!(
        draft()
            .with_prepared_outer(different.intent().clone())
            .is_err()
    );
    let payload = MessageCreatePayload::with_content(
        StrandId::new("ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9").unwrap(),
        "discussion",
        ContentBlock::text("ready payload"),
    );
    let local = draft().with_semantic_refs(vec![arkret_wire::SemanticRef::new(
        EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [7; 32]).to_string(),
        "after",
    )]);
    let frozen = local.intent().pre_encryption_outer_event().unwrap();
    let intent = local.install_payload(payload).unwrap();
    assert_eq!(intent.pre_encryption_outer_event().unwrap(), frozen);
    assert!(!intent.payload().is_empty());
    assert!(draft().with_prepared_outer(intent).is_err());
}

#[test]
fn formal_content_kat_outer_is_the_actual_event_serializer_projection() {
    let fixture =
        arkret_schema_conformance::spec_json_artifact("fixtures/content-history-fixture.json")
            .unwrap();
    let mut value = fixture["kat"]["outer_event"].clone();
    value["event_id"] = json!(EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [9; 32]
    ));
    value["payload"] = json!({});
    let event: Event = serde_json::from_value(value).unwrap();
    assert_eq!(
        EventContentMaterial::outer_event_for(&event).unwrap(),
        fixture["kat"]["outer_event"]
    );
}

#[test]
fn frozen_intent_preserves_optional_outer_members_and_never_derives_an_id() {
    let realm = RealmId::new("ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir").unwrap();
    let principal = DidCoreId::new("ak:did_core:web:alice.example").unwrap();
    let station = DidCoreId::new("ak:did_core:web:station.example").unwrap();
    let payload = MessageCreatePayload::with_content(
        StrandId::new("ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9").unwrap(),
        "main",
        ContentBlock::text("frozen outer header"),
    );
    let intent = TypedEventDraft::<event_spec::MessageCreate>::new(
        ScopeRef::Realm { realm_id: realm },
        ActorId::account(AccountId::new(principal, station)),
        payload,
    )
    .unwrap()
    .into_intent(Utc.with_ymd_and_hms(2026, 11, 9, 1, 2, 3).unwrap())
    .unwrap()
    .with_external_ref(std::collections::BTreeMap::from([(
        "x_nested".to_owned(),
        json!({"payload":"retained", "unsigned":true}),
    )]));
    let frozen = intent.pre_encryption_outer_event().unwrap();
    assert_eq!(frozen["external_ref"]["x_nested"]["payload"], "retained");
    assert_eq!(frozen["created_at"], "2026-11-09T01:02:03.000Z");
    for excluded in ["event_id", "payload", "producer_proof", "unsigned"] {
        assert!(frozen.get(excluded).is_none());
    }
    let authored = intent
        .author_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    assert_eq!(
        frozen,
        EventContentMaterial::outer_event_for(authored.event()).unwrap()
    );
    let mut changed = authored.event().clone();
    changed
        .payload
        .insert("x_replaced_body".to_owned(), json!(true));
    changed
        .refresh_content_bound_identity_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    assert_ne!(changed.event_id, authored.event().event_id);
    assert_eq!(
        frozen,
        EventContentMaterial::outer_event_for(&changed).unwrap()
    );
    changed.created_at += chrono::Duration::milliseconds(1);
    assert_ne!(
        frozen,
        EventContentMaterial::outer_event_for(&changed).unwrap()
    );
    changed.scope_ref = ScopeRef::RealmGenesis;
    assert!(EventContentMaterial::outer_event_for(&changed).is_err());
}

#[test]
fn sealed_message_is_checked_before_event_id_derivation_without_changing_outer() {
    let fixture =
        arkret_schema_conformance::spec_json_artifact("fixtures/content-history-fixture.json")
            .unwrap();
    let message: arkret_models_collaboration::message_authoring::MessageAuthoringIntent =
        serde_json::from_value(fixture["local_message_authoring"].clone()).unwrap();
    let producer: arkret_models_crypto::ContentEndpoint =
        serde_json::from_value(fixture["kat"]["content_context"]["producer"].clone()).unwrap();
    let intent = TypedEventDraft::<event_spec::MessageCreate>::new(
        serde_json::from_value(fixture["kat"]["outer_event"]["scope_ref"].clone()).unwrap(),
        producer.actor_id.clone(),
        message.payload(),
    )
    .unwrap()
    .into_intent(
        serde_json::from_value(fixture["kat"]["outer_event"]["created_at"].clone()).unwrap(),
    )
    .unwrap();
    assert_eq!(
        intent.pre_encryption_outer_event().unwrap(),
        fixture["kat"]["outer_event"]
    );
    intent
        .validate_message_encryption_binding(&message, &producer)
        .unwrap();
    let changed = intent
        .clone()
        .with_external_ref(std::collections::BTreeMap::from([(
            "x_extra".to_owned(),
            json!(true),
        )]));
    assert!(
        changed
            .validate_message_encryption_binding(&message, &producer)
            .is_err()
    );
    let authored = intent
        .author_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .unwrap();
    message
        .validate_encryption_binding(authored.event(), &producer)
        .unwrap();
}

#[test]
fn typed_content_replacement_preserves_frozen_outer_and_revalidates_payload_kind() {
    let fixture =
        arkret_schema_conformance::spec_json_artifact("fixtures/content-history-fixture.json")
            .unwrap();
    let message: arkret_models_collaboration::message_authoring::MessageAuthoringIntent =
        serde_json::from_value(fixture["local_message_authoring"].clone()).unwrap();
    let producer: arkret_models_crypto::ContentEndpoint =
        serde_json::from_value(fixture["kat"]["content_context"]["producer"].clone()).unwrap();
    let plain = MessageCreatePayload::with_content(
        message.strand_id.clone(),
        "discussion",
        ContentBlock::text("staged private message"),
    );
    let draft = TypedEventDraft::<event_spec::MessageCreate>::new(
        serde_json::from_value(fixture["kat"]["outer_event"]["scope_ref"].clone()).unwrap(),
        producer.actor_id,
        plain,
    )
    .unwrap()
    .into_intent(
        serde_json::from_value(fixture["kat"]["outer_event"]["created_at"].clone()).unwrap(),
    )
    .unwrap()
    .with_external_ref(std::collections::BTreeMap::from([(
        "x_exact".to_owned(),
        json!({"payload":"retained","unsigned":true}),
    )]));
    let frozen = draft.pre_encryption_outer_event().unwrap();
    let sealed = draft
        .clone()
        .with_typed_payload::<event_spec::MessageCreate>(message.payload())
        .unwrap();
    assert_eq!(sealed.pre_encryption_outer_event().unwrap(), frozen);
    assert_ne!(sealed.payload(), draft.payload());
    assert_eq!(sealed.created_at(), draft.created_at());
    let mut invalid_kind = serde_json::to_value(&draft).unwrap();
    invalid_kind["kind"] = json!("ak.message.revise");
    let invalid_kind: arkret_event_draft::EventIntent =
        serde_json::from_value(invalid_kind).unwrap();
    assert!(
        invalid_kind
            .with_typed_payload::<event_spec::MessageCreate>(message.payload())
            .is_err()
    );
    let mut invalid_content = message.payload();
    invalid_content.content = Some(ContentBlock::text("mixed cleartext and ciphertext"));
    assert!(
        draft
            .with_typed_payload::<event_spec::MessageCreate>(invalid_content)
            .is_err()
    );
}
