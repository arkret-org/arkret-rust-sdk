use arkret_canonical::canonical_json_bytes;
use arkret_event_draft::TypedEventDraft;
use arkret_models_collaboration::events_payloads::{ContentBlock, MessageCreatePayload};
use arkret_wire::{
    AccountId, ActorId, DidCoreId, EventKind, RealmId, ScopeRef, StrandId, event_spec,
};
use chrono::{TimeZone, Utc};

#[test]
fn typed_authoring_matches_the_minimal_event_envelope() {
    let realm_id = RealmId::new("ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir").unwrap();
    let scope = ScopeRef::Realm { realm_id };
    let actor = DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example").unwrap();
    let payload = MessageCreatePayload::with_content(
        StrandId::new("ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9").unwrap(),
        "main",
        ContentBlock::text("typed authoring KAT"),
    );
    let created_at = Utc.with_ymd_and_hms(2026, 8, 9, 1, 2, 3).single().unwrap();
    let typed = TypedEventDraft::<event_spec::MessageCreate>::new(
        scope.clone(),
        ActorId::account(AccountId::new(actor.clone(), actor.clone())),
        payload.clone(),
    )
    .unwrap()
    .author_with_digest_suite(created_at, arkret_canonical::DigestSuite::Sha256)
    .unwrap();
    let raw = arkret_wire::test_support::raw_event_at(
        EventKind::MessageCreate.as_str(),
        scope,
        actor.clone(),
        actor,
        serde_json::to_value(payload).unwrap(),
        created_at,
    )
    .unwrap();

    assert_eq!(typed.event(), &raw);
    assert_eq!(
        canonical_json_bytes(typed.event()).unwrap(),
        canonical_json_bytes(&raw).unwrap()
    );
    typed.verify_identity().unwrap();
}
