use arkret_canonical::canonical_json_bytes;
use arkret_event_draft::TypedEventDraft;
use arkret_models_collaboration::events_payloads::{ContentBlock, MessageCreatePayload};
use arkret_wire::{
    DidCoreId, EventId, EventKind, Hlc, RealmId, ScopeRef, SealBasis, SealId, StrandId, event_spec,
};
use chrono::{TimeZone, Utc};

fn fixture() -> (ScopeRef, DidCoreId, MessageCreatePayload) {
    let scope = ScopeRef::Realm {
        realm_id: RealmId::new("ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir").unwrap(),
    };
    let actor = DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example").unwrap();
    let payload = MessageCreatePayload::with_content(
        StrandId::new("ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9").unwrap(),
        "main",
        ContentBlock::text("typed authoring KAT"),
    );
    (scope, actor, payload)
}

#[test]
fn typed_authoring_matches_the_raw_canonical_chain_byte_for_byte() {
    let (scope, actor, payload) = fixture();
    let created_at = Utc.with_ymd_and_hms(2026, 8, 9, 1, 2, 3).single().unwrap();
    let hlc = Hlc::new("01970e589d21-0001-a13f9c2e").unwrap();
    let typed = TypedEventDraft::<event_spec::MessageCreate>::new(
        scope.clone(),
        actor.clone(),
        actor.clone(),
        payload.clone(),
    )
    .unwrap()
    .author_with_digest_suite(
        7,
        hlc.clone(),
        created_at,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    let raw = arkret_wire::test_support::raw_event_at(
        EventKind::MessageCreate.as_str(),
        scope,
        actor.clone(),
        actor,
        7,
        hlc,
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

#[test]
fn typed_authoring_materializes_prev_refs_and_seal_basis() {
    let (scope, actor, payload) = fixture();
    let prev = EventId::new(format!("ak:event:A{}", "b".repeat(43))).unwrap();
    let seal = SealId::new(format!("ak:seal:sha256:{}", "c".repeat(64))).unwrap();
    let basis = SealBasis {
        leaves: vec![seal.clone()],
    };
    let event =
        TypedEventDraft::<event_spec::MessageCreate>::new(scope, actor.clone(), actor, payload)
            .unwrap()
            .with_prev_refs(vec![prev.clone()])
            .with_seal_basis(basis.clone())
            .author_with_digest_suite(
                8,
                Hlc::new("01970e589d21-0002-a13f9c2e").unwrap(),
                Utc.with_ymd_and_hms(2026, 8, 9, 1, 2, 4).single().unwrap(),
                arkret_canonical::DigestSuite::Sha256,
            )
            .unwrap();

    assert_eq!(event.prev_refs, vec![prev]);
    assert_eq!(event.seal_basis, Some(basis));
    event.verify_identity().unwrap();
}

/// A marker cannot be paired with another marker's payload type.
///
/// ```compile_fail
/// # use arkret_event_draft::TypedEventDraft;
/// # use arkret_models_collaboration::events_payloads::{ContentBlock, MessageCreatePayload, RealmCreatePayload};
/// # use arkret_wire::{DidCoreId, RealmId, ScopeRef, StrandId, event_spec};
/// # let scope = ScopeRef::Realm { realm_id: RealmId::new("ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir").unwrap() };
/// # let actor = DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example").unwrap();
/// # let message = MessageCreatePayload::with_content(StrandId::new("ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9").unwrap(), "main", ContentBlock::text("hello"));
/// let _ = TypedEventDraft::<event_spec::RealmCreate>::new(scope, actor, message);
/// ```
pub struct MarkerPayloadCompileFail;
