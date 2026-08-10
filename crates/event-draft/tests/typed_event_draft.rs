use arkret_canonical::canonical_json_bytes;
use arkret_event_draft::TypedEventDraft;
use arkret_models_collaboration::events_payloads::{ContentBlock, MessageCreatePayload};
use arkret_wire::{DidCoreId, EventKind, Hlc, RealmId, ScopeRef, StrandId, event_spec};
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
fn typed_authoring_is_byte_compatible_with_the_legacy_canonical_chain() {
    let (scope, actor, payload) = fixture();
    let created_at = Utc.with_ymd_and_hms(2026, 8, 9, 1, 2, 3).single().unwrap();
    let hlc = Hlc::new("01970e589d21-0001-a13f9c2e").unwrap();
    let typed = TypedEventDraft::<event_spec::MessageCreate>::new(
        scope.clone(),
        actor.clone(),
        payload.clone(),
    )
    .unwrap()
    .author(7, hlc.clone(), created_at)
    .unwrap();
    let legacy = arkret_wire::test_support::raw_event_at(
        EventKind::MessageCreate.as_str(),
        scope,
        actor,
        7,
        hlc,
        serde_json::to_value(payload).unwrap(),
        created_at,
    )
    .unwrap();

    assert_eq!(typed, legacy);
    assert_eq!(
        canonical_json_bytes(&typed).unwrap(),
        canonical_json_bytes(&legacy).unwrap()
    );
    assert_eq!(typed.event_id, typed.derive_event_id().unwrap());
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
