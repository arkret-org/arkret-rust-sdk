use arkret_event_draft::{
    EVENT_PAYLOAD_BINDINGS, EventDraftKindRegistry, event_draft_kind_conformance_vectors,
};
use arkret_wire::EventKind;

#[test]
fn event_draft_kind_registry_accepts_only_canonical_kinds() {
    let registry = EventDraftKindRegistry::default();
    let canonical = registry
        .canonicalize(EventKind::MessageCreate.as_str())
        .unwrap();
    assert_eq!(canonical.canonical_kind, EventKind::MessageCreate.as_str());
    assert!(registry.canonicalize("message_create").is_err());
    assert_eq!(registry.kinds().count(), EVENT_PAYLOAD_BINDINGS.len());
}

#[test]
fn conformance_vectors_cover_every_registered_kind() {
    let vectors = event_draft_kind_conformance_vectors();
    assert_eq!(vectors.len(), EVENT_PAYLOAD_BINDINGS.len());
}
