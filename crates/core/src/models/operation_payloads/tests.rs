use serde_json::json;

use super::*;
use crate::{canonical, *};

#[test]
fn object_create_payload_wraps_object() {
    let actor = Did::new("did:web:alice.example".to_owned()).unwrap();
    let realm_id = RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001").unwrap();
    let strand_id = StrandId::new("ck:strand:01904100-0000-7000-8000-000000000002").unwrap();
    let strand = StrandCreateObject::new(strand_id, realm_id, actor)
        .with_metadata_title("Incident")
        .with_track("discussion", StrandTrackConfig::discussion_primary());
    let payload = ObjectCreatePayload::new(strand).to_value().unwrap();
    assert_eq!(payload["object"]["schema"], STRAND_SCHEMA);
    assert_eq!(payload["object"]["stage"], "draft");
    assert_eq!(payload["object"]["metadata"]["title"], "Incident");
    canonical::validate_timestamp_canonical(payload["object"]["created_at"].as_str().unwrap())
        .unwrap();
}

#[test]
fn space_create_object_uses_canonical_timestamp() {
    let actor = Did::new("did:web:alice.example".to_owned()).unwrap();
    let realm_id = RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001").unwrap();
    let space_id = SpaceId::new("ck:space:01904100-0000-7000-8000-000000000002").unwrap();
    let space = SpaceCreateObject::new(space_id, realm_id, "board", "Board", actor);
    let payload = ObjectCreatePayload::new(space).to_value().unwrap();
    canonical::validate_timestamp_canonical(payload["object"]["created_at"].as_str().unwrap())
        .unwrap();
}

#[test]
fn morph_create_payload_uses_metadata_and_encrypted_content_names() {
    let actor = Did::new("did:web:alice.example".to_owned()).unwrap();
    let realm_id = RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001").unwrap();
    let morph_id = MorphId::new("ck:morph:01904100-0000-7000-8000-000000000002").unwrap();
    let morph = MorphCreateObject::new(morph_id, realm_id, "document", actor)
        .with_title("Spec")
        .with_summary("Draft")
        .with_encrypted_content(json!({"version": 1}));
    let payload = ObjectCreatePayload::new(morph).to_value().unwrap();
    assert_eq!(payload["object"]["metadata"]["title"], "Spec");
    assert_eq!(payload["object"]["metadata"]["summary"], "Draft");
    assert_eq!(payload["object"]["encrypted_content"]["version"], 1);
    canonical::validate_timestamp_canonical(payload["object"]["created_at"].as_str().unwrap())
        .unwrap();
    assert!(payload["object"].get("title").is_none());
    assert!(payload["object"].get("summary").is_none());
    assert!(payload["object"].get("encrypted_payload").is_none());
}

#[test]
fn message_create_payload_requires_exactly_one_content_carrier() {
    let strand_id = StrandId::new("ck:strand:01904100-0000-7000-8000-000000000002").unwrap();
    let payload = MessageCreatePayload::with_content(
        strand_id,
        "discussion",
        ContentBlock::text("hello").to_value().unwrap(),
    )
    .to_value()
    .unwrap();
    assert_eq!(payload["content"]["kind"], "ck.content.text");
    assert!(payload.get("encrypted_content").is_none());
}

#[test]
fn morph_create_object_rejects_both_content_carriers() {
    let actor = Did::new("did:web:alice.example".to_owned()).unwrap();
    let realm_id = RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001").unwrap();
    let morph_id = MorphId::new("ck:morph:01904100-0000-7000-8000-000000000003").unwrap();
    let mut morph = MorphCreateObject::new(morph_id, realm_id, "document", actor);
    morph.content = Some(json!({"kind": "ck.content.text", "body": "hello"}));
    morph.encrypted_content = Some(json!({"schema": ENCRYPTED_ENVELOPE_SCHEMA}));

    let err = morph.to_create_payload_value().unwrap_err();
    assert!(err.to_string().contains("content and encrypted_content"));
}
