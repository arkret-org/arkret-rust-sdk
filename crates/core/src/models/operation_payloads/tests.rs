use serde_json::json;

use super::*;
use crate::{canonical, *};

#[test]
fn object_create_payload_wraps_object() {
    let actor = Did::new("did:webvh:z6mkfixture:alice.example".to_owned()).unwrap();
    let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap();
    let strand_id = StrandId::new("ak:strand:01904100-0000-7000-8000-000000000002").unwrap();
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
    let actor = Did::new("did:webvh:z6mkfixture:alice.example".to_owned()).unwrap();
    let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap();
    let space_id = SpaceId::new("ak:space:01904100-0000-7000-8000-000000000002").unwrap();
    let space = SpaceCreateObject::new(space_id, realm_id, "board", "Board", actor);
    let payload = ObjectCreatePayload::new(space).to_value().unwrap();
    canonical::validate_timestamp_canonical(payload["object"]["created_at"].as_str().unwrap())
        .unwrap();
}

#[test]
fn strand_tracks_update_payload_uses_strand_id_not_target_ref() {
    let strand_id = StrandId::new("ak:strand:01904100-0000-7000-8000-000000000002").unwrap();
    let patch: Patch = serde_json::from_value(json!({
        "tracks.discussion.is_primary": {"$op": "set", "value": true}
    }))
    .unwrap();
    let payload = StrandTracksUpdatePayload::with_patch(strand_id, patch)
        .unwrap()
        .to_value()
        .unwrap();

    assert_eq!(
        payload["strand_id"],
        "ak:strand:01904100-0000-7000-8000-000000000002"
    );
    assert!(payload.get("target_ref").is_none());
    assert!(payload.get("patch").is_some());
    schema::event_payload_validator_catalog()
        .unwrap()
        .validate_payload("ck.strand.tracks.update", &payload)
        .unwrap();
}

#[test]
fn morph_create_payload_uses_metadata_and_encrypted_content_names() {
    let actor = Did::new("did:webvh:z6mkfixture:alice.example".to_owned()).unwrap();
    let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap();
    let morph_id = MorphId::new("ak:morph:01904100-0000-7000-8000-000000000002").unwrap();
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
    let strand_id = StrandId::new("ak:strand:01904100-0000-7000-8000-000000000002").unwrap();
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
fn message_create_payload_reads_plain_body_and_first_media_block() {
    let strand_id = StrandId::new("ak:strand:01904100-0000-7000-8000-000000000002").unwrap();
    let blob_ref = format!("ak:blob:sha256:{}", "a".repeat(64));
    let media = ContentBlock::new(CONTENT_KIND_FILE, "spec.pdf")
        .with_field("mime_type", json!("application/pdf"))
        .with_field("filename", json!("spec.pdf"))
        .with_field("size_bytes", json!(7));
    let content = ContentBlock::new(CONTENT_KIND_COMPOSITE, "caption text")
        .with_part(ContentBlock::text("caption text"))
        .with_part(media);
    let mut payload =
        MessageCreatePayload::with_content(strand_id, "discussion", content.to_value().unwrap());
    payload.blob_refs.push(blob_ref.clone());

    assert_eq!(payload.plain_body().unwrap(), "caption text");
    assert!(MEDIA_CONTENT_KINDS.contains(&CONTENT_KIND_FILE));
    let block = payload.first_media_content_block().unwrap().unwrap();
    assert_eq!(block.kind, CONTENT_KIND_FILE);
    let attachment = payload.first_media_attachment().unwrap().unwrap();
    assert_eq!(attachment.blob_ref, blob_ref);
    assert_eq!(attachment.mime_type.as_deref(), Some("application/pdf"));
    assert_eq!(attachment.filename.as_deref(), Some("spec.pdf"));
    assert_eq!(attachment.size_bytes, Some(7));
    assert_eq!(attachment.caption, "caption text");
}

#[test]
fn content_block_validator_accepts_canonical_poll_block() {
    let block = json!({
        "kind": "ck.content.poll",
        "body": "ship?",
        "poll": {
            "kind": "disclosed",
            "max_selections": 1,
            "answers": [
                {"id": "yes", "text": {"kind": "ck.content.text", "body": "yes"}},
                {"id": "no", "text": {"kind": "ck.content.text", "body": "no"}}
            ]
        }
    });

    validate_content_block(&block).unwrap();
}

#[test]
fn content_block_validator_rejects_legacy_flat_poll_block() {
    let block = json!({
        "kind": "ck.content.poll",
        "body": "ship?",
        "question": "ship?",
        "options": ["yes", "no"]
    });

    let err = validate_content_block(&block).unwrap_err();
    assert_eq!(
        err.message(),
        "poll content block requires question and at least two options"
    );
}

#[test]
fn message_expiry_serializes_disappearing_wire_shape() {
    assert_eq!(DisappearingMessageExpiryTrigger::OnSend.as_str(), "on_send");
    assert_eq!(
        DisappearingMessageExpiryTrigger::OnFirstRead.as_str(),
        "on_first_read"
    );
    assert_eq!(
        DisappearingMessageExpiryTrigger::OnLastRead.as_str(),
        "on_last_read"
    );

    let expiry =
        DisappearingMessageExpiry::new(60_000, DisappearingMessageExpiryTrigger::OnFirstRead)
            .unwrap()
            .with_grace_ms(5_000);
    let value = serde_json::to_value(&expiry).unwrap();

    assert_eq!(value["ttl_ms"], 60_000);
    assert_eq!(value["trigger"], "on_first_read");
    assert!(value.get("seal_hlc").is_none());
    assert_eq!(value["grace_ms"], 5_000);
}

#[test]
fn message_expiry_rejects_non_positive_ttl() {
    let err =
        DisappearingMessageExpiry::new(0, DisappearingMessageExpiryTrigger::OnSend).unwrap_err();
    assert!(err.to_string().contains("ttl_ms"));
}

#[test]
fn message_create_payload_carries_disappearing_expiry() {
    let strand_id = StrandId::new("ak:strand:01904100-0000-7000-8000-000000000002").unwrap();
    let expiry =
        DisappearingMessageExpiry::new(60_000, DisappearingMessageExpiryTrigger::OnLastRead)
            .unwrap()
            .with_grace_ms(5_000);
    let payload = MessageCreatePayload::with_content(
        strand_id,
        "discussion",
        ContentBlock::text("hello").to_value().unwrap(),
    )
    .with_message_id("ak:message:01904100-0000-7000-8000-000000000003")
    .with_expiry(expiry)
    .to_value()
    .unwrap();

    assert_eq!(payload["expiry"]["ttl_ms"], 60_000);
    assert_eq!(payload["expiry"]["trigger"], "on_last_read");
    assert_eq!(payload["expiry"]["grace_ms"], 5_000);
    schema::event_payload_validator_catalog()
        .unwrap()
        .validate_payload("ck.message.create", &payload)
        .unwrap();
}

#[test]
fn morph_create_object_rejects_both_content_carriers() {
    let actor = Did::new("did:webvh:z6mkfixture:alice.example".to_owned()).unwrap();
    let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap();
    let morph_id = MorphId::new("ak:morph:01904100-0000-7000-8000-000000000003").unwrap();
    let mut morph = MorphCreateObject::new(morph_id, realm_id, "document", actor);
    morph.content = Some(json!({"kind": "ck.content.text", "body": "hello"}));
    morph.encrypted_content = Some(json!({"schema": ENCRYPTED_ENVELOPE_SCHEMA}));

    let err = morph.to_create_payload_value().unwrap_err();
    assert!(err.to_string().contains("content and encrypted_content"));
}
