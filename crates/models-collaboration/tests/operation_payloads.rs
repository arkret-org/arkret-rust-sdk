use std::any::TypeId;

use arkret_canonical::canonical;
use arkret_models_collaboration::events_payloads::{ObjectCreatePayload, *};
use arkret_models_collaboration::objects::profiles::{Morph, MorphMetadata};
use arkret_models_collaboration::objects::space::Space;
use arkret_models_collaboration::objects::strand::{MessageMetadata, StrandMetadata};
use arkret_models_crypto::{EncryptedEnvelope, MlsEncryptedPayload, ProtectedPayload};
use arkret_schema::event_payload_validator_catalog;
use arkret_wire::{ActorId, Did, MorphId, RealmId, SpaceId, StrandId, project_did_to_core_id};
use serde_json::json;

fn actor(value: &str) -> ActorId {
    ActorId::service(project_did_to_core_id(&Did::new(value).unwrap()).unwrap())
}

#[test]
fn agent_pair_activation_state_has_closed_two_phase_wire_values() {
    use arkret_models_collaboration::agent_operations::AgentKeyPairActivationState;

    assert_eq!(
        serde_json::to_value(AgentKeyPairActivationState::AwaitingAcceptedFrontier).unwrap(),
        json!("awaiting_accepted_frontier")
    );
    assert_eq!(
        serde_json::from_value::<AgentKeyPairActivationState>(json!("active")).unwrap(),
        AgentKeyPairActivationState::Active
    );
    assert!(
        serde_json::from_value::<AgentKeyPairActivationState>(json!("durable_but_active")).is_err()
    );
}

fn encrypted_envelope() -> EncryptedEnvelope {
    serde_json::from_value(json!({
        "version": "1.0",
        "content_type": "application/vnd.arkret.message+json",
        "encryption_context": {
            "epoch": 1,
            "group_state_ref": "ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM"
        },
        "ciphertext": "AA",
    }))
    .unwrap()
}

#[test]
fn space_create_object_uses_canonical_timestamp() {
    let actor = actor("did:webvh:z6mkfixture:alice.example");
    let realm_id = RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap();
    let space_id = SpaceId::new("ak:space:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1").unwrap();
    let space = Space::new(space_id, realm_id, "board", "Board", actor);
    let payload = ObjectCreatePayload::new(space).to_value().unwrap();
    canonical::validate_timestamp_canonical(payload["object"]["created_at"].as_str().unwrap())
        .unwrap();
}

#[test]
fn morph_create_payload_uses_metadata_and_encrypted_content_names() {
    let actor = actor("did:webvh:z6mkfixture:alice.example");
    let realm_id = RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap();
    let morph_id = MorphId::new("ak:morph:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1").unwrap();
    let mut morph = Morph::new(morph_id, realm_id, "document", actor).with_metadata_title("Spec");
    morph
        .metadata
        .get_or_insert_with(MorphMetadata::default)
        .summary = Some("Draft".to_owned());
    morph.encrypted_content = Some(encrypted_envelope());
    let payload = ObjectCreatePayload::new(morph).to_value().unwrap();
    assert_eq!(payload["object"]["metadata"]["title"], "Spec");
    assert_eq!(payload["object"]["metadata"]["summary"], "Draft");
    assert_eq!(payload["object"]["encrypted_content"]["version"], "1.0");
    canonical::validate_timestamp_canonical(payload["object"]["created_at"].as_str().unwrap())
        .unwrap();
    assert!(payload["object"].get("title").is_none());
    assert!(payload["object"].get("summary").is_none());
    assert!(payload["object"].get("encrypted_payload").is_none());
}

#[test]
fn morph_and_strand_metadata_are_distinct_closed_shapes() {
    assert_ne!(
        TypeId::of::<MorphMetadata>(),
        TypeId::of::<StrandMetadata>()
    );

    assert!(
        serde_json::from_value::<MorphMetadata>(json!({
            "title": "Morph",
            "fields": {"status": "draft"}
        }))
        .is_err()
    );
    let strand = serde_json::from_value::<StrandMetadata>(json!({
        "title": "Strand",
        "fields": {"calendar": {"all_day": true}},
        "x_display_hint": "compact"
    }))
    .unwrap();
    assert!(strand.fields.contains_key("calendar"));
    assert_eq!(strand.extra["x_display_hint"], "compact");

    let mut morph = MorphMetadata::default();
    morph.extra.insert("fields".to_owned(), json!({}));
    assert!(serde_json::to_value(morph).is_err());
    assert!(serde_json::from_value::<StrandMetadata>(json!({"created_by": "forbidden"})).is_err());
}

#[test]
fn message_create_payload_requires_exactly_one_content_carrier() {
    let strand_id =
        StrandId::new("ak:strand:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1").unwrap();
    let payload =
        MessageCreatePayload::with_content(strand_id, "discussion", ContentBlock::text("hello"))
            .to_value()
            .unwrap();
    assert_eq!(payload["content"]["kind"], "ak.content.text");
    assert!(payload.get("encrypted_content").is_none());
}

#[test]
fn message_payload_protection_axis_is_closed_and_typed() {
    let strand_id =
        StrandId::new("ak:strand:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1").unwrap();
    let plain = MessageCreatePayload::with_content(
        strand_id.clone(),
        "discussion",
        ContentBlock::text("hello"),
    );
    assert!(matches!(
        plain.protected_content().unwrap(),
        ProtectedPayload::Plain(_)
    ));

    let encrypted = MlsEncryptedPayload::<ContentBlock>::new(encrypted_envelope()).unwrap();
    let protected =
        MessageCreatePayload::with_mls_encrypted_content(strand_id, "discussion", encrypted);
    assert!(matches!(
        protected.protected_content().unwrap(),
        ProtectedPayload::Mls(_)
    ));
}

#[test]
fn typed_mls_message_payload_rejects_a_different_content_schema() {
    let mut envelope = encrypted_envelope();
    envelope.content_type = "application/vnd.arkret.reaction+json".to_owned();

    assert!(MlsEncryptedPayload::<ContentBlock>::new(envelope).is_err());
}

#[test]
fn message_metadata_payload_has_an_independent_mls_schema() {
    let mut envelope = encrypted_envelope();
    envelope.content_type = MESSAGE_METADATA_MLS_CONTENT_TYPE.to_owned();
    let encrypted_metadata = MlsEncryptedPayload::<MessageMetadata>::new(envelope.clone()).unwrap();
    let strand_id =
        StrandId::new("ak:strand:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1").unwrap();
    let payload =
        MessageCreatePayload::with_content(strand_id, "discussion", ContentBlock::text("hello"))
            .with_mls_encrypted_metadata(encrypted_metadata);

    assert!(matches!(
        payload.protected_metadata().unwrap(),
        Some(ProtectedPayload::Mls(_))
    ));
    assert!(MlsEncryptedPayload::<ContentBlock>::new(envelope).is_err());
}

#[test]
fn typed_mls_message_metadata_rejects_content_block_media_type() {
    assert!(MlsEncryptedPayload::<MessageMetadata>::new(encrypted_envelope()).is_err());
}

#[test]
fn message_event_schema_rejects_metadata_labeled_as_content_block() {
    let strand_id =
        StrandId::new("ak:strand:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1").unwrap();
    let mut payload =
        MessageCreatePayload::with_content(strand_id, "discussion", ContentBlock::text("hello"))
            .to_value()
            .unwrap();
    payload["encrypted_metadata"] = serde_json::to_value(encrypted_envelope()).unwrap();

    assert!(
        event_payload_validator_catalog()
            .unwrap()
            .validate_payload("ak.message.create", &payload)
            .is_err()
    );

    payload["encrypted_metadata"]["content_type"] = json!(MESSAGE_METADATA_MLS_CONTENT_TYPE);
    event_payload_validator_catalog()
        .unwrap()
        .validate_payload("ak.message.create", &payload)
        .unwrap();
}

#[test]
fn message_create_payload_reads_plain_body_and_first_media_block() {
    let strand_id =
        StrandId::new("ak:strand:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1").unwrap();
    let blob_ref = format!("ak:blob:sha256:{}", "a".repeat(64));
    let media = ContentBlock::new(ContentBlockKind::File, "spec.pdf")
        .with_field("mime_type", json!("application/pdf"))
        .with_field("filename", json!("spec.pdf"))
        .with_field("size_bytes", json!(7));
    let content = ContentBlock::new(ContentBlockKind::Composite, "caption text")
        .with_part(ContentBlock::text("caption text"))
        .with_part(media);
    let mut payload = MessageCreatePayload::with_content(strand_id, "discussion", content);
    payload.blob_refs.push(blob_ref.clone());

    assert_eq!(payload.plain_body().unwrap(), "caption text");
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
        "kind": "ak.content.poll",
        "body": "ship?",
        "poll": {
            "kind": "disclosed",
            "max_selections": 1,
            "answers": [
                {"id": "yes", "text": {"kind": "ak.content.text", "body": "yes"}},
                {"id": "no", "text": {"kind": "ak.content.text", "body": "no"}}
            ]
        }
    });

    validate_content_block(&block).unwrap();
}

#[test]
fn morph_create_payload_rejects_both_content_carriers() {
    let actor = actor("did:webvh:z6mkfixture:alice.example");
    let realm_id = RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap();
    let morph_id = MorphId::new("ak:morph:AcsFZ3o2tOdN3EFpNceeLV-aI3jZkB9S34_4YIwJ5DLy").unwrap();
    let mut morph = Morph::new(morph_id, realm_id, "document", actor);
    morph.content = Some(ContentBlock::text("hello"));
    morph.encrypted_content = Some(encrypted_envelope());

    let payload = ObjectCreatePayload::new(morph).to_value().unwrap();
    assert!(
        event_payload_validator_catalog()
            .unwrap()
            .validate_payload("ak.morph.create", &payload)
            .is_err()
    );
}
