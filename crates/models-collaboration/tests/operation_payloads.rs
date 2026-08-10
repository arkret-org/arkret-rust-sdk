use arkret_canonical::canonical;
use arkret_models_collaboration::events_payloads::{ObjectCreatePayload, *};
use arkret_models_collaboration::objects::profiles::{Morph, MorphMetadata};
use arkret_models_collaboration::objects::space::Space;
use arkret_models_collaboration::objects::strand::MessageMetadata;
use arkret_models_crypto::{
    EncryptedEnvelope, MlsEncryptedPayload, PlainPayload, ProtectedPayload,
};
use arkret_schema::event_payload_validator_catalog;
use arkret_wire::{Did, MorphId, RealmId, SpaceId, StrandId};
use serde_json::json;

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
        "scheme": "mls_rfc9420",
        "version": "1.0",
        "group_id": "AA",
        "epoch": 1,
        "content_type": "application/vnd.arkret.message+json",
        "ciphertext": "AA",
        "aad_visibility_event_id": "hidden",
        "aad": {
            "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "scope_digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "event_kind": "ak.message.create"
        },
        "key_ref": {
            "algorithm": "MLS",
            "group_state_ref": "ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM"
        },
        "payload_digest": format!("sha256:{}", "a".repeat(64)),
        "aad_digest": format!("sha256:{}", "b".repeat(64))
    }))
    .unwrap()
}

#[test]
fn space_create_object_uses_canonical_timestamp() {
    let actor = Did::new("did:webvh:z6mkfixture:alice.example".to_owned()).unwrap();
    let realm_id = RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap();
    let space_id = SpaceId::new("ak:space:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1").unwrap();
    let space = Space::new(space_id, realm_id, "board", "Board", actor);
    let payload = ObjectCreatePayload::new(space).to_value().unwrap();
    canonical::validate_timestamp_canonical(payload["object"]["created_at"].as_str().unwrap())
        .unwrap();
}

#[test]
fn morph_create_payload_uses_metadata_and_encrypted_content_names() {
    let actor = Did::new("did:webvh:z6mkfixture:alice.example".to_owned()).unwrap();
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
    let plain = MessageCreatePayload::with_protected_content(
        strand_id.clone(),
        "discussion",
        ProtectedPayload::from(PlainPayload::new(ContentBlock::text("hello"))),
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
    assert!(MEDIA_CONTENT_KINDS.contains(&CONTENT_KIND_FILE));
    let block = payload.first_media_content_block().unwrap().unwrap();
    assert_eq!(block.kind, ContentBlockKind::File);
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
fn content_block_validator_rejects_legacy_flat_poll_block() {
    let block = json!({
        "kind": "ak.content.poll",
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
    let strand_id =
        StrandId::new("ak:strand:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1").unwrap();
    let expiry =
        DisappearingMessageExpiry::new(60_000, DisappearingMessageExpiryTrigger::OnLastRead)
            .unwrap()
            .with_grace_ms(5_000);
    let payload =
        MessageCreatePayload::with_content(strand_id, "discussion", ContentBlock::text("hello"))
            .with_expiry(expiry)
            .to_value()
            .unwrap();

    assert!(payload.get("message_id").is_none());
    assert_eq!(payload["expiry"]["ttl_ms"], 60_000);
    assert_eq!(payload["expiry"]["trigger"], "on_last_read");
    assert_eq!(payload["expiry"]["grace_ms"], 5_000);
    event_payload_validator_catalog()
        .unwrap()
        .validate_payload("ak.message.create", &payload)
        .unwrap();
}

#[test]
fn message_create_payload_rejects_a_second_producer_chosen_identity() {
    let payload = serde_json::json!({
        "strand_id": "ak:strand:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
        "message_id": "ak:message:AcsFZ3o2tOdN3EFpNceeLV-aI3jZkB9S34_4YIwJ5DLy",
        "track_name": "discussion",
        "content": {"kind": "ak.content.text", "body": "hello"}
    });

    assert!(serde_json::from_value::<MessageCreatePayload>(payload).is_err());
}

#[test]
fn morph_create_payload_rejects_both_content_carriers() {
    let actor = Did::new("did:webvh:z6mkfixture:alice.example".to_owned()).unwrap();
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
