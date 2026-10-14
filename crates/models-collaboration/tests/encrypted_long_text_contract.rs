//! Authenticated long-text attachments share the canonical encrypted model.

use arkret_models_collaboration::events_payloads::message::{ContentBlock, validate_content_block};
use arkret_models_crypto::EncryptedAttachment;
use arkret_schema_conformance::{default_spec_artifacts_dir, schema_registry_from_spec_artifacts};
use serde_json::{Value, json};

fn attachment() -> Value {
    json!({
        "blob_ref": format!("ak:blob:sha256:{}", "ab".repeat(32)),
        "encrypted": true,
        "scheme": "ak.blob.stream_aead.v1",
        "encryption_algorithm": "mls_exporter_aead_xchacha20poly1305_stream",
        "key_ref": {"algorithm": "MLS", "group_state_ref": "ak:event:AQNy1zG98lAoTz0YOf-2Yp2-GXeJioPlyg8nW6qxW-OB"},
        "content_key_salt": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
        "nonce_prefix": "AAAAAAAAAAAAAAAAAAAAAAAAAA",
        "segment_bytes": 262144,
        "size_bytes": 300000,
        "media_type": "text/markdown"
    })
}

fn content() -> Value {
    json!({"kind": "ak.content.long_text", "body": "authenticated fallback",
        "body_kind": "prefix", "attachment": attachment()})
}

#[test]
fn encrypted_media_resolves_by_resource_and_rejects_conflicting_authenticated_metadata() {
    let main = attachment();
    let mut other = main.clone();
    other["blob_ref"] = json!(format!("ak:blob:sha256:{}", "cd".repeat(32)));
    let value = json!({"kind":"ak.content.file", "body":"private.md", "blob_ref":main["blob_ref"],
        "mime_type":main["media_type"],"size_bytes":main["size_bytes"],"attachments":[other,main]});
    let resolved = ContentBlock::from_value(value.clone())
        .unwrap()
        .rendered_encrypted_attachment()
        .unwrap()
        .unwrap();
    assert_eq!(
        resolved.blob_ref().as_str(),
        value["blob_ref"].as_str().unwrap()
    );
    for (field, changed) in [
        (
            "blob_ref",
            json!(format!("ak:blob:sha256:{}", "ef".repeat(32))),
        ),
        ("mime_type", json!("image/png")),
        ("size_bytes", json!(1)),
    ] {
        let mut changed_value = value.clone();
        changed_value[field] = changed;
        assert!(
            ContentBlock::from_value(changed_value)
                .unwrap()
                .rendered_encrypted_attachment()
                .is_err()
        );
    }
    let mut ambiguous = value;
    let mut conflict = ambiguous["attachments"][1].clone();
    conflict["media_type"] = json!("image/png");
    ambiguous["attachments"]
        .as_array_mut()
        .unwrap()
        .push(conflict);
    assert!(
        ContentBlock::from_value(ambiguous)
            .unwrap()
            .rendered_encrypted_attachment()
            .is_err()
    );
}

#[test]
fn required_salt_round_trips_through_sdk_and_formal_schema() {
    let artifacts = default_spec_artifacts_dir().unwrap();
    let mut registry = schema_registry_from_spec_artifacts(&artifacts).unwrap();
    let schema: Value = serde_json::from_slice(
        &std::fs::read(artifacts.join("schemas/event-payload.schema.json")).unwrap(),
    )
    .unwrap();
    registry
        .register_fragment(
            "test:encrypted-long-text",
            schema,
            "#/$defs/content_block_long_text",
        )
        .unwrap();
    let value = content();
    registry
        .validate_value("test:encrypted-long-text", &value)
        .unwrap();
    let typed = ContentBlock::from_value(value.clone()).unwrap();
    typed.validate_long_text().unwrap();
    validate_content_block(&value).unwrap();
    assert_eq!(typed.to_value().unwrap(), value);
    let mut missing = value;
    missing["attachment"]
        .as_object_mut()
        .unwrap()
        .remove("content_key_salt");
    assert!(
        registry
            .validate_value("test:encrypted-long-text", &missing)
            .is_err()
    );
    assert!(
        ContentBlock::from_value(missing)
            .unwrap()
            .validate_long_text()
            .is_err()
    );
}

#[test]
fn encrypted_long_text_rejects_invalid_salt_refs_algorithms_and_geometry() {
    for (field, changed) in [
        ("content_key_salt", json!("AA")),
        (
            "content_key_salt",
            json!("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="),
        ),
        ("encrypted", json!(false)),
        (
            "key_ref",
            json!({"algorithm":"MLS", "group_state_ref":"invalid"}),
        ),
        (
            "key_ref",
            json!({"algorithm":"MLS", "group_state_ref":"ak:event:AQNy1zG98lAoTz0YOf-2Yp2-GXeJioPlyg8nW6qxW-OB", "key_id":"forbidden"}),
        ),
        ("encryption_algorithm", json!("made_up_stream")),
        ("segment_bytes", json!(1023)),
        ("segment_bytes", json!(8388609)),
        ("size_bytes", json!(u64::MAX)),
        ("epoch", json!(0)),
        ("segment_count", json!(2)),
    ] {
        let mut value = content();
        value["attachment"][field] = changed;
        assert!(
            ContentBlock::from_value(value)
                .unwrap()
                .validate_long_text()
                .is_err(),
            "{field}"
        );
    }
}

#[test]
fn producer_normalizes_before_deriving_fallback_size_and_line_count() {
    let full_body = "😀\r\n".repeat(60000);
    let mut value = attachment();
    value["size_bytes"] = json!(300000);
    let typed: EncryptedAttachment = serde_json::from_value(value.clone()).unwrap();
    let block = ContentBlock::encrypted_long_text(&full_body, typed).unwrap();
    assert!(!block.body.contains('\r'));
    assert!(block.body.len() <= 4096);
    assert_eq!(block.extra_u64("line_count"), Some(60000));
    assert_eq!(block.extra["attachment"], value);
    assert!(!block.extra.contains_key("blob_ref"));
    assert!(!block.extra.contains_key("media_type"));
    let wrong_size: EncryptedAttachment = serde_json::from_value(attachment()).unwrap();
    assert!(ContentBlock::encrypted_long_text("short", wrong_size).is_err());
}
