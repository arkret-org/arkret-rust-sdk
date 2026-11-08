#![cfg(feature = "content-history")]

use arkret_canonical::{base64url_decode, base64url_encode, canonical_json_bytes};
use arkret_crypto::content_history::*;
use arkret_models_crypto::{
    ContentContext, ContentRootContext, ContentRootSecret, EncryptedEnvelope, EventContentMaterial,
    EventContentPreEncryptionHeader, EventContentRoutingContext, HistoryGrant,
};
use arkret_schema_conformance::spec_json_artifact;
use serde_json::Value;

fn fixture() -> Value {
    spec_json_artifact("fixtures/content-history-fixture.json")
        .expect("pinned formal content-history fixture")
}

fn root(f: &Value) -> ContentRootSecret {
    ContentRootSecret::new(
        hex::decode(f["kat"]["root_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    )
}

fn header(f: &Value) -> EventContentPreEncryptionHeader {
    let envelope: EncryptedEnvelope = serde_json::from_value(f["kat"]["envelope"].clone()).unwrap();
    let context: ContentContext =
        serde_json::from_value(f["kat"]["content_context"].clone()).unwrap();
    let actor_json =
        String::from_utf8(canonical_json_bytes(&context.producer.actor_id).unwrap()).unwrap();
    EventContentPreEncryptionHeader::reconstruct(
        "1.0",
        envelope.content_type.clone(),
        envelope.encryption_scheme,
        context.root_context.effective_scope.clone(),
        f["kat"]["outer_event"]["kind"].as_str().unwrap(),
        context.root_context.epoch,
        context.root_context.group_state_ref.clone(),
        actor_json,
        EventContentRoutingContext::None,
        EventContentMaterial {
            content_context: context,
            outer_event: f["kat"]["outer_event"].clone(),
            protection: serde_json::from_value(
                f["kat"]["envelope"]["encryption_context"]["protection"].clone(),
            )
            .unwrap(),
            key_commitment: serde_json::from_value(
                f["kat"]["envelope"]["encryption_context"]["key_commitment"].clone(),
            )
            .unwrap(),
        },
    )
    .unwrap()
}

#[test]
fn formal_exporter_root_body_kdf_aad_and_aead_are_byte_exact() {
    let f = fixture();
    let context: ContentRootContext =
        serde_json::from_value(f["kat"]["root_context"].clone()).unwrap();
    let exporter = hex::decode(f["kat"]["exporter_secret_hex"].as_str().unwrap()).unwrap();
    let r = root_from_exporter_secret(&exporter, &context).unwrap();
    assert_eq!(hex::encode(r.expose()), f["kat"]["root_hex"]);
    let h = header(&f);
    let key = derive_content_key(&r, &h.material.content_context).unwrap();
    assert_eq!(hex::encode(key.as_ref()), f["kat"]["key_hex"]);
    assert_eq!(
        hex::encode(h.canonical_bytes().unwrap()),
        f["kat"]["aad_hex"]
    );
    let plain = hex::decode(f["kat"]["plaintext_hex"].as_str().unwrap()).unwrap();
    let sealed = seal_content(&r, &h, &plain).unwrap();
    assert_eq!(sealed, f["kat"]["envelope"]["ciphertext"]);
    assert_eq!(open_content(&r, &h, &sealed).unwrap(), plain);
    assert!(!format!("{r:?}").contains(f["kat"]["root_hex"].as_str().unwrap()));
}

#[test]
fn missing_backup_dependency_refuses_seal_and_historical_open() {
    let f = fixture();
    let mut h = header(&f);
    h.material.protection.backup_refs.clear();
    let r = root(&f);
    assert!(seal_content(&r, &h, b"content without recoverability").is_err());
    assert!(open_content(&r, &h, f["kat"]["envelope"]["ciphertext"].as_str().unwrap()).is_err());
}

#[test]
fn original_metadata_endpoint_key_and_root_changes_fail_closed() {
    let f = fixture();
    let r = root(&f);
    let h = header(&f);
    let sealed = f["kat"]["envelope"]["ciphertext"].as_str().unwrap();
    let mut changed = h.clone();
    changed.material.outer_event["x_vendor"] = serde_json::json!(true);
    assert!(open_content(&r, &changed, sealed).is_err());
    changed = h.clone();
    changed
        .material
        .content_context
        .producer
        .signature_key_base64url = base64url_encode([3; 32]);
    assert!(open_content(&r, &changed, sealed).is_err());
    changed = h.clone();
    changed
        .material
        .content_context
        .producer
        .authorization_event_ref =
        serde_json::from_value(f["hpke_grant"]["grant"]["recipient_key_event_ref"].clone())
            .unwrap();
    assert!(open_content(&r, &changed, sealed).is_err());
    assert!(open_content(&ContentRootSecret::new([5; 32]), &h, sealed).is_err());
    assert!(open_content(&r, &h, &(sealed.to_owned() + "=")).is_err());
}

#[test]
fn same_actor_same_salt_distinct_endpoints_derive_distinct_keys() {
    let f = fixture();
    let r = root(&f);
    let first = header(&f).material.content_context;
    let mut second = first.clone();
    second.producer.endpoint = arkret_wire::MlsWelcomeRecipientEndpoint::Device {
        device_id: arkret_wire::DeviceId::new("ak:device:019a0000-0000-7000-8000-000000000099")
            .unwrap(),
    };
    assert_ne!(
        derive_content_key(&r, &first).unwrap().as_ref(),
        derive_content_key(&r, &second).unwrap().as_ref()
    );
    assert_eq!(first.producer.actor_id, second.producer.actor_id);
}

#[test]
fn individually_granted_dek_opens_only_its_committed_body() {
    let f = fixture();
    let h = header(&f);
    let key = derive_content_key(&root(&f), &h.material.content_context).unwrap();
    let ciphertext = f["kat"]["envelope"]["ciphertext"].as_str().unwrap();
    assert_eq!(
        open_content_from_granted_key(&key, &h, ciphertext).unwrap(),
        hex::decode(f["kat"]["plaintext_hex"].as_str().unwrap()).unwrap()
    );
    assert!(open_content_from_granted_key(&[0; 16], &h, ciphertext).is_err());
    let mut different = h;
    different.material.content_context.content_key_salt = base64url_encode([13; 32]);
    assert!(open_content_from_granted_key(&key, &different, ciphertext).is_err());
}

#[test]
fn hpke_grants_open_the_frozen_codec_and_reject_header_recipient_and_truncation() {
    let f = fixture();
    let grant: HistoryGrant = serde_json::from_value(f["hpke_grant"]["grant"].clone()).unwrap();
    let private = hex::decode(f["hpke_grant"]["recipient_private_hex"].as_str().unwrap()).unwrap();
    for (entry, kat) in grant
        .entries
        .iter()
        .zip(f["hpke_grant"]["entries"].as_array().unwrap())
    {
        assert_eq!(
            hex::encode(history_grant_header(&grant, &entry.selector).unwrap()),
            kat["info_hex"]
        );
        let key = open_history_key(
            &grant,
            &entry.selector,
            &private,
            &entry.sealed_key_base64url,
        )
        .unwrap();
        assert_eq!(hex::encode(key.as_slice()), kat["plaintext_hex"]);
        let sealed = seal_history_key(&grant, &entry.selector, &key).unwrap();
        assert_eq!(
            open_history_key(&grant, &entry.selector, &private, &sealed)
                .unwrap()
                .as_slice(),
            key.as_slice()
        );
        let mut wrong = grant.clone();
        wrong.expires_at += chrono::Duration::seconds(1);
        assert!(open_history_key(&wrong, &entry.selector, &private, &sealed).is_err());
        assert!(open_history_key(&grant, &entry.selector, &[7; 32], &sealed).is_err());
        assert!(
            open_history_key(
                &grant,
                &entry.selector,
                &private,
                &base64url_encode(&base64url_decode(&sealed).unwrap()[..40])
            )
            .is_err()
        );
    }
}

#[test]
fn closed_models_reject_missing_scheme_unknown_strategy_and_fake_ready() {
    let f = fixture();
    let mut envelope = f["kat"]["envelope"].clone();
    envelope
        .as_object_mut()
        .unwrap()
        .remove("encryption_scheme");
    assert!(serde_json::from_value::<EncryptedEnvelope>(envelope).is_err());
    let mut coordinate = f["kat"]["root_context"].clone();
    coordinate["encryption_backup_strategy"] = serde_json::json!("ak.encryption_backup.unknown.v1");
    assert!(serde_json::from_value::<ContentRootContext>(coordinate).is_err());
    let mut checkpoint: arkret_models_crypto::ContentRecoveryCheckpoint =
        serde_json::from_value(f["recovery_checkpoint"].clone()).unwrap();
    checkpoint.validate().unwrap();
    checkpoint.cleanup_blob_ref = None;
    assert!(checkpoint.validate().is_err());
}

#[cfg(all(feature = "backup", feature = "identity-root"))]
#[test]
fn twenty_four_words_open_the_complete_original_hpke_root_keybag() {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let f = fixture();
    let material = arkret_crypto::identity_root::derive_identity_recovery_key_material_from_bip39(
        f["hpke_grant"]["mnemonic"].as_str().unwrap(),
        "",
        1,
    )
    .unwrap();
    let envelope: arkret_models_crypto::KeyBackup =
        serde_json::from_value(f["root_backup"]["envelope"].clone()).unwrap();
    let signing = ed25519_dalek::SigningKey::from_bytes(
        &hex::decode(f["kat"]["signing_seed_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let verify = |bytes: &[u8], proof: &arkret_models_crypto::KeyBackupSignatureProof| {
        let signature =
            Signature::from_slice(&base64url_decode(proof.signature.as_str()).unwrap()).unwrap();
        VerifyingKey::from(&signing)
            .verify(bytes, &signature)
            .map_err(|_| {
                arkret_crypto::Error::Crypto("original backup signature failed".to_owned())
            })
    };
    assert_eq!(
        hex::encode(content_root_backup_info(&envelope).unwrap()),
        f["root_backup"]["info_hex"]
    );
    let bag =
        open_content_root_backup(&envelope, &material.backup_hpke_derived_private_key, verify)
            .unwrap();
    assert_eq!(
        serde_json::to_value(bag).unwrap(),
        f["root_backup"]["plaintext"]
    );
    assert_eq!(
        hex::encode(content_root_backup_info(&envelope).unwrap()),
        f["root_backup"]["info_hex"]
    );
    assert!(open_content_root_backup(&envelope, &[9; 32], verify).is_err());
}
