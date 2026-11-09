#![cfg(all(feature = "content-history", feature = "backup"))]

//! Crypto construction only. The frozen metadata does not establish native
//! writer authority, recipient-policy acceptance or physical storage.

use arkret_canonical::base64url_decode;
use arkret_crypto::backup::KeyBackupAuthBinding;
use arkret_crypto::content_history::{
    ContentRootBackupAuthor, ContentRootBackupDraft, content_root_backup_info,
    open_content_root_backup,
};
use arkret_models_crypto::{
    ContentRootBackupEntry, KeyBackup, KeyBackupPlaintext, SecretStorageEntry,
};
use arkret_schema_conformance::spec_json_artifact;
use ed25519_dalek::{Signer as _, Verifier as _};

struct Fixture {
    draft: ContentRootBackupDraft,
    roots: Vec<ContentRootBackupEntry>,
    public: Vec<u8>,
    private: Vec<u8>,
    signing: ed25519_dalek::SigningKey,
    bag: KeyBackupPlaintext,
    info: Vec<u8>,
}

fn fixture() -> Fixture {
    let f = spec_json_artifact("fixtures/content-history-fixture.json").unwrap();
    let envelope: KeyBackup = serde_json::from_value(f["root_backup"]["envelope"].clone()).unwrap();
    let bag: KeyBackupPlaintext =
        serde_json::from_value(f["root_backup"]["plaintext"].clone()).unwrap();
    let roots = bag
        .items
        .iter()
        .map(|item| {
            let SecretStorageEntry::ContentRoot(root) = item else {
                panic!("formal root block")
            };
            root.clone()
        })
        .collect();
    let material = arkret_crypto::identity_root::derive_identity_recovery_key_material_from_bip39(
        f["hpke_grant"]["mnemonic"].as_str().unwrap(),
        "",
        1,
    )
    .unwrap();
    let public = material.backup_hpke_public_key.to_vec();
    let signing = ed25519_dalek::SigningKey::from_bytes(
        &hex::decode(f["kat"]["signing_seed_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let draft = ContentRootBackupDraft {
        backup_id: envelope.backup_id,
        actor_id: envelope.actor_id,
        created_at: envelope.created_at,
        expires_at: envelope.expires_at.flatten(),
        author: ContentRootBackupAuthor::Device {
            binding: KeyBackupAuthBinding {
                device_id: envelope.signature_proof.device_id.unwrap(),
                verification_method: envelope.signature_proof.verification_method,
                signature_algorithm: envelope.signature_proof.signature_algorithm,
                device_authorize_event_id: envelope
                    .signature_proof
                    .device_authorize_event_id
                    .unwrap(),
            },
            source: envelope.source_commit_ref.unwrap(),
        },
        recipient_key_ref: envelope.encryption.recipient_key_ref.unwrap(),
        recovery_policy_ref: envelope.recovery_policy_ref.unwrap(),
        domain_separation: envelope.domain_separation,
        series_id: envelope.series_id,
        series_sequence: envelope.series_sequence,
        supersedes: envelope.supersedes_id.zip(envelope.supersedes_digest),
        custody: envelope
            .custodian_actor_id
            .zip(envelope.custody_authorization_ref),
    };
    Fixture {
        draft,
        roots,
        public,
        private: material.backup_hpke_derived_private_key.to_vec(),
        signing,
        bag,
        info: hex::decode(f["root_backup"]["info_hex"].as_str().unwrap()).unwrap(),
    }
}

#[test]
fn fresh_root_block_signs_only_the_real_ciphertext_and_opens_the_complete_frozen_bag() {
    let f = fixture();
    let mut signed = Vec::new();
    let envelope = f
        .draft
        .seal(f.roots, &f.public, |bytes| {
            let value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
            assert!(value["signature_proof"].get("signature").is_none());
            assert_eq!(
                base64url_decode(value["encryption"]["aead"]["enc"].as_str().unwrap())
                    .unwrap()
                    .len(),
                32
            );
            let ciphertext = base64url_decode(value["ciphertext"].as_str().unwrap()).unwrap();
            assert_eq!(
                value["ciphertext_digest"],
                arkret_canonical::sha256_digest(&ciphertext)
            );
            signed = bytes.to_vec();
            Ok(f.signing.sign(bytes).to_bytes().to_vec())
        })
        .unwrap();
    assert_eq!(signed, envelope.signing_payload_bytes().unwrap());
    assert_eq!(content_root_backup_info(&envelope).unwrap(), f.info);
    let bag = open_content_root_backup(&envelope, &f.private, |bytes, proof| {
        let signature =
            ed25519_dalek::Signature::from_slice(&base64url_decode(proof.signature.as_str())?)
                .unwrap();
        f.signing
            .verifying_key()
            .verify(bytes, &signature)
            .map_err(|e| arkret_crypto::Error::Crypto(e.to_string()))
    })
    .unwrap();
    assert_eq!(
        serde_json::to_value(bag).unwrap(),
        serde_json::to_value(f.bag).unwrap()
    );
    assert!(open_content_root_backup(&envelope, &[9; 32], |_, _| Ok(())).is_err());
}

#[test]
fn bad_root_or_series_never_reaches_the_signer() {
    let f = fixture();
    let mut wrong = f.roots.clone();
    wrong[0].root_ref =
        arkret_wire::Hash::new(arkret_canonical::sha256_digest(b"other-root")).unwrap();
    assert!(
        f.draft
            .clone()
            .seal(wrong, &f.public, |_| panic!("invalid root reached signer"))
            .is_err()
    );
    let mut duplicate = f.roots.clone();
    duplicate.push(f.roots[0].clone());
    assert!(
        f.draft
            .clone()
            .seal(duplicate, &f.public, |_| panic!("duplicate reached signer"))
            .is_err()
    );
    let mut invalid_series = f.draft;
    invalid_series.series_sequence = 0;
    invalid_series.supersedes = Some((
        invalid_series.backup_id.clone(),
        arkret_wire::Hash::new(arkret_canonical::sha256_digest(b"previous")).unwrap(),
    ));
    assert!(
        invalid_series
            .seal(f.roots, &f.public, |_| panic!(
                "invalid series reached signer"
            ))
            .is_err()
    );
}

#[test]
fn short_signature_and_agent_without_custody_cannot_form_an_envelope() {
    let f = fixture();
    assert!(
        f.draft
            .clone()
            .seal(f.roots.clone(), &f.public, |_| Ok(vec![1]))
            .is_err()
    );
    let mut agent = f.draft;
    let ContentRootBackupAuthor::Device { binding, .. } = agent.author else {
        panic!("Device fixture")
    };
    agent.author = ContentRootBackupAuthor::Agent {
        verification_method: binding.verification_method,
        authorization_event_ref: binding.device_authorize_event_id,
    };
    agent.custody = None;
    assert!(
        agent
            .seal(f.roots, &f.public, |_| panic!(
                "unqualified Agent reached signer"
            ))
            .is_err()
    );
}
