//! Local root-block construction. Native writer, recipient policy and durable
//! PUT qualification remain the owning client's and server's responsibility.

use arkret_canonical::{base64url_decode, base64url_encode, canonical_json_bytes};
use arkret_models_crypto::{
    BackupKind, ContentRootBackupEntry, KeyBackup, KeyBackupDomainSeparation, KeyBackupPlaintext,
    KeyBackupRecipientMethod, KeyBackupSourceCommitRef, RecoveryPolicyRef, SecretStorageEntry,
};
use arkret_wire::{ActorId, BackupId, BackupSeriesId, DidUrl, EventId, Hash, SchemaId};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::backup::{KeyBackupAuthBinding, VaultBinding};
use crate::{Error, Result};

/// An unsigned local selector, never a wire proof or a claim of native authority.
#[derive(Clone, Debug)]
pub enum ContentRootBackupAuthor {
    Device {
        binding: KeyBackupAuthBinding,
        source: KeyBackupSourceCommitRef,
    },
    Agent {
        verification_method: DidUrl,
        authorization_event_ref: EventId,
    },
}

/// Only real public inputs are present before encryption and signing. This
/// draft has no Serialize implementation and contains no provisional ciphertext,
/// encapsulated key, digest, signature or secret root.
#[derive(Clone, Debug)]
pub struct ContentRootBackupDraft {
    pub backup_id: BackupId,
    pub actor_id: ActorId,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub author: ContentRootBackupAuthor,
    pub recipient_key_ref: String,
    pub recovery_policy_ref: RecoveryPolicyRef,
    pub domain_separation: KeyBackupDomainSeparation,
    pub series_id: BackupSeriesId,
    pub series_sequence: u64,
    pub supersedes: Option<(BackupId, Hash)>,
    pub custody: Option<(ActorId, EventId)>,
}

/// A native Device's first-use backup. The public prepare input is supplied by
/// one bound current result, not reconstructed from unrelated current refs.
/// The manager archive private key is never an authoring input.
#[derive(Clone, Debug)]
pub struct RealmActorContentRootBackupDraft {
    pub backup_id: BackupId,
    pub realm_actor_id: arkret_wire::RealmActorId,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub author: KeyBackupAuthBinding,
    pub prepare_input: arkret_models_crypto::ContentBackupNextPrepareInput,
    pub domain_separation: KeyBackupDomainSeparation,
    pub series_sequence: u64,
    pub supersedes: Option<(BackupId, Hash)>,
}

impl RealmActorContentRootBackupDraft {
    pub fn seal(
        self,
        root: ContentRootBackupEntry,
        sign: impl FnOnce(&[u8]) -> Result<Vec<u8>>,
    ) -> Result<KeyBackup> {
        self.prepare_input.validate()?;
        root.root_context.validate()?;
        arkret_models_crypto::validate_realm_actor_backup_scope(
            &self.realm_actor_id,
            &root.root_context.effective_scope,
        )?;
        if self.author.signature_algorithm
            != arkret_models_crypto::KeyBackupSignatureAlgorithm::Ed25519
            || (self.series_sequence == 0) != self.supersedes.is_none()
            || super::content_root_ref(&root.root_base64url, &root.root_context)? != root.root_ref
        {
            return Err(Error::Protocol(
                "invalid native root backup author, root or predecessor".into(),
            ));
        }
        self.domain_separation.validate()?;
        let recipient = &self.prepare_input.content_backup_recipient;
        let recipient_public = base64url_decode(&recipient.public_key_base64url)?;
        crate::hpke::validate_x25519_recipient_key(&recipient_public)?;
        let actor_id = ActorId::Realm {
            realm_actor_id: self.realm_actor_id,
        };
        let series_id = self.prepare_input.active_series_id;
        let bag = KeyBackupPlaintext {
            schema: SchemaId::KeyBackupPlaintextV1,
            backup_id: self.backup_id.clone(),
            backup_kind: BackupKind::SecretStorage,
            series_id: series_id.clone(),
            series_sequence: self.series_sequence,
            items: vec![SecretStorageEntry::ContentRoot(root)],
            extra: Default::default(),
        };
        let contents = bag
            .items
            .iter()
            .map(SecretStorageEntry::content_index)
            .collect::<Vec<_>>();
        bag.validate_against(&contents)?;
        let binding = VaultBinding {
            backup_id: self.backup_id.clone(),
            subdomain: self.domain_separation.subdomain.clone(),
            actor_id: actor_id.clone(),
            device_id: Some(self.author.device_id.clone()),
            backup_kind: BackupKind::SecretStorage,
            backup_version: "kb_content_roots".into(),
            created_at: self.created_at,
            item_kinds: vec!["content_epoch_root".into()],
            recipient_method: KeyBackupRecipientMethod::RealmActorRecovery,
            recipient_key_ref: Some(recipient.key_agreement_ref.to_string()),
            aead_aad_extensions: self.domain_separation.aead_aad_extensions.clone(),
        };
        let aad =
            crate::backup::native_key_backup_aead_aad(&binding, &self.prepare_input.auth_binding)
                .map_err(|e| Error::Protocol(e.to_string()))?;
        let info = canonical_json_bytes(&json!({"backup_id":self.backup_id,"series_id":series_id,
            "series_sequence":self.series_sequence,"actor_id":actor_id,"backup_kind":BackupKind::SecretStorage,
            "backup_version":"kb_content_roots","created_at":arkret_canonical::format_timestamp_canonical(self.created_at)}))?;
        let plaintext = Zeroizing::new(canonical_json_bytes(&bag)?);
        let sealed =
            crate::hpke::seal_x25519_chacha20poly1305(&recipient_public, &plaintext, &info, &aad)?;
        let sealed = base64url_decode(sealed)?;
        let mut value = json!({"backup_id":self.backup_id,"actor_id":actor_id,"device_id":self.author.device_id,
            "backup_kind":BackupKind::SecretStorage,"backup_version":"kb_content_roots",
            "created_at":arkret_canonical::format_timestamp_canonical(self.created_at),
            "encryption":{"recipient_method":"realm_actor_recovery","recipient_key_ref":recipient.key_agreement_ref,
                "hpke_suite":arkret_wire::HPKE_SUITE_X25519_CHACHA20POLY1305_V1,
                "aead":{"name":"chacha20_poly1305","enc":base64url_encode(&sealed[..32])}},
            "domain_separation":self.domain_separation,"contents":contents,
            "ciphertext":base64url_encode(&sealed[32..]),"ciphertext_digest":arkret_canonical::sha256_digest(&sealed[32..]),
            "series_id":series_id,"series_sequence":self.series_sequence,"auth_binding":self.prepare_input.auth_binding,
            "signature_proof":{"device_id":self.author.device_id,"verification_method":self.author.verification_method,
                "signature_algorithm":"Ed25519","device_authorize_event_id":self.author.device_authorize_event_id}});
        if let Some((id, digest)) = self.supersedes {
            value["supersedes_id"] = serde_json::to_value(id)?;
            value["supersedes_digest"] = serde_json::to_value(digest)?;
        }
        let transcript = canonical_json_bytes(&value)?;
        let signature = sign(&transcript)?;
        if signature.len() != 64 {
            return Err(Error::Protocol(
                "native root signer must return an actual Ed25519 signature".into(),
            ));
        }
        value["signature_proof"]["signature"] = Value::String(base64url_encode(signature));
        let backup: KeyBackup = serde_json::from_value(value)?;
        backup.validate()?;
        if backup.signing_payload_bytes()? != transcript {
            return Err(Error::Protocol(
                "native root transcript changed during construction".into(),
            ));
        }
        Ok(backup)
    }
}

impl ContentRootBackupDraft {
    /// Create a fresh immutable, unmixed root-only block. Root commitments and
    /// the entire public index are rebuilt from the actual secret entries.
    /// The callback receives the final envelope transcript after real HPKE.
    pub fn seal(
        self,
        roots: Vec<ContentRootBackupEntry>,
        recipient_public: &[u8],
        sign: impl FnOnce(&[u8]) -> Result<Vec<u8>>,
    ) -> Result<KeyBackup> {
        if roots.is_empty()
            || (self.series_sequence == 0) != self.supersedes.is_none()
            || self.recipient_key_ref.is_empty()
            || self.recovery_policy_ref.policy_version == 0
            || self
                .expires_at
                .is_some_and(|expires| expires <= self.created_at)
        {
            return Err(Error::Protocol(
                "invalid root backup draft or series".into(),
            ));
        }
        self.domain_separation.validate()?;
        let mut secret_ids = std::collections::BTreeSet::new();
        for root in &roots {
            if !secret_ids.insert(&root.secret_id)
                || super::content_root_ref(&root.root_base64url, &root.root_context)?
                    != root.root_ref
            {
                return Err(Error::Protocol(
                    "invalid root backup entry or commitment".into(),
                ));
            }
        }
        let bag = KeyBackupPlaintext {
            schema: SchemaId::KeyBackupPlaintextV1,
            backup_id: self.backup_id.clone(),
            backup_kind: BackupKind::SecretStorage,
            series_id: self.series_id.clone(),
            series_sequence: self.series_sequence,
            items: roots
                .into_iter()
                .map(SecretStorageEntry::ContentRoot)
                .collect(),
            extra: Default::default(),
        };
        let contents = bag
            .items
            .iter()
            .map(SecretStorageEntry::content_index)
            .collect::<Vec<_>>();
        bag.validate_against(&contents)?;
        let (device_id, source_commit_ref, signature_header) = match self.author {
            ContentRootBackupAuthor::Device { binding, source } => (
                Some(binding.device_id.clone()),
                Some(source),
                json!({"device_id":binding.device_id,
                    "verification_method":binding.verification_method,
                    "signature_algorithm":binding.signature_algorithm,
                    "device_authorize_event_id":binding.device_authorize_event_id}),
            ),
            ContentRootBackupAuthor::Agent {
                verification_method,
                authorization_event_ref,
            } => {
                if self.custody.is_none() {
                    return Err(Error::Protocol(
                        "Agent root backup requires explicit custody".into(),
                    ));
                }
                (
                    None,
                    None,
                    json!({"verification_method":verification_method,
                    "signature_algorithm":"Ed25519", "agent_authorization_event_ref":authorization_event_ref}),
                )
            }
        };
        let binding = VaultBinding {
            backup_id: self.backup_id.clone(),
            subdomain: self.domain_separation.subdomain.clone(),
            actor_id: self.actor_id.clone(),
            device_id: device_id.clone(),
            backup_kind: BackupKind::SecretStorage,
            backup_version: "kb_content_roots".into(),
            created_at: self.created_at,
            item_kinds: vec!["content_epoch_root".into()],
            recipient_method: KeyBackupRecipientMethod::RecoveryPublicKey,
            recipient_key_ref: Some(self.recipient_key_ref.clone()),
            aead_aad_extensions: self.domain_separation.aead_aad_extensions.clone(),
        };
        let aad = binding.aad().map_err(|e| Error::Protocol(e.to_string()))?;
        let info = canonical_json_bytes(&json!({
            "backup_id":self.backup_id,"series_id":self.series_id,
            "series_sequence":self.series_sequence,"actor_id":self.actor_id,
            "backup_kind":BackupKind::SecretStorage,"backup_version":"kb_content_roots",
            "created_at":arkret_canonical::format_timestamp_canonical(self.created_at),
        }))?;
        let plaintext = Zeroizing::new(canonical_json_bytes(&bag)?);
        let sealed =
            crate::hpke::seal_x25519_chacha20poly1305(recipient_public, &plaintext, &info, &aad)?;
        let sealed = base64url_decode(sealed)?;
        let mut value = json!({
            "backup_id":self.backup_id,"actor_id":self.actor_id,
            "backup_kind":BackupKind::SecretStorage,"backup_version":"kb_content_roots",
            "created_at":arkret_canonical::format_timestamp_canonical(self.created_at),
            "encryption":{"recipient_method":KeyBackupRecipientMethod::RecoveryPublicKey,
                "hpke_suite":arkret_wire::HPKE_SUITE_X25519_CHACHA20POLY1305_V1,
                "recipient_key_ref":self.recipient_key_ref,
                "aead":{"name":arkret_models_crypto::KeyBackupAeadName::Chacha20Poly1305,
                    "enc":base64url_encode(&sealed[..32])}},
            "domain_separation":self.domain_separation,"contents":contents,
            "ciphertext":base64url_encode(&sealed[32..]),
            "ciphertext_digest":arkret_canonical::sha256_digest(&sealed[32..]),
            "signature_proof":signature_header,"series_id":self.series_id,
            "series_sequence":self.series_sequence,"recovery_policy_ref":self.recovery_policy_ref,
        });
        let object = value.as_object_mut().expect("constructed object");
        if let Some(expires) = self.expires_at {
            object.insert(
                "expires_at".into(),
                json!(arkret_canonical::format_timestamp_canonical(expires)),
            );
        }
        if let Some(device) = device_id {
            object.insert("device_id".into(), json!(device));
        }
        if let Some(source) = source_commit_ref {
            object.insert("source_commit_ref".into(), json!(source));
        }
        if let Some((id, digest)) = self.supersedes {
            object.insert("supersedes_id".into(), json!(id));
            object.insert("supersedes_digest".into(), json!(digest));
        }
        if let Some((custodian, authorization)) = self.custody {
            object.insert("custodian_actor_id".into(), json!(custodian));
            object.insert("custody_authorization_ref".into(), json!(authorization));
        }
        let signed_bytes = canonical_json_bytes(&value)?;
        let signature = sign(&signed_bytes)?;
        if signature.len() != 64 {
            return Err(Error::Protocol(
                "root backup signer did not return an Ed25519 signature".into(),
            ));
        }
        value["signature_proof"]["signature"] = Value::String(base64url_encode(signature));
        let envelope: KeyBackup = serde_json::from_value(value)?;
        envelope.validate()?;
        if envelope.signing_payload_bytes()? != signed_bytes {
            return Err(Error::Protocol(
                "root backup transcript changed during construction".into(),
            ));
        }
        Ok(envelope)
    }
}

#[cfg(all(test, feature = "identity-root"))]
mod native_tests {
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;

    fn fixture() -> Value {
        serde_json::from_str(include_str!("../../../../../arkret-spec/spec/v1/artifacts/fixtures/realm-actor-content-backup-fixture.json")).unwrap()
    }

    #[test]
    fn native_root_draft_uses_real_hpke_and_ed_with_exact_native_aad() {
        let f = fixture();
        let original: KeyBackup = serde_json::from_value(f["native_packet"].clone()).unwrap();
        assert_eq!(
            hex::encode(crate::backup::key_backup_aead_aad(&original).unwrap()),
            f["kat"]["aad_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(super::super::content_root_backup_info(&original).unwrap()),
            f["kat"]["info_hex"].as_str().unwrap()
        );
        let private =
            hex::decode(f["test_material"]["archive_private_hex"].as_str().unwrap()).unwrap();
        let public = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: base64url_decode(
                f["test_material"]["device_public_base64url"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap(),
        };
        let mut plaintext =
            super::super::open_content_root_backup(&original, &private, |bytes, proof| {
                arkret_signatures::proof::verify_ed25519_raw_transcript_signature(
                    bytes,
                    proof.signature.as_str(),
                    &public,
                )
                .map_err(|e| Error::Protocol(e.to_string()))
            })
            .unwrap();
        let SecretStorageEntry::ContentRoot(root) = plaintext.items.remove(0) else {
            panic!("native root fixture");
        };
        let seed: [u8; 32] = hex::decode(f["test_material"]["device_seed_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let signer = SigningKey::from_bytes(&seed);
        let draft = RealmActorContentRootBackupDraft {
            backup_id: original.backup_id.clone(),
            realm_actor_id: original.actor_id.as_realm_actor_id().unwrap().clone(),
            created_at: original.created_at,
            author: KeyBackupAuthBinding {
                device_id: original.signature_proof.device_id.clone().unwrap(),
                verification_method: original.signature_proof.verification_method.clone(),
                signature_algorithm: original.signature_proof.signature_algorithm,
                device_authorize_event_id: original
                    .signature_proof
                    .device_authorize_event_id
                    .clone()
                    .unwrap(),
            },
            prepare_input: arkret_models_crypto::ContentBackupNextPrepareInput {
                auth_binding: original.auth_binding.clone().unwrap(),
                content_backup_recipient: serde_json::from_value(f["recipient"].clone()).unwrap(),
                active_series_id: original.series_id.clone(),
            },
            domain_separation: original.domain_separation.clone(),
            series_sequence: 0,
            supersedes: None,
        };
        let backup = draft
            .seal(root, |bytes| Ok(signer.sign(bytes).to_bytes().to_vec()))
            .unwrap();
        let opened = super::super::open_content_root_backup(&backup, &private, |bytes, proof| {
            arkret_signatures::proof::verify_ed25519_raw_transcript_signature(
                bytes,
                proof.signature.as_str(),
                &public,
            )
            .map_err(|e| Error::Protocol(e.to_string()))
        })
        .unwrap();
        assert_eq!(serde_json::to_value(opened).unwrap(), f["plaintext"]);
        assert!(
            serde_json::to_value(&backup)
                .unwrap()
                .get("expires_at")
                .is_none()
        );
        assert!(backup.recovery_policy_ref.is_none());
        assert!(backup.source_commit_ref.is_none());
        let mut bad = backup;
        bad.auth_binding.as_mut().unwrap().device_generation += 1;
        assert!(
            super::super::open_content_root_backup(&bad, &private, |bytes, proof| {
                arkret_signatures::proof::verify_ed25519_raw_transcript_signature(
                    bytes,
                    proof.signature.as_str(),
                    &public,
                )
                .map_err(|e| Error::Protocol(e.to_string()))
            })
            .is_err()
        );
    }

    #[test]
    fn legacy_account_and_agent_expiry_null_and_value_keep_signed_bytes_and_open() {
        let f: Value = serde_json::from_str(include_str!(
            "../../../../../arkret-spec/spec/v1/artifacts/fixtures/content-history-fixture.json"
        ))
        .unwrap();
        let original: KeyBackup =
            serde_json::from_value(f["root_backup"]["envelope"].clone()).unwrap();
        let bag: KeyBackupPlaintext =
            serde_json::from_value(f["root_backup"]["plaintext"].clone()).unwrap();
        let SecretStorageEntry::ContentRoot(root) = bag.items[0].clone() else {
            panic!("root fixture");
        };
        let private =
            hex::decode(f["hpke_grant"]["recipient_private_hex"].as_str().unwrap()).unwrap();
        let public = crate::hpke::x25519_public_key(&private).unwrap();
        for agent in [false, true] {
            let seed = if agent {
                [71; 32]
            } else {
                std::array::from_fn(|i| i as u8)
            };
            let signing = SigningKey::from_bytes(&seed);
            let fingerprint = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                signing.verifying_key().as_bytes(),
            );
            let method = DidUrl::new(format!("did:key:{fingerprint}#{fingerprint}")).unwrap();
            let reference = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [72; 32]);
            // These are local cryptographic authoring inputs; current Agent
            // custody/authorization is independently required at real admission.
            let (actor, author, custody) = if agent {
                let controller = original.actor_id.as_account_id().unwrap();
                (
                    ActorId::account(arkret_wire::AccountId::new(
                        arkret_wire::DidCoreId::new("ak:did_core:web:agent.example").unwrap(),
                        controller.station_id.clone(),
                    )),
                    ContentRootBackupAuthor::Agent {
                        verification_method: method,
                        authorization_event_ref: reference.clone(),
                    },
                    Some((original.actor_id.clone(), reference)),
                )
            } else {
                (
                    original.actor_id.clone(),
                    ContentRootBackupAuthor::Device {
                        binding: KeyBackupAuthBinding {
                            device_id: original.signature_proof.device_id.clone().unwrap(),
                            verification_method: method,
                            signature_algorithm: original.signature_proof.signature_algorithm,
                            device_authorize_event_id: original
                                .signature_proof
                                .device_authorize_event_id
                                .clone()
                                .unwrap(),
                        },
                        source: original.source_commit_ref.clone().unwrap(),
                    },
                    None,
                )
            };
            let base = ContentRootBackupDraft {
                backup_id: original.backup_id.clone(),
                actor_id: actor,
                created_at: original.created_at,
                expires_at: None,
                author,
                recipient_key_ref: original.encryption.recipient_key_ref.clone().unwrap(),
                recovery_policy_ref: original.recovery_policy_ref.clone().unwrap(),
                domain_separation: original.domain_separation.clone(),
                series_id: original.series_id.clone(),
                series_sequence: 0,
                supersedes: None,
                custody,
            }
            .seal(vec![root.clone()], &public, |bytes| {
                Ok(signing.sign(bytes).to_bytes().to_vec())
            })
            .unwrap();
            for expires in [None, Some(original.created_at + chrono::Duration::days(1))] {
                let mut packet = base.clone();
                packet.expires_at = Some(expires);
                packet.signature_proof.signature =
                    arkret_wire::Base64UrlString::new(base64url_encode(
                        signing
                            .sign(&packet.signing_payload_bytes().unwrap())
                            .to_bytes(),
                    ))
                    .unwrap();
                let wire = serde_json::to_value(&packet).unwrap();
                assert!(wire.get("expires_at").is_some());
                let restored: KeyBackup = serde_json::from_value(wire.clone()).unwrap();
                assert_eq!(serde_json::to_value(&restored).unwrap(), wire);
                assert_eq!(
                    restored.signing_payload_bytes().unwrap(),
                    packet.signing_payload_bytes().unwrap()
                );
                let opened =
                    super::super::open_content_root_backup(&restored, &private, |bytes, proof| {
                        arkret_signatures::proof::verify_ed25519_raw_transcript_signature(
                            bytes,
                            proof.signature.as_str(),
                            &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                                bytes: signing.verifying_key().to_bytes().to_vec(),
                            },
                        )
                        .map_err(|e| Error::Protocol(e.to_string()))
                    })
                    .unwrap();
                assert_eq!(
                    serde_json::to_value(opened).unwrap(),
                    serde_json::to_value(&bag).unwrap()
                );
            }
        }
    }
}
