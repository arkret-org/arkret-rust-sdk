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
