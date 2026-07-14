//! Typed key-backup HTTP client for `ak.keys.backups.*`.

use arkret_http_client::Client;

use crate::{
    BackupId, KeyBackup, KeysBackupsDeleteRequestBody, KeysBackupsUnlockRequestBody,
    Result as SdkResult,
};

/// Typed key-backup HTTP client wrapping a [`arkret_http_client::Client`].
///
/// All methods return `Result<_, arkret_http_client::Error>` so the API and
/// retry/backoff config strand through the underlying client builder. The
/// caller is expected to construct the inner [`Client`] with the
/// appropriate auth (Bearer / DeviceProof / ServiceSignature).
#[derive(Clone, Debug)]
pub struct KeyBackupClient {
    client: Client,
}

impl KeyBackupClient {
    /// Wrap an authenticated [`Client`].
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// Borrow the underlying HTTP client (for sharing across multiple
    /// typed wrappers built from the same connection pool).
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// `PUT /_arkret/self/keys/backups/{backup_id}`.
    pub async fn put_key_backup(
        &self,
        backup_id: &str,
        record: &KeyBackup,
    ) -> SdkResult<arkret_core::KeysBackupsPutOutcome> {
        let path = format!("/_arkret/self/keys/backups/{backup_id}");
        self.client.put(&path, record).await
    }

    /// `POST /_arkret/self/keys/backups/{backup_id}/unlock`.
    pub async fn unlock_key_backup(
        &self,
        backup_id: &str,
        request: &KeysBackupsUnlockRequestBody,
    ) -> SdkResult<KeyBackup> {
        let backup_id = BackupId::new(backup_id.to_owned())?;
        self.client.unlock_key_backup(&backup_id, request).await
    }

    /// `GET /_arkret/self/keys/backups` (list current backups for the
    /// authenticated principal).
    pub async fn list_key_backups(&self) -> SdkResult<arkret_core::KeysBackupsList> {
        self.client.get("/_arkret/self/keys/backups").await
    }

    /// `DELETE /_arkret/self/keys/backups/{backup_id}`.
    pub async fn delete_key_backup(
        &self,
        backup_id: &str,
        request: &KeysBackupsDeleteRequestBody,
    ) -> SdkResult<arkret_core::KeysBackupsDeleteOutcome> {
        let backup_id = BackupId::new(backup_id.to_owned())?;
        self.client.delete_key_backup(&backup_id, request).await
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;

    fn backup_record() -> KeyBackup {
        let created_at = Utc::now();
        KeyBackup {
            backup_id: BackupId::new("ak:backup:01964137-0000-7000-8000-000000000000").unwrap(),
            actor_id: crate::Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            device_id: Some(
                crate::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000000").unwrap(),
            ),
            backup_class: crate::BackupClass::SecretStorage,
            mixed_secret_storage: false,
            backup_version: "kb_1".to_owned(),
            created_at,
            updated_at: None,
            expires_at: None,
            encryption: arkret_core::KeyBackupEncryption {
                recipient_method: arkret_core::KeyBackupRecipientMethod::PassphraseKdf,
                recipient_key_ref: None,
                kdf: Some(arkret_core::KeyBackupKdf {
                    name: arkret_core::KeyBackupKdfName::Argon2id,
                    salt: crate::Base64UrlString::new("c2FsdA").unwrap(),
                    params: arkret_core::KeyBackupKdfParams {
                        memory_kib: Some(65_536),
                        iterations: Some(3),
                        parallelism: Some(1),
                        digest_algorithm: None,
                        extra: Default::default(),
                    },
                    degraded_profile_reason: None,
                    extra: Default::default(),
                }),
                aead: arkret_core::KeyBackupAead {
                    name: arkret_core::KeyBackupAeadName::Xchacha20Poly1305,
                    aead_profile: Some("ak.aead.xchacha20_poly1305.v1".to_owned()),
                    nonce: Some(crate::Base64UrlString::new("nonce").unwrap()),
                    nonce_salt: Some(crate::Base64UrlString::new("nonce_salt_value").unwrap()),
                    enc: None,
                    extra: Default::default(),
                },
                key_commitment: None,
                hpke_suite: None,
                extra: Default::default(),
            },
            domain_separation: arkret_core::KeyBackupDomainSeparation {
                hkdf_info: "arkret-key-backup/secret_storage/aead/v1".to_owned(),
                subdomain: "aead".to_owned(),
                aead_aad: arkret_core::KeyBackupDomainSeparationAad {
                    schema: "ak.schema.key_backup.v1".to_owned(),
                    actor_id: crate::Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
                    device_id: "ak:device:01964137-0000-7000-8000-000000000000".to_owned(),
                    backup_class: crate::BackupClass::SecretStorage,
                    backup_version: "kb_1".to_owned(),
                    created_at,
                    item_types: vec!["recovery_secret".to_owned()],
                    managed_principal_bindings: Vec::new(),
                    recipient_method: Some(arkret_core::KeyBackupRecipientMethod::PassphraseKdf),
                    recipient_key_ref: None,
                    extra: Default::default(),
                },
                extra: Default::default(),
            },
            contents: vec![crate::KeyBackupContentItem {
                item_type: "recovery_secret".to_owned(),
                realm_id: None,
                managed_principal_binding: None,
                mls_group_id: None,
                epoch: None,
                first_event_id: None,
                last_event_id: None,
                secret_id: Some("recovery".to_owned()),
                secret_version: Some(1),
                extra: Default::default(),
            }],
            ciphertext: "ciphertext".to_owned(),
            ciphertext_digest:
                "sha256:2108421084217842908421084210842121084210842178429084210842108421".to_owned(),
            plaintext_commitment: None,
            auth_data: Some(arkret_core::KeyBackupAuthData {
                device_id: crate::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000000")
                    .unwrap(),
                verification_method: crate::DidUrl::new(
                    "did:webvh:z6mkfixture:alice.example#device",
                )
                .unwrap(),
                signature_algorithm: arkret_core::KeyBackupSignatureAlgorithm::Ed25519,
                signature: crate::Base64UrlString::new("c2ln").unwrap(),
                ssk_generation: std::num::NonZeroU64::new(1),
                device_authorize_event_id: None,
                signed_fields: [
                    "backup_id",
                    "actor_id",
                    "backup_class",
                    "backup_version",
                    "series_id",
                    "series_seq",
                    "encryption",
                    "domain_separation",
                    "contents",
                    "ciphertext_digest",
                ]
                .map(str::to_owned)
                .to_vec(),
                extra: Default::default(),
            }),
            retention: None,
            series_id: arkret_core::BackupSeriesId::new(
                "ak:backup_series:01964137-0000-7000-8000-000000000000",
            )
            .unwrap(),
            series_seq: 0,
            supersedes: None,
            supersedes_digest: None,
            frontier_ref: None,
            recovery_policy_ref: None,
            extra: Default::default(),
        }
    }

    #[test]
    fn key_backup_record_round_trips() {
        let record = backup_record();
        let json = serde_json::to_value(&record).unwrap();
        assert_eq!(json["backup_id"], record.backup_id.as_str());
        assert_eq!(json["backup_class"], "secret_storage");
        let back: KeyBackup = serde_json::from_value(json).unwrap();
        assert_eq!(back.backup_id, record.backup_id);
        assert_eq!(back.backup_version, "kb_1");
    }

    #[test]
    fn key_backup_put_response_round_trips() {
        let record = backup_record();
        let backup_id = record.backup_id.clone();
        let response = arkret_core::KeysBackupsPutOutcome {
            status: arkret_core::KeyBackupPutStatus::Accepted,
            backup_id: backup_id.clone(),
            ciphertext_digest: record.ciphertext_digest,
        };
        let json = serde_json::to_value(&response).unwrap();
        let back: arkret_core::KeysBackupsPutOutcome = serde_json::from_value(json).unwrap();
        assert_eq!(back.backup_id, backup_id);
        assert_eq!(back.status, arkret_core::KeyBackupPutStatus::Accepted);
    }
}
