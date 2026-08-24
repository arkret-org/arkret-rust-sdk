//! Typed key-backup HTTP client for `ak.keys.backups.*`.

use arkret_models_crypto::{
    KeyBackup, KeysBackupsDeleteChallenge, KeysBackupsDeleteRequestBody,
    KeysBackupsIssueDeleteChallengeRequestBody, KeysBackupsUnlockRequestBody,
};
use arkret_wire::BackupId;

use crate::{Client, Result as SdkResult};

/// Typed key-backup HTTP client wrapping a [`crate::Client`].
///
/// All methods return `Result<_, crate::Error>` so the API and
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
    ) -> SdkResult<arkret_models_crypto::KeysBackupsReplaceOutcome> {
        record.validate()?;
        let backup_id = BackupId::new(backup_id.to_owned())?;
        if backup_id != record.backup_id {
            return Err(crate::Error::Protocol(
                "key backup path/body backup_id mismatch".to_owned(),
            ));
        }
        let digest = arkret_canonical::canonical_sha256(record)?;
        let idempotency_key = format!("arkret-key-backup-{}", digest.trim_start_matches("sha256:"));
        self.client
            .put_key_backup(&backup_id, record, &idempotency_key)
            .await
    }

    /// `POST /_arkret/self/keys/backups/{backup_id}/unlock`.
    pub async fn unlock_key_backup(
        &self,
        backup_id: &str,
        request: &KeysBackupsUnlockRequestBody,
    ) -> SdkResult<KeyBackup> {
        let backup_id = BackupId::new(backup_id.to_owned())?;
        let record = self.client.unlock_key_backup(&backup_id, request).await?;
        record.validate()?;
        Ok(record)
    }

    /// `GET /_arkret/self/keys/backups` (list current backups for the
    /// authenticated principal).
    pub async fn list_key_backups(&self) -> SdkResult<arkret_models_crypto::KeysBackupsList> {
        self.client.get("/_arkret/self/keys/backups").await
    }

    /// `POST /_arkret/self/keys/backups/{backup_id}/delete-challenge`.
    ///
    /// The first half of the §7.8.1 delete flow: the returned challenge is what
    /// [`delete_key_backup`](Self::delete_key_backup)'s proof signs over.
    pub async fn issue_key_backup_delete_challenge(
        &self,
        backup_id: &str,
        request: &KeysBackupsIssueDeleteChallengeRequestBody,
    ) -> SdkResult<KeysBackupsDeleteChallenge> {
        let backup_id = BackupId::new(backup_id.to_owned())?;
        self.client
            .issue_key_backup_delete_challenge(&backup_id, request)
            .await
    }

    /// `DELETE /_arkret/self/keys/backups/{backup_id}`.
    pub async fn delete_key_backup(
        &self,
        backup_id: &str,
        request: &KeysBackupsDeleteRequestBody,
    ) -> SdkResult<arkret_models_crypto::KeysBackupsDeleteOutcome> {
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
            actor_id: arkret_wire::DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
            device_id: Some(
                arkret_wire::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000000")
                    .unwrap(),
            ),
            backup_kind: arkret_models_crypto::BackupKind::SecretStorage,
            mixed_secret_storage: false,
            backup_version: "kb_1".to_owned(),
            created_at,
            updated_at: None,
            expires_at: None,
            encryption: arkret_models_crypto::KeyBackupEncryption {
                recipient_method: arkret_models_crypto::KeyBackupRecipientMethod::PassphraseKdf,
                recipient_key_ref: None,
                kdf: Some(arkret_models_crypto::KeyBackupKdf {
                    name: arkret_models_crypto::KeyBackupKdfName::Argon2id,
                    salt: arkret_wire::Base64UrlString::new("c2FsdA").unwrap(),
                    params: arkret_models_crypto::KeyBackupKdfParams {
                        memory_kib: Some(65_536),
                        iterations: Some(3),
                        parallelism: Some(1),
                        digest_algorithm: None,
                        extra: Default::default(),
                    },
                    degraded_profile_reason: None,
                    extra: Default::default(),
                }),
                aead: arkret_models_crypto::KeyBackupAead {
                    name: arkret_models_crypto::KeyBackupAeadName::Xchacha20Poly1305,
                    aead_profile: Some("ak.aead.xchacha20_poly1305.v1".to_owned()),
                    nonce: Some(arkret_wire::Base64UrlString::new("nonce").unwrap()),
                    nonce_salt: Some(
                        arkret_wire::Base64UrlString::new("nonce_salt_value").unwrap(),
                    ),
                    enc: None,
                    extra: Default::default(),
                },
                key_commitment: Some(format!("sha256:{}", "a".repeat(64))),
                hpke_suite: None,
                extra: Default::default(),
            },
            domain_separation: arkret_models_crypto::KeyBackupDomainSeparation {
                subdomain: "aead".to_owned(),
                aead_aad_extensions: Default::default(),
            },
            contents: vec![arkret_models_crypto::KeyBackupContentItem::SecretStorage(
                arkret_models_crypto::SecretStorageContentIndex {
                    item_kind: arkret_models_crypto::SecretStorageItemKind::PrivateAccountState,
                    realm_id: None,
                    from_epoch: None,
                    to_epoch: None,
                    secret_id: Some("recovery".to_owned()),
                    secret_version: Some(1),
                    extra: Default::default(),
                },
            )],
            ciphertext: "Y2lwaGVydGV4dA".to_owned(),
            ciphertext_digest: arkret_canonical::sha256_digest(b"ciphertext"),
            plaintext_commitment: None,
            auth_data: Some(arkret_models_crypto::KeyBackupAuthData {
                device_id: arkret_wire::DeviceId::new(
                    "ak:device:01964137-0000-7000-8000-000000000000",
                )
                .unwrap(),
                verification_method: arkret_wire::DidUrl::new(
                    "did:webvh:z6mkfixture:alice.example#device",
                )
                .unwrap(),
                signature_algorithm: arkret_models_crypto::KeyBackupSignatureAlgorithm::Ed25519,
                signature: arkret_wire::Base64UrlString::new("c2ln").unwrap(),
                device_authorize_event_id: arkret_wire::EventId::new(
                    "ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM",
                )
                .unwrap(),
                extra: Default::default(),
            }),
            retention: None,
            series_id: arkret_wire::BackupSeriesId::new(
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
        record.validate().unwrap();
        let json = serde_json::to_value(&record).unwrap();
        assert_eq!(json["backup_id"], record.backup_id.as_str());
        assert_eq!(json["backup_kind"], "secret_storage");
        let back: KeyBackup = serde_json::from_value(json).unwrap();
        assert_eq!(back.backup_id, record.backup_id);
        assert_eq!(back.backup_version, "kb_1");
    }

    #[test]
    fn key_backup_put_response_round_trips() {
        let record = backup_record();
        let backup_id = record.backup_id.clone();
        let response = arkret_models_crypto::KeysBackupsReplaceOutcome {
            status: arkret_models_crypto::KeyBackupPutStatus::Accepted,
            backup_id: backup_id.clone(),
            ciphertext_digest: record.ciphertext_digest,
        };
        let json = serde_json::to_value(&response).unwrap();
        let back: arkret_models_crypto::KeysBackupsReplaceOutcome =
            serde_json::from_value(json).unwrap();
        assert_eq!(back.backup_id, backup_id);
        assert_eq!(
            back.status,
            arkret_models_crypto::KeyBackupPutStatus::Accepted
        );
    }
}
