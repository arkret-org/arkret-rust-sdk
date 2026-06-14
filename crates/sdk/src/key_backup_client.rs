//! Typed key-backup HTTP client for `ck.keys.backups.*`.

use cokret_http_client::Client;

use crate::{BackupId, KeysBackupsDeleteRequestBody, ProtocolKeyBackup, Result as SdkResult};

/// Typed key-backup HTTP client wrapping a [`cokret_http_client::Client`].
///
/// All methods return `Result<_, cokret_http_client::Error>` so the API and
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

    /// `PUT /_cokret/self/keys/backups/{backup_id}`.
    pub async fn put_key_backup(
        &self,
        backup_id: &str,
        record: &ProtocolKeyBackup,
    ) -> SdkResult<cokret_core::KeysBackupsPutOutcome> {
        let path = format!("/_cokret/self/keys/backups/{backup_id}");
        self.client.put(&path, record).await
    }

    /// `GET /_cokret/self/keys/backups/{backup_id}`.
    pub async fn get_key_backup(&self, backup_id: &str) -> SdkResult<ProtocolKeyBackup> {
        let path = format!("/_cokret/self/keys/backups/{backup_id}");
        self.client.get(&path).await
    }

    /// `GET /_cokret/self/keys/backups` (list current backups for the
    /// authenticated principal).
    pub async fn list_key_backups(&self) -> SdkResult<cokret_core::KeysBackupsList> {
        self.client.get("/_cokret/self/keys/backups").await
    }

    /// `DELETE /_cokret/self/keys/backups/{backup_id}`.
    pub async fn delete_key_backup(
        &self,
        backup_id: &str,
        request: &KeysBackupsDeleteRequestBody,
    ) -> SdkResult<cokret_core::KeysBackupsDeleteOutcome> {
        let backup_id = BackupId::new(backup_id.to_owned())?;
        self.client.delete_key_backup(&backup_id, request).await
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use serde_json::json;

    use super::*;

    fn backup_record() -> ProtocolKeyBackup {
        ProtocolKeyBackup {
            backup_id: "ck:backup:01964137-0000-7000-8000-000000000000".to_owned(),
            actor_id: crate::Did::new("did:web:alice.example").unwrap(),
            device_id: Some(
                crate::DeviceId::new("ck:device:01964137-0000-7000-8000-000000000000").unwrap(),
            ),
            backup_class: crate::KeyBackupClass::SecretStorage,
            mixed_secret_storage: false,
            backup_version: "kb_1".to_owned(),
            created_at: Utc::now(),
            updated_at: None,
            expires_at: None,
            encryption: crate::KeyBackupEncryption {
                recipient_method: "passphrase_kdf".to_owned(),
                recipient_key_ref: None,
                kdf: Some(json!({
                    "name": "argon2id",
                    "salt": "salt",
                    "params": {
                        "memory_kib": 65_536,
                        "iterations": 3,
                        "parallelism": 1
                    }
                })),
                aead: json!({"name": "xchacha20_poly1305", "nonce": "nonce"}),
                key_commitment: None,
            },
            contents: vec![crate::KeyBackupContentItem {
                item_type: "recovery_secret".to_owned(),
                realm_id: None,
                mls_group_id: None,
                epoch: None,
                first_event_id: None,
                last_event_id: None,
                secret_id: Some("recovery".to_owned()),
                extra: json!({}),
            }],
            ciphertext: "ciphertext".to_owned(),
            ciphertext_digest:
                "sha256:2108421084217842908421084210842121084210842178429084210842108421".to_owned(),
            plaintext_commitment: None,
            auth_data: None,
            retention: None,
        }
    }

    #[test]
    fn key_backup_record_round_trips() {
        let record = backup_record();
        let json = serde_json::to_value(&record).unwrap();
        assert_eq!(json["backup_id"], record.backup_id);
        assert_eq!(json["backup_class"], "secret_storage");
        let back: ProtocolKeyBackup = serde_json::from_value(json).unwrap();
        assert_eq!(back.backup_id, record.backup_id);
        assert_eq!(back.backup_version, "kb_1");
    }

    #[test]
    fn key_backup_put_response_round_trips() {
        let record = backup_record();
        let backup_id = cokret_core::BackupId::new(record.backup_id.clone()).unwrap();
        let response = cokret_core::KeysBackupsPutOutcome {
            status: cokret_core::KeyBackupPutStatus::Accepted,
            backup_id: backup_id.clone(),
            ciphertext_digest: record.ciphertext_digest.clone(),
        };
        let json = serde_json::to_value(&response).unwrap();
        let back: cokret_core::KeysBackupsPutOutcome = serde_json::from_value(json).unwrap();
        assert_eq!(back.backup_id, backup_id);
        assert_eq!(back.status, cokret_core::KeyBackupPutStatus::Accepted);
    }
}
