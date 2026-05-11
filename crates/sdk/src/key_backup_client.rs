//! Typed key-backup HTTP client for `cx.keys.backups.*`.

use serde::{Deserialize, Serialize};

use contrix_http_client::Client;

use crate::{ProtocolKeyBackup, Result as SdkResult};

/// Response for `cx.keys.backups.put`.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct KeyBackupPutResponse {
    pub status: String,
    pub backup_id: String,
    pub ciphertext_digest: String,
}

/// Response for `cx.keys.backups.list`.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct KeyBackupListResponse {
    pub backups: Vec<ProtocolKeyBackup>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Typed key-backup HTTP client wrapping a [`contrix_http_client::Client`].
///
/// All methods return `Result<_, contrix_http_client::Error>` so the API and
/// retry/backoff config flow through the underlying client builder. The
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

    /// `PUT /api/v1/keys/backups/{backup_id}`.
    pub async fn put_key_backup(
        &self,
        backup_id: &str,
        record: &ProtocolKeyBackup,
    ) -> SdkResult<KeyBackupPutResponse> {
        let path = format!("/api/v1/keys/backups/{backup_id}");
        self.client.put(&path, record).await
    }

    /// `GET /api/v1/keys/backups/{backup_id}`.
    pub async fn get_key_backup(&self, backup_id: &str) -> SdkResult<ProtocolKeyBackup> {
        let path = format!("/api/v1/keys/backups/{backup_id}");
        self.client.get(&path).await
    }

    /// `GET /api/v1/keys/backups` (list current backups for the
    /// authenticated principal).
    pub async fn list_key_backups(&self) -> SdkResult<KeyBackupListResponse> {
        self.client.get("/api/v1/keys/backups").await
    }

    /// `DELETE /api/v1/keys/backups/{backup_id}`.
    pub async fn delete_key_backup(&self, backup_id: &str) -> SdkResult<KeyBackupDeleteResponse> {
        let path = format!("/api/v1/keys/backups/{backup_id}");
        self.client.delete(&path).await
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyBackupDeleteResponse {
    pub deleted: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;

    fn backup_record() -> ProtocolKeyBackup {
        ProtocolKeyBackup {
            backup_id: "cx:backup:01964137-0000-7000-8000-000000000000".to_owned(),
            actor_id: crate::Did::new("did:web:alice.example").unwrap(),
            device_id: Some(
                crate::DeviceId::new("cx:device:01964137-0000-7000-8000-000000000000").unwrap(),
            ),
            backup_class: crate::KeyBackupClass::DidRecovery,
            backup_version: "kb_1".to_owned(),
            created_at: Utc::now(),
            updated_at: None,
            expires_at: None,
            encryption: crate::KeyBackupEncryption {
                recipient_method: "passphrase_kdf".to_owned(),
                recipient_key_ref: None,
                kdf: Some(json!({"name": "argon2id", "salt": "salt"})),
                aead: json!({"name": "xchacha20_poly1305", "nonce": "nonce"}),
                key_commitment: None,
            },
            contents: vec![crate::KeyBackupContentItem {
                item_type: "recovery_secret".to_owned(),
                space_id: None,
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
        assert_eq!(json["backup_class"], "did_recovery");
        let back: ProtocolKeyBackup = serde_json::from_value(json).unwrap();
        assert_eq!(back.backup_id, record.backup_id);
        assert_eq!(back.backup_version, "kb_1");
    }

    #[test]
    fn key_backup_put_response_round_trips() {
        let record = backup_record();
        let response = KeyBackupPutResponse {
            status: "accepted".to_owned(),
            backup_id: record.backup_id.clone(),
            ciphertext_digest: record.ciphertext_digest.clone(),
        };
        let json = serde_json::to_value(&response).unwrap();
        let back: KeyBackupPutResponse = serde_json::from_value(json).unwrap();
        assert_eq!(back.backup_id, record.backup_id);
    }
}
