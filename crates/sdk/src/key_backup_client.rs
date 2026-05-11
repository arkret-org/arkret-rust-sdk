//! Production typed key-backup / restore-ticket HTTP client wrapper.
//!
//! Round 24 (2026-05-09) graduates the key-backup helper from raw
//! `serde_json::Value` round-trips to a typed wrapper around
//! soland's `/api/v1/keys/backups` + `/api/v1/keys/backups/{id}/restore-*`
//! endpoints. Wire shapes mirror `soland/src/routing/key_backup_restore.rs`
//! with a single typed `KeyBackupRecord` / `RestoreTicket` model so the
//! SDK exposes `Result<KeyBackupRecord, Error>` instead of
//! `Result<serde_json::Value>`.
//!
//! The contract still tolerates the trailing `state` + `todos` fields
//! (the soland scaffold response shape) because the v1 protocol is not
//! yet released — when soland upgrades from the in-memory scaffold to
//! durable persistence those fields just become empty / absent and the
//! typed model continues to deserialize.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use contrix_http_client::Client;

use crate::{DeviceId, Did, Result as SdkResult};

/// Typed encrypted key-backup record returned by
/// `PUT/GET /api/v1/keys/backups/{backup_id}`.
///
/// `key_material_encrypted` is the opaque ciphertext blob the server
/// stores; `scheme` and `version` identify the encryption profile per
/// `crypto-media/key-management.md` §7.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KeyBackupRecord {
    /// Stable opaque backup identifier.
    #[serde(rename = "backup_id", alias = "id")]
    pub id: String,
    /// Owning principal.
    pub actor_id: Did,
    /// Optional sender device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    /// Encrypted key material (base64 / opaque blob, opaque to the SDK).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_material_encrypted: Option<String>,
    /// Encryption scheme identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    /// Backup version (rotation cursor).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Server-side creation/update timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "updated_at")]
    pub created_at: Option<DateTime<Utc>>,
    /// Server scaffold metadata (echoed through; ignored by typed callers).
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub extra: Value,
}

/// Wire wrapper for the soland `KeysBackupsPutResponse` shape, exposed so
/// callers that need the full envelope (including the scaffold-flag field)
/// can opt in.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct KeyBackupResponse {
    pub ok: bool,
    pub backup: Value,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub todos: Vec<String>,
}

/// Wire wrapper for the soland `KeysBackupsListResponse` shape.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct KeyBackupListResponse {
    pub backups: Vec<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub todos: Vec<String>,
}

/// Typed restore-ticket lifecycle record. Mirrors the
/// `cx.restore_ticket.v1` contract embedded in
/// [`crate::devices::ProtocolKeyBackupRestoreTicket`] but adds the
/// fields a client sees on the wire.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RestoreTicket {
    pub id: String,
    #[serde(rename = "actor_id")]
    pub account_id: Did,
    #[serde(default)]
    pub backup_id: Option<String>,
    /// Lifecycle state (`authz_pending`, `authz_checked`, `policy_checked`,
    /// `approved`, `materialized`).
    pub status: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_next_transitions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
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
        record: &KeyBackupRecord,
    ) -> SdkResult<KeyBackupResponse> {
        let path = format!("/api/v1/keys/backups/{backup_id}");
        self.client.put(&path, record).await
    }

    /// `GET /api/v1/keys/backups/{backup_id}`.
    pub async fn get_key_backup(&self, backup_id: &str) -> SdkResult<KeyBackupResponse> {
        let path = format!("/api/v1/keys/backups/{backup_id}");
        self.client.get(&path).await
    }

    /// `GET /api/v1/keys/backups` (list current backups for the
    /// authenticated principal).
    pub async fn list_key_backups(&self) -> SdkResult<KeyBackupListResponse> {
        self.client.get("/api/v1/keys/backups").await
    }

    /// `POST /api/v1/keys/backups/{backup_id}/restore/start` — kick off
    /// a restore-ticket lifecycle and return the typed ticket.
    pub async fn start_restore_ticket(
        &self,
        backup_id: &str,
        body: &Value,
    ) -> SdkResult<RestoreTicket> {
        let path = format!("/api/v1/keys/backups/{backup_id}/restore/start");
        self.client.post(&path, body).await
    }

    /// `GET /api/v1/keys/backups/{backup_id}/restore/{ticket_id}` — read
    /// the current ticket state.
    pub async fn get_restore_ticket(
        &self,
        backup_id: &str,
        ticket_id: &str,
    ) -> SdkResult<RestoreTicket> {
        let path = format!("/api/v1/keys/backups/{backup_id}/restore/{ticket_id}");
        self.client.get(&path).await
    }

    /// `POST /api/v1/keys/backups/{backup_id}/restore/{ticket_id}/advance`.
    pub async fn advance_restore_ticket(
        &self,
        backup_id: &str,
        ticket_id: &str,
        transition: &str,
    ) -> SdkResult<RestoreTicket> {
        let path = format!("/api/v1/keys/backups/{backup_id}/restore/{ticket_id}/advance");
        let body = serde_json::json!({ "transition": transition });
        self.client.post(&path, &body).await
    }

    /// `POST /api/v1/keys/backups/{backup_id}/restore/{ticket_id}/cancel`.
    pub async fn cancel_restore_ticket(
        &self,
        backup_id: &str,
        ticket_id: &str,
    ) -> SdkResult<RestoreTicket> {
        let path = format!("/api/v1/keys/backups/{backup_id}/restore/{ticket_id}/cancel");
        self.client.post(&path, &serde_json::json!({})).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_backup_record_round_trips() {
        let record = KeyBackupRecord {
            id: "bk_1".to_owned(),
            actor_id: Did::new("did:web:alice.example").unwrap(),
            device_id: Some(DeviceId::new("dev_alice_phone").unwrap()),
            key_material_encrypted: Some("base64-blob".to_owned()),
            scheme: Some("did_recovery".to_owned()),
            version: Some("v1".to_owned()),
            created_at: Some(Utc::now()),
            extra: Value::Null,
        };
        let json = serde_json::to_value(&record).unwrap();
        assert_eq!(json["backup_id"], "bk_1");
        let back: KeyBackupRecord = serde_json::from_value(json).unwrap();
        assert_eq!(back.id, "bk_1");
        assert_eq!(back.scheme.as_deref(), Some("did_recovery"));
    }

    #[test]
    fn key_backup_record_accepts_id_alias() {
        let json = serde_json::json!({
            "id": "bk_legacy",
            "actor_id": "did:web:alice.example",
        });
        let back: KeyBackupRecord = serde_json::from_value(json).unwrap();
        assert_eq!(back.id, "bk_legacy");
    }

    #[test]
    fn restore_ticket_round_trips() {
        let ticket = RestoreTicket {
            id: "rt_1".to_owned(),
            account_id: Did::new("did:web:alice.example").unwrap(),
            backup_id: Some("bk_1".to_owned()),
            status: "authz_pending".to_owned(),
            allowed_next_transitions: vec!["authz_checked".to_owned()],
            expires_at: Some(Utc::now()),
            created_at: Some(Utc::now()),
        };
        let json = serde_json::to_value(&ticket).unwrap();
        assert_eq!(json["actor_id"], "did:web:alice.example");
        let back: RestoreTicket = serde_json::from_value(json).unwrap();
        assert_eq!(back.id, "rt_1");
        assert_eq!(back.status, "authz_pending");
    }
}
