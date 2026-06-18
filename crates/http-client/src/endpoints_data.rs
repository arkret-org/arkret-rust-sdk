//! Blob, key, key-backup, and device-message endpoint methods on [`Client`].

use cokret_core::{
    BackupId, BlobMetadata, BlobRef, BlobUploadMetadata, BlobUploadOutcome,
    DeviceMessagesAckOutcome, DeviceMessagesAckRequestBody, DeviceMessagesGetOutcome,
    DeviceMessagesPutOutcome, DeviceMessagesPutRequestBody, KeyBackup, KeyBackupSummary,
    KeyBackupsListQuery, KeyPackagesClaimOutcome, KeyPackagesClaimRequestBody,
    KeyPackagesConsumeOutcome, KeyPackagesConsumeRequestBody, KeyPackagesRevokeOutcome,
    KeyPackagesRevokeRequestBody, KeyPackagesUploadOutcome, KeyPackagesUploadRequestBody,
    KeysBackupsDeleteOutcome, KeysBackupsDeleteRequestBody, KeysBackupsList, KeysBackupsPutOutcome,
    KeysBackupsUnlockRequestBody, KeysClaimOutcome, KeysClaimRequestBody, KeysQueryOutcome,
    KeysQueryRequestBody, KeysUploadOutcome, KeysUploadRequestBody, Result,
};
use reqwest::Method;
use reqwest::header::HeaderMap;

use crate::client_internals::transport_error;
use crate::{Client, ClientRequestOptions};

impl Client {
    pub async fn blob_metadata(&self, blob_ref: &BlobRef) -> Result<BlobMetadata> {
        let builder = self
            .request(Method::GET, "/_cokret/self/blob/get")?
            .query(&[("blob_ref", blob_ref.as_str())]);
        self.send_json(builder).await
    }

    pub async fn blob_head(&self, blob_ref: &BlobRef) -> Result<HeaderMap> {
        let builder = self
            .request(Method::HEAD, "/_cokret/self/blob/get")?
            .query(&[("blob_ref", blob_ref.as_str())]);
        self.send_empty(builder).await
    }

    pub async fn blob_upload(&self, body: &BlobUploadMetadata) -> Result<BlobUploadOutcome> {
        self.post("/_cokret/self/blob/upload", body).await
    }

    pub async fn blob_upload_bytes(
        &self,
        metadata: &BlobUploadMetadata,
        bytes: Vec<u8>,
    ) -> Result<BlobUploadOutcome> {
        let mut builder = self
            .request(Method::POST, "/_cokret/self/blob/upload")?
            .header("X-Cokret-Blob-Metadata", serde_json::to_string(metadata)?);
        if let Some(media_type) = &metadata.media_type {
            builder = builder.header("Content-Type", media_type);
        }
        if let Some(filename) = &metadata.filename {
            builder = builder.header(
                "Content-Disposition",
                format!("attachment; filename=\"{filename}\""),
            );
        }
        if let Some(content_digest) = &metadata.content_digest {
            builder = builder.header("Digest", content_digest.as_str());
        }
        self.send_json(builder.body(bytes)).await
    }

    pub async fn blob_download(&self, blob_ref: &BlobRef, range: Option<&str>) -> Result<Vec<u8>> {
        let mut builder = self
            .request(Method::GET, "/_cokret/self/blob/get")?
            .query(&[("blob_ref", blob_ref.as_str())]);
        if let Some(range) = range {
            builder = builder.header("Range", range);
        }
        let response = self.send_response(builder).await?;
        Ok(response.bytes().await.map_err(transport_error)?.to_vec())
    }

    pub async fn keys_upload(&self, request: &KeysUploadRequestBody) -> Result<KeysUploadOutcome> {
        self.post("/_cokret/self/keys/upload", request).await
    }

    pub async fn keys_query(&self, request: &KeysQueryRequestBody) -> Result<KeysQueryOutcome> {
        self.post("/_cokret/self/keys/query", request).await
    }

    pub async fn keys_claim(&self, request: &KeysClaimRequestBody) -> Result<KeysClaimOutcome> {
        self.post("/_cokret/self/keys/claim", request).await
    }

    pub async fn keypackages_upload(
        &self,
        request: &KeyPackagesUploadRequestBody,
    ) -> Result<KeyPackagesUploadOutcome> {
        self.post("/_cokret/self/keys/keypackages/upload", request)
            .await
    }

    pub async fn keypackages_claim(
        &self,
        request: &KeyPackagesClaimRequestBody,
    ) -> Result<KeyPackagesClaimOutcome> {
        self.post("/_cokret/self/keys/keypackages/claim", request)
            .await
    }

    pub async fn keypackages_consume(
        &self,
        request: &KeyPackagesConsumeRequestBody,
    ) -> Result<KeyPackagesConsumeOutcome> {
        self.post("/_cokret/self/keys/keypackages/consume", request)
            .await
    }

    pub async fn keypackages_revoke(
        &self,
        request: &KeyPackagesRevokeRequestBody,
    ) -> Result<KeyPackagesRevokeOutcome> {
        self.post("/_cokret/self/keys/keypackages/revoke", request)
            .await
    }

    /// Upload (create or update) an encrypted [`KeyBackup`] envelope.
    /// Spec: `crypto-media/key-management.md` §7.2 +
    /// `sync/service-http-binding.md` §3 (PUT
    /// `/_cokret/self/keys/backups/{backup_id}`). The envelope's
    /// `ciphertext_digest` is the server-side idempotency / dedup key.
    pub async fn put_key_backup(
        &self,
        backup_id: &BackupId,
        body: &KeyBackup,
    ) -> Result<KeysBackupsPutOutcome> {
        let path = format!("/_cokret/self/keys/backups/{}", backup_id.as_str());
        self.put(&path, body).await
    }

    /// List existing key backups for the authorized actor. Honors the
    /// `backup_class` / `cursor` / `limit` filters from
    /// [`KeyBackupsListQuery`] (key-management.md §7.5).
    pub async fn list_key_backups(&self, query: &KeyBackupsListQuery) -> Result<KeysBackupsList> {
        let mut builder = self.request(Method::GET, "/_cokret/self/keys/backups")?;
        if let Some(class) = query.backup_class {
            let class_str = match class {
                cokret_core::BackupClass::DidRecovery => "did_recovery",
                cokret_core::BackupClass::SecretStorage => "secret_storage",
                cokret_core::BackupClass::MlsHistory => "mls_history",
            };
            builder = builder.query(&[("backup_class", class_str)]);
        }
        if let Some(ref cursor) = query.cursor {
            builder = builder.query(&[("cursor", cursor.as_str())]);
        }
        if let Some(limit) = query.limit {
            builder = builder.query(&[("limit", limit.to_string())]);
        }
        self.send_json(builder).await
    }

    /// Convenience variant that returns just the summary list. Equivalent to
    /// [`list_key_backups`](Self::list_key_backups) with default query.
    pub async fn list_all_key_backups(&self) -> Result<Vec<KeyBackupSummary>> {
        let response: KeysBackupsList = self
            .list_key_backups(&KeyBackupsListQuery {
                backup_class: None,
                cursor: None,
                limit: None,
            })
            .await?;
        Ok(response.backups)
    }

    /// Unlock and fetch a single encrypted [`KeyBackup`] envelope for local
    /// decryption. The full ciphertext is returned only through the
    /// proof-bearing command body registered as
    /// `POST /_cokret/self/keys/backups/{backup_id}/unlock`.
    pub async fn unlock_key_backup(
        &self,
        backup_id: &BackupId,
        request: &KeysBackupsUnlockRequestBody,
    ) -> Result<KeyBackup> {
        let path = format!("/_cokret/self/keys/backups/{}/unlock", backup_id.as_str());
        self.post(&path, request).await
    }

    /// Delete an existing key backup envelope. Spec §7.4 marks this as a
    /// high-risk operation; the caller must supply the typed
    /// [`KeysBackupsDeleteRequestBody`] with a valid proof and (optionally) a
    /// human-readable reason.
    pub async fn delete_key_backup(
        &self,
        backup_id: &BackupId,
        request: &KeysBackupsDeleteRequestBody,
    ) -> Result<KeysBackupsDeleteOutcome> {
        let path = format!("/_cokret/self/keys/backups/{}", backup_id.as_str());
        let builder = self.request(Method::DELETE, &path)?.json(request);
        self.send_json(builder).await
    }

    pub async fn send_device_messages(
        &self,
        idempotency_key: &str,
        request: &DeviceMessagesPutRequestBody,
    ) -> Result<DeviceMessagesPutOutcome> {
        let options = ClientRequestOptions::new().idempotency_key(idempotency_key);
        self.post_with_options("/_cokret/self/device_messages", request, &options)
            .await
    }

    pub async fn receive_device_messages(
        &self,
        from: Option<&str>,
        limit: Option<u32>,
    ) -> Result<DeviceMessagesGetOutcome> {
        let mut builder = self.request(Method::GET, "/_cokret/self/device_messages")?;
        if let Some(from) = from {
            builder = builder.query(&[("from", from)]);
        }
        if let Some(limit) = limit {
            builder = builder.query(&[("limit", limit)]);
        }
        self.send_json(builder).await
    }

    pub async fn ack_device_messages(
        &self,
        request: &DeviceMessagesAckRequestBody,
    ) -> Result<DeviceMessagesAckOutcome> {
        self.post("/_cokret/self/device_messages/ack", request)
            .await
    }
}
