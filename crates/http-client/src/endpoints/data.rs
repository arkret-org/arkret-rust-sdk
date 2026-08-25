//! Blob, key, key-backup, and device-message endpoint methods on [`Client`].

use arkret_canonical::base64url::base64_standard_encode;
use arkret_models_collaboration::objects::blob::{
    BlobPresignOutcome, BlobPresignRequestBody, BlobUploadMetadata, BlobUploadOutcome,
};
use arkret_models_collaboration::sync_frames::account_sync::{
    DeviceMessagesAckOutcome, DeviceMessagesAckRequestBody, DeviceMessagesGetOutcome,
    DeviceMessagesSendOutcome, DeviceMessagesSendRequestBody,
};
use arkret_models_crypto::{
    BackupSeriesEraseOutcome, BackupSeriesEraseRequestBody, KeyBackup, KeyBackupSummary,
    KeyBackupsListQuery, KeyPackagesClaimOutcome, KeyPackagesClaimRequestBody,
    KeyPackagesConsumeOutcome, KeyPackagesConsumeRequestBody, KeyPackagesRevokeOutcome,
    KeyPackagesRevokeRequestBody, KeyPackagesUploadOutcome, KeyPackagesUploadRequestBody,
    KeysBackupsDeleteChallenge, KeysBackupsDeleteOutcome, KeysBackupsDeleteRequestBody,
    KeysBackupsIssueDeleteChallengeRequestBody, KeysBackupsList, KeysBackupsReplaceOutcome,
    KeysBackupsUnlockRequestBody, KeysClaimOutcome, KeysClaimRequestBody, KeysQueryOutcome,
    KeysQueryRequestBody, KeysUploadOutcome, KeysUploadRequestBody,
};
use arkret_models_discovery::ServiceDescribe;
use arkret_models_identity::account::{
    AccountDataDeleteOutcome, AccountDataDeleteRequestBody, AccountDataReplaceRequestBody,
    AccountDataRow,
};
use arkret_wire::{BackupId, BlobRef};
use reqwest::Method;
use reqwest::header::{HeaderMap, RANGE};
use url::Url;

use crate::client_internals::{
    MAX_RESPONSE_BODY_BYTES, read_body_limited, validate_base_url, validate_header_value,
};
use crate::{Client, ClientRequestOptions, Error, Result, reject_path_segment};

/// Protocol-level feature id the server must advertise before a caller uses
/// the optional tus upload binding.
pub const RESUMABLE_UPLOAD_FEATURE: &str = "ak.feature.blob.resumable_upload.tus.v1";
/// Default ciphertext size where callers should prefer the resumable binding
/// over the canonical single-shot multipart upload when the server advertises
/// it. Below this threshold the extra tus round-trips usually do not pay off.
pub const RESUMABLE_UPLOAD_THRESHOLD_BYTES: usize = 2 * 1024 * 1024;
/// One chunk per request keeps memory bounded and limits the resume window.
const DEFAULT_RESUMABLE_CHUNK_BYTES: usize = 1024 * 1024;
const TUS_VERSION: &str = "1.0.0";
const DEFAULT_MAX_CHUNK_RETRIES: usize = 3;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobResumableUploadOptions {
    pub metadata: Vec<(String, String)>,
    pub chunk_bytes: usize,
    pub max_chunk_retries: usize,
}

impl Default for BlobResumableUploadOptions {
    fn default() -> Self {
        Self {
            metadata: Vec::new(),
            chunk_bytes: DEFAULT_RESUMABLE_CHUNK_BYTES,
            max_chunk_retries: DEFAULT_MAX_CHUNK_RETRIES,
        }
    }
}

impl BlobResumableUploadOptions {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.push((key.into(), value.into()));
        self
    }

    #[must_use]
    pub fn chunk_bytes(mut self, chunk_bytes: usize) -> Self {
        self.chunk_bytes = chunk_bytes;
        self
    }
}

pub fn blob_resumable_upload_base_url(description: &ServiceDescribe) -> Option<Url> {
    if !description
        .supported_features
        .iter()
        .any(|feature| feature == RESUMABLE_UPLOAD_FEATURE)
    {
        return None;
    }
    let binding = description
        .supported_bindings
        .iter()
        .find(|binding| binding.kind == arkret_wire::BindingKind::Tus)?;
    if let Some(operations) = binding
        .extra
        .get("operations")
        .and_then(|value| value.as_array())
        && !operations.iter().any(|operation| {
            operation.as_str() == Some(arkret_wire::ServiceOperationId::SELF_BLOB_UPLOAD_CREATE)
        })
    {
        return None;
    }
    let base_url = binding.base_url.as_deref()?;
    Url::parse(base_url).ok()
}

fn b64_metadata_value(value: &str) -> String {
    base64_standard_encode(value)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobDownloadOptions {
    pub purpose: Option<String>,
    pub range: Option<String>,
    pub max_bytes: usize,
}

impl Default for BlobDownloadOptions {
    fn default() -> Self {
        Self {
            purpose: None,
            range: None,
            max_bytes: MAX_RESPONSE_BODY_BYTES,
        }
    }
}

impl BlobDownloadOptions {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn purpose(mut self, purpose: impl Into<String>) -> Self {
        self.purpose = Some(purpose.into());
        self
    }

    #[must_use]
    pub fn range(mut self, range: impl Into<String>) -> Self {
        self.range = Some(range.into());
        self
    }

    #[must_use]
    pub fn max_bytes(mut self, max_bytes: usize) -> Self {
        self.max_bytes = max_bytes;
        self
    }
}

impl Client {
    fn tus_request(&self, method: Method, url: Url) -> Result<reqwest::RequestBuilder> {
        validate_base_url(&url, self.allow_insecure_localhost)?;
        if url.origin() != self.base_url.origin() {
            return Err(Error::Protocol(
                "resumable upload URL must have the principal server origin".to_owned(),
            ));
        }
        let method_for_auth = method.clone();
        let mut builder = self.http.request(method, url.clone());
        if let Some(user_agent) = &self.user_agent {
            builder = builder.header(reqwest::header::USER_AGENT, user_agent);
        }
        #[cfg(not(target_arch = "wasm32"))]
        let builder = match self.default_timeout {
            Some(timeout) => builder.timeout(timeout),
            None => builder,
        };
        self.apply_auth(builder, &method_for_auth, &url)
    }

    pub async fn blob_head(&self, blob_ref: &BlobRef) -> Result<HeaderMap> {
        let builder = self
            .request(Method::HEAD, "/_arkret/self/blob/get")?
            .query(&[("blob_ref", blob_ref.as_str())]);
        self.send_empty(builder).await
    }

    pub async fn blob_upload(&self, body: &BlobUploadMetadata) -> Result<BlobUploadOutcome> {
        self.post("/_arkret/self/blob/upload", body).await
    }

    pub async fn blob_presign(&self, body: &BlobPresignRequestBody) -> Result<BlobPresignOutcome> {
        self.post("/_arkret/self/blob/presign", body).await
    }

    pub async fn blob_upload_bytes(
        &self,
        metadata: &BlobUploadMetadata,
        bytes: Vec<u8>,
    ) -> Result<BlobUploadOutcome> {
        let media_type = metadata
            .media_type
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("application/octet-stream");
        let mut content = reqwest::multipart::Part::bytes(bytes)
            .mime_str(media_type)
            .map_err(|error| Error::Protocol(format!("blob media_type: {error}")))?;
        if let Some(filename) = metadata.filename.as_ref() {
            content = content.file_name(filename.clone());
        }
        let mut form = reqwest::multipart::Form::new()
            .part("content", content)
            .text("size_bytes", metadata.size_bytes.to_string())
            .text("media_type", media_type.to_owned());
        if let Some(realm_id) = metadata.realm_id.as_ref() {
            form = form.text("realm_id", realm_id.as_str().to_owned());
        }
        if let Some(content_digest) = metadata.content_digest.as_ref() {
            form = form.text("content_digest", content_digest.as_str().to_owned());
        }
        if let Some(filename) = metadata.filename.as_ref() {
            form = form.text("filename", filename.clone());
        }
        if let Some(purpose) = metadata.purpose.as_ref() {
            form = form.text("purpose", purpose.clone());
        }
        let builder = self
            .request(Method::POST, "/_arkret/self/blob/upload")?
            .multipart(form);
        self.send_json(builder).await
    }

    /// Download blob bytes with the default response-size cap.
    pub async fn blob_download(&self, blob_ref: &BlobRef, range: Option<&str>) -> Result<Vec<u8>> {
        let options = match range {
            Some(range) => BlobDownloadOptions::new().range(range.to_owned()),
            None => BlobDownloadOptions::new(),
        };
        self.blob_download_bytes(blob_ref, &options).await
    }

    /// Open an authenticated blob download response for progressive readers.
    ///
    /// Callers that need segment-by-segment decryption or playback should use
    /// this method with `Range` and consume the returned response stream
    /// directly. The convenience bytes methods below add a memory cap before
    /// materializing the response into a `Vec<u8>`.
    pub async fn blob_download_response(
        &self,
        blob_ref: &BlobRef,
        options: &BlobDownloadOptions,
    ) -> Result<reqwest::Response> {
        self.blob_download_response_with_options(
            blob_ref,
            options,
            &ClientRequestOptions::default(),
        )
        .await
    }

    pub async fn blob_download_response_with_options(
        &self,
        blob_ref: &BlobRef,
        options: &BlobDownloadOptions,
        request_options: &ClientRequestOptions,
    ) -> Result<reqwest::Response> {
        let mut builder = self
            .request(Method::GET, "/_arkret/self/blob/get")?
            .query(&[("blob_ref", blob_ref.as_str())]);
        if let Some(purpose) = options
            .purpose
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            builder = builder.query(&[("purpose", purpose)]);
        }
        if let Some(range) = options
            .range
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            validate_header_value("Range", range)?;
            builder = builder.header(RANGE, range);
        }
        let builder = self.apply_request_options(builder, request_options)?;
        self.send_response(builder).await
    }

    /// Download blob bytes. The body is read incrementally with the cap in
    /// [`BlobDownloadOptions::max_bytes`] so a hostile peer cannot materialize
    /// an unbounded or gzip-amplified body into memory.
    pub async fn blob_download_bytes(
        &self,
        blob_ref: &BlobRef,
        options: &BlobDownloadOptions,
    ) -> Result<Vec<u8>> {
        self.blob_download_bytes_with_options(blob_ref, options, &ClientRequestOptions::default())
            .await
    }

    pub async fn blob_download_bytes_with_options(
        &self,
        blob_ref: &BlobRef,
        options: &BlobDownloadOptions,
        request_options: &ClientRequestOptions,
    ) -> Result<Vec<u8>> {
        let limit = options.max_bytes;
        if limit == 0 {
            return Err(Error::Protocol(
                "blob download max_bytes must be greater than zero".to_owned(),
            ));
        }
        let response = self
            .blob_download_response_with_options(blob_ref, options, request_options)
            .await?;
        read_body_limited(response, limit).await
    }

    /// Drive one payload through a describe-discovered tus binding:
    /// create -> PATCH loop -> finalize. Any caller-level fallback to the
    /// canonical multipart upload should remain outside this primitive.
    pub async fn blob_upload_resumable(
        &self,
        base_url: Url,
        payload: &[u8],
        options: &BlobResumableUploadOptions,
    ) -> Result<BlobUploadOutcome> {
        if options.chunk_bytes == 0 {
            return Err(Error::Protocol(
                "resumable upload chunk_bytes must be greater than zero".to_owned(),
            ));
        }
        let upload_metadata = options
            .metadata
            .iter()
            .map(|(key, value)| format!("{key} {}", b64_metadata_value(value)))
            .collect::<Vec<_>>()
            .join(",");
        let create = self
            .execute(
                self.tus_request(Method::POST, base_url.clone())?
                    .header("tus-resumable", TUS_VERSION)
                    .header("upload-length", payload.len().to_string())
                    .header("upload-metadata", upload_metadata),
            )
            .await?;
        if create.status() != reqwest::StatusCode::CREATED {
            return Err(Error::Protocol(format!(
                "resumable upload create failed with status {}",
                create.status()
            )));
        }
        let location = create
            .headers()
            .get("location")
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| {
                Error::Protocol("resumable upload create returned no Location".to_owned())
            })?;
        let upload_url = base_url
            .join(location)
            .map_err(|error| Error::Protocol(format!("unresolvable upload Location: {error}")))?;
        if upload_url.origin() != base_url.origin() {
            return Err(Error::Protocol(
                "resumable upload Location changed origin".to_owned(),
            ));
        }

        let mut offset: usize = 0;
        let mut retries = 0usize;
        while offset < payload.len() {
            let end = (offset + options.chunk_bytes).min(payload.len());
            let chunk = payload[offset..end].to_vec();
            let patch = self
                .execute(
                    self.tus_request(Method::PATCH, upload_url.clone())?
                        .header("tus-resumable", TUS_VERSION)
                        .header("content-type", "application/offset+octet-stream")
                        .header("upload-offset", offset.to_string())
                        .body(chunk),
                )
                .await;
            let committed = match patch {
                Ok(response) if response.status() == reqwest::StatusCode::NO_CONTENT => response
                    .headers()
                    .get("upload-offset")
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<usize>().ok()),
                Ok(response)
                    if response.status() == reqwest::StatusCode::CONFLICT
                        || response.status() == reqwest::StatusCode::NOT_FOUND =>
                {
                    None
                }
                Ok(response) => {
                    return Err(Error::Protocol(format!(
                        "resumable chunk failed with status {}",
                        response.status()
                    )));
                }
                Err(_) => None,
            };
            match committed {
                Some(new_offset) if new_offset > offset => {
                    offset = new_offset;
                    retries = 0;
                }
                Some(_) => {
                    retries += 1;
                    if retries > options.max_chunk_retries {
                        return Err(Error::Protocol(
                            "resumable upload offset did not advance (server returned non-monotonic Upload-Offset)"
                                .to_owned(),
                        ));
                    }
                    offset = self.resumable_committed_offset(&upload_url).await?;
                }
                None => {
                    retries += 1;
                    if retries > options.max_chunk_retries {
                        return Err(Error::Protocol(
                            "resumable upload exceeded chunk retry budget".to_owned(),
                        ));
                    }
                    offset = self.resumable_committed_offset(&upload_url).await?;
                }
            }
        }

        let finalize_url = finalize_url_for(&upload_url)?;
        self.send_json(self.tus_request(Method::POST, finalize_url)?)
            .await
    }

    async fn resumable_committed_offset(&self, upload_url: &Url) -> Result<usize> {
        let response = self
            .execute(
                self.tus_request(Method::HEAD, upload_url.clone())?
                    .header("tus-resumable", TUS_VERSION),
            )
            .await?;
        if !response.status().is_success() {
            return Err(Error::Protocol(format!(
                "resumable upload resume probe failed with status {}",
                response.status()
            )));
        }
        response
            .headers()
            .get("upload-offset")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok())
            .ok_or_else(|| Error::Protocol("resume probe returned no Upload-Offset".to_owned()))
    }

    pub async fn keys_upload(&self, request: &KeysUploadRequestBody) -> Result<KeysUploadOutcome> {
        self.post("/_arkret/self/keys/upload", request).await
    }

    pub async fn keys_query(&self, request: &KeysQueryRequestBody) -> Result<KeysQueryOutcome> {
        self.post("/_arkret/self/keys/query", request).await
    }

    pub async fn keys_claim(&self, request: &KeysClaimRequestBody) -> Result<KeysClaimOutcome> {
        self.post("/_arkret/self/keys/claim", request).await
    }

    pub async fn keypackages_upload(
        &self,
        request: &KeyPackagesUploadRequestBody,
    ) -> Result<KeyPackagesUploadOutcome> {
        self.post("/_arkret/self/keys/keypackages/upload", request)
            .await
    }

    pub async fn keypackages_claim(
        &self,
        request: &KeyPackagesClaimRequestBody,
    ) -> Result<KeyPackagesClaimOutcome> {
        self.post("/_arkret/self/keys/keypackages/claim", request)
            .await
    }

    pub async fn keypackages_consume(
        &self,
        request: &KeyPackagesConsumeRequestBody,
    ) -> Result<KeyPackagesConsumeOutcome> {
        self.post("/_arkret/self/keys/keypackages/consume", request)
            .await
    }

    pub async fn keypackages_revoke(
        &self,
        request: &KeyPackagesRevokeRequestBody,
    ) -> Result<KeyPackagesRevokeOutcome> {
        self.post("/_arkret/self/keys/keypackages/revoke", request)
            .await
    }

    /// Upload (create or update) an encrypted [`KeyBackup`] envelope.
    /// Spec: `crypto-media/key-management.md` §7.2 +
    /// `sync/service-http-binding.md` §3 (PUT
    /// `/_arkret/self/keys/backups/{backup_id}`). The envelope's
    /// The caller owns the stable idempotency key and MUST reuse it only for
    /// byte-identical retries of the same backup body.
    pub(crate) async fn put_key_backup(
        &self,
        backup_id: &BackupId,
        body: &KeyBackup,
        idempotency_key: &str,
    ) -> Result<KeysBackupsReplaceOutcome> {
        let path = format!("/_arkret/self/keys/backups/{}", backup_id.as_str());
        let options = ClientRequestOptions::new().idempotency_key(idempotency_key);
        self.put_with_options(&path, body, &options).await
    }

    /// List existing key backups for the authorized actor. Honors the
    /// `series_id` / `backup_kind` / `cursor` / `limit` filters from
    /// [`KeyBackupsListQuery`] (key-management.md §7.5).
    pub async fn list_key_backups(&self, query: &KeyBackupsListQuery) -> Result<KeysBackupsList> {
        let mut builder = self.request(Method::GET, "/_arkret/self/keys/backups")?;
        if let Some(ref series_id) = query.series_id {
            builder = builder.query(&[("series_id", series_id.as_str())]);
        }
        if let Some(class) = query.backup_kind {
            builder = builder.query(&[("backup_kind", class.as_str())]);
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
                series_id: None,
                backup_kind: None,
                cursor: None,
                limit: None,
            })
            .await?;
        Ok(response.backups)
    }

    /// Unlock and fetch a single encrypted [`KeyBackup`] envelope for local
    /// decryption. The full ciphertext is returned only through the
    /// proof-bearing command body registered as
    /// `POST /_arkret/self/keys/backups/{backup_id}/unlock`.
    pub async fn unlock_key_backup(
        &self,
        backup_id: &BackupId,
        request: &KeysBackupsUnlockRequestBody,
    ) -> Result<KeyBackup> {
        let path = format!("/_arkret/self/keys/backups/{}/unlock", backup_id.as_str());
        self.post(&path, request).await
    }

    /// Ask the service to mint (or re-return) the single-use delete challenge a
    /// high-risk delete proof is bound to.
    ///
    /// `key-management.md` §7.8.1: freshness is issued by the service, and a
    /// caller-minted nonce is never accepted. While a challenge for the same
    /// `(principal_id, backup_id, request_id)` is still valid the service
    /// returns that same challenge, so a retry of this call does not invalidate
    /// a proof already signed against it; a different `request_id` mints a new
    /// one.
    pub async fn issue_key_backup_delete_challenge(
        &self,
        backup_id: &BackupId,
        request: &KeysBackupsIssueDeleteChallengeRequestBody,
    ) -> Result<KeysBackupsDeleteChallenge> {
        let path = format!(
            "/_arkret/self/keys/backups/{}/delete-challenge",
            backup_id.as_str()
        );
        self.post(&path, request).await
    }

    /// Delete an existing key backup envelope. Spec §7.8 marks this as a
    /// high-risk operation; the caller must supply the typed
    /// [`KeysBackupsDeleteRequestBody`] carrying the `challenge_id` obtained
    /// from [`issue_key_backup_delete_challenge`](Self::issue_key_backup_delete_challenge),
    /// the `request_id` both calls share, one of the three registered proof
    /// branches and (optionally) a human-readable reason.
    pub async fn delete_key_backup(
        &self,
        backup_id: &BackupId,
        request: &KeysBackupsDeleteRequestBody,
    ) -> Result<KeysBackupsDeleteOutcome> {
        let path = format!("/_arkret/self/keys/backups/{}", backup_id.as_str());
        self.delete_with_body(&path, request).await
    }

    /// Read one account-data entry.
    pub async fn account_data_get(&self, account_data_key: &str) -> Result<AccountDataRow> {
        reject_path_segment(account_data_key)?;
        self.get(&format!("/_arkret/self/account_data/{account_data_key}"))
            .await
    }

    /// Replace one account-data value with the holder-signed `ak.account_data.set`.
    ///
    /// `expected_revision`, the key and the value all live inside
    /// `set_event.event.payload`, so the CAS precondition is covered by the
    /// holder's signature rather than restated beside it.
    pub async fn account_data_replace(
        &self,
        account_data_key: &str,
        request: &AccountDataReplaceRequestBody,
    ) -> Result<AccountDataRow> {
        reject_path_segment(account_data_key)?;
        self.put(
            &format!("/_arkret/self/account_data/{account_data_key}"),
            request,
        )
        .await
    }

    /// Erase one account-data entry with the holder-signed tombstone.
    ///
    /// The DELETE carries a body because that is the only place the holder's
    /// signature can go; `delete_key_backup` above already shows a DELETE may
    /// carry one.
    pub async fn account_data_delete(
        &self,
        account_data_key: &str,
        request: &AccountDataDeleteRequestBody,
    ) -> Result<AccountDataDeleteOutcome> {
        reject_path_segment(account_data_key)?;
        let path = format!("/_arkret/self/account_data/{account_data_key}");
        let builder = self.canonical_json_body(self.request(Method::DELETE, &path)?, request)?;
        self.send_json(builder).await
    }

    pub async fn erase_backup_series(
        &self,
        request: &BackupSeriesEraseRequestBody,
    ) -> Result<BackupSeriesEraseOutcome> {
        let outcome: BackupSeriesEraseOutcome = self
            .post("/_arkret/self/keys/backup-series/erase", request)
            .await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }

    pub async fn send_device_messages(
        &self,
        idempotency_key: &str,
        request: &DeviceMessagesSendRequestBody,
    ) -> Result<DeviceMessagesSendOutcome> {
        let options = ClientRequestOptions::new().idempotency_key(idempotency_key);
        self.post_with_options("/_arkret/self/device_messages", request, &options)
            .await
    }

    pub async fn receive_device_messages(
        &self,
        from: Option<&str>,
        limit: Option<u32>,
    ) -> Result<DeviceMessagesGetOutcome> {
        let mut builder = self.request(Method::GET, "/_arkret/self/device_messages")?;
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
        self.post("/_arkret/self/device_messages/ack", request)
            .await
    }
}

fn finalize_url_for(upload_url: &Url) -> Result<Url> {
    let mut finalize_url = upload_url.clone();
    let path = format!("{}/finalize", finalize_url.path().trim_end_matches('/'));
    finalize_url.set_path(&path);
    finalize_url.set_query(None);
    Ok(finalize_url)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::ClientBuilder;

    #[test]
    fn resumable_metadata_values_use_standard_base64() {
        assert_eq!(b64_metadata_value("file_transfer"), "ZmlsZV90cmFuc2Zlcg==");
        assert_eq!(b64_metadata_value("true"), "dHJ1ZQ==");
    }

    #[test]
    fn resumable_upload_base_url_requires_feature_and_operation() {
        let mut description: ServiceDescribe = serde_json::from_value(json!({
            "protocol_version": "1.0",
            "service_kind": "principal_server",
            "service_id": "ak:did_core:web:server.local",
            "service_resolution": {
                "full_id": "did:web:server.local",
                "method_history_head": "sha256:fixture",
                "version_id": "fixture-v1"
            },
            "trust_domain": "ak:trust_domain:server.local",
            "supported_profiles": [],
            "supported_operations": [],
            "supported_bindings": [{
                "kind": "tus",
                "base_url": "https://server.local/uploads/",
                "operations": ["ak.self.blob.upload.create"]
            }],
            "supported_features": [RESUMABLE_UPLOAD_FEATURE],
            "auth_metadata": {"mode": "development", "methods": []},
            "limits": {},
            "plaintext_visibility": {"data_classes": [], "max_visibility": "none"},
            "implemented_features": [],
            "claimed_profiles": [],
            "verified_profiles": [],
            "experimental_features": [],
            "interop_surfaces": [],
            "development_mode": false,
            "rate_limit_policy": {}
        }))
        .unwrap();

        assert_eq!(
            blob_resumable_upload_base_url(&description)
                .map(|url| url.to_string())
                .as_deref(),
            Some("https://server.local/uploads/")
        );

        description.supported_features.clear();
        assert!(blob_resumable_upload_base_url(&description).is_none());
    }

    #[test]
    fn finalize_url_appends_path_segment_and_drops_query() {
        let upload_url = Url::parse("https://server.local/uploads/abc?token=bad").unwrap();
        assert_eq!(
            finalize_url_for(&upload_url).unwrap().as_str(),
            "https://server.local/uploads/abc/finalize"
        );
    }

    #[test]
    fn resumable_requests_reject_cross_origin_and_unapproved_plaintext_localhost() {
        let client = ClientBuilder::new(Url::parse("https://server.local/").unwrap())
            .build()
            .unwrap();
        assert!(
            client
                .tus_request(
                    Method::POST,
                    Url::parse("https://attacker.example/uploads").unwrap(),
                )
                .is_err()
        );
        assert!(
            client
                .tus_request(
                    Method::POST,
                    Url::parse("http://127.0.0.1:9999/uploads").unwrap(),
                )
                .is_err()
        );

        let local = ClientBuilder::new(Url::parse("http://127.0.0.1:8787/").unwrap())
            .allow_insecure_localhost()
            .build()
            .unwrap();
        assert!(
            local
                .tus_request(
                    Method::POST,
                    Url::parse("http://127.0.0.1:8787/uploads").unwrap(),
                )
                .is_ok()
        );
    }
}
