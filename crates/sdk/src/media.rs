//! Media, blob and attachment helpers.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{AEAD_ALGORITHM, BlobRef, Did, Error, Result, SpaceId, crypto};

/// Stored media metadata.
///
/// `space_id` is the Space anchor used by `media-and-blob.md` §5 to scope
/// download authorization and garbage-collect blobs when a Space is
/// dissolved or migrated. It is `None` only for genuinely global blobs
/// (e.g. a public organization avatar) — those callers MUST guarantee the
/// blob does not contain Space-private content.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaMetadata {
    /// Blob reference.
    pub blob_ref: BlobRef,
    /// SHA-256 digest.
    pub sha256: String,
    /// Size in bytes.
    pub size: u64,
    /// Media type.
    pub media_type: String,
    /// Optional filename.
    pub filename: Option<String>,
    /// Uploading user.
    pub uploaded_by: Did,
    /// Upload time.
    pub uploaded_at: DateTime<Utc>,
    /// Space anchor for download authorization and GC (B-23,
    /// `media-and-blob.md` §2). `None` only for global blobs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space_id: Option<SpaceId>,
}

/// Thumbnail metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Thumbnail {
    /// Thumbnail blob reference.
    pub blob_ref: BlobRef,
    /// Source blob reference.
    pub source_blob_ref: BlobRef,
    /// Thumbnail media type.
    pub media_type: String,
    /// Maximum width requested.
    pub width: u32,
    /// Maximum height requested.
    pub height: u32,
    /// Thumbnail size in bytes.
    pub size: u64,
}

/// Attachment metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attachment {
    /// Attachment ID.
    pub id: String,
    /// Blob reference.
    pub blob_ref: BlobRef,
    /// Filename.
    pub filename: String,
    /// Media type.
    pub media_type: String,
    /// Plaintext size for encrypted attachments, blob size otherwise.
    pub size: u64,
    /// Encryption metadata if stored encrypted.
    pub encryption: Option<EncryptedAttachment>,
}

/// Encrypted attachment envelope metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedAttachment {
    /// Algorithm identifier for the local envelope.
    pub algorithm: String,
    /// Key digest for matching restore keys.
    pub key_sha256: String,
    /// Plaintext SHA-256 digest.
    pub plaintext_sha256: String,
}

/// Authenticated download grant scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DownloadGrantScope {
    Blob,
    Attachment,
}

/// Time- and use-bound grant for authenticated blob downloads.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedDownloadGrant {
    pub grant_id: String,
    pub blob_ref: BlobRef,
    pub subject: Did,
    pub issuer: Did,
    pub scope: DownloadGrantScope,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub max_uses: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
}

impl AuthenticatedDownloadGrant {
    /// Validate the grant against a caller, target blob and observed use count.
    pub fn validate(
        &self,
        subject: &Did,
        blob_ref: &BlobRef,
        at: DateTime<Utc>,
        uses: u32,
    ) -> Result<()> {
        if &self.subject != subject {
            return Err(Error::Protocol("download grant subject mismatch".to_owned()));
        }
        if &self.blob_ref != blob_ref {
            return Err(Error::Protocol("download grant blob mismatch".to_owned()));
        }
        if at > self.expires_at {
            return Err(Error::Protocol("download grant expired".to_owned()));
        }
        if let Some(max_uses) = self.max_uses
            && uses >= max_uses
        {
            return Err(Error::Protocol("download grant use limit exceeded".to_owned()));
        }
        Ok(())
    }
}

/// In-memory blob and media store.
#[derive(Clone, Debug, Default)]
pub struct MemoryBlobStore {
    blobs: BTreeMap<BlobRef, Vec<u8>>,
    metadata: BTreeMap<BlobRef, MediaMetadata>,
    thumbnails: BTreeMap<BlobRef, Thumbnail>,
    attachments: BTreeMap<String, Attachment>,
    download_grants: BTreeMap<String, AuthenticatedDownloadGrant>,
    download_grant_uses: BTreeMap<String, u32>,
}

impl MemoryBlobStore {
    /// Create an empty blob store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Upload bytes and return metadata.
    pub fn upload(
        &mut self,
        bytes: impl AsRef<[u8]>,
        media_type: impl Into<String>,
        filename: Option<String>,
        uploaded_by: Did,
    ) -> Result<MediaMetadata> {
        self.upload_in_space(bytes, media_type, filename, uploaded_by, None)
    }

    /// Upload bytes scoped to a Space — preferred when the blob is private
    /// to that Space so it can be GC'd on Space migration / dissolution.
    pub fn upload_in_space(
        &mut self,
        bytes: impl AsRef<[u8]>,
        media_type: impl Into<String>,
        filename: Option<String>,
        uploaded_by: Did,
        space_id: Option<SpaceId>,
    ) -> Result<MediaMetadata> {
        let bytes = bytes.as_ref();
        let blob_ref = blob_ref_for(bytes)?;
        let metadata = MediaMetadata {
            blob_ref: blob_ref.clone(),
            sha256: sha256_hex(bytes),
            size: bytes.len() as u64,
            media_type: media_type.into(),
            filename,
            uploaded_by,
            uploaded_at: Utc::now(),
            space_id,
        };
        self.blobs.insert(blob_ref.clone(), bytes.to_vec());
        self.metadata.insert(blob_ref, metadata.clone());
        Ok(metadata)
    }

    /// Download bytes by blob reference.
    pub fn download(&self, blob_ref: &BlobRef) -> Option<&[u8]> {
        self.blobs.get(blob_ref).map(Vec::as_slice)
    }

    /// Get metadata by blob reference.
    pub fn metadata(&self, blob_ref: &BlobRef) -> Option<&MediaMetadata> {
        self.metadata.get(blob_ref)
    }

    /// Generate and store a lightweight thumbnail preview.
    ///
    /// This does not decode image pixels. It creates a deterministic preview
    /// blob from the first bytes and requested dimensions, which is enough for
    /// clients to cache and later replace with a platform image pipeline.
    pub fn generate_thumbnail(
        &mut self,
        source_blob_ref: &BlobRef,
        width: u32,
        height: u32,
    ) -> Result<Thumbnail> {
        let source = self
            .blobs
            .get(source_blob_ref)
            .ok_or_else(|| Error::Protocol("source blob not found".to_owned()))?;
        let mut preview = format!("thumbnail:{width}x{height}:").into_bytes();
        preview.extend(source.iter().take(256));
        let blob_ref = blob_ref_for(&preview)?;
        self.blobs.insert(blob_ref.clone(), preview.clone());

        let thumbnail = Thumbnail {
            blob_ref,
            source_blob_ref: source_blob_ref.clone(),
            media_type: "image/preview".to_owned(),
            width,
            height,
            size: preview.len() as u64,
        };
        self.thumbnails.insert(source_blob_ref.clone(), thumbnail.clone());
        Ok(thumbnail)
    }

    /// Get the generated thumbnail for a source blob.
    pub fn thumbnail(&self, source_blob_ref: &BlobRef) -> Option<&Thumbnail> {
        self.thumbnails.get(source_blob_ref)
    }

    /// Upload an attachment.
    pub fn upload_attachment(
        &mut self,
        id: impl Into<String>,
        filename: impl Into<String>,
        media_type: impl Into<String>,
        bytes: impl AsRef<[u8]>,
        uploaded_by: Did,
    ) -> Result<Attachment> {
        let filename = filename.into();
        let media_type = media_type.into();
        let metadata =
            self.upload(bytes.as_ref(), media_type.clone(), Some(filename.clone()), uploaded_by)?;
        let attachment = Attachment {
            id: id.into(),
            blob_ref: metadata.blob_ref,
            filename,
            media_type,
            size: metadata.size,
            encryption: None,
        };
        self.attachments.insert(attachment.id.clone(), attachment.clone());
        Ok(attachment)
    }

    /// Download attachment bytes.
    pub fn download_attachment(&self, id: &str) -> Option<&[u8]> {
        self.attachments.get(id).and_then(|attachment| self.download(&attachment.blob_ref))
    }

    /// Upload an encrypted attachment using authenticated encryption.
    pub fn upload_encrypted_attachment(
        &mut self,
        id: impl Into<String>,
        filename: impl Into<String>,
        media_type: impl Into<String>,
        plaintext: impl AsRef<[u8]>,
        key: &[u8],
        uploaded_by: Did,
    ) -> Result<Attachment> {
        let plaintext = plaintext.as_ref();
        let ciphertext = crypto::seal(plaintext, key, b"contrix-media-attachment-v1")?;
        let filename = filename.into();
        let media_type = media_type.into();
        let metadata = self.upload(
            &ciphertext,
            "application/octet-stream",
            Some(filename.clone()),
            uploaded_by,
        )?;
        let attachment = Attachment {
            id: id.into(),
            blob_ref: metadata.blob_ref,
            filename,
            media_type,
            size: plaintext.len() as u64,
            encryption: Some(EncryptedAttachment {
                algorithm: AEAD_ALGORITHM.to_owned(),
                key_sha256: sha256_hex(key),
                plaintext_sha256: sha256_hex(plaintext),
            }),
        };
        self.attachments.insert(attachment.id.clone(), attachment.clone());
        Ok(attachment)
    }

    /// Download and decrypt an encrypted attachment.
    pub fn download_decrypted_attachment(&self, id: &str, key: &[u8]) -> Result<Vec<u8>> {
        let attachment = self
            .attachments
            .get(id)
            .ok_or_else(|| Error::Protocol("attachment not found".to_owned()))?;
        let encryption = attachment
            .encryption
            .as_ref()
            .ok_or_else(|| Error::Protocol("attachment is not encrypted".to_owned()))?;
        if encryption.key_sha256 != sha256_hex(key) {
            return Err(Error::Protocol("attachment key mismatch".to_owned()));
        }
        let ciphertext = self
            .download(&attachment.blob_ref)
            .ok_or_else(|| Error::Protocol("attachment blob not found".to_owned()))?;
        if encryption.algorithm != AEAD_ALGORITHM {
            return Err(Error::Protocol("unsupported attachment encryption algorithm".to_owned()));
        }
        let plaintext = crypto::open(ciphertext, key, b"contrix-media-attachment-v1")?;
        if encryption.plaintext_sha256 != sha256_hex(&plaintext) {
            return Err(Error::Protocol("attachment digest mismatch".to_owned()));
        }
        Ok(plaintext)
    }

    /// Get an attachment by ID.
    pub fn attachment(&self, id: &str) -> Option<&Attachment> {
        self.attachments.get(id)
    }

    /// Remove an attachment by ID. Returns `true` if the attachment existed.
    pub fn remove_attachment(&mut self, id: &str) -> bool {
        self.attachments.remove(id).is_some()
    }

    /// Return the number of stored attachments.
    pub fn attachment_count(&self) -> usize {
        self.attachments.len()
    }

    /// Iterate over all stored attachments.
    pub fn all_attachments(&self) -> impl Iterator<Item = &Attachment> {
        self.attachments.values()
    }

    /// Issue an authenticated download grant for an existing blob.
    pub fn issue_download_grant(
        &mut self,
        grant_id: impl Into<String>,
        blob_ref: BlobRef,
        subject: Did,
        issuer: Did,
        expires_at: DateTime<Utc>,
        max_uses: Option<u32>,
    ) -> Result<AuthenticatedDownloadGrant> {
        if !self.blobs.contains_key(&blob_ref) {
            return Err(Error::Protocol("download grant target blob not found".to_owned()));
        }
        if expires_at <= Utc::now() {
            return Err(Error::Protocol("download grant expires in the past".to_owned()));
        }
        let grant = AuthenticatedDownloadGrant {
            grant_id: grant_id.into(),
            blob_ref,
            subject,
            issuer,
            scope: DownloadGrantScope::Blob,
            issued_at: Utc::now(),
            expires_at,
            max_uses,
            proof: None,
        };
        self.download_grant_uses.insert(grant.grant_id.clone(), 0);
        self.download_grants.insert(grant.grant_id.clone(), grant.clone());
        Ok(grant)
    }

    /// Download blob bytes through an authenticated grant.
    pub fn download_with_grant(
        &mut self,
        grant_id: &str,
        subject: &Did,
        at: DateTime<Utc>,
    ) -> Result<&[u8]> {
        let grant = self
            .download_grants
            .get(grant_id)
            .cloned()
            .ok_or_else(|| Error::Protocol("download grant not found".to_owned()))?;
        let uses = self.download_grant_uses.get(grant_id).copied().unwrap_or_default();
        grant.validate(subject, &grant.blob_ref, at, uses)?;
        *self.download_grant_uses.entry(grant_id.to_owned()).or_default() += 1;
        self.download(&grant.blob_ref)
            .ok_or_else(|| Error::Protocol("download grant target blob not found".to_owned()))
    }

    /// Get a stored authenticated download grant.
    pub fn download_grant(&self, grant_id: &str) -> Option<&AuthenticatedDownloadGrant> {
        self.download_grants.get(grant_id)
    }
}

/// Sanitize a media type for safe `Content-Type` headers.
///
/// Strips parameters, validates the `type/subtype` form, and lowercases.
/// Returns `None` for obviously invalid or injection-prone values.
pub fn safe_content_type(media_type: &str) -> Option<String> {
    let trimmed = media_type.trim().split(';').next()?.trim().to_ascii_lowercase();
    let (type_part, subtype_part) = trimmed.split_once('/')?;
    if type_part.is_empty()
        || subtype_part.is_empty()
        || !type_part.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(b, b'!' | b'#' | b'$' | b'&' | b'.' | b'+' | b'-' | b'^' | b'_')
        })
        || !subtype_part.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(b, b'!' | b'#' | b'$' | b'&' | b'.' | b'+' | b'-' | b'^' | b'_')
        })
        || trimmed.contains('\n')
        || trimmed.contains('\r')
        || trimmed.contains('\0')
    {
        return None;
    }
    Some(trimmed)
}

/// Build a safe `Content-Disposition: attachment` header value.
///
/// The filename is percent-encoded to prevent header injection. Falls back to
/// `file.bin` if the name is empty or contains only unsafe characters.
pub fn safe_content_disposition(filename: &str) -> String {
    let sanitized: String =
        filename.chars().filter(|c| !matches!(c, '\n' | '\r' | '\0' | '"' | '\\')).collect();
    let sanitized = sanitized.trim();
    if sanitized.is_empty() {
        return "attachment; filename=\"file.bin\"".to_owned();
    }
    let encoded: String = sanitized
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c.to_string()
            } else {
                format!("%{:02X}", c as u32)
            }
        })
        .collect();
    format!("attachment; filename=\"{encoded}\"")
}

fn blob_ref_for(bytes: &[u8]) -> Result<BlobRef> {
    Ok(BlobRef::new(format!("sha256:{}", sha256_hex(bytes)))?)
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:web:{name}.example")).unwrap()
    }

    #[test]
    fn media_uploads_downloads_metadata_and_thumbnail() {
        let mut store = MemoryBlobStore::new();
        let metadata = store
            .upload(b"image-bytes", "image/png", Some("a.png".to_owned()), did("alice"))
            .unwrap();

        assert_eq!(store.download(&metadata.blob_ref), Some(&b"image-bytes"[..]));
        assert_eq!(store.metadata(&metadata.blob_ref).unwrap().media_type, "image/png");

        let thumbnail = store.generate_thumbnail(&metadata.blob_ref, 64, 64).unwrap();
        assert_eq!(thumbnail.source_blob_ref, metadata.blob_ref);
        assert!(store.thumbnail(&thumbnail.source_blob_ref).is_some());
    }

    #[test]
    fn media_uploads_downloads_and_encrypts_attachments() {
        let mut store = MemoryBlobStore::new();
        let attachment = store
            .upload_attachment("a1", "note.txt", "text/plain", b"hello", did("alice"))
            .unwrap();
        assert_eq!(attachment.size, 5);
        assert_eq!(store.download_attachment("a1"), Some(&b"hello"[..]));

        let encrypted = store
            .upload_encrypted_attachment(
                "a2",
                "secret.txt",
                "text/plain",
                b"secret",
                b"key",
                did("alice"),
            )
            .unwrap();
        assert!(encrypted.encryption.is_some());
        assert_ne!(store.download_attachment("a2"), Some(&b"secret"[..]));
        assert_eq!(store.download_decrypted_attachment("a2", b"key").unwrap(), b"secret");
        assert!(store.download_decrypted_attachment("a2", b"wrong").is_err());
    }

    #[test]
    fn media_remove_attachment_and_count() {
        let mut store = MemoryBlobStore::new();
        store.upload_attachment("a1", "file.txt", "text/plain", b"data", did("alice")).unwrap();
        store.upload_attachment("a2", "img.png", "image/png", b"png", did("bob")).unwrap();
        assert_eq!(store.attachment_count(), 2);

        assert!(store.remove_attachment("a1"));
        assert_eq!(store.attachment_count(), 1);
        assert!(store.attachment("a1").is_none());
        assert!(!store.remove_attachment("a1"));

        let all: Vec<_> = store.all_attachments().map(|a| a.id.as_str()).collect();
        assert_eq!(all, vec!["a2"]);
    }

    #[test]
    fn media_download_grants_validate_subject_expiry_and_use_limit() {
        let mut store = MemoryBlobStore::new();
        let metadata = store
            .upload(b"download", "text/plain", Some("d.txt".to_owned()), did("alice"))
            .unwrap();
        let expires_at = Utc::now() + chrono::Duration::minutes(5);
        let subject = did("bob");
        let grant = store
            .issue_download_grant(
                "grant1",
                metadata.blob_ref.clone(),
                subject.clone(),
                did("alice"),
                expires_at,
                Some(1),
            )
            .unwrap();

        assert_eq!(store.download_grant("grant1"), Some(&grant));
        assert_eq!(
            store.download_with_grant("grant1", &subject, Utc::now()).unwrap(),
            &b"download"[..]
        );
        assert!(store.download_with_grant("grant1", &subject, Utc::now()).is_err());
        assert!(grant.validate(&did("mallory"), &metadata.blob_ref, Utc::now(), 0).is_err());
        assert!(
            grant
                .validate(
                    &subject,
                    &metadata.blob_ref,
                    Utc::now() + chrono::Duration::minutes(10),
                    0,
                )
                .is_err()
        );
    }

    #[test]
    fn safe_content_type_validates_and_lowercases() {
        assert_eq!(safe_content_type("text/plain"), Some("text/plain".to_owned()));
        assert_eq!(safe_content_type("Image/PNG; charset=utf-8"), Some("image/png".to_owned()));
        assert_eq!(safe_content_type("  application/json  "), Some("application/json".to_owned()));
        assert!(safe_content_type("not-a-mime-type").is_none());
        assert!(safe_content_type("").is_none());
        assert!(safe_content_type("text/").is_none());
        assert!(safe_content_type("/plain").is_none());
        assert!(safe_content_type("text/plain\nX-Injected: evil").is_none());
    }

    #[test]
    fn safe_content_disposition_encodes_unsafe_chars() {
        assert_eq!(safe_content_disposition("report.pdf"), "attachment; filename=\"report.pdf\"");
        assert_eq!(
            safe_content_disposition("my file (1).txt"),
            "attachment; filename=\"my%20file%20%281%29.txt\""
        );
        assert_eq!(safe_content_disposition(""), "attachment; filename=\"file.bin\"");
        assert!(safe_content_disposition("file\nname.txt").contains("file"));
    }
}
