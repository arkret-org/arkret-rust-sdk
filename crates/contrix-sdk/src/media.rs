//! Media, blob and attachment helpers.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{BlobRef, Did, Error, Result};

/// Stored media metadata.
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

/// In-memory blob and media store.
#[derive(Clone, Debug, Default)]
pub struct MemoryBlobStore {
    blobs: BTreeMap<BlobRef, Vec<u8>>,
    metadata: BTreeMap<BlobRef, MediaMetadata>,
    thumbnails: BTreeMap<BlobRef, Thumbnail>,
    attachments: BTreeMap<String, Attachment>,
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
            blob_ref: blob_ref.clone(),
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

    /// Upload an encrypted attachment using a deterministic local XOR stream.
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
        let ciphertext = xor_sha256_stream(plaintext, key);
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
                algorithm: "xorsha256.v1".to_owned(),
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
        let plaintext = xor_sha256_stream(ciphertext, key);
        if encryption.plaintext_sha256 != sha256_hex(&plaintext) {
            return Err(Error::Protocol("attachment digest mismatch".to_owned()));
        }
        Ok(plaintext)
    }

    /// Get an attachment by ID.
    pub fn attachment(&self, id: &str) -> Option<&Attachment> {
        self.attachments.get(id)
    }
}

fn blob_ref_for(bytes: &[u8]) -> Result<BlobRef> {
    BlobRef::new(format!("sha256:{}", sha256_hex(bytes)))
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn xor_sha256_stream(input: &[u8], key: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len());
    let mut counter = 0u64;
    for chunk in input.chunks(32) {
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.update(counter.to_le_bytes());
        let stream = hasher.finalize();
        for (index, byte) in chunk.iter().enumerate() {
            output.push(byte ^ stream[index]);
        }
        counter += 1;
    }
    output
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
}
