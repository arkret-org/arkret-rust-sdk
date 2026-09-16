//! File-transfer AEAD transcripts (models/file-transfer.md section 4).

use arkret_canonical::base64url::base64url_decode;
use arkret_canonical::canonical::canonical_json_bytes;
use arkret_models_collaboration::objects::productivity::{
    FileTransferEncryption, FileTransferRecord,
};
use arkret_models_crypto::stream_segment_count;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde_json::json;

use crate::{Error, Result};

const AEAD_TAG_LEN: u64 = 16;

/// Locally-derived ciphertext geometry for one file-transfer segment.
///
/// This is not a wire type. The authenticated record remains the only source
/// of `plaintext_size_bytes` and `segment_bytes`; callers use this derived
/// value solely to issue an exact HTTP byte-range request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileTransferSegment {
    pub index: u32,
    pub count: u32,
    pub ciphertext_start: u64,
    pub ciphertext_end: u64,
    pub ciphertext_len: usize,
    pub plaintext_len: usize,
}

fn invalid(message: impl Into<String>) -> Error {
    Error::Protocol(message.into())
}

fn transcript(
    encryption: &FileTransferEncryption,
    media_type: &str,
    size: u64,
    index: u32,
) -> Result<([u8; 24], Vec<u8>, usize)> {
    let mut nonce = [0; 24];
    if let Some(segment_bytes) = encryption.segment_bytes {
        let count =
            stream_segment_count(size, segment_bytes).map_err(|e| invalid(e.to_string()))?;
        if index >= count {
            return Err(invalid("segment_bounds_invalid"));
        }
        let prefix = encryption
            .nonce_prefix
            .as_deref()
            .ok_or_else(|| invalid("missing nonce_prefix"))?;
        let decoded = base64url_decode(prefix).map_err(|e| invalid(e.to_string()))?;
        if decoded.len() != 19 {
            return Err(invalid("invalid nonce_prefix length"));
        }
        nonce[..19].copy_from_slice(&decoded);
        nonce[19..23].copy_from_slice(&index.to_be_bytes());
        nonce[23] = u8::from(index == count - 1);
        let mut aad = serde_json::to_value(&encryption.aad).map_err(|e| invalid(e.to_string()))?;
        let object = aad
            .as_object_mut()
            .ok_or_else(|| invalid("invalid file-transfer AAD"))?;
        object.extend([
            ("scheme".into(), json!(encryption.scheme)),
            ("nonce_prefix".into(), json!(prefix)),
            ("segment_index".into(), json!(index)),
            ("last_segment_flag".into(), json!(nonce[23])),
            ("segment_count".into(), json!(count)),
            ("media_type".into(), json!(media_type)),
            ("size_bytes".into(), json!(size)),
        ]);
        let length = (size - u64::from(index) * u64::from(segment_bytes))
            .min(u64::from(segment_bytes)) as usize;
        Ok((nonce, canonical_json_bytes(&aad)?, length))
    } else {
        let encoded = encryption
            .nonce
            .as_deref()
            .ok_or_else(|| invalid("missing nonce"))?;
        let decoded = base64url_decode(encoded).map_err(|e| invalid(e.to_string()))?;
        if decoded.len() != nonce.len() || index != 0 {
            return Err(invalid("invalid whole-file nonce or index"));
        }
        nonce.copy_from_slice(&decoded);
        Ok((
            nonce,
            canonical_json_bytes(&encryption.aad)?,
            usize::try_from(size).map_err(|_| invalid("file too large"))?,
        ))
    }
}

/// Validate the authenticated record geometry and derive its segment count.
///
/// Both stream and whole-file records use the same `plaintext + 16-byte tag
/// per segment` stored-object length rule. Validating it before any range
/// request prevents an attacker-controlled record from driving an invalid
/// download plan.
pub fn segment_count(record: &FileTransferRecord) -> Result<u32> {
    record.validate().map_err(|e| invalid(e.to_string()))?;
    let count = record
        .encryption
        .segment_bytes
        .map(|bytes| stream_segment_count(record.plaintext_size_bytes, bytes))
        .transpose()
        .map_err(|e| invalid(e.to_string()))?
        .unwrap_or(1);
    let expected = record
        .plaintext_size_bytes
        .checked_add(u64::from(count) * AEAD_TAG_LEN)
        .ok_or_else(|| invalid("segment_bounds_invalid"))?;
    if expected != record.blob_size_bytes {
        return Err(invalid(
            "segment_stream_truncated: unexpected ciphertext length",
        ));
    }
    Ok(count)
}

/// Derive the exact inclusive ciphertext byte range for one segment.
pub fn segment(record: &FileTransferRecord, index: u32) -> Result<FileTransferSegment> {
    let count = segment_count(record)?;
    if index >= count {
        return Err(invalid("segment_bounds_invalid"));
    }
    let nominal_plaintext_len = record
        .encryption
        .segment_bytes
        .map(u64::from)
        .unwrap_or(record.plaintext_size_bytes);
    let plaintext_start = u64::from(index)
        .checked_mul(nominal_plaintext_len)
        .ok_or_else(|| invalid("segment_bounds_invalid"))?;
    let plaintext_len = record
        .plaintext_size_bytes
        .checked_sub(plaintext_start)
        .ok_or_else(|| invalid("segment_bounds_invalid"))?
        .min(nominal_plaintext_len);
    let ciphertext_start = plaintext_start
        .checked_add(u64::from(index) * AEAD_TAG_LEN)
        .ok_or_else(|| invalid("segment_bounds_invalid"))?;
    let ciphertext_len = plaintext_len
        .checked_add(AEAD_TAG_LEN)
        .ok_or_else(|| invalid("segment_bounds_invalid"))?;
    let ciphertext_end = ciphertext_start
        .checked_add(ciphertext_len)
        .and_then(|value| value.checked_sub(1))
        .ok_or_else(|| invalid("segment_bounds_invalid"))?;
    Ok(FileTransferSegment {
        index,
        count,
        ciphertext_start,
        ciphertext_end,
        ciphertext_len: usize::try_from(ciphertext_len)
            .map_err(|_| invalid("segment_bounds_invalid"))?,
        plaintext_len: usize::try_from(plaintext_len)
            .map_err(|_| invalid("segment_bounds_invalid"))?,
    })
}

/// Authenticate and open one exact segment from a file-transfer record.
///
/// The caller must still verify the complete concatenated ciphertext digest
/// before committing a persisted output. A successfully opened segment may be
/// sent to a transactional sink or progressive consumer as allowed by the
/// file-transfer streaming contract.
pub fn decrypt_segment(
    record: &FileTransferRecord,
    index: u32,
    ciphertext: &[u8],
    content_key: &[u8; 32],
) -> Result<Vec<u8>> {
    let plan = segment(record, index)?;
    if ciphertext.len() != plan.ciphertext_len {
        return Err(invalid("segment_bounds_invalid"));
    }
    let (nonce, aad, plaintext_len) = transcript(
        &record.encryption,
        &record.media_type,
        record.plaintext_size_bytes,
        index,
    )?;
    if plaintext_len != plan.plaintext_len {
        return Err(invalid("segment_bounds_invalid"));
    }
    XChaCha20Poly1305::new(content_key.into())
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| invalid("segment_aead_failed"))
}

/// Encrypt an immutable descriptor; its Blob digest is computed only afterwards.
pub fn encrypt(
    encryption: &FileTransferEncryption,
    media_type: &str,
    plaintext: &[u8],
    content_key: &[u8; 32],
) -> Result<Vec<u8>> {
    encryption.validate().map_err(|e| invalid(e.to_string()))?;
    let size = plaintext.len() as u64;
    let count = encryption
        .segment_bytes
        .map(|bytes| stream_segment_count(size, bytes))
        .transpose()
        .map_err(|e| invalid(e.to_string()))?
        .unwrap_or(1);
    let cipher = XChaCha20Poly1305::new(content_key.into());
    let mut ciphertext = Vec::new();
    let mut offset = 0;
    for index in 0..count {
        let (nonce, aad, length) = transcript(encryption, media_type, size, index)?;
        let segment = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &plaintext[offset..offset + length],
                    aad: &aad,
                },
            )
            .map_err(|_| invalid("file-transfer encryption failed"))?;
        ciphertext.extend_from_slice(&segment);
        offset += length;
    }
    Ok(ciphertext)
}

/// Authenticate the entire stored object before releasing plaintext to callers.
pub fn decrypt(
    record: &FileTransferRecord,
    ciphertext: &[u8],
    content_key: &[u8; 32],
) -> Result<Vec<u8>> {
    record.validate().map_err(|e| invalid(e.to_string()))?;
    let content_digest = record
        .blob_ref
        .strip_prefix("ak:blob:")
        .ok_or_else(|| invalid("file-transfer blob_ref is not content-addressed"))?;
    let (suite, _) = content_digest
        .split_once(':')
        .ok_or_else(|| invalid("unsupported content digest"))?;
    if arkret_canonical::canonical::digest_with_suite(suite, ciphertext)? != content_digest
        || ciphertext.len() as u64 != record.blob_size_bytes
    {
        return Err(invalid("digest_mismatch"));
    }
    let count = segment_count(record)?;
    let capacity =
        usize::try_from(record.plaintext_size_bytes).map_err(|_| invalid("file too large"))?;
    let mut plaintext = Vec::with_capacity(capacity);
    for index in 0..count {
        let plan = segment(record, index)?;
        let start = usize::try_from(plan.ciphertext_start)
            .map_err(|_| invalid("segment_bounds_invalid"))?;
        let end = start
            .checked_add(plan.ciphertext_len)
            .ok_or_else(|| invalid("segment_bounds_invalid"))?;
        let opened = decrypt_segment(record, index, &ciphertext[start..end], content_key)?;
        plaintext.extend_from_slice(&opened);
    }
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use arkret_canonical::base64url::base64url_encode;
    use serde_json::Value;

    use super::*;

    fn descriptor() -> FileTransferEncryption {
        serde_json::from_value(json!({
            "scheme": "ak.blob.stream_aead.v1",
            "aead_profile": "ak.aead.xchacha20_poly1305.v1",
            "nonce_prefix": base64url_encode(&[0; 19]), "segment_bytes": 1024,
            "aad": {"schema": "ak.schema.file_transfer.v1", "purpose": "file_transfer",
                "transfer_id": "0123456789abcdefghijkl",
                "origin_device_id": "ak:device:01904100-0000-7000-8000-000000000001",
                "created_at": "2026-08-31T00:00:00.000Z"},
            "key_delivery": {"method": "account_data_wrapped_key", "content_key": base64url_encode(&[7; 32])}
        })).unwrap()
    }

    fn transfer_record(
        encryption: FileTransferEncryption,
        size: usize,
        ciphertext: &[u8],
    ) -> FileTransferRecord {
        let digest = arkret_canonical::canonical::digest_with_suite("sha256", ciphertext).unwrap();
        serde_json::from_value(json!({
            "kind": "file_transfer", "transfer_id": encryption.aad.transfer_id,
            "blob_ref": format!("ak:blob:{digest}"),
            "blob_size_bytes": ciphertext.len(), "media_type": "text/plain",
            "plaintext_size_bytes": size, "access": {"visibility": "actor_private"},
            "origin_device_id": encryption.aad.origin_device_id,
            "created_at": encryption.aad.created_at, "updated_hlc": "01970e589d21-0004-a13f9c2e",
            "retention_expires_at": "2026-09-01T00:00:00.000Z", "status": "available",
            "encryption": encryption,
        }))
        .unwrap()
    }

    #[test]
    fn empty_stream_transcript_is_exact_and_has_one_authenticated_segment() {
        let encryption = descriptor();
        let (nonce, aad, length) = transcript(&encryption, "text/plain", 0, 0).unwrap();
        let mut expected_nonce = [0; 24];
        expected_nonce[23] = 1;
        assert_eq!(nonce, expected_nonce);
        assert_eq!(length, 0);
        let expected_aad = br#"{"created_at":"2026-08-31T00:00:00.000Z","last_segment_flag":1,"media_type":"text/plain","nonce_prefix":"AAAAAAAAAAAAAAAAAAAAAAAAAA","origin_device_id":"ak:device:01904100-0000-7000-8000-000000000001","purpose":"file_transfer","schema":"ak.schema.file_transfer.v1","scheme":"ak.blob.stream_aead.v1","segment_count":1,"segment_index":0,"size_bytes":0,"transfer_id":"0123456789abcdefghijkl"}"#;
        assert_eq!(aad, expected_aad);
        let independently_sealed = XChaCha20Poly1305::new((&[7; 32]).into())
            .encrypt(
                &XNonce::from(expected_nonce),
                Payload {
                    msg: &[],
                    aad: expected_aad,
                },
            )
            .unwrap();
        assert_eq!(
            encrypt(&encryption, "text/plain", &[], &[7; 32]).unwrap(),
            independently_sealed
        );
        assert_eq!(independently_sealed.len(), 16);
    }

    #[test]
    fn stream_boundaries_round_trip_and_reject_tampered_authenticated_geometry() {
        for size in [0, 1, 1024, 1025, 2048, 2049] {
            let plaintext = vec![42; size];
            let encryption = descriptor();
            let ciphertext = encrypt(&encryption, "text/plain", &plaintext, &[7; 32]).unwrap();
            let record = transfer_record(encryption.clone(), size, &ciphertext);
            assert_eq!(decrypt(&record, &ciphertext, &[7; 32]).unwrap(), plaintext);
            assert!(decrypt(&record, &ciphertext, &[8; 32]).is_err());
            let mut changed = record.clone();
            changed.plaintext_size_bytes += 1;
            assert!(decrypt(&changed, &ciphertext, &[7; 32]).is_err());
            changed = record.clone();
            changed.media_type = "application/octet-stream".into();
            assert!(decrypt(&changed, &ciphertext, &[7; 32]).is_err());
            let mut tampered = ciphertext.clone();
            tampered[0] ^= 1;
            assert!(decrypt(&record, &tampered, &[7; 32]).is_err());
            assert!(decrypt(&record, &ciphertext[..ciphertext.len() - 1], &[7; 32]).is_err());
            if size == 2048 {
                let mut reordered = ciphertext.clone();
                reordered.rotate_left(1040);
                // Refresh the digest to isolate segment authentication from the
                // independent complete-Blob digest rejection.
                let swapped = transfer_record(encryption, size, &reordered);
                assert!(decrypt(&swapped, &reordered, &[7; 32]).is_err());
            }
        }
    }

    #[test]
    fn range_plan_and_segment_open_match_the_whole_file_kat() {
        let plaintext = vec![42; 2049];
        let encryption = descriptor();
        let ciphertext = encrypt(&encryption, "text/plain", &plaintext, &[7; 32]).unwrap();
        let record = transfer_record(encryption, plaintext.len(), &ciphertext);
        let expected_ranges = [(0, 1039), (1040, 2079), (2080, 2096)];
        let mut opened = Vec::new();

        for (index, expected_range) in expected_ranges.into_iter().enumerate() {
            let plan = segment(&record, index as u32).unwrap();
            assert_eq!((plan.ciphertext_start, plan.ciphertext_end), expected_range);
            opened.extend_from_slice(
                &decrypt_segment(
                    &record,
                    index as u32,
                    &ciphertext[plan.ciphertext_start as usize..=plan.ciphertext_end as usize],
                    &[7; 32],
                )
                .unwrap(),
            );
        }

        assert_eq!(opened, plaintext);
        assert_eq!(opened, decrypt(&record, &ciphertext, &[7; 32]).unwrap());
    }

    #[test]
    fn descriptor_rejects_removed_count_and_present_null_nonce() {
        for (key, value) in [("segment_count", json!(1)), ("nonce", Value::Null)] {
            let mut value_map = serde_json::to_value(descriptor()).unwrap();
            value_map[key] = value;
            assert!(serde_json::from_value::<FileTransferEncryption>(value_map).is_err());
        }
    }
}
