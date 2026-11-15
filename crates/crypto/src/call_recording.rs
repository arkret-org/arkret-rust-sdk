//! RTC recording STREAM codec. This is not the attachment codec.
//!
//! The key must come from the original authorized MLS epoch. This byte layer
//! does not establish current authority or execute a host's epoch-install fence.
//! A producer freezes emitted ciphertext and the final descriptor durably before
//! retrying an upload. There is deliberately no API for resuming encryption with
//! an old nonce prefix after a crash or an uncertain sink write.

use arkret_canonical::base64url_encode;
use arkret_canonical::canonical::{ContentHasher, DigestSuite, canonical_json_bytes, digest_suite};
use arkret_models_collaboration::events_payloads::call::{
    CallRecordingArtifact, CallRecordingEncryption, CallRecordingEncryptionAlgorithm,
    CallRecordingEncryptionContext, recording_stream_geometry, validate_recording_media_type,
    validate_recording_nonce_prefix,
};
use arkret_models_crypto::{EncryptedAttachmentKeyRef, MAX_SEGMENT_COUNT};
use arkret_wire::{Base64UrlString, BlobRef, ExporterLabelId};
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use serde::Serialize;
use zeroize::{Zeroize, Zeroizing};

use crate::{Error, Result};

const TAG_BYTES: usize = 16;

#[derive(Serialize)]
struct SegmentAad<'a> {
    encryption_algorithm: &'a str,
    exporter_label: &'a str,
    context: &'a CallRecordingEncryptionContext,
    key_ref: &'a EncryptedAttachmentKeyRef,
    nonce_prefix: &'a Base64UrlString,
    segment_bytes: u32,
    media_type: &'a str,
    segment_index: u32,
    last_segment_flag: u8,
}

/// The online transcript excludes output-derived lengths and BlobRef.
pub fn recording_segment_aad(
    encryption: &CallRecordingEncryption,
    media_type: &str,
    segment_index: u32,
    last_segment: bool,
) -> Result<Vec<u8>> {
    encryption.validate()?;
    validate_recording_media_type(media_type)?;
    if segment_index >= MAX_SEGMENT_COUNT {
        return Err(Error::Protocol(
            "recording segment index exceeds STREAM bound".into(),
        ));
    }
    Ok(canonical_json_bytes(&SegmentAad {
        encryption_algorithm: encryption.encryption_algorithm.as_str(),
        exporter_label: &encryption.exporter_label,
        context: &encryption.context,
        key_ref: &encryption.key_ref,
        nonce_prefix: &encryption.nonce_prefix,
        segment_bytes: encryption.segment_bytes,
        media_type,
        segment_index,
        last_segment_flag: u8::from(last_segment),
    })?)
}

/// `prefix[19] || u32_be(index) || last_flag[1]`.
pub fn recording_segment_nonce(prefix: &[u8; 19], index: u32, last: bool) -> Result<[u8; 24]> {
    if index >= MAX_SEGMENT_COUNT {
        return Err(Error::Protocol(
            "recording segment index exceeds STREAM bound".into(),
        ));
    }
    let mut nonce = [0; 24];
    nonce[..19].copy_from_slice(prefix);
    nonce[19..23].copy_from_slice(&index.to_be_bytes());
    nonce[23] = u8::from(last);
    Ok(nonce)
}

/// Local completion coordinates, not another wire descriptor. Hosts copy these
/// values into the single CallRecordingArtifact and freeze the exact ciphertext.
pub struct RecordingStreamOutput {
    encryption: CallRecordingEncryption,
    media_type: String,
    size_bytes: u64,
    blob_ref: BlobRef,
}

impl RecordingStreamOutput {
    pub fn encryption(&self) -> &CallRecordingEncryption {
        &self.encryption
    }
    pub fn media_type(&self) -> &str {
        &self.media_type
    }
    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }
    pub fn blob_ref(&self) -> &BlobRef {
        &self.blob_ref
    }
}

/// Holds at most the last plaintext segment. A failed emit poisons this attempt:
/// the sink may already have persisted bytes and must not be retried as encryption.
pub struct RecordingStreamEncoder {
    key: Zeroizing<[u8; 32]>,
    encryption: CallRecordingEncryption,
    media_type: String,
    prefix: [u8; 19],
    pending: Zeroizing<Vec<u8>>,
    index: u32,
    size_bytes: u64,
    hasher: ContentHasher,
    failed: bool,
}

impl RecordingStreamEncoder {
    /// A new attempt always draws a fresh prefix, including an attempt following
    /// partial output or a crash. Exact retry reuses frozen bytes, not this method.
    pub fn fresh(
        key: [u8; 32],
        context: CallRecordingEncryptionContext,
        key_ref: EncryptedAttachmentKeyRef,
        segment_bytes: u32,
        media_type: String,
        suite: DigestSuite,
    ) -> Result<Self> {
        let key = Zeroizing::new(key);
        let mut prefix = [0; 19];
        getrandom::fill(&mut prefix).map_err(|error| Error::Crypto(error.to_string()))?;
        Self::with_prefix(
            *key,
            context,
            key_ref,
            segment_bytes,
            media_type,
            suite,
            prefix,
        )
    }

    fn with_prefix(
        key: [u8; 32],
        context: CallRecordingEncryptionContext,
        key_ref: EncryptedAttachmentKeyRef,
        segment_bytes: u32,
        media_type: String,
        suite: DigestSuite,
        prefix: [u8; 19],
    ) -> Result<Self> {
        let key = Zeroizing::new(key);
        let encryption = CallRecordingEncryption {
            encryption_algorithm:
                CallRecordingEncryptionAlgorithm::MlsExporterAeadXchacha20poly1305Stream,
            exporter_label: ExporterLabelId::RTC_RECORDING_KEY_V1.to_owned(),
            context,
            key_ref,
            nonce_prefix: Base64UrlString::new(base64url_encode(prefix))
                .map_err(|error| Error::Protocol(error.to_owned()))?,
            segment_bytes,
        };
        encryption.validate()?;
        validate_recording_media_type(&media_type)?;
        Ok(Self {
            key,
            encryption,
            media_type,
            prefix,
            pending: Zeroizing::new(Vec::with_capacity(segment_bytes as usize)),
            index: 0,
            size_bytes: 0,
            hasher: ContentHasher::new(suite),
            failed: false,
        })
    }

    pub fn encryption(&self) -> &CallRecordingEncryption {
        &self.encryption
    }

    /// Sink calls are synchronous so an epoch writer fence can cover both the
    /// plaintext admission and the corresponding irreversible ciphertext output.
    pub fn push_to(
        &mut self,
        mut plaintext: &[u8],
        mut emit: impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        if self.failed {
            return Err(Error::Protocol("recording attempt is poisoned".into()));
        }
        while !plaintext.is_empty() {
            if self.pending.len() == self.encryption.segment_bytes as usize {
                if let Err(error) = self.emit_segment(false, &mut emit) {
                    self.failed = true;
                    return Err(error);
                }
            }
            let take = plaintext
                .len()
                .min(self.encryption.segment_bytes as usize - self.pending.len());
            self.pending.extend_from_slice(&plaintext[..take]);
            plaintext = &plaintext[take..];
        }
        Ok(())
    }

    fn emit_segment(
        &mut self,
        last: bool,
        emit: &mut impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        if self.index >= MAX_SEGMENT_COUNT || (!last && self.index == MAX_SEGMENT_COUNT - 1) {
            return Err(Error::Protocol(
                "recording exceeds maximum segment count".into(),
            ));
        }
        let nonce = recording_segment_nonce(&self.prefix, self.index, last)?;
        let aad = recording_segment_aad(&self.encryption, &self.media_type, self.index, last)?;
        let cipher = XChaCha20Poly1305::new((&*self.key).into());
        let ciphertext = cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: &self.pending,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Crypto("recording segment encryption failed".into()))?;
        let next = self
            .size_bytes
            .checked_add(ciphertext.len() as u64)
            .ok_or_else(|| Error::Protocol("recording ciphertext size overflow".into()))?;
        self.failed = true;
        emit(&ciphertext)?;
        self.hasher.update(&ciphertext);
        self.size_bytes = next;
        self.index += 1;
        self.pending.zeroize();
        self.pending.clear();
        self.failed = false;
        Ok(())
    }

    /// May finish an old stopped writer after an epoch transition: it seals only
    /// its already-admitted final segment and never admits new plaintext.
    pub fn finish(
        mut self,
        mut emit: impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<RecordingStreamOutput> {
        if self.failed {
            return Err(Error::Protocol("recording attempt is poisoned".into()));
        }
        self.emit_segment(true, &mut emit)?;
        let (_, count) = recording_stream_geometry(self.size_bytes, self.encryption.segment_bytes)?;
        if count != self.index {
            return Err(Error::Protocol("recording stream geometry mismatch".into()));
        }
        let blob_ref = BlobRef::new(format!("ak:blob:{}", self.hasher.finish()))?;
        Ok(RecordingStreamOutput {
            encryption: self.encryption,
            media_type: self.media_type,
            size_bytes: self.size_bytes,
            blob_ref,
        })
    }
}

/// Bounded receiver. Segment plaintext emitted here is provisional until
/// `finish` verifies the whole BlobRef. A host must not publish/mark complete or
/// replace the durable artifact before that final success. No sink retry is
/// allowed after an uncertain write; create a fresh decoder for frozen bytes.
pub struct RecordingStreamDecoder {
    key: Zeroizing<[u8; 32]>,
    encryption: CallRecordingEncryption,
    media_type: String,
    prefix: [u8; 19],
    pending: Zeroizing<Vec<u8>>,
    expected_digest: String,
    expected_size: u64,
    plaintext_size: u64,
    count: u32,
    next: u32,
    received: u64,
    hasher: ContentHasher,
    failed: bool,
}

impl RecordingStreamDecoder {
    pub fn new(key: [u8; 32], artifact: &CallRecordingArtifact) -> Result<Self> {
        let key = Zeroizing::new(key);
        artifact.validate()?;
        let (plaintext_size, count) =
            recording_stream_geometry(artifact.size_bytes, artifact.encryption.segment_bytes)?;
        let digest = artifact
            .blob_ref
            .as_str()
            .strip_prefix("ak:blob:")
            .ok_or_else(|| Error::Protocol("invalid recording BlobRef".into()))?;
        let suite = digest
            .split_once(':')
            .ok_or_else(|| Error::Protocol("invalid recording digest".into()))?
            .0;
        Ok(Self {
            key,
            encryption: artifact.encryption.clone(),
            media_type: artifact.media_type.clone(),
            prefix: validate_recording_nonce_prefix(&artifact.encryption.nonce_prefix)?,
            pending: Zeroizing::new(Vec::with_capacity(
                artifact.encryption.segment_bytes as usize + TAG_BYTES,
            )),
            expected_digest: digest.to_owned(),
            expected_size: artifact.size_bytes,
            plaintext_size,
            count,
            next: 0,
            received: 0,
            hasher: ContentHasher::new(digest_suite(suite)?),
            failed: false,
        })
    }

    pub fn push_to(
        &mut self,
        ciphertext: &[u8],
        mut emit: impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        if self.failed {
            return Err(Error::Protocol("recording decoder is poisoned".into()));
        }
        let result = self.push_inner(ciphertext, &mut emit);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn push_inner(
        &mut self,
        mut ciphertext: &[u8],
        emit: &mut impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        let received = self
            .received
            .checked_add(ciphertext.len() as u64)
            .filter(|size| *size <= self.expected_size)
            .ok_or_else(|| Error::Protocol("recording contains excess ciphertext".into()))?;
        self.hasher.update(ciphertext);
        self.received = received;
        while !ciphertext.is_empty() {
            if self.next >= self.count {
                return Err(Error::Protocol("recording has excess segments".into()));
            }
            let last = self.next + 1 == self.count;
            let plain_len = if last {
                self.plaintext_size
                    - u64::from(self.encryption.segment_bytes) * u64::from(self.count - 1)
            } else {
                u64::from(self.encryption.segment_bytes)
            };
            let segment_len = usize::try_from(plain_len)
                .map_err(|_| Error::Protocol("recording segment exceeds address space".into()))?
                + TAG_BYTES;
            let take = ciphertext.len().min(segment_len - self.pending.len());
            self.pending.extend_from_slice(&ciphertext[..take]);
            ciphertext = &ciphertext[take..];
            if self.pending.len() == segment_len {
                let nonce = recording_segment_nonce(&self.prefix, self.next, last)?;
                let aad =
                    recording_segment_aad(&self.encryption, &self.media_type, self.next, last)?;
                let cipher = XChaCha20Poly1305::new((&*self.key).into());
                let plaintext = Zeroizing::new(
                    cipher
                        .decrypt(
                            (&nonce).into(),
                            Payload {
                                msg: &self.pending,
                                aad: &aad,
                            },
                        )
                        .map_err(|_| {
                            Error::Crypto("recording segment authentication failed".into())
                        })?,
                );
                if plaintext.len() as u64 != plain_len {
                    return Err(Error::Protocol(
                        "recording segment plaintext length mismatch".into(),
                    ));
                }
                self.failed = true;
                emit(&plaintext)?;
                self.pending.zeroize();
                self.pending.clear();
                self.next += 1;
                self.failed = false;
            }
        }
        Ok(())
    }

    pub fn finish(self) -> Result<()> {
        if self.failed
            || self.received != self.expected_size
            || !self.pending.is_empty()
            || self.next != self.count
        {
            return Err(Error::Protocol(
                "recording ciphertext truncated or decoder poisoned".into(),
            ));
        }
        if self.hasher.finish() != self.expected_digest {
            return Err(Error::Protocol("recording whole BlobRef mismatch".into()));
        }
        Ok(())
    }
}

/// Opens one complete stored object. No plaintext is returned before the whole
/// BlobRef and every AEAD tag, index and final-segment bit have been checked.
/// MLS source and history-read authority are separate, mandatory caller gates.
pub fn decrypt_recording(
    key: &[u8; 32],
    artifact: &CallRecordingArtifact,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    artifact.validate()?;
    if u64::try_from(ciphertext.len()).ok() != Some(artifact.size_bytes) {
        return Err(Error::Protocol(
            "recording stored ciphertext length differs from artifact".into(),
        ));
    }
    let (plain_bytes, _) =
        recording_stream_geometry(artifact.size_bytes, artifact.encryption.segment_bytes)?;
    let capacity = usize::try_from(plain_bytes)
        .map_err(|_| Error::Protocol("recording plaintext exceeds address space".into()))?;
    let mut plaintext = Zeroizing::new(Vec::new());
    plaintext
        .try_reserve_exact(capacity)
        .map_err(|_| Error::Protocol("recording plaintext allocation failed".into()))?;
    let mut decoder = RecordingStreamDecoder::new(*key, artifact)?;
    decoder.push_to(ciphertext, |segment| {
        plaintext.extend_from_slice(segment);
        Ok(())
    })?;
    decoder.finish()?;
    if plaintext.len() != capacity {
        return Err(Error::Protocol(
            "recording decrypted geometry mismatch".into(),
        ));
    }
    Ok(plaintext)
}

#[cfg(test)]
mod tests;
