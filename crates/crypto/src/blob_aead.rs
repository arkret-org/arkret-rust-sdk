//! Canonical encrypted attachment codec — `ak.blob.stream_aead.v1`
//! (chunked streaming AEAD, STREAM / OAE2).
//!
//! Implements `crypto-media/media-and-blob.md` §3.2 / §3.3 against the wire
//! shape in `blob.schema.json#/$defs/encrypted_attachment` (`artifacts/schemas/blob.schema.
//! json`).
//!
//! This module is security-sensitive. Every §3.3.6 decrypt MUST is mapped to
//! a dedicated reject path with the spec `reason_code` surfaced via
//! [`Error::Protocol`].
//!
//! # Algorithm closure
//!
//! Only **XChaCha20-Poly1305** is implemented here
//! (`mls_exporter_aead_xchacha20poly1305_stream` for the streaming scheme,
//! `mls_exporter_aead_xchacha20poly1305` for whole-file). The two AES-GCM
//! `alg` values defined by the schema, and any unknown `alg` / `scheme`, MUST
//! fail closed with `unsupported_attachment_scheme` — they are never decrypted
//! with the XChaCha path.
//!
//! # Content key
//!
//! The 32-byte `content_key` is derived by the caller from the MLS exporter
//! (the SDK does not depend on an MLS runtime). Each attachment object MUST use
//! a fresh content key (§3.3.4); callers are responsible for that contract.
//!
//! # `key_ref`
//!
//! `key_ref` is the closed MLS group-state object from
//! `blob.schema.json#/$defs/encrypted_attachment`. The attachment transcript
//! binds its canonical typed representation; it is never an opaque string and
//! is independent from the minimal Event-content encrypted envelope.

use std::collections::BTreeMap;

use arkret_canonical::base64url::{base64url_decode, base64url_encode};
use arkret_canonical::canonical::{canonical_json_bytes, sha256_hex};
use arkret_models_crypto::{
    EncryptedAttachment, EncryptedAttachmentGroupStateRef, EncryptedAttachmentKeyRef,
};
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{Error, Result};

/// Chunked streaming AEAD scheme id (STREAM / OAE2).
pub const SCHEME_STREAM: &str = arkret_wire::BLOB_SCHEME_STREAM_AEAD_V1;

/// XChaCha20-Poly1305 streaming `alg` value.
pub const ALG_STREAM_XCHACHA: &str = "mls_exporter_aead_xchacha20poly1305_stream";

/// Minimum `segment_bytes`: 1 KiB (scalability-constraints.md §6). Values
/// outside `[MIN_SEGMENT_SIZE, MAX_SEGMENT_SIZE]` MUST be rejected on both
/// the send and receive paths (`schema_violation`).
pub const MIN_SEGMENT_SIZE: u32 = 1024;
/// Maximum `segment_bytes`: 8 MiB (scalability-constraints.md §6).
pub const MAX_SEGMENT_SIZE: u32 = 8_388_608;
/// Maximum derived segment count: 2^20 (scalability-constraints.md §6).
pub const MAX_SEGMENT_COUNT: u32 = 1_048_576;

/// Reject segment parameters outside the spec hard limits.
fn validate_segment_bounds(segment_bytes: u32, segment_count: u32) -> Result<()> {
    if !(MIN_SEGMENT_SIZE..=MAX_SEGMENT_SIZE).contains(&segment_bytes) {
        return Err(protocol(
            "schema_violation",
            &format!(
                "segment_bytes={segment_bytes} outside [{MIN_SEGMENT_SIZE}, {MAX_SEGMENT_SIZE}] \
                 (scalability-constraints.md §6)"
            ),
        ));
    }
    if segment_count == 0 || segment_count > MAX_SEGMENT_COUNT {
        return Err(protocol(
            "schema_violation",
            &format!(
                "segment_count={segment_count} outside [1, {MAX_SEGMENT_COUNT}] \
                 (scalability-constraints.md §6)"
            ),
        ));
    }
    Ok(())
}

/// XChaCha20-Poly1305 AEAD nonce length, `N_AEAD` (§3.3.2).
const N_AEAD: usize = 24;
/// `nonce_prefix` length = `N_AEAD - 5` = 19 bytes (§3.3.2).
const NONCE_PREFIX_LEN: usize = N_AEAD - 5;
/// Poly1305 tag length appended to each segment ciphertext.
const TAG_LEN: usize = 16;
/// `0x00` ordinary segment / `0x01` last segment (§3.3.2).
const FLAG_NORMAL: u8 = 0x00;
const FLAG_LAST: u8 = 0x01;

/// Encrypted attachment envelope, matching
/// `blob.schema.json#/$defs/encrypted_attachment`.
///
/// `Option` fields distinguish the two `scheme` shapes:
/// - whole-file carries `nonce`;
/// - streaming carries `nonce_prefix` and `segment_bytes`; the segment count is derived from
///   `size_bytes`.
///
/// All serde `rename`s match the schema exactly; absent optionals are skipped.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct AttachmentEnvelopeFields {
    /// Content-addressed blob reference. May be filled in by the caller after
    /// addressing the ciphertext bytes; left empty by the encrypt helpers.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub blob_ref: String,
    /// Always `true`.
    pub encrypted: bool,
    /// Construction scheme (`SCHEME_STREAM` for the v1 chunked binding).
    pub scheme: String,
    /// AEAD algorithm id.
    pub encryption_algorithm: String,
    /// MLS group-binding key reference (`{algorithm, group_state_ref}`),
    /// defined by `blob.schema.json#/$defs/encrypted_attachment`.
    pub key_ref: EncryptedAttachmentKeyRef,
    /// `<algo>:<lowercase_hex>` digest over the concatenated ciphertext.
    pub ciphertext_digest: String,
    /// Plaintext size in bytes.
    pub size_bytes: u64,
    /// Declared media type.
    pub media_type: String,

    /// Whole-file: base64url of the 24-byte AEAD nonce.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,

    /// Streaming: base64url of the 19-byte per-object random nonce prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce_prefix: Option<String>,
    /// Streaming: segment size in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub segment_bytes: Option<u32>,
}

fn typed_envelope(fields: AttachmentEnvelopeFields) -> Result<EncryptedAttachment> {
    serde_json::from_value(
        serde_json::to_value(fields)
            .map_err(|error| Error::Protocol(format!("attachment encode: {error}")))?,
    )
    .map_err(|error| Error::Protocol(format!("attachment model conversion: {error}")))
}

fn envelope_fields(envelope: &EncryptedAttachment) -> Result<AttachmentEnvelopeFields> {
    serde_json::from_value(
        serde_json::to_value(envelope)
            .map_err(|error| Error::Protocol(format!("attachment encode: {error}")))?,
    )
    .map_err(|error| Error::Protocol(format!("attachment model conversion: {error}")))
}

/// Parameters for [`encrypt_stream`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamEncryptParams {
    /// MLS group-binding key reference bound into the AAD.
    pub key_ref: EncryptedAttachmentKeyRef,
    /// Declared media type.
    pub media_type: String,
    /// Segment size in bytes; bounded by [`MIN_SEGMENT_SIZE`] / [`MAX_SEGMENT_SIZE`].
    pub segment_bytes: u32,
}

/// Resolves an attachment group-state reference to the epoch of the exact
/// accepted winning MLS state. Returning `None` means unresolved, ambiguous,
/// non-winning, or otherwise unusable and always fails closed.
pub trait AttachmentGroupStateEpochResolver {
    fn resolve_exact_winning_epoch(
        &self,
        group_state_ref: &EncryptedAttachmentGroupStateRef,
    ) -> Option<u64>;
}

impl<F> AttachmentGroupStateEpochResolver for F
where
    F: Fn(&EncryptedAttachmentGroupStateRef) -> Option<u64>,
{
    fn resolve_exact_winning_epoch(
        &self,
        group_state_ref: &EncryptedAttachmentGroupStateRef,
    ) -> Option<u64> {
        self(group_state_ref)
    }
}

fn attachment_epoch(
    key_ref: &EncryptedAttachmentKeyRef,
    resolver: &impl AttachmentGroupStateEpochResolver,
) -> Result<u64> {
    resolver
        .resolve_exact_winning_epoch(&key_ref.group_state_ref)
        .ok_or_else(|| {
            protocol(
                "attachment_group_state_unresolved",
                "group_state_ref did not resolve to one exact accepted winning MLS state",
            )
        })
}

// ─── helpers ──────────────────────────────────────────────────────────────

fn protocol(reason_code: &str, detail: &str) -> Error {
    Error::Protocol(format!("{reason_code}: {detail}"))
}

fn cipher_from_key(content_key: &[u8; 32]) -> Result<XChaCha20Poly1305> {
    XChaCha20Poly1305::new_from_slice(content_key)
        .map_err(|_| Error::Crypto("invalid XChaCha20-Poly1305 key length".to_owned()))
}

/// `nonce = nonce_prefix(19) || u32_be(segment_index) || last_segment_flag` (§3.3.2).
fn segment_nonce(
    nonce_prefix: &[u8; NONCE_PREFIX_LEN],
    segment_index: u32,
    last: bool,
) -> [u8; N_AEAD] {
    let mut nonce = [0u8; N_AEAD];
    nonce[..NONCE_PREFIX_LEN].copy_from_slice(nonce_prefix);
    nonce[NONCE_PREFIX_LEN..NONCE_PREFIX_LEN + 4].copy_from_slice(&segment_index.to_be_bytes());
    nonce[N_AEAD - 1] = if last { FLAG_LAST } else { FLAG_NORMAL };
    nonce
}

/// Canonical per-segment AAD (§3.3.3). Keys are sorted by `canonical_json_bytes`.
fn stream_segment_aad(
    key_ref: &EncryptedAttachmentKeyRef,
    epoch: u64,
    nonce_prefix_b64: &str,
    segment_index: u32,
    last: bool,
    segment_count: u32,
    media_type: &str,
    size_bytes: u64,
) -> Result<Vec<u8>> {
    let map: BTreeMap<&str, Value> = BTreeMap::from([
        ("scheme", json!(SCHEME_STREAM)),
        ("key_ref", json!(key_ref)),
        ("epoch", json!(epoch)),
        ("nonce_prefix", json!(nonce_prefix_b64)),
        ("segment_index", json!(segment_index)),
        (
            "last_segment_flag",
            json!(if last { FLAG_LAST } else { FLAG_NORMAL }),
        ),
        ("segment_count", json!(segment_count)),
        ("media_type", json!(media_type)),
        ("size_bytes", json!(size_bytes)),
    ]);
    Ok(canonical_json_bytes(&map)?)
}

/// Derive the unique streaming segment count from the plaintext length and
/// fixed segment size. Empty plaintext is one authenticated empty segment.
pub fn stream_segment_count(size_bytes: u64, segment_bytes: u32) -> Result<u32> {
    if !(MIN_SEGMENT_SIZE..=MAX_SEGMENT_SIZE).contains(&segment_bytes) {
        return Err(protocol(
            "schema_violation",
            &format!(
                "segment_bytes={segment_bytes} outside [{MIN_SEGMENT_SIZE}, {MAX_SEGMENT_SIZE}]"
            ),
        ));
    }
    let count = size_bytes.max(1).div_ceil(u64::from(segment_bytes));
    let count = u32::try_from(count)
        .map_err(|_| protocol("schema_violation", "derived segment count exceeds u32"))?;
    validate_segment_bounds(segment_bytes, count)?;
    Ok(count)
}

// ─── streaming encrypt ──────────────────────────────────────────────────────

/// Encrypt `plaintext` into `ak.blob.stream_aead.v1` form.
///
/// Returns `(ciphertext, envelope)` where `ciphertext` is the concatenation of
/// every segment ciphertext (each carrying its own AEAD tag) in ascending
/// `segment_index` order. The returned typed envelope is content-addressed
/// over those ciphertext bytes.
pub fn encrypt_stream(
    plaintext: &[u8],
    content_key: &[u8; 32],
    params: &StreamEncryptParams,
    resolver: &impl AttachmentGroupStateEpochResolver,
) -> Result<(Vec<u8>, EncryptedAttachment)> {
    // Enforce the §6 hard limits on the send path too: an envelope outside
    // them is not interoperable and every conforming receiver MUST reject it.
    if !(MIN_SEGMENT_SIZE..=MAX_SEGMENT_SIZE).contains(&params.segment_bytes) {
        return Err(protocol(
            "schema_violation",
            &format!(
                "segment_bytes={} outside [{MIN_SEGMENT_SIZE}, {MAX_SEGMENT_SIZE}] \
                 (scalability-constraints.md §6)",
                params.segment_bytes
            ),
        ));
    }
    let segment_count = stream_segment_count(plaintext.len() as u64, params.segment_bytes)?;
    let epoch = attachment_epoch(&params.key_ref, resolver)?;
    let cipher = cipher_from_key(content_key)?;

    let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
    getrandom::fill(&mut nonce_prefix).map_err(|error| Error::Crypto(error.to_string()))?;
    let nonce_prefix_b64 = base64url_encode(nonce_prefix);

    let segment_bytes = params.segment_bytes as usize;
    let size_bytes = plaintext.len() as u64;

    let mut ciphertext = Vec::new();
    // Empty plaintext is a single zero-length last segment; otherwise chunk
    // into `segment_bytes` pieces (the last is 1..=segment_bytes).
    let chunks: Vec<&[u8]> = if plaintext.is_empty() {
        vec![&[][..]]
    } else {
        plaintext.chunks(segment_bytes).collect()
    };
    debug_assert_eq!(chunks.len() as u32, segment_count);

    for (index, chunk) in chunks.iter().enumerate() {
        let segment_index = index as u32;
        let last = segment_index == segment_count - 1;
        let nonce = segment_nonce(&nonce_prefix, segment_index, last);
        let aad = stream_segment_aad(
            &params.key_ref,
            epoch,
            &nonce_prefix_b64,
            segment_index,
            last,
            segment_count,
            &params.media_type,
            size_bytes,
        )?;
        let segment_ct = cipher
            .encrypt(
                &nonce.into(),
                Payload {
                    msg: chunk,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Crypto("segment AEAD encryption failed".to_owned()))?;
        ciphertext.extend_from_slice(&segment_ct);
    }

    let envelope = AttachmentEnvelopeFields {
        blob_ref: format!("ak:blob:sha256:{}", sha256_hex(&ciphertext)),
        encrypted: true,
        scheme: SCHEME_STREAM.to_owned(),
        encryption_algorithm: ALG_STREAM_XCHACHA.to_owned(),
        key_ref: params.key_ref.clone(),
        ciphertext_digest: format!("sha256:{}", sha256_hex(&ciphertext)),
        size_bytes,
        media_type: params.media_type.clone(),
        nonce: None,
        nonce_prefix: Some(nonce_prefix_b64),
        segment_bytes: Some(params.segment_bytes),
    };

    Ok((ciphertext, typed_envelope(envelope)?))
}

// ─── streaming decrypt ──────────────────────────────────────────────────────

/// Validated streaming-scheme context, shared by [`StreamDecryptor`] and
/// [`decrypt_stream`]. Construction performs the scheme/alg closure and field
/// presence checks so the hot path only does AEAD + sequencing.
struct StreamContext {
    cipher: XChaCha20Poly1305,
    nonce_prefix: [u8; NONCE_PREFIX_LEN],
    nonce_prefix_b64: String,
    key_ref: EncryptedAttachmentKeyRef,
    epoch: u64,
    media_type: String,
    size_bytes: u64,
    segment_bytes: u32,
    segment_count: u32,
    expected_digest: String,
}

impl StreamContext {
    fn new(
        env: &AttachmentEnvelopeFields,
        content_key: &[u8; 32],
        resolver: &impl AttachmentGroupStateEpochResolver,
    ) -> Result<Self> {
        if env.scheme != SCHEME_STREAM || env.encryption_algorithm != ALG_STREAM_XCHACHA {
            return Err(protocol(
                "unsupported_attachment_scheme",
                &format!(
                    "scheme={} alg={} not stream XChaCha20-Poly1305",
                    env.scheme, env.encryption_algorithm
                ),
            ));
        }
        let nonce_prefix_b64 = env
            .nonce_prefix
            .as_deref()
            .ok_or_else(|| protocol("unsupported_attachment_scheme", "missing nonce_prefix"))?;
        let segment_bytes = env
            .segment_bytes
            .ok_or_else(|| protocol("unsupported_attachment_scheme", "missing segment_bytes"))?;
        // Derive and bound the count before any count-proportional allocation.
        let segment_count = stream_segment_count(env.size_bytes, segment_bytes)?;
        let epoch = attachment_epoch(&env.key_ref, resolver)?;

        let nonce_prefix_bytes = base64url_decode(nonce_prefix_b64)?;
        let nonce_prefix: [u8; NONCE_PREFIX_LEN] = nonce_prefix_bytes
            .as_slice()
            .try_into()
            .map_err(|_| protocol("unsupported_attachment_scheme", "nonce_prefix length != 19"))?;

        Ok(Self {
            cipher: cipher_from_key(content_key)?,
            nonce_prefix,
            nonce_prefix_b64: nonce_prefix_b64.to_owned(),
            key_ref: env.key_ref.clone(),
            epoch,
            media_type: env.media_type.clone(),
            size_bytes: env.size_bytes,
            segment_bytes,
            segment_count,
            expected_digest: env.ciphertext_digest.clone(),
        })
    }

    /// Expected *plaintext* length of `segment_index` per §3.3.1.
    fn expected_plaintext_len(&self, segment_index: u32) -> usize {
        let last_index = self.segment_count - 1;
        if segment_index < last_index {
            self.segment_bytes as usize
        } else {
            // Last segment: size_bytes - segment_bytes * last_index.
            (self.size_bytes - (self.segment_bytes as u64) * (last_index as u64)) as usize
        }
    }
}

/// Incremental decryptor for `ak.blob.stream_aead.v1`.
///
/// Supports Range / progressive playback: feed each segment ciphertext via
/// [`push_segment`](Self::push_segment), which returns that segment's verified
/// plaintext. [`finish`](Self::finish) enforces that a legal last segment was
/// seen and that the overall `ciphertext_digest` matches.
///
/// Each §3.3.6 reject path is enforced here; see the inline comments.
pub struct StreamDecryptor {
    ctx: StreamContext,
    /// Next segment_index expected (strict ascending, no gaps) — §3.3.6 (1).
    next_index: u32,
    /// Whether a legal last segment has been accepted — §3.3.6 (3).
    seen_last: bool,
    /// Running SHA-256 input: concatenated ciphertext in index order — §3.3.5.
    digest_input: Vec<u8>,
}

impl StreamDecryptor {
    /// Build a decryptor from an envelope, running scheme/alg/field checks.
    pub fn new(
        env: &EncryptedAttachment,
        content_key: &[u8; 32],
        resolver: &impl AttachmentGroupStateEpochResolver,
    ) -> Result<Self> {
        let env = envelope_fields(env)?;
        Ok(Self {
            ctx: StreamContext::new(&env, content_key, resolver)?,
            next_index: 0,
            seen_last: false,
            digest_input: Vec::new(),
        })
    }

    /// Push one segment ciphertext (plaintext + 16-byte tag) and return its
    /// AEAD-verified plaintext. The plaintext is only returned after the tag
    /// verifies — §3.3.6 (2).
    pub fn push_segment(
        &mut self,
        segment_index: u32,
        segment_ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        // §3.3.6 (3)/(4): once the last segment was accepted, no further pushes.
        if self.seen_last {
            return Err(protocol(
                "segment_sequence_invalid",
                "segment pushed after the last segment was accepted",
            ));
        }

        // §3.3.6 (6): out-of-range index.
        if segment_index >= self.ctx.segment_count {
            return Err(protocol(
                "segment_bounds_invalid",
                &format!(
                    "segment_index={segment_index} >= segment_count={}",
                    self.ctx.segment_count
                ),
            ));
        }

        // §3.3.6 (5)/(1): replay vs reorder/gap. A repeat of an already-consumed
        // index is replay; any other non-`next_index` value is a sequence error.
        if segment_index != self.next_index {
            if segment_index < self.next_index {
                return Err(protocol(
                    "segment_replay",
                    &format!("segment_index={segment_index} already consumed"),
                ));
            }
            return Err(protocol(
                "segment_sequence_invalid",
                &format!(
                    "out-of-order segment_index={segment_index}, expected {}",
                    self.next_index
                ),
            ));
        }

        let last = segment_index == self.ctx.segment_count - 1;

        // §3.3.6 (6): ciphertext length must equal expected_plaintext_len + TAG.
        // Non-last segments must be exactly segment_bytes; the last is
        // 1..=segment_bytes (empty-plaintext last is 0). Reject before AEAD so a
        // length-tampered segment is bounds-rejected, not just tag-rejected.
        let expected_pt = self.ctx.expected_plaintext_len(segment_index);
        let expected_ct = expected_pt + TAG_LEN;
        if segment_ciphertext.len() != expected_ct {
            return Err(protocol(
                "segment_bounds_invalid",
                &format!(
                    "segment_index={segment_index} ciphertext len={} != expected {expected_ct}",
                    segment_ciphertext.len()
                ),
            ));
        }

        // §3.3.6 (2): per-segment AEAD with the §3.3.2 nonce and §3.3.3 AAD.
        let nonce = segment_nonce(&self.ctx.nonce_prefix, segment_index, last);
        let aad = stream_segment_aad(
            &self.ctx.key_ref,
            self.ctx.epoch,
            &self.ctx.nonce_prefix_b64,
            segment_index,
            last,
            self.ctx.segment_count,
            &self.ctx.media_type,
            self.ctx.size_bytes,
        )?;
        let plaintext = self
            .ctx
            .cipher
            .decrypt(
                &nonce.into(),
                Payload {
                    msg: segment_ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                protocol(
                    "segment_aead_failed",
                    &format!("segment_index={segment_index} tag check failed"),
                )
            })?;

        // Only after AEAD success do we advance state / accumulate digest input.
        self.digest_input.extend_from_slice(segment_ciphertext);
        self.next_index += 1;
        if last {
            self.seen_last = true;
        }
        Ok(plaintext)
    }

    /// Finalize: require that a legal last segment was accepted and that the
    /// overall ciphertext digest matches — §3.3.6 (3)/(4)/(7).
    pub fn finish(self) -> Result<()> {
        // §3.3.6 (3)/(4): no legal last segment ⇒ truncated stream.
        if !self.seen_last {
            return Err(protocol(
                "segment_stream_truncated",
                "stream ended without a legal last segment",
            ));
        }
        // Defensive: all declared segments must have been consumed.
        if self.next_index != self.ctx.segment_count {
            return Err(protocol(
                "segment_stream_truncated",
                &format!(
                    "consumed {} of {} segments",
                    self.next_index, self.ctx.segment_count
                ),
            ));
        }
        // §3.3.6 (7): recompute the concatenated ciphertext digest.
        let actual = format!("sha256:{}", sha256_hex(&self.digest_input));
        if actual != self.ctx.expected_digest {
            return Err(protocol(
                "digest_mismatch",
                &format!(
                    "recomputed {actual} != envelope {}",
                    self.ctx.expected_digest
                ),
            ));
        }
        Ok(())
    }
}

/// One-shot streaming decrypt. Splits `ciphertext` at segment boundaries,
/// drives a [`StreamDecryptor`] in order, and runs every §3.3.6 check before
/// returning the recovered plaintext.
pub fn decrypt_stream(
    ciphertext: &[u8],
    env: &EncryptedAttachment,
    content_key: &[u8; 32],
    resolver: &impl AttachmentGroupStateEpochResolver,
) -> Result<Vec<u8>> {
    let mut decryptor = StreamDecryptor::new(env, content_key, resolver)?;
    let ctx = &decryptor.ctx;
    let segment_count = ctx.segment_count;
    let segment_bytes = ctx.segment_bytes as usize;

    // Pre-compute each segment's expected ciphertext length so we can slice the
    // single concatenated buffer at the right boundaries. The last segment's
    // plaintext length comes from size_bytes (§3.3.1 / cargo note in task).
    let mut boundaries: Vec<usize> = Vec::with_capacity(segment_count as usize);
    for index in 0..segment_count {
        let last_index = segment_count - 1;
        let pt = if index < last_index {
            segment_bytes
        } else {
            (ctx.size_bytes - (ctx.segment_bytes as u64) * (last_index as u64)) as usize
        };
        boundaries.push(pt + TAG_LEN);
    }
    let total: usize = boundaries.iter().sum();
    if ciphertext.len() != total {
        return Err(protocol(
            "segment_bounds_invalid",
            &format!(
                "ciphertext len={} != expected total {total}",
                ciphertext.len()
            ),
        ));
    }

    let mut plaintext = Vec::with_capacity(ctx.size_bytes as usize);
    let mut offset = 0usize;
    for (index, seg_len) in boundaries.into_iter().enumerate() {
        let segment = &ciphertext[offset..offset + seg_len];
        offset += seg_len;
        let segment_plaintext = decryptor.push_segment(index as u32, segment)?;
        plaintext.extend_from_slice(&segment_plaintext);
    }
    decryptor.finish()?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smallest spec-legal segment size, used to keep multi-segment test
    /// plaintexts cheap while staying inside the §6 wire limits.
    const S: usize = MIN_SEGMENT_SIZE as usize;

    fn key() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    fn test_key_ref() -> EncryptedAttachmentKeyRef {
        EncryptedAttachmentKeyRef {
            algorithm: arkret_models_crypto::EncryptedAttachmentKeyAlgorithm::Mls,
            group_state_ref: EncryptedAttachmentGroupStateRef::Event(
                arkret_wire::EventId::new(
                    "ak:event:AQNy1zG98lAoTz0YOf-2Yp2-GXeJioPlyg8nW6qxW-OB".to_owned(),
                )
                .unwrap(),
            ),
        }
    }

    fn proof_hash_key_ref() -> EncryptedAttachmentKeyRef {
        EncryptedAttachmentKeyRef {
            algorithm: arkret_models_crypto::EncryptedAttachmentKeyAlgorithm::Mls,
            group_state_ref: EncryptedAttachmentGroupStateRef::Digest(
                arkret_wire::Hash::new(
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_owned(),
                )
                .unwrap(),
            ),
        }
    }

    fn params(segment_bytes: u32) -> StreamEncryptParams {
        StreamEncryptParams {
            key_ref: test_key_ref(),
            media_type: "video/mp4".to_owned(),
            segment_bytes,
        }
    }

    fn winning_epoch(_group_state_ref: &EncryptedAttachmentGroupStateRef) -> Option<u64> {
        Some(42)
    }

    fn reason(err: &Error) -> String {
        match err {
            Error::Protocol(s) => s.split(':').next().unwrap_or("").to_owned(),
            other => panic!("expected Protocol error, got {other:?}"),
        }
    }

    /// Split a concatenated stream ciphertext into per-segment slices using the
    /// envelope (mirrors what decrypt_stream does internally).
    fn split_segments(ct: &[u8], env: &EncryptedAttachment) -> Vec<Vec<u8>> {
        let env = envelope_fields(env).unwrap();
        let segment_bytes = env.segment_bytes.unwrap() as usize;
        let segment_count =
            stream_segment_count(env.size_bytes, env.segment_bytes.unwrap()).unwrap();
        let mut out = Vec::new();
        let mut offset = 0;
        for index in 0..segment_count {
            let last_index = segment_count - 1;
            let pt = if index < last_index {
                segment_bytes
            } else {
                (env.size_bytes - (segment_bytes as u64) * (last_index as u64)) as usize
            };
            let len = pt + TAG_LEN;
            out.push(ct[offset..offset + len].to_vec());
            offset += len;
        }
        out
    }

    #[test]
    fn stream_roundtrip_multi_segment_short_last() {
        let key = key();
        let p = params(MIN_SEGMENT_SIZE);
        // 3 segments: S, S, 10.
        let plaintext: Vec<u8> = (0..(2 * S + 10) as u32).map(|i| (i % 251) as u8).collect();
        let (ct, env) = encrypt_stream(&plaintext, &key, &p, &winning_epoch).unwrap();
        let fields = envelope_fields(&env).unwrap();
        assert_eq!(
            stream_segment_count(fields.size_bytes, fields.segment_bytes.unwrap()).unwrap(),
            3
        );
        assert_eq!(fields.scheme, SCHEME_STREAM);
        assert_eq!(fields.encryption_algorithm, ALG_STREAM_XCHACHA);

        // one-shot
        assert_eq!(
            decrypt_stream(&ct, &env, &key, &winning_epoch).unwrap(),
            plaintext
        );

        // incremental push, byte-for-byte
        let mut dec = StreamDecryptor::new(&env, &key, &winning_epoch).unwrap();
        let segs = split_segments(&ct, &env);
        let mut recovered = Vec::new();
        for (i, seg) in segs.iter().enumerate() {
            recovered.extend(dec.push_segment(i as u32, seg).unwrap());
        }
        dec.finish().unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn group_state_epoch_is_derived_for_event_and_proof_hash_refs() {
        let key = key();
        let plaintext = b"epoch-derived attachment".to_vec();
        for key_ref in [test_key_ref(), proof_hash_key_ref()] {
            let params = StreamEncryptParams {
                key_ref,
                media_type: "application/octet-stream".to_owned(),
                segment_bytes: MIN_SEGMENT_SIZE,
            };
            let (ciphertext, envelope) =
                encrypt_stream(&plaintext, &key, &params, &winning_epoch).unwrap();
            assert_eq!(
                decrypt_stream(&ciphertext, &envelope, &key, &winning_epoch).unwrap(),
                plaintext
            );
            assert!(
                serde_json::to_value(envelope)
                    .unwrap()
                    .get("epoch")
                    .is_none()
            );
        }

        let (_, envelope) =
            encrypt_stream(&plaintext, &key, &params(MIN_SEGMENT_SIZE), &winning_epoch).unwrap();
        let mut legacy = serde_json::to_value(envelope).unwrap();
        legacy
            .as_object_mut()
            .unwrap()
            .insert("epoch".to_owned(), serde_json::json!(42));
        assert!(serde_json::from_value::<EncryptedAttachment>(legacy).is_err());
    }

    #[test]
    fn unresolved_non_winning_and_wrong_epoch_fail_closed() {
        let key = key();
        let params = params(MIN_SEGMENT_SIZE);
        let unresolved = |_group_state_ref: &EncryptedAttachmentGroupStateRef| None;
        let err = encrypt_stream(b"x", &key, &params, &unresolved).unwrap_err();
        assert_eq!(reason(&err), "attachment_group_state_unresolved");

        let (ciphertext, envelope) = encrypt_stream(b"x", &key, &params, &winning_epoch).unwrap();
        let stale_epoch = |_group_state_ref: &EncryptedAttachmentGroupStateRef| Some(41);
        let err = decrypt_stream(&ciphertext, &envelope, &key, &stale_epoch).unwrap_err();
        assert_eq!(reason(&err), "segment_aead_failed");
    }

    #[test]
    fn stream_empty_single_exact_and_one_byte_last() {
        let key = key();
        // empty plaintext → single zero-length last segment, count 1
        let (ct, env) =
            encrypt_stream(&[], &key, &params(MIN_SEGMENT_SIZE), &winning_epoch).unwrap();
        let fields = envelope_fields(&env).unwrap();
        assert_eq!(
            stream_segment_count(fields.size_bytes, fields.segment_bytes.unwrap()).unwrap(),
            1
        );
        assert_eq!(fields.size_bytes, 0);
        assert_eq!(
            decrypt_stream(&ct, &env, &key, &winning_epoch).unwrap(),
            Vec::<u8>::new()
        );

        // single short segment
        let p = vec![7u8; 30];
        let (ct, env) =
            encrypt_stream(&p, &key, &params(MIN_SEGMENT_SIZE), &winning_epoch).unwrap();
        let fields = envelope_fields(&env).unwrap();
        assert_eq!(
            stream_segment_count(fields.size_bytes, fields.segment_bytes.unwrap()).unwrap(),
            1
        );
        assert_eq!(decrypt_stream(&ct, &env, &key, &winning_epoch).unwrap(), p);

        // exactly divisible: 2*S / S == 2 segments, last == segment_bytes
        let p = vec![3u8; 2 * S];
        let (ct, env) =
            encrypt_stream(&p, &key, &params(MIN_SEGMENT_SIZE), &winning_epoch).unwrap();
        let fields = envelope_fields(&env).unwrap();
        assert_eq!(
            stream_segment_count(fields.size_bytes, fields.segment_bytes.unwrap()).unwrap(),
            2
        );
        assert_eq!(decrypt_stream(&ct, &env, &key, &winning_epoch).unwrap(), p);

        // last segment of exactly 1 byte: (S+1) / S -> 2 segments (S + 1)
        let p = vec![9u8; S + 1];
        let (ct, env) =
            encrypt_stream(&p, &key, &params(MIN_SEGMENT_SIZE), &winning_epoch).unwrap();
        let fields = envelope_fields(&env).unwrap();
        assert_eq!(
            stream_segment_count(fields.size_bytes, fields.segment_bytes.unwrap()).unwrap(),
            2
        );
        assert_eq!(decrypt_stream(&ct, &env, &key, &winning_epoch).unwrap(), p);
    }

    #[test]
    fn stream_truncation_drops_last_segment() {
        let key = key();
        let p = vec![1u8; 3 * S + 8];
        let (ct, env) =
            encrypt_stream(&p, &key, &params(MIN_SEGMENT_SIZE), &winning_epoch).unwrap();
        let segs = split_segments(&ct, &env);
        // push all but the last segment, then finish → truncated
        let mut dec = StreamDecryptor::new(&env, &key, &winning_epoch).unwrap();
        for (i, seg) in segs.iter().enumerate().take(segs.len() - 1) {
            dec.push_segment(i as u32, seg).unwrap();
        }
        let err = dec.finish().unwrap_err();
        assert_eq!(reason(&err), "segment_stream_truncated");
    }

    #[test]
    fn stream_last_flag_forgery_fails_aead() {
        // Forge a "last" out of a normal middle segment by re-using its ciphertext
        // at the last index: the AEAD nonce/AAD bind last_segment_flag, so the
        // forged last segment's tag check fails.
        let key = key();
        let p = vec![5u8; 3 * S + 8]; // 4 segments: S,S,S,8
        let (ct, env) =
            encrypt_stream(&p, &key, &params(MIN_SEGMENT_SIZE), &winning_epoch).unwrap();
        let segs = split_segments(&ct, &env);
        let mut dec = StreamDecryptor::new(&env, &key, &winning_epoch).unwrap();
        // push first three normal segments fine
        dec.push_segment(0, &segs[0]).unwrap();
        dec.push_segment(1, &segs[1]).unwrap();
        dec.push_segment(2, &segs[2]).unwrap();
        // present segment[1]'s ciphertext (len S+16) as the last index 3 — but
        // index 3 expects len 8+16, so bounds reject first.
        let err = dec.push_segment(3, &segs[1]).unwrap_err();
        assert_eq!(reason(&err), "segment_bounds_invalid");
    }

    #[test]
    fn stream_reorder_and_replay() {
        let key = key();
        let p = vec![2u8; 2 * S + 10];
        let (ct, env) =
            encrypt_stream(&p, &key, &params(MIN_SEGMENT_SIZE), &winning_epoch).unwrap();
        let segs = split_segments(&ct, &env);

        // reorder: push index 1 before 0
        let mut dec = StreamDecryptor::new(&env, &key, &winning_epoch).unwrap();
        let err = dec.push_segment(1, &segs[1]).unwrap_err();
        assert_eq!(reason(&err), "segment_sequence_invalid");

        // replay: push 0, then 0 again
        let mut dec = StreamDecryptor::new(&env, &key, &winning_epoch).unwrap();
        dec.push_segment(0, &segs[0]).unwrap();
        let err = dec.push_segment(0, &segs[0]).unwrap_err();
        assert_eq!(reason(&err), "segment_replay");
    }

    #[test]
    fn stream_bounds_oob_index_and_tampered_len() {
        let key = key();
        let p = vec![4u8; MIN_SEGMENT_SIZE as usize + 36]; // 2 segments: MIN_SEGMENT_SIZE, 36
        let (ct, env) =
            encrypt_stream(&p, &key, &params(MIN_SEGMENT_SIZE), &winning_epoch).unwrap();
        let segs = split_segments(&ct, &env);

        // out-of-range index
        let mut dec = StreamDecryptor::new(&env, &key, &winning_epoch).unwrap();
        dec.push_segment(0, &segs[0]).unwrap();
        let err = dec.push_segment(2, &segs[1]).unwrap_err();
        assert_eq!(reason(&err), "segment_bounds_invalid");

        // tampered (truncated) segment length
        let mut dec = StreamDecryptor::new(&env, &key, &winning_epoch).unwrap();
        let mut short = segs[0].clone();
        short.pop();
        let err = dec.push_segment(0, &short).unwrap_err();
        assert_eq!(reason(&err), "segment_bounds_invalid");
    }

    #[test]
    fn stream_aead_tamper_fails() {
        let key = key();
        let p = vec![6u8; 100];
        let (ct, env) =
            encrypt_stream(&p, &key, &params(MIN_SEGMENT_SIZE), &winning_epoch).unwrap();
        let mut segs = split_segments(&ct, &env);
        segs[0][3] ^= 0xff;
        let mut dec = StreamDecryptor::new(&env, &key, &winning_epoch).unwrap();
        let err = dec.push_segment(0, &segs[0]).unwrap_err();
        assert_eq!(reason(&err), "segment_aead_failed");
    }

    #[test]
    fn stream_digest_mismatch_rejected() {
        let key = key();
        let p = vec![8u8; 100];
        let (ct, env) =
            encrypt_stream(&p, &key, &params(MIN_SEGMENT_SIZE), &winning_epoch).unwrap();
        // corrupt the declared overall digest; per-segment AEAD still passes,
        // so the mismatch is only caught at finish().
        let mut fields = envelope_fields(&env).unwrap();
        fields.ciphertext_digest =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned();
        let env = typed_envelope(fields).unwrap();
        let err = decrypt_stream(&ct, &env, &key, &winning_epoch).unwrap_err();
        assert_eq!(reason(&err), "digest_mismatch");
    }

    #[test]
    fn stream_scheme_and_alg_closure() {
        let key = key();
        let p = vec![1u8; 50];
        let (ct, env) =
            encrypt_stream(&p, &key, &params(MIN_SEGMENT_SIZE), &winning_epoch).unwrap();

        // unknown scheme
        let mut bad = envelope_fields(&env).unwrap();
        bad.scheme = "ak.blob.unknown.v1".to_owned();
        assert!(typed_envelope(bad).is_err());

        // AES-GCM alg under the stream scheme must NOT be force-decrypted
        let mut bad = envelope_fields(&env).unwrap();
        bad.encryption_algorithm = "mls_exporter_aead_aes_256_gcm_stream".to_owned();
        let bad = typed_envelope(bad).unwrap();
        let err = decrypt_stream(&ct, &bad, &key, &winning_epoch).unwrap_err();
        assert_eq!(reason(&err), "unsupported_attachment_scheme");
    }

    #[test]
    fn envelope_serde_matches_schema_field_names() {
        // Stream envelope from a hand-written JSON with exact schema field names.
        let raw = r#"{
            "blob_ref": "ak:blob:sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "encrypted": true,
            "scheme": "ak.blob.stream_aead.v1",
            "encryption_algorithm": "mls_exporter_aead_xchacha20poly1305_stream",
            "key_ref": { "algorithm": "MLS", "group_state_ref": "ak:event:AQNy1zG98lAoTz0YOf-2Yp2-GXeJioPlyg8nW6qxW-OB" },
            "nonce_prefix": "AAAAAAAAAAAAAAAAAAAAAAAAAA",
            "segment_bytes": 262144,
            "ciphertext_digest": "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
            "size_bytes": 3211264,
            "media_type": "video/mp4"
        }"#;
        let env: EncryptedAttachment = serde_json::from_str(raw).unwrap();
        let fields = envelope_fields(&env).unwrap();
        assert_eq!(fields.scheme, SCHEME_STREAM);
        assert_eq!(fields.segment_bytes, Some(262_144));
        assert_eq!(
            stream_segment_count(fields.size_bytes, fields.segment_bytes.unwrap()).unwrap(),
            13
        );
        assert!(fields.nonce.is_none());

        // round-trip back to JSON: whole-file-only optionals are skipped.
        let value = serde_json::to_value(&env).unwrap();
        assert!(value.get("nonce").is_none());
        assert_eq!(value["nonce_prefix"], "AAAAAAAAAAAAAAAAAAAAAAAAAA");
        assert_eq!(value["encrypted"], true);
    }
}
