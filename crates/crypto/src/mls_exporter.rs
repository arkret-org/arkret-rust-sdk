//! RFC 9420 `KDF.Label` encoding, `ExpandWithLabel` and `MLS-Exporter`.
//!
//! These are the byte-level primitives every Arkret exporter-derived secret is
//! built from (`crypto-media/encryption-and-audit.md` §10.1, `encoding.md`
//! §2.1.2). They live in `arkret-crypto` rather than `arkret-mls` because the
//! AEAD nonce contract in [`crate::aead_nonce`] derives sender prefixes with
//! exactly this formula and must not reimplement it: a second derivation is a
//! second wire format, and only one of them can be the one peers reproduce.

use hkdf::Hkdf;
use sha2::{Digest, Sha256, Sha384};

use crate::{Error, Result};

/// RFC 9420 label prefix binding every derivation to the MLS 1.0 KDF domain.
pub const MLS_LABEL_PREFIX: &str = "MLS 1.0 ";
/// `MLS-Exporter`'s inner `ExpandWithLabel` label.
pub const MLS_EXPORTED_LABEL: &str = "exported";
/// `KDF.Nh` for the SHA-256 KDF used by every registered v1 ciphersuite.
pub const MLS_HASH_LEN: usize = 32;

/// Primitive selection for independent KATs; this does not activate a suite.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MlsExporterHash {
    Sha256,
    Sha384,
}

fn encode_mls_varint(value: usize, output: &mut Vec<u8>) -> Result<()> {
    let value = u32::try_from(value)
        .map_err(|_| Error::Crypto("MLS vector length exceeds uint32".to_owned()))?;
    match value {
        0..=63 => output.push(value as u8),
        64..=16_383 => output.extend_from_slice(&(value as u16 | 0x4000).to_be_bytes()),
        16_384..=1_073_741_823 => output.extend_from_slice(&(value | 0x8000_0000).to_be_bytes()),
        _ => {
            return Err(Error::Crypto(
                "MLS vector length exceeds varint range".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Encode the RFC 9420 `KDFLabel` struct consumed as HKDF-Expand `info`.
pub fn mls_kdf_label(length: usize, label: &str, context: &[u8]) -> Result<Vec<u8>> {
    let length = u16::try_from(length)
        .map_err(|_| Error::Crypto("MLS KDF output length exceeds uint16".to_owned()))?;
    let full_label = format!("{MLS_LABEL_PREFIX}{label}");
    let mut encoded = Vec::with_capacity(2 + full_label.len() + context.len() + 8);
    encoded.extend_from_slice(&length.to_be_bytes());
    encode_mls_varint(full_label.len(), &mut encoded)?;
    encoded.extend_from_slice(full_label.as_bytes());
    encode_mls_varint(context.len(), &mut encoded)?;
    encoded.extend_from_slice(context);
    Ok(encoded)
}

/// RFC 9420 `ExpandWithLabel(secret, label, context, length)`.
pub fn mls_expand_with_label(
    secret: &[u8],
    label: &str,
    context: &[u8],
    length: usize,
) -> Result<Vec<u8>> {
    let hkdf = Hkdf::<Sha256>::from_prk(secret)
        .map_err(|_| Error::Crypto("MLS exporter secret is too short".to_owned()))?;
    let info = mls_kdf_label(length, label, context)?;
    let mut output = vec![0u8; length];
    hkdf.expand(&info, output.as_mut_slice())
        .map_err(|_| Error::Crypto("MLS ExpandWithLabel failed".to_owned()))?;
    Ok(output)
}

/// RFC 9420 `MLS-Exporter(label, context, length)` evaluated from an epoch
/// exporter secret.
///
/// The label and the context are two separate exporter parameters: the label
/// derives an intermediate secret, and only the *hash* of the context feeds the
/// second expansion. Folding one into the other counts the label twice and
/// yields output no conformant peer reproduces.
pub fn mls_exporter_from_secret(
    exporter_secret: &[u8],
    label: &str,
    context: &[u8],
    length: usize,
) -> Result<Vec<u8>> {
    if exporter_secret.len() < MLS_HASH_LEN || label.is_empty() || length == 0 {
        return Err(Error::Crypto(
            "MLS exporter requires a 32-byte secret, non-empty label, and output".to_owned(),
        ));
    }
    let derived = mls_expand_with_label(exporter_secret, label, &[], MLS_HASH_LEN)?;
    let context_hash = Sha256::digest(context);
    mls_expand_with_label(&derived, MLS_EXPORTED_LABEL, &context_hash, length)
}

/// RFC 9420 exporter with an explicit cipher-suite Hash/KDF.
/// Live groups use their negotiated runtime exporter, never this KAT adapter.
pub fn mls_exporter_from_secret_with_hash(
    exporter_secret: &[u8],
    label: &str,
    context: &[u8],
    length: usize,
    hash: MlsExporterHash,
) -> Result<Vec<u8>> {
    let nh = match hash {
        MlsExporterHash::Sha256 => 32,
        MlsExporterHash::Sha384 => 48,
    };
    if exporter_secret.len() != nh || label.is_empty() || length == 0 {
        return Err(Error::Crypto(
            "invalid MLS exporter primitive inputs".into(),
        ));
    }
    if hash == MlsExporterHash::Sha256 {
        return mls_exporter_from_secret(exporter_secret, label, context, length);
    }
    let root_info = mls_kdf_label(nh, label, &[])?;
    let mut root = vec![0; nh];
    Hkdf::<Sha384>::from_prk(exporter_secret)
        .map_err(|_| Error::Crypto("invalid SHA-384 exporter secret".into()))?
        .expand(&root_info, &mut root)
        .map_err(|_| Error::Crypto("MLS DeriveSecret failed".into()))?;
    let info = mls_kdf_label(length, MLS_EXPORTED_LABEL, &Sha384::digest(context))?;
    let mut output = vec![0; length];
    Hkdf::<Sha384>::from_prk(&root)
        .map_err(|_| Error::Crypto("invalid SHA-384 derived secret".into()))?
        .expand(&info, &mut output)
        .map_err(|_| Error::Crypto("MLS exporter expansion failed".into()))?;
    Ok(output)
}
