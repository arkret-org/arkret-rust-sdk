//! Registered epoch-content KDF, AEAD and recipient-bound history HPKE.
//! This layer does not infer original authority or durable backup acceptance.

use aes_gcm::Aes128Gcm;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use arkret_canonical::{base64url_decode, base64url_encode, canonical_json_bytes};
use arkret_models_crypto::{
    ContentContext, ContentRootContext, ContentRootSecret, EventContentPreEncryptionHeader,
    HistoryGrant, HistoryKeySelector,
};
use arkret_wire::Hash;
use serde::Serialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{Error, Result};

pub const CONTENT_ROOT_LABEL: &str = "ak.epoch-content-root-v1";
pub const CONTENT_KEY_LABEL: &str = "ak.content-v1";
const ZERO_NONCE: [u8; 12] = [0; 12];

/// Digest a frozen canonical inventory. Native census completeness is independent.
pub fn recovery_inventory_digest(
    inventory: &arkret_models_crypto::ContentRecoveryInventory,
) -> Result<Hash> {
    inventory.validate()?;
    commitment(b"ak.content.recovery_inventory.v1\n", inventory, &[])
}

/// Digest one complete, ordered cleanup result for that same inventory.
/// Winning Commit proofs and durable new roots/backups are verified separately.
pub fn recovery_cleanup_digest(
    inventory: &arkret_models_crypto::ContentRecoveryInventory,
    cleanup: &arkret_models_crypto::ContentCleanupInventory,
) -> Result<Hash> {
    cleanup.validate_for_inventory(inventory, &recovery_inventory_digest(inventory)?)?;
    commitment(b"ak.content.cleanup_inventory.v1\n", cleanup, &[])
}

fn commitment(domain: &[u8], context: &impl Serialize, secret: &[u8]) -> Result<Hash> {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(canonical_json_bytes(context)?);
    digest.update(secret);
    Ok(Hash::new(format!(
        "sha256:{}",
        hex::encode(digest.finalize())
    ))?)
}

/// KAT adapter only. Production obtains the registered exporter from OpenMLS.
pub fn root_from_exporter_secret(
    secret: &[u8],
    context: &ContentRootContext,
) -> Result<ContentRootSecret> {
    context.validate()?;
    let root = Zeroizing::new(crate::mls_exporter::mls_exporter_from_secret(
        secret,
        CONTENT_ROOT_LABEL,
        &canonical_json_bytes(context)?,
        32,
    )?);
    Ok(ContentRootSecret::new(root.as_slice().try_into().map_err(
        |_| Error::Crypto("invalid content exporter width".to_owned()),
    )?))
}

pub fn content_root_ref(root: &ContentRootSecret, context: &ContentRootContext) -> Result<Hash> {
    context.validate()?;
    commitment(b"ak.content.root_ref.v1\n", context, root.expose())
}

pub fn fresh_content_key_salt() -> Result<String> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes)
        .map_err(|error| Error::Crypto(format!("content salt CSPRNG: {error}")))?;
    Ok(base64url_encode(bytes))
}

pub fn derive_content_key(
    root: &ContentRootSecret,
    context: &ContentContext,
) -> Result<Zeroizing<[u8; 16]>> {
    context.validate()?;
    if content_root_ref(root, &context.root_context)? != context.root_ref {
        return Err(Error::Protocol(
            "content root commitment mismatch".to_owned(),
        ));
    }
    let context_hash = Sha256::digest(canonical_json_bytes(context)?);
    let key = Zeroizing::new(crate::mls_exporter::mls_expand_with_label(
        root.expose(),
        CONTENT_KEY_LABEL,
        &context_hash,
        16,
    )?);
    Ok(Zeroizing::new(key.as_slice().try_into().map_err(|_| {
        Error::Crypto("invalid content key width".to_owned())
    })?))
}

pub fn content_key_commitment(context: &ContentContext, key: &[u8; 16]) -> Result<Hash> {
    context.validate()?;
    crate::key_commitment::content_key_commitment_sha256(context, key)
}

pub fn derive_attachment_content_key(
    root: &ContentRootSecret,
    context: &arkret_models_crypto::AttachmentContentKeyContext,
) -> Result<Zeroizing<[u8; 32]>> {
    context.validate()?;
    let context_hash = Sha256::digest(canonical_json_bytes(context)?);
    let bytes = Zeroizing::new(crate::mls_exporter::mls_expand_with_label(
        root.expose(),
        "ak.blob-content-key-v1",
        &context_hash,
        32,
    )?);
    Ok(Zeroizing::new(bytes.as_slice().try_into().map_err(
        |_| Error::Crypto("invalid attachment key width".to_owned()),
    )?))
}

fn checked_key(
    root: &ContentRootSecret,
    header: &EventContentPreEncryptionHeader,
) -> Result<Zeroizing<[u8; 16]>> {
    header.validate()?;
    let key = derive_content_key(root, &header.material.content_context)?;
    let expected = content_key_commitment(&header.material.content_context, &key)?;
    if !bool::from(
        expected
            .as_str()
            .as_bytes()
            .ct_eq(header.material.key_commitment.as_str().as_bytes()),
    ) {
        return Err(Error::Protocol(
            "content key commitment mismatch".to_owned(),
        ));
    }
    Ok(key)
}

/// The caller persists the salt/intent and complete root backup dependencies first.
pub fn seal_content(
    root: &ContentRootSecret,
    header: &EventContentPreEncryptionHeader,
    plaintext: &[u8],
) -> Result<String> {
    let key = checked_key(root, header)?;
    let aad = header.canonical_bytes()?;
    let cipher = Aes128Gcm::new_from_slice(key.as_ref())
        .map_err(|_| Error::Crypto("invalid content key".to_owned()))?;
    let ciphertext = cipher
        .encrypt(
            (&ZERO_NONCE).into(),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Crypto("content AEAD seal failed".to_owned()))?;
    Ok(base64url_encode(ciphertext))
}

/// Original Event proof and original native producer facts are checked before this call.
pub fn open_content(
    root: &ContentRootSecret,
    header: &EventContentPreEncryptionHeader,
    ciphertext: &str,
) -> Result<Vec<u8>> {
    let key = checked_key(root, header)?;
    open_content_from_granted_key(&key, header, ciphertext)
}

/// Open one individually authorized body DEK without acquiring its epoch root.
pub fn open_content_from_granted_key(
    key: &[u8; 16],
    header: &EventContentPreEncryptionHeader,
    ciphertext: &str,
) -> Result<Vec<u8>> {
    header.validate()?;
    let expected = content_key_commitment(&header.material.content_context, key)?;
    if !bool::from(
        expected
            .as_str()
            .as_bytes()
            .ct_eq(header.material.key_commitment.as_str().as_bytes()),
    ) {
        return Err(Error::Protocol(
            "granted content key commitment mismatch".to_owned(),
        ));
    }
    let bytes = base64url_decode(ciphertext)?;
    if base64url_encode(&bytes) != ciphertext || bytes.len() < 16 {
        return Err(Error::Protocol(
            "noncanonical or truncated content ciphertext".to_owned(),
        ));
    }
    let aad = header.canonical_bytes()?;
    let cipher = Aes128Gcm::new_from_slice(key.as_ref())
        .map_err(|_| Error::Crypto("invalid content key".to_owned()))?;
    cipher
        .decrypt(
            (&ZERO_NONCE).into(),
            Payload {
                msg: &bytes,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Crypto("content AEAD authentication failed".to_owned()))
}

#[derive(Serialize)]
struct GrantHeader<'a> {
    recipient: &'a arkret_models_crypto::ContentEndpoint,
    recipient_hpke_key_base64url: &'a str,
    recipient_key_event_ref: &'a arkret_wire::EventId,
    history_cut: &'a arkret_wire::CommittedEventRef,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    expires_at: &'a chrono::DateTime<chrono::Utc>,
    selector: &'a HistoryKeySelector,
}

pub fn history_grant_header(
    grant: &HistoryGrant,
    selector: &HistoryKeySelector,
) -> Result<Vec<u8>> {
    grant.recipient.validate()?;
    Ok(canonical_json_bytes(&GrantHeader {
        recipient: &grant.recipient,
        recipient_hpke_key_base64url: &grant.recipient_hpke_key_base64url,
        recipient_key_event_ref: &grant.recipient_key_event_ref,
        history_cut: &grant.history_cut,
        expires_at: &grant.expires_at,
        selector,
    })?)
}

fn key_length(selector: &HistoryKeySelector, length: usize) -> Result<()> {
    if !match selector {
        HistoryKeySelector::EpochRoot { .. } => length == 32,
        HistoryKeySelector::ContentKey { .. } => matches!(length, 16 | 32),
    } {
        return Err(Error::Protocol(
            "history secret has the wrong selector width".to_owned(),
        ));
    }
    Ok(())
}

pub fn seal_history_key(
    grant: &HistoryGrant,
    selector: &HistoryKeySelector,
    secret: &[u8],
) -> Result<String> {
    key_length(selector, secret.len())?;
    if let HistoryKeySelector::EpochRoot {
        root_context,
        root_ref,
        ..
    } = selector
    {
        let root = ContentRootSecret::new(
            secret
                .try_into()
                .map_err(|_| Error::Protocol("invalid history root width".to_owned()))?,
        );
        if content_root_ref(&root, root_context)? != *root_ref {
            return Err(Error::Protocol(
                "history grant root commitment mismatch".to_owned(),
            ));
        }
    }
    let public = base64url_decode(&grant.recipient_hpke_key_base64url)?;
    if public.len() != 32 || base64url_encode(&public) != grant.recipient_hpke_key_base64url {
        return Err(Error::Protocol("noncanonical history HPKE key".to_owned()));
    }
    let header = history_grant_header(grant, selector)?;
    crate::hpke::seal_x25519_chacha20poly1305(&public, secret, &header, &header)
}

pub fn open_history_key(
    grant: &HistoryGrant,
    selector: &HistoryKeySelector,
    private: &[u8],
    sealed: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let packed = base64url_decode(sealed)?;
    if !matches!(packed.len(), 64 | 80) || base64url_encode(&packed) != sealed {
        return Err(Error::Protocol(
            "history HPKE requires canonical enc || ciphertext || tag".to_owned(),
        ));
    }
    let public = crate::hpke::x25519_public_key(private)?;
    if base64url_encode(public) != grant.recipient_hpke_key_base64url {
        return Err(Error::Protocol(
            "history HPKE recipient mismatch".to_owned(),
        ));
    }
    let header = history_grant_header(grant, selector)?;
    let key = Zeroizing::new(crate::hpke::open_x25519_chacha20poly1305(
        private, sealed, &header, &header,
    )?);
    key_length(selector, key.len())?;
    if let HistoryKeySelector::EpochRoot {
        root_context,
        root_ref,
        ..
    } = selector
    {
        let root = ContentRootSecret::new(
            key.as_slice()
                .try_into()
                .map_err(|_| Error::Protocol("invalid history root width".to_owned()))?,
        );
        if content_root_ref(&root, root_context)? != *root_ref {
            return Err(Error::Protocol(
                "opened history root commitment mismatch".to_owned(),
            ));
        }
    }
    Ok(key)
}

#[cfg(feature = "backup")]
pub fn content_root_backup_info(envelope: &arkret_models_crypto::KeyBackup) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct Info<'a> {
        backup_id: &'a arkret_wire::BackupId,
        series_id: &'a arkret_wire::BackupSeriesId,
        series_sequence: u64,
        actor_id: &'a arkret_wire::ActorId,
        backup_kind: arkret_models_crypto::BackupKind,
        backup_version: &'a str,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        created_at: &'a chrono::DateTime<chrono::Utc>,
    }
    Ok(canonical_json_bytes(&Info {
        backup_id: &envelope.backup_id,
        series_id: &envelope.series_id,
        series_sequence: envelope.series_sequence,
        actor_id: &envelope.actor_id,
        backup_kind: envelope.backup_kind,
        backup_version: &envelope.backup_version,
        created_at: &envelope.created_at,
    })?)
}

#[cfg(feature = "backup")]
fn validate_root_bag(
    envelope: &arkret_models_crypto::KeyBackup,
    bag: &arkret_models_crypto::KeyBackupPlaintext,
) -> Result<()> {
    use arkret_models_crypto::SecretStorageEntry;
    bag.validate_against(&envelope.contents)?;
    if bag.backup_id != envelope.backup_id
        || bag.backup_kind != envelope.backup_kind
        || bag.series_id != envelope.series_id
        || bag.series_sequence != envelope.series_sequence
    {
        return Err(Error::Protocol(
            "root keybag identity or series mismatch".to_owned(),
        ));
    }
    for item in &bag.items {
        let SecretStorageEntry::ContentRoot(root) = item else {
            return Err(Error::Protocol(
                "content root block contains another secret class".to_owned(),
            ));
        };
        if content_root_ref(&root.root_base64url, &root.root_context)? != root.root_ref {
            return Err(Error::Protocol(
                "backup root commitment mismatch".to_owned(),
            ));
        }
    }
    Ok(())
}

#[cfg(feature = "backup")]
fn encoded_backup_bytes(bytes: impl AsRef<[u8]>) -> Result<arkret_wire::Base64UrlString> {
    arkret_wire::Base64UrlString::new(base64url_encode(bytes))
        .map_err(|error| Error::Protocol(error.to_owned()))
}

/// Seal a prepared immutable root block and sign every actual envelope member.
/// Recipient public material must already come from the accepted recovery policy.
#[cfg(feature = "backup")]
pub fn seal_content_root_backup(
    mut envelope: arkret_models_crypto::KeyBackup,
    bag: &arkret_models_crypto::KeyBackupPlaintext,
    recipient_public: &[u8],
    sign: impl FnOnce(&[u8]) -> Result<Vec<u8>>,
) -> Result<arkret_models_crypto::KeyBackup> {
    validate_root_bag(&envelope, bag)?;
    let plaintext = Zeroizing::new(canonical_json_bytes(bag)?);
    let info = content_root_backup_info(&envelope)?;
    let aad = crate::backup::key_backup_aead_aad(&envelope)
        .map_err(|error| Error::Protocol(error.to_string()))?;
    let sealed =
        crate::hpke::seal_x25519_chacha20poly1305(recipient_public, &plaintext, &info, &aad)?;
    let bytes = base64url_decode(sealed)?;
    envelope.encryption.aead.enc = Some(encoded_backup_bytes(&bytes[..32])?);
    envelope.ciphertext = encoded_backup_bytes(&bytes[32..])?;
    envelope.ciphertext_digest = Hash::new(arkret_canonical::sha256_digest(&bytes[32..]))?;
    envelope.validate()?;
    envelope.signature_proof.signature =
        encoded_backup_bytes(sign(&envelope.signing_payload_bytes()?)?)?;
    Ok(envelope)
}

/// Verify the exact original signer first, then open and compare the entire index.
/// The verifier checks native authority at creation, not current-device freshness.
#[cfg(feature = "backup")]
pub fn open_content_root_backup(
    envelope: &arkret_models_crypto::KeyBackup,
    recipient_private: &[u8],
    verify_original: impl FnOnce(&[u8], &arkret_models_crypto::KeyBackupSignatureProof) -> Result<()>,
) -> Result<arkret_models_crypto::KeyBackupPlaintext> {
    envelope.validate()?;
    verify_original(
        &envelope.signing_payload_bytes()?,
        &envelope.signature_proof,
    )?;
    let ciphertext = base64url_decode(envelope.ciphertext.as_str())?;
    if base64url_encode(&ciphertext) != envelope.ciphertext.as_str()
        || envelope.ciphertext_digest.as_str() != arkret_canonical::sha256_digest(&ciphertext)
    {
        return Err(Error::Protocol(
            "root backup ciphertext commitment mismatch".to_owned(),
        ));
    }
    let enc = envelope
        .encryption
        .aead
        .enc
        .as_ref()
        .ok_or_else(|| Error::Protocol("root backup lacks enc".to_owned()))?;
    let mut bytes = base64url_decode(enc.as_str())?;
    if bytes.len() != 32 || base64url_encode(&bytes) != enc.as_str() {
        return Err(Error::Protocol(
            "invalid root backup encapsulated key".to_owned(),
        ));
    }
    bytes.extend_from_slice(&ciphertext);
    let info = content_root_backup_info(envelope)?;
    let aad = crate::backup::key_backup_aead_aad(envelope)
        .map_err(|error| Error::Protocol(error.to_string()))?;
    let plaintext = Zeroizing::new(crate::hpke::open_x25519_chacha20poly1305(
        recipient_private,
        &base64url_encode(bytes),
        &info,
        &aad,
    )?);
    let bag: arkret_models_crypto::KeyBackupPlaintext = serde_json::from_slice(&plaintext)?;
    validate_root_bag(envelope, &bag)?;
    Ok(bag)
}
