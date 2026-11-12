//! Manager-only private archive transfer. A successful open is not a physical
//! custody theorem: the importer must durably store the entire verified cut
//! before the SDK makes the challenge-bound confirmation available.

use arkret_models_crypto::SecretBytes;
use arkret_models_integration::*;
use arkret_wire::{DetachedSignatureContext, DidUrl, Hash};
use ed25519_dalek::SigningKey;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::{DidDocument, IdentityError, Result};

const TRANSFER_DOMAIN: &[u8] = b"ak.realm_actor_content_backup_handover.v1\n";
const CONFIRMATION_DOMAIN: &[u8] = b"ak.realm_actor_content_backup_handover_confirmation.v1\n";

fn invalid(message: impl std::fmt::Display) -> IdentityError {
    IdentityError::Protocol(message.to_string())
}

fn offer_input(
    offer: &RealmActorContentBackupHandoverOffer,
) -> Result<RealmActorContentBackupHandoverOfferSignatureInput> {
    Ok(serde_json::from_value(arkret_canonical::unsigned_value(
        offer,
        &["signature"],
    )?)?)
}

pub fn sign_realm_actor_backup_handover_offer(
    input: RealmActorContentBackupHandoverOfferSignatureInput,
    method: DidUrl,
    signed_at: chrono::DateTime<chrono::Utc>,
    key: &SigningKey,
) -> Result<RealmActorContentBackupHandoverOffer> {
    input.realm_actor_id.validate()?;
    input.next_content_backup_recipient.validate()?;
    if input.expires_at <= signed_at {
        return Err(invalid("archive offer expired before signing"));
    }
    let signature = arkret_signatures::detached_object::sign_detached_object(
        &input,
        DetachedSignatureContext::RealmActorContentBackupOffer,
        method,
        signed_at,
        key,
    )?;
    let mut value = serde_json::to_value(input)?;
    value["signature"] = serde_json::to_value(signature)?;
    Ok(serde_json::from_value(value)?)
}

fn verify_handover_offer_original(
    offer: &RealmActorContentBackupHandoverOffer,
    accepted_new_service_document: &DidDocument,
) -> Result<()> {
    offer.realm_actor_id.validate()?;
    offer.next_content_backup_recipient.validate()?;
    if arkret_wire::project_did_to_core_id(&accepted_new_service_document.id)?
        != offer.new_service_id
        || offer.expires_at <= offer.signature.created_at
    {
        return Err(invalid(
            "archive offer does not bind the accepted new Service or freshness cut",
        ));
    }
    crate::validate_verification_method_relationship(
        accepted_new_service_document,
        &offer.signature.verification_method,
        &accepted_new_service_document.id,
        crate::DidVerificationRelationship::AssertionMethod,
    )
    .map_err(invalid)?;
    let key = crate::public_key_material_from_document(
        accepted_new_service_document,
        &offer.signature.verification_method,
    )
    .map_err(invalid)?;
    arkret_signatures::detached_object::verify_detached_object_signature(
        &offer.signature,
        &offer_input(offer)?,
        DetachedSignatureContext::RealmActorContentBackupOffer,
        &key,
    )
    .map_err(Into::into)
}

pub fn verify_realm_actor_backup_handover_offer(
    offer: &RealmActorContentBackupHandoverOffer,
    accepted_original_service_document: &DidDocument,
    evaluated_at: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    verify_handover_offer_original(offer, accepted_original_service_document)?;
    import_evaluated_at(offer, evaluated_at, None)?;
    Ok(())
}

fn import_evaluated_at(
    offer: &RealmActorContentBackupHandoverOffer,
    confirmed_at: chrono::DateTime<chrono::Utc>,
    retained_imported_at: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<chrono::DateTime<chrono::Utc>> {
    let imported_at = retained_imported_at.unwrap_or(confirmed_at);
    if imported_at < offer.signature.created_at
        || imported_at >= offer.expires_at
        || imported_at > confirmed_at
        || confirmed_at < offer.signature.created_at
    {
        return Err(invalid(
            "archive offer was not durably imported during its original validity interval",
        ));
    }
    Ok(imported_at)
}

fn transfer_info(offer: &RealmActorContentBackupHandoverOffer) -> Result<Vec<u8>> {
    let offer_digest = Hash::new(arkret_canonical::canonical_sha256(offer)?)?;
    let mut info = TRANSFER_DOMAIN.to_vec();
    info.extend(arkret_canonical::canonical_json_bytes(&serde_json::json!({
        "realm_actor_id":offer.realm_actor_id,"manager_ref":offer.manager_ref,
        "new_service_id":offer.new_service_id,"offer_digest":offer_digest,"inventory_digest":offer.inventory_digest}))?);
    Ok(info)
}

fn confirmation_input(
    plaintext: &RealmActorContentBackupHandoverPlaintext,
) -> Result<RealmActorContentBackupHandoverConfirmationSignatureInput> {
    let handover_digest = Hash::new(arkret_canonical::canonical_sha256(plaintext)?)?;
    let inventory_digest = plaintext.inventory_manifest.inventory_digest()?;
    let mut transcript = CONFIRMATION_DOMAIN.to_vec();
    transcript.extend(arkret_canonical::canonical_json_bytes(&serde_json::json!({
        "offer_digest":plaintext.offer_digest,"inventory_digest":inventory_digest,"handover_digest":handover_digest}))?);
    let mut mac =
        Hmac::<Sha256>::new_from_slice(plaintext.challenge_base64url.expose()).map_err(invalid)?;
    mac.update(&transcript);
    Ok(RealmActorContentBackupHandoverConfirmationSignatureInput {
        offer_digest: plaintext.offer_digest.clone(),
        inventory_digest,
        handover_digest,
        challenge_response_base64url: arkret_canonical::base64url_encode(
            mac.finalize().into_bytes(),
        ),
    })
}

fn validate_plaintext(
    offer: &RealmActorContentBackupHandoverOffer,
    plaintext: &RealmActorContentBackupHandoverPlaintext,
) -> Result<()> {
    if plaintext.offer_digest.as_str() != arkret_canonical::canonical_sha256(offer)?
        || plaintext.inventory_manifest.realm_actor_id != offer.realm_actor_id
        || plaintext.inventory_manifest.manager_ref != offer.manager_ref
        || plaintext.inventory_manifest.archive_revision != offer.archive_revision
        || plaintext.inventory_manifest.inventory_digest()? != offer.inventory_digest
    {
        return Err(invalid(
            "private archive does not bind the full immutable offered inventory cut",
        ));
    }
    let mut keys = std::collections::BTreeMap::new();
    for key in &plaintext.recipient_keys {
        key.content_backup_recipient.validate()?;
        if key.content_backup_recipient.public_key_base64url
            == offer.next_content_backup_recipient.public_key_base64url
        {
            return Err(invalid(
                "new manager must use a fresh independent archive recipient key",
            ));
        }
        let derived = arkret_crypto::hpke::x25519_public_key(key.private_key_base64url.expose())
            .map_err(invalid)?;
        if arkret_canonical::base64url_encode(derived)
            != key.content_backup_recipient.public_key_base64url
            || keys
                .insert(
                    arkret_canonical::canonical_json_bytes(&key.recipient_ref)?,
                    &key.content_backup_recipient,
                )
                .is_some()
        {
            return Err(invalid(
                "archive contains duplicate or mismatching original recipient private keys",
            ));
        }
    }
    let mut declarations = std::collections::BTreeSet::new();
    for entry in &plaintext.inventory_manifest.entries {
        if let RealmActorArchiveInventoryEntry::Recipient(entry) = entry {
            declarations.insert(arkret_canonical::canonical_json_bytes(
                &entry.recipient_ref,
            )?);
        }
    }
    if keys
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        != declarations
    {
        return Err(invalid(
            "private archive key set must exactly equal its retained original declarations",
        ));
    }
    for entry in &plaintext.inventory_manifest.entries {
        match entry {
            RealmActorArchiveInventoryEntry::Recipient(entry) => {
                if keys
                    .get(&arkret_canonical::canonical_json_bytes(
                        &entry.recipient_ref,
                    )?)
                    .copied()
                    != Some(&entry.content_backup_recipient)
                {
                    return Err(invalid(
                        "archive omits a retained recipient key or declaration",
                    ));
                }
            }
            RealmActorArchiveInventoryEntry::Backup(entry) => {
                let binding = entry.backup.auth_binding.as_ref().ok_or_else(|| {
                    invalid("archive backup lacks its original native recipient binding")
                })?;
                let recipient = keys
                    .get(&arkret_canonical::canonical_json_bytes(
                        &binding.recipient_ref,
                    )?)
                    .ok_or_else(|| {
                        invalid("archive cannot open every retained first-PUT packet")
                    })?;
                entry.backup.validate_native_recipient(recipient)?;
            }
            RealmActorArchiveInventoryEntry::Series(_) => {}
        }
    }
    Ok(())
}

/// Retained only in the old manager's private transfer capability.
pub struct PendingRealmActorBackupHandover {
    sealed: RealmActorContentBackupSealedHandover,
    expected: RealmActorContentBackupHandoverConfirmationSignatureInput,
}
impl Drop for PendingRealmActorBackupHandover {
    fn drop(&mut self) {
        self.expected.challenge_response_base64url.zeroize();
    }
}

// Local private storage format only. It is neither a protocol DTO nor a
// serializable current/source authority. Its bytes must be authenticated and
// encrypted by the independent manager vault before they become durable.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateHandoverCheckpoint {
    sealed: RealmActorContentBackupSealedHandover,
    sealed_digest: Hash,
    offer_digest: Hash,
    inventory_digest: Hash,
    handover_digest: Hash,
    expected_mac: SecretBytes,
}
const PRIVATE_CHECKPOINT_PREFIX: &[u8] = b"arkret.local.manager-archive-handover-checkpoint\n";
impl std::fmt::Debug for PendingRealmActorBackupHandover {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PendingRealmActorBackupHandover(<private>)")
    }
}
impl PendingRealmActorBackupHandover {
    pub fn sealed(&self) -> &RealmActorContentBackupSealedHandover {
        &self.sealed
    }

    pub fn export_private_checkpoint(&self) -> Result<arkret_keystore::KeyBytes> {
        let decoded = Zeroizing::new(arkret_canonical::base64url_decode(
            &self.expected.challenge_response_base64url,
        )?);
        let expected_mac = SecretBytes::new(
            decoded
                .as_slice()
                .try_into()
                .map_err(|_| invalid("invalid pending transfer MAC width"))?,
        );
        let checkpoint = PrivateHandoverCheckpoint {
            sealed: self.sealed.clone(),
            sealed_digest: Hash::new(arkret_canonical::canonical_sha256(&self.sealed)?)?,
            offer_digest: self.expected.offer_digest.clone(),
            inventory_digest: self.expected.inventory_digest.clone(),
            handover_digest: self.expected.handover_digest.clone(),
            expected_mac,
        };
        let mut bytes = PRIVATE_CHECKPOINT_PREFIX.to_vec();
        bytes.extend(arkret_canonical::canonical_json_bytes(&checkpoint)?);
        Ok(arkret_keystore::KeyBytes::new(bytes))
    }

    /// Restore only an authenticated private-vault checkpoint. Public sealed
    /// packets cannot construct this state. No current permission is restored;
    /// the caller independently checks current manager/offer/transaction gates.
    pub fn resume_private_checkpoint(private: &arkret_keystore::KeyBytes) -> Result<Self> {
        let bytes = private
            .as_slice()
            .strip_prefix(PRIVATE_CHECKPOINT_PREFIX)
            .ok_or_else(|| invalid("not a private manager archive handover checkpoint"))?;
        let checkpoint: PrivateHandoverCheckpoint = serde_json::from_slice(bytes)?;
        if checkpoint.sealed_digest.as_str()
            != arkret_canonical::canonical_sha256(&checkpoint.sealed)?
            || checkpoint.offer_digest.as_str()
                != arkret_canonical::canonical_sha256(&checkpoint.sealed.offer)?
            || checkpoint.inventory_digest != checkpoint.sealed.offer.inventory_digest
            || !checkpoint.handover_digest.as_str().starts_with("sha256:")
            || arkret_canonical::base64url_decode(&checkpoint.sealed.enc)?.len() != 32
        {
            return Err(invalid(
                "private archive checkpoint is not bound to its original sealed offer/header",
            ));
        }
        Ok(Self {
            sealed: checkpoint.sealed,
            expected: RealmActorContentBackupHandoverConfirmationSignatureInput {
                offer_digest: checkpoint.offer_digest,
                inventory_digest: checkpoint.inventory_digest,
                handover_digest: checkpoint.handover_digest,
                challenge_response_base64url: arkret_canonical::base64url_encode(
                    checkpoint.expected_mac.expose(),
                ),
            },
        })
    }

    pub fn verify_confirmation(
        &self,
        confirmation: &RealmActorContentBackupHandoverConfirmation,
        accepted_new_service_document: &DidDocument,
    ) -> Result<()> {
        if confirmation.offer_digest != self.expected.offer_digest
            || confirmation.inventory_digest != self.expected.inventory_digest
            || confirmation.handover_digest != self.expected.handover_digest
            || !bool::from(subtle::ConstantTimeEq::ct_eq(
                confirmation.challenge_response_base64url.as_bytes(),
                self.expected.challenge_response_base64url.as_bytes(),
            ))
        {
            return Err(invalid(
                "archive import confirmation does not answer the sealed challenge and complete cut",
            ));
        }
        if arkret_wire::project_did_to_core_id(&accepted_new_service_document.id)?
            != self.sealed.offer.new_service_id
        {
            return Err(invalid("archive confirmation belongs to another Service"));
        }
        crate::validate_verification_method_relationship(
            accepted_new_service_document,
            &confirmation.signature.verification_method,
            &accepted_new_service_document.id,
            crate::DidVerificationRelationship::AssertionMethod,
        )
        .map_err(invalid)?;
        let key = crate::public_key_material_from_document(
            accepted_new_service_document,
            &confirmation.signature.verification_method,
        )
        .map_err(invalid)?;
        arkret_signatures::detached_object::verify_detached_object_signature(
            &confirmation.signature,
            &self.expected,
            DetachedSignatureContext::RealmActorContentBackupConfirmation,
            &key,
        )
        .map_err(Into::into)
    }
}

pub fn seal_realm_actor_backup_handover(
    offer: RealmActorContentBackupHandoverOffer,
    accepted_new_service_document: &DidDocument,
    manifest: RealmActorArchiveInventoryManifest,
    recipient_keys: Vec<RealmActorContentBackupPrivateRecipientKey>,
    evaluated_at: chrono::DateTime<chrono::Utc>,
) -> Result<PendingRealmActorBackupHandover> {
    verify_realm_actor_backup_handover_offer(&offer, accepted_new_service_document, evaluated_at)?;
    let mut challenge = [0; 32];
    getrandom::fill(&mut challenge).map_err(invalid)?;
    let plaintext = RealmActorContentBackupHandoverPlaintext {
        offer_digest: Hash::new(arkret_canonical::canonical_sha256(&offer)?)?,
        inventory_manifest: manifest,
        recipient_keys,
        challenge_base64url: SecretBytes::new(challenge),
    };
    validate_plaintext(&offer, &plaintext)?;
    let expected = confirmation_input(&plaintext)?;
    let raw = Zeroizing::new(arkret_canonical::canonical_json_bytes(&plaintext)?);
    let public = arkret_canonical::base64url_decode(
        &offer.next_content_backup_recipient.public_key_base64url,
    )?;
    let framed = arkret_crypto::hpke::seal_x25519_chacha20poly1305(
        &public,
        &raw,
        &transfer_info(&offer)?,
        &arkret_canonical::canonical_json_bytes(&offer)?,
    )
    .map_err(invalid)?;
    let bytes = arkret_canonical::base64url_decode(framed)?;
    Ok(PendingRealmActorBackupHandover {
        sealed: RealmActorContentBackupSealedHandover {
            offer,
            hpke_suite: RealmActorContentBackupSealedHandoverHpkeSuite::Value,
            enc: arkret_canonical::base64url_encode(&bytes[..32]),
            ciphertext_base64url: arkret_canonical::base64url_encode(&bytes[32..]),
        },
        expected,
    })
}

/// Trusted runtime inputs from two independent Service-document cuts. This is
/// neither a wire carrier nor deserializable current authority.
pub struct RealmActorBackupHandoverImportContext<'a> {
    pub offer_original_document: &'a DidDocument,
    pub confirmation_current_document: &'a DidDocument,
    pub confirmation_method: DidUrl,
    pub confirmation_signing_key: &'a SigningKey,
    pub confirmed_at: chrono::DateTime<chrono::Utc>,
}

/// Exact private-vault lookup identity. Its hashes bind the complete sealed
/// packet and decrypted cut; it grants no manager or current permission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmActorBackupHandoverImportIdentity {
    pub realm_actor_id: arkret_wire::RealmActorId,
    pub sealed_digest: Hash,
    pub offer_digest: Hash,
    pub inventory_digest: Hash,
    pub handover_digest: Hash,
}

fn validate_confirmation_signer(
    offer: &RealmActorContentBackupHandoverOffer,
    context: &RealmActorBackupHandoverImportContext<'_>,
) -> Result<()> {
    let document = context.confirmation_current_document;
    if arkret_wire::project_did_to_core_id(&document.id)? != offer.new_service_id
        || context.confirmed_at < offer.signature.created_at
    {
        return Err(invalid(
            "archive confirmation does not bind the current new Service/time",
        ));
    }
    crate::validate_verification_method_relationship(
        document,
        &context.confirmation_method,
        &document.id,
        crate::DidVerificationRelationship::AssertionMethod,
    )
    .map_err(invalid)?;
    let key = crate::public_key_material_from_document(document, &context.confirmation_method)
        .map_err(invalid)?;
    if key.ed25519_bytes()? != context.confirmation_signing_key.verifying_key().to_bytes() {
        return Err(invalid(
            "archive confirmation signer differs from its current accepted Service document",
        ));
    }
    Ok(())
}

/// Open and verify the complete private cut before durable import and signing.
/// `retained_imported_at` must read an existing immutable manager-vault record
/// for this exact identity; it must never guess/backdate a new import. An absent
/// record evaluates offer freshness at `confirmed_at`, before mutation. The
/// durable callback imports the verified cut atomically and preserves the given
/// original import time on cold/idempotent replay. Both callbacks are trusted
/// local storage adapters, never public verified flags or network DTOs.
pub fn import_realm_actor_backup_handover(
    sealed: &RealmActorContentBackupSealedHandover,
    fresh_private: &SecretBytes,
    authority: &crate::VerifiedRealmAuthority,
    keys: &dyn crate::RealmAuthorityKeyDirectory,
    context: &RealmActorBackupHandoverImportContext<'_>,
    retained_imported_at: impl FnOnce(
        &RealmActorBackupHandoverImportIdentity,
    ) -> Result<Option<chrono::DateTime<chrono::Utc>>>,
    durable_import: impl FnOnce(
        &RealmActorBackupHandoverImportIdentity,
        &RealmActorContentBackupHandoverPlaintext,
        chrono::DateTime<chrono::Utc>,
    ) -> Result<()>,
) -> Result<RealmActorContentBackupHandoverConfirmation> {
    verify_handover_offer_original(&sealed.offer, context.offer_original_document)?;
    validate_confirmation_signer(&sealed.offer, context)?;
    if arkret_canonical::base64url_encode(
        arkret_crypto::hpke::x25519_public_key(fresh_private.expose()).map_err(invalid)?,
    ) != sealed
        .offer
        .next_content_backup_recipient
        .public_key_base64url
    {
        return Err(invalid(
            "fresh manager archive private key does not match its signed offer",
        ));
    }
    let mut frame = arkret_canonical::base64url_decode(&sealed.enc)?;
    if frame.len() != 32 {
        return Err(invalid("invalid archive HPKE encapsulated key"));
    }
    frame.extend(arkret_canonical::base64url_decode(
        &sealed.ciphertext_base64url,
    )?);
    let bytes = Zeroizing::new(
        arkret_crypto::hpke::open_x25519_chacha20poly1305(
            fresh_private.expose(),
            &arkret_canonical::base64url_encode(frame),
            &transfer_info(&sealed.offer)?,
            &arkret_canonical::canonical_json_bytes(&sealed.offer)?,
        )
        .map_err(invalid)?,
    );
    let plaintext: RealmActorContentBackupHandoverPlaintext = serde_json::from_slice(&bytes)?;
    validate_plaintext(&sealed.offer, &plaintext)?;
    let identity = RealmActorBackupHandoverImportIdentity {
        realm_actor_id: sealed.offer.realm_actor_id.clone(),
        sealed_digest: Hash::new(arkret_canonical::canonical_sha256(sealed)?)?,
        offer_digest: plaintext.offer_digest.clone(),
        inventory_digest: plaintext.inventory_manifest.inventory_digest()?,
        handover_digest: Hash::new(arkret_canonical::canonical_sha256(&plaintext)?)?,
    };
    let original_imported_at = import_evaluated_at(
        &sealed.offer,
        context.confirmed_at,
        retained_imported_at(&identity)?,
    )?;
    crate::verify_realm_actor_archive_inventory(&plaintext.inventory_manifest, authority, keys)?;
    for entry in &plaintext.inventory_manifest.entries {
        if let RealmActorArchiveInventoryEntry::Backup(entry) = entry {
            crate::verify_realm_actor_content_backup_source(
                &entry.backup,
                &entry.native_source,
                authority,
            )?;
            let key = plaintext
                .recipient_keys
                .iter()
                .find(|key| key.recipient_ref == entry.native_source.admission.recipient_ref)
                .ok_or_else(|| invalid("archive lacks original packet recipient private key"))?;
            arkret_crypto::content_history::open_content_root_backup(
                &entry.backup,
                key.private_key_base64url.expose(),
                |_, _| {
                    crate::verify_realm_actor_content_backup_source(
                        &entry.backup,
                        &entry.native_source,
                        authority,
                    )
                    .map_err(|error| arkret_crypto::Error::Protocol(error.to_string()))
                },
            )
            .map_err(invalid)?;
        }
    }
    let input = confirmation_input(&plaintext)?;
    durable_import(&identity, &plaintext, original_imported_at)?;
    let signature = arkret_signatures::detached_object::sign_detached_object(
        &input,
        DetachedSignatureContext::RealmActorContentBackupConfirmation,
        context.confirmation_method.clone(),
        context.confirmed_at,
        context.confirmation_signing_key,
    )?;
    let mut value = serde_json::to_value(input)?;
    value["signature"] = serde_json::to_value(signature)?;
    Ok(serde_json::from_value(value)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn formal_private_transfer_uses_registered_hpke_domains_and_real_challenge_response() {
        let f:serde_json::Value=serde_json::from_str(include_str!("../../../../arkret-spec/spec/v1/artifacts/fixtures/realm-actor-content-backup-fixture.json")).unwrap();
        let sealed: RealmActorContentBackupSealedHandover =
            serde_json::from_value(f["private_handover"]["sealed"].clone()).unwrap();
        assert_eq!(
            arkret_canonical::base64url_encode(transfer_info(&sealed.offer).unwrap()),
            arkret_canonical::base64url_encode(hex_bytes(
                f["private_handover"]["info_hex"].as_str().unwrap()
            ))
        );
        let private = hex_bytes(
            f["test_material"]["next_archive_private_hex"]
                .as_str()
                .unwrap(),
        );
        let mut framed = arkret_canonical::base64url_decode(&sealed.enc).unwrap();
        framed.extend(arkret_canonical::base64url_decode(&sealed.ciphertext_base64url).unwrap());
        let plaintext = Zeroizing::new(
            arkret_crypto::hpke::open_x25519_chacha20poly1305(
                &private,
                &arkret_canonical::base64url_encode(&framed),
                &transfer_info(&sealed.offer).unwrap(),
                &arkret_canonical::canonical_json_bytes(&sealed.offer).unwrap(),
            )
            .unwrap(),
        );
        let raw_plaintext: serde_json::Value = serde_json::from_slice(&plaintext).unwrap();
        // Diagnose each concrete formal branch before the untagged union so a
        // schema-mapped field regression names its original entry and error.
        for entry in raw_plaintext["inventory_manifest"]["entries"]
            .as_array()
            .unwrap()
        {
            let result = match entry["kind"].as_str().unwrap() {
                "backup" => serde_json::from_value::<RealmActorArchiveBackupEntry>(entry.clone())
                    .map(|_| ()),
                "recipient" => {
                    serde_json::from_value::<RealmActorArchiveRecipientEntry>(entry.clone())
                        .map(|_| ())
                }
                "series" => serde_json::from_value::<RealmActorArchiveSeriesEntry>(entry.clone())
                    .map(|_| ()),
                other => panic!("unexpected formal inventory entry {other}"),
            };
            result.unwrap_or_else(|error| panic!("formal inventory {}: {error}", entry["kind"]));
        }
        let plaintext: RealmActorContentBackupHandoverPlaintext =
            serde_json::from_value(raw_plaintext).unwrap();
        validate_plaintext(&sealed.offer, &plaintext).unwrap();
        let expected = confirmation_input(&plaintext).unwrap();
        assert_eq!(
            expected.challenge_response_base64url,
            f["private_handover"]["confirmation"]["challenge_response_base64url"]
        );
        let wrong = [17; 32];
        assert!(
            arkret_crypto::hpke::open_x25519_chacha20poly1305(
                &wrong,
                &arkret_canonical::base64url_encode(&framed),
                &transfer_info(&sealed.offer).unwrap(),
                &arkret_canonical::canonical_json_bytes(&sealed.offer).unwrap()
            )
            .is_err()
        );
        assert!(
            !format!("{plaintext:?}").contains(&arkret_canonical::base64url_encode(
                plaintext.challenge_base64url.expose()
            ))
        );
        let method = &sealed.offer.signature.verification_method;
        let did = crate::verification_method_did(method.as_str()).unwrap();
        let public = arkret_canonical::base64url_decode(
            f["handover_offer_case"]["public_key_base64url"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let public: [u8; 32] = public.as_slice().try_into().unwrap();
        let document: DidDocument = serde_json::from_value(serde_json::json!({
            "id":did,"verificationMethod":[{"id":method,"type":"Multikey","controller":did,
                "publicKeyMultibase":arkret_canonical::ed25519_pubkey_to_did_key_multibase(&public)}],"assertionMethod":[method]
        })).unwrap();
        let confirmation: RealmActorContentBackupHandoverConfirmation =
            serde_json::from_value(f["private_handover"]["confirmation"].clone()).unwrap();
        let pending = PendingRealmActorBackupHandover { sealed, expected };
        pending
            .verify_confirmation(&confirmation, &document)
            .unwrap();
        let sealed_before = arkret_canonical::canonical_json_bytes(pending.sealed()).unwrap();
        let checkpoint = pending.export_private_checkpoint().unwrap();
        drop(pending);
        let restored =
            PendingRealmActorBackupHandover::resume_private_checkpoint(&checkpoint).unwrap();
        assert_eq!(
            arkret_canonical::canonical_json_bytes(restored.sealed()).unwrap(),
            sealed_before
        );
        restored
            .verify_confirmation(&confirmation, &document)
            .unwrap();
        let mut tampered: serde_json::Value = serde_json::from_slice(
            checkpoint
                .as_slice()
                .strip_prefix(PRIVATE_CHECKPOINT_PREFIX)
                .unwrap(),
        )
        .unwrap();
        tampered["sealed"]["ciphertext_base64url"] =
            serde_json::json!(arkret_canonical::base64url_encode([2; 32]));
        let mut tampered_bytes = PRIVATE_CHECKPOINT_PREFIX.to_vec();
        tampered_bytes.extend(arkret_canonical::canonical_json_bytes(&tampered).unwrap());
        assert!(
            PendingRealmActorBackupHandover::resume_private_checkpoint(
                &arkret_keystore::KeyBytes::new(tampered_bytes)
            )
            .is_err()
        );
    }
    fn formal_offer_document() -> (
        serde_json::Value,
        RealmActorContentBackupSealedHandover,
        DidDocument,
    ) {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../arkret-spec/spec/v1/artifacts/fixtures/realm-actor-content-backup-fixture.json"
        )).unwrap();
        let sealed: RealmActorContentBackupSealedHandover =
            serde_json::from_value(fixture["private_handover"]["sealed"].clone()).unwrap();
        let method = &sealed.offer.signature.verification_method;
        let did = crate::verification_method_did(method.as_str()).unwrap();
        let public = arkret_canonical::base64url_decode(
            fixture["handover_offer_case"]["public_key_base64url"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let public: [u8; 32] = public.as_slice().try_into().unwrap();
        // Leaf signature relationship inputs: callers independently qualify
        // each original/current document. No current document is patched with
        // an old verification method to make the old offer pass.
        let document = serde_json::from_value(serde_json::json!({
            "id":did,"verificationMethod":[{"id":method,"type":"Multikey","controller":did,
                "publicKeyMultibase":arkret_canonical::ed25519_pubkey_to_did_key_multibase(&public)}],"assertionMethod":[method]
        })).unwrap();
        (fixture, sealed, document)
    }

    #[test]
    fn cold_import_after_service_key_rotation_preserves_offer_and_signs_confirmation_at_real_now() {
        let (fixture, sealed, original_document) = formal_offer_document();
        let first_imported_at = sealed.offer.signature.created_at + chrono::Duration::seconds(1);
        let now = sealed.offer.expires_at + chrono::Duration::hours(1);
        assert_eq!(
            import_evaluated_at(&sealed.offer, now, Some(first_imported_at)).unwrap(),
            first_imported_at
        );
        verify_handover_offer_original(&sealed.offer, &original_document).unwrap();
        let current_key = SigningKey::from_bytes(&[93; 32]);
        let method = DidUrl::new(format!("{}#rotated-current", original_document.id)).unwrap();
        let current_document: DidDocument = serde_json::from_value(serde_json::json!({
            "id":original_document.id,"verificationMethod":[{"id":method,"type":"Multikey","controller":original_document.id,
            "publicKeyMultibase":arkret_canonical::ed25519_pubkey_to_did_key_multibase(current_key.verifying_key().as_bytes())}],
            "assertionMethod":[method]
        })).unwrap();
        let context = RealmActorBackupHandoverImportContext {
            offer_original_document: &original_document,
            confirmation_current_document: &current_document,
            confirmation_method: method.clone(),
            confirmation_signing_key: &current_key,
            confirmed_at: now,
        };
        validate_confirmation_signer(&sealed.offer, &context).unwrap();
        assert!(verify_handover_offer_original(&sealed.offer, &current_document).is_err());
        let old_context = RealmActorBackupHandoverImportContext {
            confirmation_current_document: &original_document,
            ..context
        };
        assert!(validate_confirmation_signer(&sealed.offer, &old_context).is_err());
        let plaintext: RealmActorContentBackupHandoverPlaintext =
            serde_json::from_value(fixture["private_handover"]["plaintext"].clone()).unwrap();
        let expected = confirmation_input(&plaintext).unwrap();
        let signature = arkret_signatures::detached_object::sign_detached_object(
            &expected,
            DetachedSignatureContext::RealmActorContentBackupConfirmation,
            method,
            now,
            &current_key,
        )
        .unwrap();
        assert_eq!(signature.created_at, now);
        assert_ne!(signature.created_at, first_imported_at);
        let mut value = serde_json::to_value(&expected).unwrap();
        value["signature"] = serde_json::to_value(signature).unwrap();
        let confirmation: RealmActorContentBackupHandoverConfirmation =
            serde_json::from_value(value).unwrap();
        let pending = PendingRealmActorBackupHandover { sealed, expected };
        let packet_before = arkret_canonical::canonical_json_bytes(pending.sealed()).unwrap();
        let checkpoint = pending.export_private_checkpoint().unwrap();
        drop(pending);
        let restored =
            PendingRealmActorBackupHandover::resume_private_checkpoint(&checkpoint).unwrap();
        assert_eq!(
            arkret_canonical::canonical_json_bytes(restored.sealed()).unwrap(),
            packet_before
        );
        restored
            .verify_confirmation(&confirmation, &current_document)
            .unwrap();
        assert!(
            restored
                .verify_confirmation(&confirmation, &original_document)
                .is_err()
        );
    }

    #[test]
    fn expired_offer_without_durable_import_and_invalid_retained_import_times_are_refused() {
        let (_, sealed, document) = formal_offer_document();
        let now = sealed.offer.expires_at + chrono::Duration::seconds(1);
        assert!(verify_realm_actor_backup_handover_offer(&sealed.offer, &document, now).is_err());
        assert!(import_evaluated_at(&sealed.offer, now, None).is_err());
        for invalid in [
            sealed.offer.signature.created_at - chrono::Duration::seconds(1),
            sealed.offer.expires_at,
            now + chrono::Duration::seconds(1),
        ] {
            assert!(import_evaluated_at(&sealed.offer, now, Some(invalid)).is_err());
        }
    }

    fn hex_bytes(hex: &str) -> Vec<u8> {
        hex.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|s| u8::from_str_radix(std::str::from_utf8(s).unwrap(), 16).unwrap())
            .collect()
    }
}
