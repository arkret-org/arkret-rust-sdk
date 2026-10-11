use arkret_models_collaboration::mls_roster_authority::{
    MlsAddAuthorityAttestation, MlsAttestAddRequestBody, MlsRosterAddSigningKeys,
    MlsRosterAuthorityManifest, MlsRosterAuthorityReadOutcome, MlsRosterAuthorityReadRequestBody,
    MlsRosterRecord, MlsRosterSigningKey, MlsSelfRosterAuthorityReadOutcome,
};
use arkret_models_crypto::peer_keypackage_claim_receipt_signing_bytes;
use arkret_models_identity::{AuthenticatedServiceResolution, DidDocument};
use arkret_wire::{ActorId, DidCoreId, DidUrl, EventId, WireError};

use crate::verify_peer_keypackage_claim_receipt_signature;

fn verify_station_signature(
    station_id: &DidCoreId,
    signed_at: chrono::DateTime<chrono::Utc>,
    signature: &arkret_models_crypto::KeyOperationSignature,
    signing_bytes: &[u8],
    resolution: &AuthenticatedServiceResolution,
) -> Result<(), WireError> {
    if &resolution.service_id != station_id {
        return Err(WireError::Protocol(
            "MLS roster signature resolution belongs to another Station".to_owned(),
        ));
    }
    if resolution.service_kind != "station" {
        return Err(WireError::Protocol(
            "MLS roster signature resolution is not a Station".to_owned(),
        ));
    }
    let document =
        arkret_identity::authenticated_service_document_at(resolution, station_id, signed_at)
            .map_err(|error| WireError::Protocol(error.to_string()))?;
    verify_station_signature_in_document(signature, signing_bytes, &document)
}

fn verify_station_signature_in_document(
    signature: &arkret_models_crypto::KeyOperationSignature,
    signing_bytes: &[u8],
    document: &DidDocument,
) -> Result<(), WireError> {
    let verification_method = DidUrl::new(signature.kid.as_str().to_owned())
        .map_err(|error| WireError::Protocol(error.to_owned()))?;
    arkret_identity::validate_verification_method_relationship(
        document,
        &verification_method,
        &document.id,
        arkret_identity::DidVerificationRelationship::AssertionMethod,
    )
    .map_err(|error| WireError::Protocol(error.to_string()))?;
    let public_key =
        arkret_identity::public_key_material_from_document(document, &verification_method)
            .map_err(|error| WireError::Protocol(error.to_string()))?
            .ed25519_bytes()
            .map_err(|error| WireError::Protocol(error.to_string()))?;
    arkret_signatures::keypackages::verify_keypackage_signing_input(
        &public_key,
        verification_method.as_str(),
        signing_bytes,
        signature,
    )
    .map_err(|error| WireError::Protocol(error.to_string()))
}

/// Verify the signed recipient-Station Add fact using that Station's key at
/// the historical replica cut. Accepted Proposal and MLS bytes are checked by
/// the governance/client caller against its own accepted stream material.
pub fn verify_mls_add_authority_attestation_signature(
    attestation: &MlsAddAuthorityAttestation,
    resolution: &AuthenticatedServiceResolution,
) -> Result<(), WireError> {
    attestation.validate_shape()?;
    verify_station_signature(
        &attestation.attestor_station_id,
        attestation.attested_at,
        &attestation.signature,
        &attestation.signing_bytes()?,
        resolution,
    )
}

/// Verify both Station signatures and the original full claim outcome before
/// governance retains the signed minimal attestation.
pub fn verify_mls_attest_add_request(
    request: &MlsAttestAddRequestBody,
    resolution: &AuthenticatedServiceResolution,
) -> Result<(), WireError> {
    request.validate_claim_binding()?;
    verify_peer_keypackage_claim_receipt_signature(
        &request.claim_outcome.claim_receipt,
        resolution,
    )?;
    verify_mls_add_authority_attestation_signature(&request.attestation, resolution)
}

/// Verify the governance Station's signature and exact selector binding for
/// one roster manifest. Page completeness and RFC public-tree matching remain
/// mandatory after all pages are fetched.
pub fn verify_mls_roster_authority_manifest_signature(
    manifest: &MlsRosterAuthorityManifest,
    request: &MlsRosterAuthorityReadRequestBody,
    expected_governance_station: &DidCoreId,
    expected_authority_head_event_ref: &EventId,
    resolution: &AuthenticatedServiceResolution,
) -> Result<(), WireError> {
    manifest.validate_for_request(request)?;
    if &manifest.governance_station_id != expected_governance_station
        || &manifest.authority_head_commit_event_ref != expected_authority_head_event_ref
    {
        return Err(WireError::Protocol(
            "MLS roster signer or authority head differs from accepted current".to_owned(),
        ));
    }
    verify_station_signature(
        &manifest.governance_station_id,
        manifest.issued_at,
        &manifest.signature,
        &manifest.signing_bytes()?,
        resolution,
    )
}

/// Verify transport completeness, the signed full-array digest and both
/// historical Add Station signatures. The caller must still reconcile these
/// records with accepted Commit/Proposal provenance and RFC public tree bytes.
pub fn verify_mls_roster_authority_pages(
    pages: &[MlsRosterAuthorityReadOutcome],
    request: &MlsRosterAuthorityReadRequestBody,
    expected_governance_station: &DidCoreId,
    expected_authority_head_event_ref: &EventId,
    governance_resolution: &AuthenticatedServiceResolution,
) -> Result<(), WireError> {
    let first = pages
        .first()
        .ok_or_else(|| WireError::Protocol("MLS roster has no signed pages".to_owned()))?;
    verify_mls_roster_authority_manifest_signature(
        &first.manifest,
        request,
        expected_governance_station,
        expected_authority_head_event_ref,
        governance_resolution,
    )?;
    verify_roster_page_set(pages, |record| {
        if let MlsRosterRecord::Add {
            attestation,
            attestor_resolution,
            ..
        } = record
        {
            verify_station_signature(
                &attestation.attestor_station_id,
                attestation.claim_receipt.claimed_at,
                &attestation.claim_receipt.signature,
                &peer_keypackage_claim_receipt_signing_bytes(&attestation.claim_receipt)
                    .map_err(|error| WireError::Protocol(error.to_string()))?,
                attestor_resolution,
            )?;
            verify_mls_add_authority_attestation_signature(attestation, attestor_resolution)?;
        }
        Ok(())
    })
}

fn verify_roster_page_set(
    pages: &[MlsRosterAuthorityReadOutcome],
    verify_add: impl Fn(&MlsRosterRecord) -> Result<(), WireError>,
) -> Result<(), WireError> {
    let first = pages
        .first()
        .ok_or_else(|| WireError::Protocol("MLS roster has no pages".into()))?;
    if pages.len() as u64 != first.manifest.page_count {
        return Err(WireError::Protocol(
            "MLS roster page count mismatch".to_owned(),
        ));
    }
    let manifest_bytes = arkret_canonical::canonical_json_bytes(&first.manifest)
        .map_err(|error| WireError::Protocol(error.to_string()))?;
    let mut records = Vec::new();
    for (index, page) in pages.iter().enumerate() {
        let response_bytes = arkret_canonical::canonical_json_bytes(page)
            .map_err(|error| WireError::Protocol(error.to_string()))?;
        if page.page_index != index as u64
            || arkret_canonical::canonical_json_bytes(&page.manifest)
                .map_err(|error| WireError::Protocol(error.to_string()))?
                != manifest_bytes
            || page.records.is_empty()
            || page.records.len() > 8
            || response_bytes.len() > 2_097_152
            || (index + 1 < pages.len()) != page.next_cursor.is_some()
        {
            return Err(WireError::Protocol(
                "MLS roster page is missing, reordered or from another cut".to_owned(),
            ));
        }
        records.extend(page.records.iter());
    }
    if records.len() as u64 != first.manifest.total_records {
        return Err(WireError::Protocol(
            "MLS roster record count mismatch".to_owned(),
        ));
    }
    let digest = arkret_canonical::canonical_sha256(&records)
        .map_err(|error| WireError::Protocol(error.to_string()))?;
    if digest != first.manifest.records_digest.as_str() {
        return Err(WireError::Protocol(
            "MLS roster record digest mismatch".to_owned(),
        ));
    }
    let mut previous_add: Option<(u64, u64, EventId, u64, ActorId)> = None;
    for (index, record) in records.iter().enumerate() {
        record.validate_shape()?;
        match record {
            MlsRosterRecord::Genesis {
                genesis_event_ref, ..
            } if index == 0 => {
                if genesis_event_ref != &first.manifest.genesis_event_ref {
                    return Err(WireError::Protocol(
                        "MLS roster Genesis differs from signed manifest".to_owned(),
                    ));
                }
            }
            MlsRosterRecord::Add {
                commit_event_ref,
                consumed_proposal_ordinal,
                sender_actor_id,
                attestation,
                ..
            } if index > 0 => {
                if commit_event_ref != &attestation.commit_event_ref
                    || attestation.realm_id != first.manifest.realm_id
                    || attestation.effective_scope != first.manifest.effective_scope
                    || attestation.mls_group_id != first.manifest.mls_group_id
                    || attestation.genesis_event_ref != first.manifest.genesis_event_ref
                    || attestation.epoch > first.manifest.target_epoch
                {
                    return Err(WireError::Protocol(
                        "MLS roster Add does not belong to signed group cut".to_owned(),
                    ));
                }
                if let Some((position, epoch, commit, ordinal, sender)) = &previous_add
                    && (attestation.commit_stream_position < *position
                        || attestation.epoch < *epoch
                        || (attestation.commit_stream_position == *position
                            && (commit_event_ref != commit
                                || consumed_proposal_ordinal <= ordinal
                                || sender_actor_id != sender)))
                {
                    return Err(WireError::Protocol(
                        "MLS roster Add chronology conflicts with signed order".to_owned(),
                    ));
                }
                if attestation.claim_receipt.destination_id != attestation.attestor_station_id {
                    return Err(WireError::Protocol(
                        "MLS roster Add claim receipt names another Station".to_owned(),
                    ));
                }
                verify_add(record)?;
                previous_add = Some((
                    attestation.commit_stream_position,
                    attestation.epoch,
                    commit_event_ref.clone(),
                    *consumed_proposal_ordinal,
                    sender_actor_id.clone(),
                ));
            }
            _ => {
                return Err(WireError::Protocol(
                    "MLS roster Genesis is missing or duplicated".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn roster_error(error: impl std::fmt::Display) -> WireError {
    WireError::Protocol(error.to_string())
}

fn station_signing_key(
    station: &DidCoreId,
    at: chrono::DateTime<chrono::Utc>,
    signature: &arkret_models_crypto::KeyOperationSignature,
    bytes: &[u8],
    resolution: &AuthenticatedServiceResolution,
) -> Result<MlsRosterSigningKey, WireError> {
    verify_station_signature(station, at, signature, bytes, resolution)?;
    let document = arkret_identity::authenticated_service_document_at(resolution, station, at)
        .map_err(roster_error)?;
    let method = DidUrl::new(signature.kid.as_str()).map_err(roster_error)?;
    let public_key = arkret_identity::public_key_material_from_document(&document, &method)
        .map_err(roster_error)?
        .ed25519_bytes()
        .map_err(roster_error)?;
    Ok(MlsRosterSigningKey {
        verification_method: method,
        public_key_b64u: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
            public_key,
        ))
        .map_err(roster_error)?,
    })
}

/// Server-side projection after full historical Station verification. The
/// original signed page and every frozen closure remain unchanged.
pub fn project_mls_self_roster_authority_page(
    page: MlsRosterAuthorityReadOutcome,
    request: &MlsRosterAuthorityReadRequestBody,
    governance: &DidCoreId,
    expected_head: &EventId,
    resolution: &AuthenticatedServiceResolution,
) -> Result<MlsSelfRosterAuthorityReadOutcome, WireError> {
    verify_mls_roster_authority_manifest_signature(
        &page.manifest,
        request,
        governance,
        expected_head,
        resolution,
    )?;
    if page.records.is_empty()
        || page.records.len() > 8
        || page.page_index >= page.manifest.page_count
        || page.next_cursor.is_some() != (page.page_index + 1 < page.manifest.page_count)
    {
        return Err(roster_error("MLS roster page shape is invalid"));
    }
    let manifest_signing_key = station_signing_key(
        governance,
        page.manifest.issued_at,
        &page.manifest.signature,
        &page.manifest.signing_bytes()?,
        resolution,
    )?;
    let mut add_signing_keys = Vec::new();
    for record in &page.records {
        record.validate_shape()?;
        if let MlsRosterRecord::Add {
            attestation,
            attestor_resolution,
            ..
        } = record
        {
            let station = &attestation.attestor_station_id;
            let receipt = &attestation.claim_receipt;
            if receipt.destination_id != *station {
                return Err(roster_error("MLS claim belongs to another Station"));
            }
            add_signing_keys.push(MlsRosterAddSigningKeys {
                record_digest: arkret_wire::Hash::new(
                    arkret_canonical::canonical_sha256(record).map_err(roster_error)?,
                )
                .map_err(roster_error)?,
                claim_receipt_signing_key: station_signing_key(
                    station,
                    receipt.claimed_at,
                    &receipt.signature,
                    &peer_keypackage_claim_receipt_signing_bytes(receipt).map_err(roster_error)?,
                    attestor_resolution,
                )?,
                attestation_signing_key: station_signing_key(
                    station,
                    attestation.attested_at,
                    &attestation.signature,
                    &attestation.signing_bytes()?,
                    attestor_resolution,
                )?,
            });
        }
    }
    let result = MlsSelfRosterAuthorityReadOutcome {
        roster: page,
        manifest_signing_key,
        add_signing_keys,
    };
    if arkret_canonical::canonical_json_bytes(&result)
        .map_err(roster_error)?
        .len()
        > 2_097_152
    {
        return Err(roster_error(
            "self MLS roster exceeds canonical response budget",
        ));
    }
    Ok(result)
}

fn verify_self_station_signature(
    station: &DidCoreId,
    signature: &arkret_models_crypto::KeyOperationSignature,
    bytes: &[u8],
    key: &MlsRosterSigningKey,
) -> Result<(), WireError> {
    let (did, fragment) = key
        .verification_method
        .as_str()
        .split_once('#')
        .ok_or_else(|| roster_error("MLS signing method lacks fragment"))?;
    if fragment.is_empty()
        || key.verification_method.as_str() != signature.kid.as_str()
        || arkret_wire::project_did_to_core_id(&arkret_wire::Did::new(did).map_err(roster_error)?)
            .map_err(roster_error)?
            != *station
    {
        return Err(roster_error(
            "self MLS signing key differs from original signer",
        ));
    }
    let public =
        arkret_canonical::base64url_decode(key.public_key_b64u.as_str()).map_err(roster_error)?;
    if public.len() != 32
        || arkret_canonical::base64url_encode(&public) != key.public_key_b64u.as_str()
    {
        return Err(roster_error("self MLS key is not canonical Ed25519"));
    }
    let public: [u8; 32] = public
        .try_into()
        .map_err(|_| roster_error("invalid self MLS key length"))?;
    arkret_signatures::keypackages::verify_keypackage_signing_input(
        &public,
        key.verification_method.as_str(),
        bytes,
        signature,
    )
    .map_err(roster_error)
}

/// Ordinary-client verification consumes only the exact authenticated own-
/// Station keys. It independently verifies original signatures and the full
/// ordered transcript, without running any method-native history verifier.
/// Consume selectors returned by the caller's durably authenticated own
/// Station. This is not a portable proof or a native history verifier.
pub fn verify_mls_member_roster_authority_pages(
    pages: &[MlsSelfRosterAuthorityReadOutcome],
    request: &arkret_models_collaboration::mls_roster_authority::MlsMemberRosterAuthorityReadRequestBody,
) -> Result<MlsRosterAuthorityReadRequestBody, WireError> {
    let manifest = &pages
        .first()
        .ok_or_else(|| roster_error("self MLS roster has no pages"))?
        .roster
        .manifest;
    manifest.validate_for_member_request(request)?;
    let peer = request.with_accepted_genesis(manifest.genesis_event_ref.clone());
    verify_mls_self_roster_authority_pages(
        pages,
        &peer,
        &manifest.governance_station_id,
        &manifest.authority_head_commit_event_ref,
    )?;
    Ok(peer)
}

pub fn verify_mls_self_roster_authority_pages(
    pages: &[MlsSelfRosterAuthorityReadOutcome],
    request: &MlsRosterAuthorityReadRequestBody,
    governance: &DidCoreId,
    expected_head: &EventId,
) -> Result<(), WireError> {
    let first = pages
        .first()
        .ok_or_else(|| roster_error("self MLS roster has no pages"))?;
    first.roster.manifest.validate_for_request(request)?;
    if first.roster.manifest.governance_station_id != *governance
        || first.roster.manifest.authority_head_commit_event_ref != *expected_head
    {
        return Err(roster_error(
            "self MLS manifest differs from accepted governance/head",
        ));
    }
    for page in pages {
        if arkret_canonical::canonical_json_bytes(page)
            .map_err(roster_error)?
            .len()
            > 2_097_152
        {
            return Err(roster_error(
                "self MLS roster exceeds canonical response budget",
            ));
        }
        verify_self_station_signature(
            governance,
            &page.roster.manifest.signature,
            &page.roster.manifest.signing_bytes()?,
            &page.manifest_signing_key,
        )?;
        let mut keys = page.add_signing_keys.iter();
        for record in &page.roster.records {
            if let MlsRosterRecord::Add { attestation, .. } = record {
                let key = keys
                    .next()
                    .ok_or_else(|| roster_error("self MLS Add key is missing"))?;
                if arkret_canonical::canonical_sha256(record).map_err(roster_error)?
                    != key.record_digest.as_str()
                {
                    return Err(roster_error("self MLS Add key binds another record"));
                }
                let receipt = &attestation.claim_receipt;
                verify_self_station_signature(
                    &attestation.attestor_station_id,
                    &receipt.signature,
                    &peer_keypackage_claim_receipt_signing_bytes(receipt).map_err(roster_error)?,
                    &key.claim_receipt_signing_key,
                )?;
                verify_self_station_signature(
                    &attestation.attestor_station_id,
                    &attestation.signature,
                    &attestation.signing_bytes()?,
                    &key.attestation_signing_key,
                )?;
            }
        }
        if keys.next().is_some() {
            return Err(roster_error("self MLS roster has surplus Add keys"));
        }
    }
    let roster = pages
        .iter()
        .map(|page| page.roster.clone())
        .collect::<Vec<_>>();
    verify_roster_page_set(&roster, |_| Ok(()))
}

/// Exact self-wrapper budget for deterministic governance page partitioning.
/// Public Ed25519 keys all have the same 43-character canonical encoding.
pub fn mls_self_roster_authority_page_encoded_size(
    page: &MlsRosterAuthorityReadOutcome,
) -> Result<usize, WireError> {
    let key = |signature: &arkret_models_crypto::KeyOperationSignature| -> Result<MlsRosterSigningKey, WireError> {
        Ok(MlsRosterSigningKey {
            verification_method: DidUrl::new(signature.kid.as_str()).map_err(roster_error)?,
            public_key_b64u: arkret_wire::Base64UrlString::new("A".repeat(43)).map_err(roster_error)?,
        })
    };
    let add_signing_keys = page
        .records
        .iter()
        .filter_map(|record| {
            if let MlsRosterRecord::Add { attestation, .. } = record {
                Some((record, attestation))
            } else {
                None
            }
        })
        .map(|(record, attestation)| {
            Ok(MlsRosterAddSigningKeys {
                record_digest: arkret_wire::Hash::new(
                    arkret_canonical::canonical_sha256(record).map_err(roster_error)?,
                )
                .map_err(roster_error)?,
                claim_receipt_signing_key: key(&attestation.claim_receipt.signature)?,
                attestation_signing_key: key(&attestation.signature)?,
            })
        })
        .collect::<Result<Vec<_>, WireError>>()?;
    arkret_canonical::canonical_json_bytes(&MlsSelfRosterAuthorityReadOutcome {
        roster: page.clone(),
        manifest_signing_key: key(&page.manifest.signature)?,
        add_signing_keys,
    })
    .map(|bytes| bytes.len())
    .map_err(roster_error)
}

#[cfg(test)]
mod tests {
    use arkret_identity::{DidKeyResolver, DidResolver};
    use arkret_models_crypto::{
        KeyOperationSignature, PeerKeyPackageClaimReceipt, PeerKeyPackagesClaimUnsignedRequest,
    };
    use arkret_models_identity::{
        AuthenticatedServiceResolution, ResolutionDidBindingEvidenceKind,
        ResolutionDidBindingEvidenceReceipt, ResolutionMethodEvidenceBoundary,
        ResolutionMethodHistoryEvidence,
    };
    use arkret_wire::{
        ActorId, Base64UrlString, BlobRef, Did, EventId, Hash, KeypackageClaimId, MlsGroupId,
        MlsWelcomeDeliveryId, MlsWelcomeRecipientEndpoint, NonEmptyString, RealmId, ScopeRef,
        project_did_to_core_id,
    };

    use super::*;

    #[test]
    fn roster_station_signatures_require_historical_assertion_method() {
        let seed = [41_u8; 32];
        let signer = ed25519_dalek::SigningKey::from_bytes(&seed);
        let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            signer.verifying_key().as_bytes(),
        );
        let did = Did::new(format!("did:key:{multibase}")).unwrap();
        let station = project_did_to_core_id(&did).unwrap();
        let document = DidKeyResolver::new().resolve_did(&did).unwrap().document;
        let head = arkret_canonical::sha256_digest(did.as_str().as_bytes());
        let version = format!(
            "synthetic-did-sha256:{}",
            head.trim_start_matches("sha256:")
        );
        let resolution = AuthenticatedServiceResolution {
            service_id: station.clone(),
            service_kind: "station".to_owned(),
            method_history_evidence: ResolutionMethodHistoryEvidence::DidKeyExpansion {
                boundary: ResolutionMethodEvidenceBoundary {
                    from_method_history_head: head.clone(),
                    to_method_history_head: head,
                    from_version_id: version.clone(),
                    to_version_id: version,
                },
                evidence: ResolutionDidBindingEvidenceReceipt {
                    kind: ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
                    method: "key".to_owned(),
                    document_digest: arkret_models_identity::normalized_did_document_digest(
                        &document,
                    )
                    .unwrap(),
                    method_proofs: vec![],
                },
            },
            normalized_did_document: document.clone(),
        };
        let method = format!("{}#{multibase}", did.as_str());
        let bytes = b"ak.mls_roster_authority_manifest.v1\n{\"fixture\":true}";
        let signature =
            arkret_signatures::keypackages::sign_keypackage_signing_input(&seed, &method, bytes)
                .unwrap();
        let at = "2026-09-29T00:00:00Z".parse().unwrap();
        assert!(verify_station_signature(&station, at, &signature, bytes, &resolution).is_ok());
        assert!(
            verify_station_signature(&station, at, &signature, b"changed", &resolution).is_err()
        );
        let mut revoked = document.clone();
        revoked.raw_properties.remove("assertionMethod");
        assert!(verify_station_signature_in_document(&signature, bytes, &revoked).is_err());
        let mut non_assertion = document;
        non_assertion
            .raw_properties
            .insert("assertionMethod".to_owned(), serde_json::json!([]));
        assert!(verify_station_signature_in_document(&signature, bytes, &non_assertion).is_err());
    }

    fn event() -> EventId {
        EventId::new("ak:event:ARELvWOpF6BRhrks3DlbQy-9XIE6aAQQumDQp7fA4Ape").unwrap()
    }

    fn manifest() -> (
        MlsRosterAuthorityReadRequestBody,
        MlsRosterAuthorityManifest,
    ) {
        let realm_id =
            RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap();
        let station = DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let request = MlsRosterAuthorityReadRequestBody {
            realm_id: realm_id.clone(),
            effective_scope: ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            mls_group_id: MlsGroupId::new("QjKOSorlqs3IquY7OikTUTy_Z0mMiL0X2mK4jAOT4R4").unwrap(),
            genesis_event_ref: event(),
            target_commit_event_ref: event(),
            target_epoch: 0,
            caller_actor_id: ActorId::service(station.clone()),
            cursor: None,
        };
        let manifest = MlsRosterAuthorityManifest {
            governance_station_id: station,
            realm_id,
            effective_scope: request.effective_scope.clone(),
            mls_group_id: request.mls_group_id.clone(),
            genesis_event_ref: event(),
            group_info_ref: BlobRef::new(format!("ak:blob:sha256:{}", "1".repeat(64))).unwrap(),
            ratchet_tree_ref: BlobRef::new(format!("ak:blob:sha256:{}", "2".repeat(64))).unwrap(),
            target_commit_event_ref: event(),
            target_epoch: 0,
            authority_head_commit_event_ref: event(),
            caller_actor_id: request.caller_actor_id.clone(),
            total_records: 1,
            page_count: 1,
            records_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            issued_at: "2026-09-29T00:00:00Z".parse().unwrap(),
            signature: KeyOperationSignature {
                kid: NonEmptyString::new("did:web:station.example#signing-1").unwrap(),
                signature_algorithm: Some(NonEmptyString::new("Ed25519").unwrap()),
                sig: Base64UrlString::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                    .unwrap(),
            },
        };
        (request, manifest)
    }

    #[test]
    fn roster_manifest_signature_transcript_rejects_mutations_and_wrong_domain() {
        let (request, mut manifest) = manifest();
        manifest.validate_for_request(&request).unwrap();
        let mut zero_pages = manifest.clone();
        zero_pages.page_count = 0;
        assert!(zero_pages.validate_for_request(&request).is_err());
        let mut extra_pages = manifest.clone();
        extra_pages.page_count = 2;
        assert!(extra_pages.validate_for_request(&request).is_err());
        let mut nine_records_in_one_page = manifest.clone();
        nine_records_in_one_page.total_records = 9;
        assert!(
            nine_records_in_one_page
                .validate_for_request(&request)
                .is_err()
        );
        let mut genesis_scope_request = request.clone();
        genesis_scope_request.effective_scope = ScopeRef::RealmGenesis;
        assert!(genesis_scope_request.validate().is_err());
        let mut wrong_cut_request = request.clone();
        wrong_cut_request.target_epoch = 1;
        assert!(manifest.validate_for_request(&wrong_cut_request).is_err());
        let signing_bytes = manifest.signing_bytes().unwrap();
        assert!(signing_bytes.starts_with(b"ak.mls_roster_authority_manifest.v1\n"));
        let seed = [23; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let public_key = signing_key.verifying_key().to_bytes();
        let kid = "did:web:station.example#signing-1";
        manifest.signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
            &seed,
            kid,
            &signing_bytes,
        )
        .unwrap();
        arkret_signatures::keypackages::verify_keypackage_signing_input(
            &public_key,
            kid,
            &manifest.signing_bytes().unwrap(),
            &manifest.signature,
        )
        .unwrap();
        let signed_manifest = manifest.clone();
        for mutate in [
            |manifest: &mut MlsRosterAuthorityManifest| {
                manifest.group_info_ref =
                    BlobRef::new(format!("ak:blob:sha256:{}", "3".repeat(64))).unwrap();
            },
            |manifest: &mut MlsRosterAuthorityManifest| {
                manifest.ratchet_tree_ref =
                    BlobRef::new(format!("ak:blob:sha256:{}", "4".repeat(64))).unwrap();
            },
        ] {
            let mut tampered = signed_manifest.clone();
            mutate(&mut tampered);
            assert!(
                arkret_signatures::keypackages::verify_keypackage_signing_input(
                    &public_key,
                    kid,
                    &tampered.signing_bytes().unwrap(),
                    &tampered.signature,
                )
                .is_err()
            );
        }
        manifest.total_records = 9;
        assert!(
            arkret_signatures::keypackages::verify_keypackage_signing_input(
                &public_key,
                kid,
                &manifest.signing_bytes().unwrap(),
                &manifest.signature,
            )
            .is_err()
        );
        assert!(manifest.validate_for_request(&request).is_err());
        let mut wrong_domain = b"ak.mls_add_authority_attestation.v1\n".to_vec();
        wrong_domain
            .extend_from_slice(&signing_bytes[b"ak.mls_roster_authority_manifest.v1\n".len()..]);
        assert!(
            arkret_signatures::keypackages::verify_keypackage_signing_input(
                &public_key,
                kid,
                &wrong_domain,
                &manifest.signature,
            )
            .is_err()
        );
    }

    fn signed_two_page_roster() -> (
        MlsRosterAuthorityReadRequestBody,
        Vec<MlsRosterAuthorityReadOutcome>,
        AuthenticatedServiceResolution,
    ) {
        let seed = [41_u8; 32];
        let signer = ed25519_dalek::SigningKey::from_bytes(&seed);
        let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            signer.verifying_key().as_bytes(),
        );
        let did = Did::new(format!("did:key:{multibase}")).unwrap();
        let station = project_did_to_core_id(&did).unwrap();
        let method = format!("{}#{multibase}", did.as_str());
        let document = DidKeyResolver::new().resolve_did(&did).unwrap().document;
        let head = arkret_canonical::sha256_digest(did.as_str().as_bytes());
        let version = format!(
            "synthetic-did-sha256:{}",
            head.trim_start_matches("sha256:")
        );
        let resolution = AuthenticatedServiceResolution {
            service_id: station.clone(),
            service_kind: "station".to_owned(),
            method_history_evidence: ResolutionMethodHistoryEvidence::DidKeyExpansion {
                boundary: ResolutionMethodEvidenceBoundary {
                    from_method_history_head: head.clone(),
                    to_method_history_head: head,
                    from_version_id: version.clone(),
                    to_version_id: version,
                },
                evidence: ResolutionDidBindingEvidenceReceipt {
                    kind: ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
                    method: "key".to_owned(),
                    document_digest: arkret_models_identity::normalized_did_document_digest(
                        &document,
                    )
                    .unwrap(),
                    method_proofs: vec![],
                },
            },
            normalized_did_document: document,
        };
        let (mut request, mut manifest) = manifest();
        let genesis = request.genesis_event_ref.clone();
        let commit = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [12; 32]);
        request.target_commit_event_ref = commit.clone();
        request.target_epoch = 1;
        manifest.governance_station_id = station.clone();
        manifest.target_commit_event_ref = commit.clone();
        manifest.target_epoch = 1;
        manifest.authority_head_commit_event_ref = commit.clone();
        manifest.total_records = 2;
        manifest.page_count = 2;
        let at = manifest.issued_at;
        let actor = ActorId::service(station.clone());
        let claim_request: PeerKeyPackagesClaimUnsignedRequest = serde_json::from_value(
            serde_json::json!({
                "claim_request_id": "AQ",
                "intended_realm_id": request.realm_id,
                "mls_group_id": request.mls_group_id,
                "claim_purpose": "realm_membership",
                "required_capabilities": ["mls"],
                "expires_at": arkret_canonical::format_timestamp_canonical(at + chrono::TimeDelta::hours(1)),
            }),
        )
        .unwrap();
        let placeholder = || KeyOperationSignature {
            kid: NonEmptyString::new(method.clone()).unwrap(),
            signature_algorithm: Some(NonEmptyString::new("Ed25519").unwrap()),
            sig: Base64UrlString::new("AQ").unwrap(),
        };
        let mut receipt = PeerKeyPackageClaimReceipt {
            claim_request_id: claim_request.claim_request_id.clone(),
            request_digest: Hash::new(format!("sha256:{}", "1".repeat(64))).unwrap(),
            claims_digest: Hash::new(format!("sha256:{}", "2".repeat(64))).unwrap(),
            source_id: station.clone(),
            destination_id: station.clone(),
            request: claim_request,
            claimed_at: at,
            expires_at: at + chrono::TimeDelta::hours(1),
            signature: placeholder(),
        };
        receipt.signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
            &seed,
            &method,
            &peer_keypackage_claim_receipt_signing_bytes(&receipt).unwrap(),
        )
        .unwrap();
        let mut attestation = MlsAddAuthorityAttestation {
            attestor_station_id: station,
            realm_id: request.realm_id.clone(),
            effective_scope: request.effective_scope.clone(),
            mls_group_id: request.mls_group_id.clone(),
            genesis_event_ref: genesis.clone(),
            commit_event_ref: commit.clone(),
            commit_stream_position: 2,
            epoch: 1,
            welcome_id: MlsWelcomeDeliveryId::new(
                "ak:mls_welcome_delivery:01904100-0000-7000-8000-000000000074",
            )
            .unwrap(),
            claim_id: KeypackageClaimId::new(
                "ak:keypackage_claim:01904100-0000-7000-8000-000000000073",
            )
            .unwrap(),
            actor_id: actor.clone(),
            endpoint: MlsWelcomeRecipientEndpoint::AgentRuntime {
                verification_method: DidUrl::new(method.clone()).unwrap(),
            },
            authorization_event_ref: EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [14; 32],
            ),
            leaf_signature_key_b64u: Base64UrlString::new(arkret_canonical::base64url_encode(
                [7; 32],
            ))
            .unwrap(),
            claim_record_digest: Hash::new(format!("sha256:{}", "3".repeat(64))).unwrap(),
            claim_receipt: receipt,
            attested_at: at,
            signature: placeholder(),
        };
        attestation.signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
            &seed,
            &method,
            &attestation.signing_bytes().unwrap(),
        )
        .unwrap();
        let records = [
            MlsRosterRecord::Genesis {
                genesis_event_ref: genesis,
                actor_id: actor.clone(),
                leaf_signature_key_b64u: Base64UrlString::new(arkret_canonical::base64url_encode(
                    [5; 32],
                ))
                .unwrap(),
                endpoint: MlsWelcomeRecipientEndpoint::AgentRuntime {
                    verification_method: DidUrl::new(method.clone()).unwrap(),
                },
                authorization_event_ref: EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [15; 32],
                ),
            },
            MlsRosterRecord::Add {
                commit_event_ref: commit,
                consumed_proposal_ordinal: 0,
                sender_actor_id: actor,
                proposal_wire_b64u: Base64UrlString::new("AQ").unwrap(),
                attestation,
                attestor_resolution: resolution.clone(),
            },
        ];
        manifest.records_digest =
            Hash::new(arkret_canonical::canonical_sha256(&records).unwrap()).unwrap();
        manifest.signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
            &seed,
            &method,
            &manifest.signing_bytes().unwrap(),
        )
        .unwrap();
        let pages = vec![
            MlsRosterAuthorityReadOutcome {
                manifest: manifest.clone(),
                page_index: 0,
                records: vec![records[0].clone()],
                next_cursor: Some("AQ".to_owned()),
            },
            MlsRosterAuthorityReadOutcome {
                manifest,
                page_index: 1,
                records: vec![records[1].clone()],
                next_cursor: None,
            },
        ];
        (request, pages, resolution)
    }

    #[test]
    fn self_roster_preserves_original_records_and_rejects_key_or_transcript_substitution() {
        let (request, pages, resolution) = signed_two_page_roster();
        let governance = &pages[0].manifest.governance_station_id;
        let head = &pages[0].manifest.authority_head_commit_event_ref;
        let projected = pages
            .iter()
            .cloned()
            .map(|page| {
                let expected_size = mls_self_roster_authority_page_encoded_size(&page).unwrap();
                let result = project_mls_self_roster_authority_page(
                    page,
                    &request,
                    governance,
                    head,
                    &resolution,
                )
                .unwrap();
                assert_eq!(
                    arkret_canonical::canonical_json_bytes(&result)
                        .unwrap()
                        .len(),
                    expected_size
                );
                result
            })
            .collect::<Vec<_>>();
        verify_mls_self_roster_authority_pages(&projected, &request, governance, head).unwrap();
        let member = arkret_models_collaboration::mls_roster_authority::MlsMemberRosterAuthorityReadRequestBody {
            realm_id: request.realm_id.clone(), effective_scope: request.effective_scope.clone(),
            mls_group_id: request.mls_group_id.clone(), target_commit_event_ref: request.target_commit_event_ref.clone(),
            target_epoch: request.target_epoch, caller_actor_id: request.caller_actor_id.clone(), cursor: None,
        };
        assert_eq!(
            verify_mls_member_roster_authority_pages(&projected, &member).unwrap(),
            request
        );
        let mut unexpected_genesis = serde_json::to_value(&member).unwrap();
        unexpected_genesis["genesis_event_ref"] =
            serde_json::to_value(&request.genesis_event_ref).unwrap();
        assert!(serde_json::from_value::<arkret_models_collaboration::mls_roster_authority::MlsMemberRosterAuthorityReadRequestBody>(unexpected_genesis).is_err());
        for field in [
            "realm_id",
            "effective_scope",
            "mls_group_id",
            "target_commit_event_ref",
            "target_epoch",
            "caller_actor_id",
        ] {
            let mut changed = member.clone();
            match field {
                "realm_id" => changed.realm_id = RealmId::from_event_id(&event()),
                "effective_scope" => {
                    changed.effective_scope = ScopeRef::Circle {
                        realm_id: member.realm_id.clone(),
                        circle_id: arkret_wire::CircleId::from_event_id(&event()),
                    }
                }
                "mls_group_id" => {
                    changed.mls_group_id =
                        MlsGroupId::new(arkret_canonical::base64url_encode([19; 32])).unwrap()
                }
                "target_commit_event_ref" => {
                    changed.target_commit_event_ref =
                        EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [19; 32])
                }
                "target_epoch" => changed.target_epoch += 1,
                _ => {
                    changed.caller_actor_id = arkret_wire::ActorId::service(
                        DidCoreId::new("ak:did_core:web:other.example").unwrap(),
                    )
                }
            }
            assert!(
                verify_mls_member_roster_authority_pages(&projected, &changed).is_err(),
                "{field}"
            );
        }
        assert_eq!(
            arkret_canonical::canonical_json_bytes(
                &projected
                    .iter()
                    .map(|page| &page.roster)
                    .collect::<Vec<_>>()
            )
            .unwrap(),
            arkret_canonical::canonical_json_bytes(&pages).unwrap()
        );
        let mut changed = projected.clone();
        changed[1].add_signing_keys.clear();
        assert!(
            verify_mls_self_roster_authority_pages(&changed, &request, governance, head).is_err()
        );
        let mut changed = projected.clone();
        changed[0].add_signing_keys = changed[1].add_signing_keys.clone();
        assert!(
            verify_mls_self_roster_authority_pages(&changed, &request, governance, head).is_err()
        );
        let mut changed = projected.clone();
        changed[1].add_signing_keys[0]
            .attestation_signing_key
            .public_key_b64u =
            Base64UrlString::new(arkret_canonical::base64url_encode([9; 32])).unwrap();
        assert!(
            verify_mls_self_roster_authority_pages(&changed, &request, governance, head).is_err()
        );
        let mut changed = projected.clone();
        changed[1].add_signing_keys[0].record_digest =
            Hash::new(format!("sha256:{}", "9".repeat(64))).unwrap();
        assert!(
            verify_mls_self_roster_authority_pages(&changed, &request, governance, head).is_err()
        );
        let mut changed = projected.clone();
        changed[0].manifest_signing_key.verification_method =
            DidUrl::new("did:web:other.example#key").unwrap();
        assert!(
            verify_mls_self_roster_authority_pages(&changed, &request, governance, head).is_err()
        );
        let mut changed = projected;
        changed[1].roster.records.reverse();
        changed.reverse();
        assert!(
            verify_mls_self_roster_authority_pages(&changed, &request, governance, head).is_err()
        );
        let mut changed = pages[1].clone();
        if let MlsRosterRecord::Add {
            attestor_resolution,
            ..
        } = &mut changed.records[0]
        {
            attestor_resolution.service_kind = "agent".into();
        }
        assert!(
            project_mls_self_roster_authority_page(
                changed,
                &request,
                governance,
                head,
                &resolution
            )
            .is_err()
        );
    }

    #[test]
    fn self_roster_station_uses_native_webvh_history_at_each_original_signature_time() {
        use arkret_models_identity::service_identity::{
            CanonicalServiceUrl, ServiceRegistrationKey,
        };
        use arkret_signatures::webvh::{
            ServiceRegistrationInceptionInput, ServiceRotationInput,
            prepare_service_registration_inception_with_did_key_seed, prepare_service_rotation,
        };
        use rand_core::SeedableRng as _;
        let (request, mut pages, _) = signed_two_page_roster();
        let at = pages[0].manifest.issued_at;
        let claim_at = at - chrono::Duration::minutes(1);
        let old_seed = [41; 32];
        let new_seed = [42; 32];
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([43; 32]);
        let registration = ServiceRegistrationKey::new(
            arkret_wire::ServiceKind::Station,
            CanonicalServiceUrl::new("https://roster.example/").unwrap(),
        )
        .unwrap();
        let endpoint = "https://identity.example/".parse().unwrap();
        let inception = prepare_service_registration_inception_with_did_key_seed(
            &mut rng,
            &ServiceRegistrationInceptionInput {
                provider_endpoint: &endpoint,
                registration_key: &registration,
                also_known_as: &[],
                version_time: claim_at - chrono::Duration::seconds(1),
                did_key_fragment: Some("notary-key"),
            },
            &old_seed,
        )
        .unwrap();
        let did = Did::new(&inception.did).unwrap();
        let station = project_did_to_core_id(&did).unwrap();
        let method = format!("{}#notary-key", did.as_str());
        let mut state = inception.log_entry["state"].clone();
        state["verificationMethod"][0]["publicKeyMultibase"] =
            serde_json::json!(arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                ed25519_dalek::SigningKey::from_bytes(&new_seed)
                    .verifying_key()
                    .as_bytes()
            ));
        let rotation = prepare_service_rotation(&ServiceRotationInput {
            did: did.as_str(),
            previous_entries: std::slice::from_ref(&inception.log_entry),
            state: &state,
            current_update_seed: &inception.next_update_key_seed,
            next_update_public_key_multibase:
                &arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                    ed25519_dalek::SigningKey::from_bytes(&[44; 32])
                        .verifying_key()
                        .as_bytes(),
                ),
            version_time: claim_at + chrono::Duration::seconds(1),
        })
        .unwrap();
        let resolution = arkret_identity::build_authenticated_webvh_service_resolution(
            station.clone(),
            "station".into(),
            serde_json::from_value(state).unwrap(),
            vec![inception.log_entry.clone(), rotation.log_entry],
            vec![],
            at,
        )
        .unwrap();
        if let MlsRosterRecord::Add {
            attestation,
            attestor_resolution,
            ..
        } = &mut pages[1].records[0]
        {
            *attestor_resolution = resolution.clone();
            attestation.attestor_station_id = station.clone();
            attestation.actor_id = ActorId::service(station.clone());
            attestation.claim_receipt.destination_id = station.clone();
            attestation.claim_receipt.claimed_at = claim_at;
            attestation.claim_receipt.signature =
                arkret_signatures::keypackages::sign_keypackage_signing_input(
                    &old_seed,
                    &method,
                    &peer_keypackage_claim_receipt_signing_bytes(&attestation.claim_receipt)
                        .unwrap(),
                )
                .unwrap();
            attestation.signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
                &new_seed,
                &method,
                &attestation.signing_bytes().unwrap(),
            )
            .unwrap();
        }
        let digest = Hash::new(
            arkret_canonical::canonical_sha256(
                &pages
                    .iter()
                    .flat_map(|page| &page.records)
                    .collect::<Vec<_>>(),
            )
            .unwrap(),
        )
        .unwrap();
        for page in &mut pages {
            page.manifest.governance_station_id = station.clone();
            page.manifest.records_digest = digest.clone();
            page.manifest.signature =
                arkret_signatures::keypackages::sign_keypackage_signing_input(
                    &new_seed,
                    &method,
                    &page.manifest.signing_bytes().unwrap(),
                )
                .unwrap();
        }
        let head = &pages[0].manifest.authority_head_commit_event_ref;
        let projected = pages
            .iter()
            .cloned()
            .map(|page| {
                project_mls_self_roster_authority_page(page, &request, &station, head, &resolution)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert_ne!(
            projected[1].add_signing_keys[0]
                .claim_receipt_signing_key
                .public_key_b64u,
            projected[1].add_signing_keys[0]
                .attestation_signing_key
                .public_key_b64u
        );
        verify_mls_self_roster_authority_pages(&projected, &request, &station, head).unwrap();
        let mut wrong = projected;
        wrong[1].add_signing_keys[0].claim_receipt_signing_key =
            wrong[1].add_signing_keys[0].attestation_signing_key.clone();
        assert!(verify_mls_self_roster_authority_pages(&wrong, &request, &station, head).is_err());
        let mut broken = pages[1].clone();
        if let MlsRosterRecord::Add {
            attestor_resolution,
            ..
        } = &mut broken.records[0]
            && let ResolutionMethodHistoryEvidence::WebvhLog { log_entries, .. } =
                &mut attestor_resolution.method_history_evidence
        {
            log_entries.remove(0);
        }
        assert!(
            project_mls_self_roster_authority_page(broken, &request, &station, head, &resolution)
                .is_err()
        );
    }

    fn resign_roster_pages(pages: &mut [MlsRosterAuthorityReadOutcome]) {
        let records = pages
            .iter()
            .flat_map(|page| page.records.iter())
            .collect::<Vec<_>>();
        let mut manifest = pages[0].manifest.clone();
        manifest.records_digest =
            Hash::new(arkret_canonical::canonical_sha256(&records).unwrap()).unwrap();
        manifest.signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
            &[41; 32],
            manifest.signature.kid.as_str(),
            &manifest.signing_bytes().unwrap(),
        )
        .unwrap();
        for page in pages {
            page.manifest = manifest.clone();
        }
    }

    #[test]
    fn sidecar_add_attestation_preserves_exact_scope_and_historical_signature_checks() {
        let (request, pages, resolution) = signed_two_page_roster();
        let MlsRosterRecord::Add { attestation, .. } = &pages[1].records[0] else {
            panic!("the second record is an Add");
        };
        let mut attestation = attestation.clone();
        attestation.effective_scope = ScopeRef::Sidecar {
            realm_id: request.realm_id.clone(),
            sidecar_id: arkret_wire::SidecarId::new(
                "ak:sidecar:ASZ1iAvlGxgLC_-P6WHoR9vfijpaxbI5hoSwBx8zWTcT",
            )
            .unwrap(),
        };
        attestation.mls_group_id = attestation
            .effective_scope
            .canonical_mls_group_id()
            .unwrap();
        attestation.actor_id = ActorId::account(arkret_wire::AccountId::new(
            attestation.attestor_station_id.clone(),
            attestation.attestor_station_id.clone(),
        ));
        attestation.claim_receipt.request.mls_group_id = attestation.mls_group_id.clone();
        let kid = attestation.signature.kid.as_str().to_owned();
        attestation.claim_receipt.signature =
            arkret_signatures::keypackages::sign_keypackage_signing_input(
                &[41; 32],
                &kid,
                &peer_keypackage_claim_receipt_signing_bytes(&attestation.claim_receipt).unwrap(),
            )
            .unwrap();
        attestation.signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
            &[41; 32],
            &kid,
            &attestation.signing_bytes().unwrap(),
        )
        .unwrap();
        attestation.validate_shape().unwrap();
        verify_mls_add_authority_attestation_signature(&attestation, &resolution).unwrap();
        verify_peer_keypackage_claim_receipt_signature(&attestation.claim_receipt, &resolution)
            .unwrap();

        let mut another_sidecar = attestation.clone();
        another_sidecar.effective_scope = ScopeRef::Sidecar {
            realm_id: request.realm_id,
            sidecar_id: arkret_wire::SidecarId::new(
                "ak:sidecar:AQdmOQIzsGDs6LjeW5Icy92GXh1n9_6SGgVCJJ_2a3FV",
            )
            .unwrap(),
        };
        assert!(
            verify_mls_add_authority_attestation_signature(&another_sidecar, &resolution).is_err()
        );
        let mut wrong = attestation.clone();
        wrong.effective_scope = ScopeRef::RealmGenesis;
        assert!(wrong.validate_shape().is_err());
        wrong = attestation.clone();
        wrong.realm_id =
            RealmId::new("ak:realm:AQdmOQIzsGDs6LjeW5Icy92GXh1n9_6SGgVCJJ_2a3FV").unwrap();
        assert!(wrong.validate_shape().is_err());
        wrong = attestation.clone();
        wrong.commit_stream_position = 0;
        assert!(wrong.validate_shape().is_err());
        wrong = attestation.clone();
        wrong.epoch = 0;
        assert!(wrong.validate_shape().is_err());
        wrong = attestation.clone();
        wrong.attestor_station_id =
            project_did_to_core_id(&Did::new("did:web:another-station.example").unwrap()).unwrap();
        assert!(wrong.validate_shape().is_err());
        wrong = attestation;
        wrong.leaf_signature_key_b64u =
            Base64UrlString::new(arkret_canonical::base64url_encode([7; 31])).unwrap();
        assert!(wrong.validate_shape().is_err());
    }

    #[test]
    fn roster_pages_accept_byte_bounded_short_nonfinal_page_and_verify_two_historical_signatures() {
        let (request, mut pages, resolution) = signed_two_page_roster();
        let mut low: usize = 0;
        let mut high = 1_600_000;
        while low < high {
            let candidate = (low + high).div_ceil(2);
            if let MlsRosterRecord::Add {
                proposal_wire_b64u, ..
            } = &mut pages[1].records[0]
            {
                *proposal_wire_b64u =
                    Base64UrlString::new(arkret_canonical::base64url_encode(vec![7; candidate]))
                        .unwrap();
            }
            if arkret_canonical::canonical_json_bytes(&pages[1])
                .unwrap()
                .len()
                <= 2_097_152
            {
                low = candidate;
            } else {
                high = candidate - 1;
            }
        }
        if let MlsRosterRecord::Add {
            proposal_wire_b64u, ..
        } = &mut pages[1].records[0]
        {
            *proposal_wire_b64u =
                Base64UrlString::new(arkret_canonical::base64url_encode(vec![7; low])).unwrap();
        }
        resign_roster_pages(&mut pages);
        let mut combined_page = pages[0].clone();
        combined_page.records.push(pages[1].records[0].clone());
        combined_page.next_cursor = None;
        assert!(
            arkret_canonical::canonical_json_bytes(&pages[1])
                .unwrap()
                .len()
                <= 2_097_152
        );
        assert!(
            arkret_canonical::canonical_json_bytes(&combined_page)
                .unwrap()
                .len()
                > 2_097_152
        );
        assert_eq!(pages[0].records.len(), 1);
        assert_eq!(pages[0].manifest.page_count, 2);
        verify_mls_roster_authority_pages(
            &pages,
            &request,
            &resolution.service_id,
            &pages[0].manifest.authority_head_commit_event_ref,
            &resolution,
        )
        .unwrap();

        let mut invalid_receipt = pages.clone();
        if let MlsRosterRecord::Add { attestation, .. } = &mut invalid_receipt[1].records[0] {
            attestation.claim_receipt.signature.sig = Base64UrlString::new("AQ").unwrap();
        }
        resign_roster_pages(&mut invalid_receipt);
        assert!(
            verify_mls_roster_authority_pages(
                &invalid_receipt,
                &request,
                &resolution.service_id,
                &pages[0].manifest.authority_head_commit_event_ref,
                &resolution,
            )
            .is_err()
        );

        let mut invalid_attestation = pages.clone();
        if let MlsRosterRecord::Add { attestation, .. } = &mut invalid_attestation[1].records[0] {
            attestation.signature.sig = Base64UrlString::new("AQ").unwrap();
        }
        resign_roster_pages(&mut invalid_attestation);
        assert!(
            verify_mls_roster_authority_pages(
                &invalid_attestation,
                &request,
                &resolution.service_id,
                &pages[0].manifest.authority_head_commit_event_ref,
                &resolution,
            )
            .is_err()
        );
    }

    #[test]
    fn roster_pages_reject_wrong_attestor_resolution_and_oversized_page() {
        let (request, pages, resolution) = signed_two_page_roster();
        let mut missing_closure = serde_json::to_value(&pages[1].records[0]).unwrap();
        missing_closure
            .as_object_mut()
            .unwrap()
            .remove("attestor_resolution");
        assert!(serde_json::from_value::<MlsRosterRecord>(missing_closure).is_err());
        let verify = |candidate: &[MlsRosterAuthorityReadOutcome]| {
            verify_mls_roster_authority_pages(
                candidate,
                &request,
                &resolution.service_id,
                &pages[0].manifest.authority_head_commit_event_ref,
                &resolution,
            )
        };
        let mut wrong_service = pages.clone();
        if let MlsRosterRecord::Add {
            attestor_resolution,
            ..
        } = &mut wrong_service[1].records[0]
        {
            attestor_resolution.service_kind = "media".to_owned();
        }
        resign_roster_pages(&mut wrong_service);
        assert!(verify(&wrong_service).is_err());

        let mut wrong_station = pages.clone();
        if let MlsRosterRecord::Add {
            attestor_resolution,
            ..
        } = &mut wrong_station[1].records[0]
        {
            attestor_resolution.service_id =
                DidCoreId::new("ak:did_core:web:other-station.example").unwrap();
        }
        resign_roster_pages(&mut wrong_station);
        assert!(verify(&wrong_station).is_err());

        let mut wrong_method = pages.clone();
        if let MlsRosterRecord::Add {
            attestor_resolution,
            ..
        } = &mut wrong_method[1].records[0]
        {
            attestor_resolution
                .normalized_did_document
                .raw_properties
                .remove("assertionMethod");
        }
        resign_roster_pages(&mut wrong_method);
        assert!(verify(&wrong_method).is_err());

        let mut oversized = pages.clone();
        if let MlsRosterRecord::Add {
            proposal_wire_b64u, ..
        } = &mut oversized[1].records[0]
        {
            *proposal_wire_b64u =
                Base64UrlString::new(arkret_canonical::base64url_encode(vec![7; 1_600_000]))
                    .unwrap();
        }
        resign_roster_pages(&mut oversized);
        assert!(
            arkret_canonical::canonical_json_bytes(&oversized[1])
                .unwrap()
                .len()
                > 2_097_152
        );
        assert!(verify(&oversized).is_err());
    }

    #[test]
    fn roster_did_key_closure_survives_canonical_wire_round_trip() {
        let (request, pages, resolution) = signed_two_page_roster();
        let wire = arkret_canonical::canonical_json_bytes(&pages).unwrap();
        let restored: Vec<MlsRosterAuthorityReadOutcome> = serde_json::from_slice(&wire).unwrap();
        assert_eq!(
            arkret_canonical::canonical_json_bytes(&restored).unwrap(),
            wire
        );
        if let MlsRosterRecord::Add {
            attestation,
            attestor_resolution,
            ..
        } = &restored[1].records[0]
        {
            verify_peer_keypackage_claim_receipt_signature(
                &attestation.claim_receipt,
                attestor_resolution,
            )
            .unwrap();
        }
        verify_mls_roster_authority_pages(
            &restored,
            &request,
            &resolution.service_id,
            &pages[0].manifest.authority_head_commit_event_ref,
            &resolution,
        )
        .unwrap();
        let mut without_assertion = restored;
        if let MlsRosterRecord::Add {
            attestor_resolution,
            ..
        } = &mut without_assertion[1].records[0]
        {
            attestor_resolution
                .normalized_did_document
                .raw_properties
                .insert("assertion_methods".to_owned(), serde_json::json!([]));
        }
        resign_roster_pages(&mut without_assertion);
        assert!(
            verify_mls_roster_authority_pages(
                &without_assertion,
                &request,
                &resolution.service_id,
                &pages[0].manifest.authority_head_commit_event_ref,
                &resolution,
            )
            .is_err()
        );
    }
}

#[cfg(feature = "mls")]
pub use roster_bindings::{
    install_verified_mls_roster_bindings, install_verified_mls_self_roster_bindings,
    mls_roster_genesis_material_request,
};

#[cfg(feature = "mls")]
mod roster_bindings {
    use std::collections::{BTreeMap, BTreeSet};

    use arkret_mls::MlsVerifiedLeafBinding;
    use arkret_models_collaboration::mls_group_state_material::{
        MlsGroupStateMaterialOutcome, MlsMemberGroupStateMaterialReadRequestBody,
    };
    use arkret_models_crypto::MlsEndpointIdentity;
    use arkret_wire::MlsWelcomeRecipientEndpoint;

    use super::*;

    pub fn mls_roster_genesis_material_request(
        request: &MlsRosterAuthorityReadRequestBody,
        manifest: &MlsRosterAuthorityManifest,
    ) -> MlsMemberGroupStateMaterialReadRequestBody {
        MlsMemberGroupStateMaterialReadRequestBody {
            realm_id: request.realm_id.clone(),
            effective_scope: request.effective_scope.clone(),
            mls_group_id: request.mls_group_id.clone(),
            epoch: Default::default(),
            group_state_event_id: request.genesis_event_ref.clone(),
            caller_actor_id: request.caller_actor_id.clone(),
            target_commit_event_ref: request.target_commit_event_ref.clone(),
            target_epoch: request.target_epoch,
            group_info_ref: manifest.group_info_ref.clone(),
            ratchet_tree_ref: manifest.ratchet_tree_ref.clone(),
            max_response_bytes: None,
        }
    }

    /// Verify a complete signed roster and the exact Genesis public material,
    /// then install an every-and-only binding map for the already verified joined
    /// RFC group. The caller must obtain `request` and `expected_head` from the
    /// accepted target/current cut, not from a Welcome or an untrusted page.
    pub fn install_verified_mls_roster_bindings(
        group: &mut crate::mls::ArkretMlsGroup,
        pages: &[MlsRosterAuthorityReadOutcome],
        request: &MlsRosterAuthorityReadRequestBody,
        expected_governance: &DidCoreId,
        expected_head: &EventId,
        governance_resolution: &AuthenticatedServiceResolution,
        material: &MlsGroupStateMaterialOutcome,
    ) -> Result<(), String> {
        verify_mls_roster_authority_pages(
            pages,
            request,
            expected_governance,
            expected_head,
            governance_resolution,
        )
        .map_err(|error| format!("verify signed MLS roster: {error}"))?;
        install_roster_bindings_after_verified_signatures(group, pages, request, material)
    }

    pub fn install_verified_mls_self_roster_bindings(
        group: &mut crate::mls::ArkretMlsGroup,
        pages: &[MlsSelfRosterAuthorityReadOutcome],
        request: &arkret_models_collaboration::mls_roster_authority::MlsMemberRosterAuthorityReadRequestBody,
        material: &MlsGroupStateMaterialOutcome,
    ) -> Result<(), String> {
        let peer = verify_mls_member_roster_authority_pages(pages, request)
            .map_err(|error| format!("verify own-Station MLS roster: {error}"))?;
        let roster = pages
            .iter()
            .map(|page| page.roster.clone())
            .collect::<Vec<_>>();
        install_roster_bindings_after_verified_signatures(group, &roster, &peer, material)
    }

    fn install_roster_bindings_after_verified_signatures(
        group: &mut crate::mls::ArkretMlsGroup,
        pages: &[MlsRosterAuthorityReadOutcome],
        request: &MlsRosterAuthorityReadRequestBody,
        material: &MlsGroupStateMaterialOutcome,
    ) -> Result<(), String> {
        if group.scope() != &request.effective_scope
            || group.group_id() != request.mls_group_id
            || group.epoch() != request.target_epoch
        {
            return Err("joined MLS group differs from the accepted roster cut".to_owned());
        }
        let manifest = &pages[0].manifest;
        let material_request = mls_roster_genesis_material_request(request, manifest);
        let bytes = material
            .validate_for_request(&material_request.as_peer_request())
            .map_err(|error| {
                format!("verify MLS Genesis material digest and selectors: {error}")
            })?;
        let genesis_leaves = crate::mls::validate_public_group_state(
            &bytes.group_info_bytes,
            &bytes.ratchet_tree_bytes,
            request.mls_group_id.as_str(),
            0,
        )
        .map_err(|error| format!("verify RFC Genesis public tree: {error}"))?;
        let records = pages
            .iter()
            .flat_map(|page| page.records.iter())
            .collect::<Vec<_>>();
        let MlsRosterRecord::Genesis {
            actor_id,
            leaf_signature_key_b64u,
            endpoint,
            authorization_event_ref,
            ..
        } = records[0]
        else {
            return Err("signed MLS roster has no Genesis record".to_owned());
        };
        if genesis_leaves.len() != 1
            || genesis_leaves[0].actor_id != *actor_id
            || genesis_leaves[0].signature_key != *leaf_signature_key_b64u
        {
            return Err("signed MLS Genesis leaf differs from RFC public tree".to_owned());
        }
        let mut authorities = vec![authority_from_record(
            actor_id,
            leaf_signature_key_b64u,
            endpoint,
            authorization_event_ref,
        )?];
        for record in records.into_iter().skip(1) {
            let MlsRosterRecord::Add {
                proposal_wire_b64u,
                attestation,
                ..
            } = record
            else {
                return Err("signed MLS roster repeats Genesis".to_owned());
            };
            let proposal_bytes = crate::base64url_decode(proposal_wire_b64u.as_str())
                .map_err(|error| format!("decode signed MLS Add Proposal: {error}"))?;
            let proposal = crate::mls::verify_add_proposal_leaf(&proposal_bytes)
                .map_err(|error| format!("verify signed MLS Add Proposal: {error}"))?;
            if proposal.actor_id != attestation.actor_id
                || proposal.leaf_signature_key != attestation.leaf_signature_key_b64u
            {
                return Err("signed MLS Add differs from its RFC KeyPackage leaf".to_owned());
            }
            authorities.push(authority_from_record(
                &attestation.actor_id,
                &attestation.leaf_signature_key_b64u,
                &attestation.endpoint,
                &attestation.authorization_event_ref,
            )?);
        }
        let occupied = group
            .active_author_leaves()
            .into_iter()
            .map(|leaf| {
                let crate::mls::AuthorLeafCredential::Basic { identity } = leaf.credential else {
                    return Err("occupied MLS leaf has no BasicCredential".to_owned());
                };
                let actor_id = crate::decode_mls_basic_credential_identity(&identity)
                    .map_err(|error| format!("decode occupied MLS ActorId: {error}"))?;
                let signature_key =
                    crate::Base64UrlString::new(crate::base64url_encode(&leaf.signature_key))
                        .map_err(|error| error.to_owned())?;
                Ok(crate::mls::MlsPublicEndpointLeaf {
                    leaf_index: leaf.leaf_index,
                    actor_id,
                    signature_key,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let bindings = match_occupied_leaf_authorities(&occupied, &authorities)?;
        group
            .install_verified_leaf_bindings(bindings)
            .map_err(|error| format!("install verified MLS roster bindings: {error}"))
    }

    fn authority_from_record(
        actor_id: &ActorId,
        signature_key: &crate::Base64UrlString,
        endpoint: &MlsWelcomeRecipientEndpoint,
        authorization_event_ref: &EventId,
    ) -> Result<MlsVerifiedLeafBinding, String> {
        let (endpoint, device_authorize_event_id) = match endpoint {
            MlsWelcomeRecipientEndpoint::Device { device_id } => (
                MlsEndpointIdentity::human_device(
                    actor_id.signing_principal_id().clone(),
                    device_id.clone(),
                ),
                Some(authorization_event_ref.clone()),
            ),
            MlsWelcomeRecipientEndpoint::AgentRuntime {
                verification_method,
            } => (
                MlsEndpointIdentity::agent_runtime(
                    actor_id.signing_principal_id().clone(),
                    verification_method.clone(),
                    authorization_event_ref.clone(),
                )
                .map_err(|error| format!("verify roster Agent endpoint: {error}"))?,
                None,
            ),
        };
        actor_id
            .validate()
            .map_err(|error| format!("verify MLS roster ActorId: {error}"))?;
        if matches!(&endpoint, MlsEndpointIdentity::HumanDevice { .. })
            && !matches!(actor_id, ActorId::Account { .. })
        {
            return Err("MLS roster device endpoint is not an account Actor".to_owned());
        }
        Ok(MlsVerifiedLeafBinding {
            leaf_index: 0, // Replaced solely by the verified occupied RFC tree.
            actor_id: actor_id.clone(),
            endpoint,
            signature_key: signature_key.clone(),
            device_authorize_event_id,
        })
    }

    fn match_occupied_leaf_authorities(
        occupied: &[crate::mls::MlsPublicEndpointLeaf],
        authorities: &[MlsVerifiedLeafBinding],
    ) -> Result<Vec<MlsVerifiedLeafBinding>, String> {
        let mut exact = BTreeMap::new();
        // Every record was independently verified in signed Commit order. A
        // Remove+Add may reuse even the same Actor/key/index tuple; its later Add
        // is a new provenance event and supplies the current endpoint authority.
        for authority in authorities {
            let key = (authority.actor_id.clone(), authority.signature_key.clone());
            exact.insert(key, authority);
        }
        let mut bindings = Vec::with_capacity(occupied.len());
        let mut occupied_indices = BTreeSet::new();
        let mut occupied_keys = BTreeSet::new();
        for leaf in occupied {
            let key = (leaf.actor_id.clone(), leaf.signature_key.clone());
            if !occupied_indices.insert(leaf.leaf_index) || !occupied_keys.insert(key.clone()) {
                return Err("RFC MLS tree repeats an occupied leaf or leaf key".to_owned());
            }
            let authority = exact
                .get(&key)
                .ok_or_else(|| "occupied MLS leaf has no signed historical authority".to_owned())?;
            let mut binding = (*authority).clone();
            binding.leaf_index = leaf.leaf_index;
            bindings.push(binding);
        }
        Ok(bindings)
    }

    #[cfg(test)]
    mod roster_binding_tests {
        use super::*;

        fn actor() -> ActorId {
            ActorId::account(crate::AccountId::new(
                DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            ))
        }

        fn authority(key: &str, device_id: &str) -> MlsVerifiedLeafBinding {
            MlsVerifiedLeafBinding {
                leaf_index: 0,
                actor_id: actor(),
                endpoint: MlsEndpointIdentity::human_device(
                    actor().signing_principal_id().clone(),
                    crate::DeviceId::new(device_id).unwrap(),
                ),
                signature_key: crate::Base64UrlString::new(key).unwrap(),
                device_authorize_event_id: Some(
                    EventId::new("ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1").unwrap(),
                ),
            }
        }

        fn leaf(index: u32, key: &str) -> crate::mls::MlsPublicEndpointLeaf {
            crate::mls::MlsPublicEndpointLeaf {
                leaf_index: index,
                actor_id: actor(),
                signature_key: crate::Base64UrlString::new(key).unwrap(),
            }
        }

        #[test]
        fn same_actor_two_keys_take_distinct_rfc_leaf_indices() {
            let device_one = "ak:device:0196419b-0000-7000-8000-000000000001";
            let device_two = "ak:device:0196419b-0000-7000-8000-000000000002";
            let bindings = match_occupied_leaf_authorities(
                &[leaf(4, "AQ"), leaf(1, "Ag")],
                &[authority("Ag", device_two), authority("AQ", device_one)],
            )
            .unwrap();
            assert_eq!(bindings[0].leaf_index, 4);
            assert_eq!(bindings[0].signature_key.as_str(), "AQ");
            assert_eq!(bindings[1].leaf_index, 1);
            assert_eq!(bindings[1].signature_key.as_str(), "Ag");
            assert!(matches!(
                &bindings[1].endpoint,
                MlsEndpointIdentity::HumanDevice { device_id, .. } if device_id.as_str() == device_two
            ));
        }

        #[test]
        fn remove_then_add_can_reuse_index_only_for_the_new_leaf_key() {
            let device_one = "ak:device:0196419b-0000-7000-8000-000000000001";
            let device_two = "ak:device:0196419b-0000-7000-8000-000000000002";
            let bindings = match_occupied_leaf_authorities(
                &[leaf(2, "Ag")],
                &[authority("AQ", device_one), authority("Ag", device_two)],
            )
            .unwrap();
            assert_eq!(bindings.len(), 1);
            assert_eq!(bindings[0].leaf_index, 2);
            assert_eq!(bindings[0].signature_key.as_str(), "Ag");
        }

        #[test]
        fn missing_or_wrong_historical_leaf_authority_fails_closed() {
            assert!(match_occupied_leaf_authorities(&[leaf(4, "AQ")], &[]).is_err());
            assert!(
                match_occupied_leaf_authorities(
                    &[leaf(4, "AQ")],
                    &[authority(
                        "Ag",
                        "ak:device:0196419b-0000-7000-8000-000000000001"
                    )],
                )
                .is_err()
            );
            assert!(
                match_occupied_leaf_authorities(
                    &[leaf(4, "AQ"), leaf(4, "Ag")],
                    &[
                        authority("AQ", "ak:device:0196419b-0000-7000-8000-000000000001"),
                        authority("Ag", "ak:device:0196419b-0000-7000-8000-000000000002")
                    ],
                )
                .is_err()
            );
        }

        #[test]
        fn identical_leaf_tuple_readd_uses_later_signed_history() {
            let first = authority("AQ", "ak:device:0196419b-0000-7000-8000-000000000001");
            let mut readded = first.clone();
            readded.device_authorize_event_id = Some(
                EventId::new("ak:event:ARELvWOpF6BRhrks3DlbQy-9XIE6aAQQumDQp7fA4Ape").unwrap(),
            );
            let bindings =
                match_occupied_leaf_authorities(&[leaf(2, "AQ")], &[first, readded.clone()])
                    .unwrap();
            assert_eq!(
                bindings[0].device_authorize_event_id,
                readded.device_authorize_event_id
            );
        }
    }
}
