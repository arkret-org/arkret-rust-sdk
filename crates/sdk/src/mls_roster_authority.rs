use std::collections::HashMap;

use arkret_models_collaboration::mls_roster_authority::{
    MlsAddAuthorityAttestation, MlsAttestAddRequestBody, MlsRosterAuthorityManifest,
    MlsRosterAuthorityReadOutcome, MlsRosterAuthorityReadRequestBody, MlsRosterRecord,
};
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
        &document,
        &verification_method,
        &document.id,
        arkret_identity::DidVerificationRelationship::AssertionMethod,
    )
    .map_err(|error| WireError::Protocol(error.to_string()))?;
    let public_key =
        arkret_identity::public_key_material_from_document(&document, &verification_method)
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

/// Verify transport completeness, the signed full-array digest and every
/// historical Add Station signature. The caller must still reconcile these
/// records with accepted Commit/Proposal provenance and RFC public tree bytes.
pub fn verify_mls_roster_authority_pages(
    pages: &[MlsRosterAuthorityReadOutcome],
    request: &MlsRosterAuthorityReadRequestBody,
    expected_governance_station: &DidCoreId,
    expected_authority_head_event_ref: &EventId,
    governance_resolution: &AuthenticatedServiceResolution,
    attestor_resolutions: &HashMap<DidCoreId, AuthenticatedServiceResolution>,
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
    if pages.len() as u64 != first.manifest.page_count {
        return Err(WireError::Protocol(
            "MLS roster page count mismatch".to_owned(),
        ));
    }
    let manifest_bytes = arkret_canonical::canonical_json_bytes(&first.manifest)
        .map_err(|error| WireError::Protocol(error.to_string()))?;
    let mut records = Vec::new();
    for (index, page) in pages.iter().enumerate() {
        if page.page_index != index as u64
            || arkret_canonical::canonical_json_bytes(&page.manifest)
                .map_err(|error| WireError::Protocol(error.to_string()))?
                != manifest_bytes
            || page.records.is_empty()
            || page.records.len() > 8
            || (index + 1 < pages.len() && page.records.len() != 8)
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
                let attestor_resolution = attestor_resolutions
                    .get(&attestation.attestor_station_id)
                    .ok_or_else(|| {
                        WireError::Protocol(
                            "MLS roster Add attestor resolution is unavailable".to_owned(),
                        )
                    })?;
                verify_mls_add_authority_attestation_signature(attestation, attestor_resolution)?;
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

#[cfg(test)]
mod tests {
    use arkret_identity::{DidKeyResolver, DidResolver};
    use arkret_models_crypto::KeyOperationSignature;
    use arkret_models_identity::{
        AuthenticatedServiceResolution, ResolutionDidBindingEvidenceKind,
        ResolutionDidBindingEvidenceReceipt, ResolutionMethodEvidenceBoundary,
        ResolutionMethodHistoryEvidence,
    };
    use arkret_wire::{
        ActorId, Base64UrlString, BlobRef, Did, EventId, Hash, MlsGroupId, NonEmptyString, RealmId,
        ScopeRef, project_did_to_core_id,
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
}
