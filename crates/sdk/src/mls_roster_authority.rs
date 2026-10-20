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
    claim_issuer_resolution: &AuthenticatedServiceResolution,
    attestor_resolution: &AuthenticatedServiceResolution,
) -> Result<(), WireError> {
    request.validate_claim_binding()?;
    verify_peer_keypackage_claim_receipt_signature(
        &request.claim_outcome.claim_receipt,
        claim_issuer_resolution,
    )?;
    verify_mls_add_authority_attestation_signature(&request.attestation, attestor_resolution)
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
            claim_issuer_resolution,
            attestor_resolution,
            ..
        } = record
        {
            verify_station_signature(
                &attestation.claim_receipt.destination_id,
                attestation.claim_receipt.claimed_at,
                &attestation.claim_receipt.signature,
                &peer_keypackage_claim_receipt_signing_bytes(&attestation.claim_receipt)
                    .map_err(|error| WireError::Protocol(error.to_string()))?,
                claim_issuer_resolution
                    .as_ref()
                    .unwrap_or(attestor_resolution),
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
            claim_issuer_resolution,
            attestor_resolution,
            ..
        } = record
        {
            let station = &attestation.attestor_station_id;
            let receipt = &attestation.claim_receipt;
            add_signing_keys.push(MlsRosterAddSigningKeys {
                record_digest: arkret_wire::Hash::new(
                    arkret_canonical::canonical_sha256(record).map_err(roster_error)?,
                )
                .map_err(roster_error)?,
                claim_receipt_signing_key: station_signing_key(
                    &receipt.destination_id,
                    receipt.claimed_at,
                    &receipt.signature,
                    &peer_keypackage_claim_receipt_signing_bytes(receipt).map_err(roster_error)?,
                    claim_issuer_resolution
                        .as_ref()
                        .unwrap_or(attestor_resolution),
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
                    &receipt.destination_id,
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
#[path = "mls_roster_authority/tests.rs"]
mod tests;

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
            &request.realm_id,
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
                &request.realm_id,
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
        realm_id: &arkret_wire::RealmId,
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
        match (&endpoint, actor_id) {
            (MlsEndpointIdentity::HumanDevice { .. }, ActorId::Account { .. })
            | (MlsEndpointIdentity::AgentRuntime { .. }, ActorId::Account { .. }) => {}
            (MlsEndpointIdentity::HumanDevice { .. }, ActorId::Realm { realm_actor_id })
                if &realm_actor_id.realm_id == realm_id => {}
            _ => return Err("MLS roster endpoint differs from the Actor kind or Realm".to_owned()),
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

        #[test]
        fn realm_device_roster_requires_full_identity_and_own_realm() {
            let realm: arkret_wire::RealmId =
                "ak:realm:AUGIFvQctz4TjQTmvvO4Wdy-xdc5XP2ZnJ5Qpbh4s8Ru"
                    .parse()
                    .unwrap();
            let principal: DidCoreId = "ak:did_core:webvh:zRealmBotFixture".parse().unwrap();
            let actor = ActorId::realm(arkret_wire::RealmActorId {
                realm_id: realm.clone(),
                principal_id: principal.clone(),
            });
            let device = MlsWelcomeRecipientEndpoint::Device {
                device_id: "ak:device:0196419b-0000-7000-8000-000000000001"
                    .parse()
                    .unwrap(),
            };
            let key = crate::Base64UrlString::new("AQ".to_owned()).unwrap();
            let event =
                EventId::new("ak:event:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1").unwrap();
            let binding = authority_from_record(&realm, &actor, &key, &device, &event).unwrap();
            assert_eq!(binding.actor_id, actor);
            assert_eq!(binding.device_authorize_event_id, Some(event.clone()));
            let other = "ak:realm:AT2LoQ65P6bU2ZDxq9XbubTSMDrqzlK8EFJNmM_pxt62"
                .parse()
                .unwrap();
            assert!(authority_from_record(&other, &actor, &key, &device, &event).is_err());
            assert!(
                authority_from_record(&realm, &ActorId::service(principal), &key, &device, &event)
                    .is_err()
            );
            let agent = MlsWelcomeRecipientEndpoint::AgentRuntime {
                verification_method: DidUrl::new("did:web:bot.example#agent").unwrap(),
            };
            assert!(authority_from_record(&realm, &actor, &key, &agent, &event).is_err());
        }

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
