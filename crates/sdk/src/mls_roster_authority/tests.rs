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
fn realm_consume_uses_accepting_governor_without_rewriting_original_claim_issuer() {
    use arkret_models_crypto::{
        KeyPackageConsumeReceipt, RecipientMlsDurableReceipt, RecipientMlsDurableSigner,
    };
    use arkret_wire::{DeviceId, DidUrl, DomainSeparationId, RealmActorId};
    let (_, pages, resolution) = signed_two_page_roster();
    let MlsRosterRecord::Add { attestation, .. } = &pages[1].records[0] else {
        panic!("Add fixture")
    };
    let old = DidCoreId::new("ak:did_core:web:original-claim.example").unwrap();
    let device_key = ed25519_dalek::SigningKey::from_bytes(&[43; 32]);
    let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        device_key.verifying_key().as_bytes(),
    );
    let device_did = Did::new(format!("did:key:{multibase}")).unwrap();
    let method = DidUrl::new(format!("{device_did}#{multibase}")).unwrap();
    let actor = ActorId::realm(RealmActorId {
        realm_id: attestation.realm_id.clone(),
        principal_id: DidCoreId::new("ak:did_core:webvh:zRealmActorFixture").unwrap(),
    });
    let signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
        &[43; 32],
        method.as_str(),
        b"placeholder",
    )
    .unwrap();
    let mut durable = RecipientMlsDurableReceipt {
        domain: NonEmptyString::new(DomainSeparationId::MLS_RECIPIENT_DURABLE_RECEIPT_V1).unwrap(),
        claim_request_id: attestation.claim_receipt.claim_request_id.clone(),
        key_package_ref: NonEmptyString::new(arkret_canonical::sha256_digest(b"package")).unwrap(),
        recipient: RecipientMlsDurableSigner::RealmDevice {
            recipient_actor_id: actor.clone(),
            recipient_device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001")
                .unwrap(),
            device_verification_method: method.clone(),
        },
        recipient_id: old.clone(),
        realm_id: attestation.realm_id.clone(),
        mls_group_id: attestation.mls_group_id.clone(),
        mls_epoch: attestation.epoch,
        welcome_ref: attestation.welcome_id.clone(),
        welcome_digest: Hash::new(arkret_canonical::sha256_digest(b"welcome")).unwrap(),
        durable_at: attestation.attested_at,
        signature,
    };
    durable.signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
        &[43; 32],
        method.as_str(),
        &durable.canonical_signing_bytes().unwrap(),
    )
    .unwrap();
    let mut receipt = KeyPackageConsumeReceipt {
        domain: NonEmptyString::new(DomainSeparationId::KEYPACKAGE_CONSUME_RECEIPT_V1).unwrap(),
        request_digest: Hash::new(arkret_canonical::canonical_sha256(&durable).unwrap()).unwrap(),
        claim_id: attestation.claim_id.clone(),
        recipient_durable_receipt: durable,
        consumed_at: attestation.attested_at,
        signature: attestation.signature.clone(),
    };
    receipt.signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
        &[41; 32],
        attestation.signature.kid.as_str(),
        &receipt.canonical_signing_bytes().unwrap(),
    )
    .unwrap();
    crate::verify_peer_keypackage_consume_receipt_signature(
        &receipt,
        &resolution.service_id,
        &resolution,
    )
    .unwrap();
    assert!(
        crate::verify_peer_keypackage_consume_receipt_signature(&receipt, &old, &resolution)
            .is_err()
    );
    let mut changed = receipt.clone();
    changed.recipient_durable_receipt.recipient_id = resolution.service_id.clone();
    assert!(
        crate::verify_peer_keypackage_consume_receipt_signature(
            &changed,
            &resolution.service_id,
            &resolution
        )
        .is_err()
    );
    receipt.recipient_durable_receipt.recipient = RecipientMlsDurableSigner::Device {
        recipient_account_id: arkret_wire::AccountId::new(
            actor.signing_principal_id().clone(),
            old,
        ),
        recipient_device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001")
            .unwrap(),
        device_verification_method: method,
    };
    receipt.signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
        &[41; 32],
        attestation.signature.kid.as_str(),
        &receipt.canonical_signing_bytes().unwrap(),
    )
    .unwrap();
    assert!(
        crate::verify_peer_keypackage_consume_receipt_signature(
            &receipt,
            &resolution.service_id,
            &resolution
        )
        .is_err()
    );
}

#[test]
fn roster_station_signatures_require_historical_assertion_method() {
    let seed = [41_u8; 32];
    let signer = ed25519_dalek::SigningKey::from_bytes(&seed);
    let multibase =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(signer.verifying_key().as_bytes());
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
                document_digest: arkret_models_identity::normalized_did_document_digest(&document)
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
    assert!(verify_station_signature(&station, at, &signature, b"changed", &resolution).is_err());
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
    let realm_id = RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap();
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
    manifest.signature =
        arkret_signatures::keypackages::sign_keypackage_signing_input(&seed, kid, &signing_bytes)
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
    let multibase =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(signer.verifying_key().as_bytes());
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
                document_digest: arkret_models_identity::normalized_did_document_digest(&document)
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
    let actor = ActorId::account(arkret_wire::AccountId::new(
        station.clone(),
        station.clone(),
    ));
    let claim_request: PeerKeyPackagesClaimUnsignedRequest = serde_json::from_value(
        serde_json::json!({
            "claim_request_id": "0123456789012345678901",
            "target_agent_id": station,
            "target_agent_verification_method": method,
            "target_agent_key_authorize_event_id": EventId::from_digest(arkret_canonical::DigestSuite::Sha256,[14;32]),
            "intended_realm_id": request.realm_id,
            "mls_group_id": request.mls_group_id,
            "claim_purpose": "realm_membership",
            "required_capabilities": [arkret_models_crypto::ARKRET_CONTENT_V1],
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
        claim_authority_ref: None,
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
        claim_authority_ref: None,
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
        leaf_signature_key_b64u: Base64UrlString::new(arkret_canonical::base64url_encode([7; 32]))
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
            claim_issuer_resolution: None,
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
    assert!(verify_mls_self_roster_authority_pages(&changed, &request, governance, head).is_err());
    let mut changed = projected.clone();
    changed[0].add_signing_keys = changed[1].add_signing_keys.clone();
    assert!(verify_mls_self_roster_authority_pages(&changed, &request, governance, head).is_err());
    let mut changed = projected.clone();
    changed[1].add_signing_keys[0]
        .attestation_signing_key
        .public_key_b64u =
        Base64UrlString::new(arkret_canonical::base64url_encode([9; 32])).unwrap();
    assert!(verify_mls_self_roster_authority_pages(&changed, &request, governance, head).is_err());
    let mut changed = projected.clone();
    changed[1].add_signing_keys[0].record_digest =
        Hash::new(format!("sha256:{}", "9".repeat(64))).unwrap();
    assert!(verify_mls_self_roster_authority_pages(&changed, &request, governance, head).is_err());
    let mut changed = projected.clone();
    changed[0].manifest_signing_key.verification_method =
        DidUrl::new("did:web:other.example#key").unwrap();
    assert!(verify_mls_self_roster_authority_pages(&changed, &request, governance, head).is_err());
    let mut changed = projected;
    changed[1].roster.records.reverse();
    changed.reverse();
    assert!(verify_mls_self_roster_authority_pages(&changed, &request, governance, head).is_err());
    let mut changed = pages[1].clone();
    if let MlsRosterRecord::Add {
        attestor_resolution,
        ..
    } = &mut changed.records[0]
    {
        attestor_resolution.service_kind = "agent".into();
    }
    assert!(
        project_mls_self_roster_authority_page(changed, &request, governance, head, &resolution)
            .is_err()
    );
}

#[test]
fn self_roster_station_uses_native_webvh_history_at_each_original_signature_time() {
    use arkret_models_identity::service_identity::{CanonicalServiceUrl, ServiceRegistrationKey};
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
        next_update_public_key_multibase: &arkret_canonical::ed25519_pubkey_to_did_key_multibase(
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
                &peer_keypackage_claim_receipt_signing_bytes(&attestation.claim_receipt).unwrap(),
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
        page.manifest.signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
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
    assert!(verify_mls_add_authority_attestation_signature(&another_sidecar, &resolution).is_err());
    let mut wrong = attestation.clone();
    wrong.effective_scope = ScopeRef::RealmGenesis;
    assert!(wrong.validate_shape().is_err());
    wrong = attestation.clone();
    wrong.realm_id = RealmId::new("ak:realm:AQdmOQIzsGDs6LjeW5Icy92GXh1n9_6SGgVCJJ_2a3FV").unwrap();
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
            Base64UrlString::new(arkret_canonical::base64url_encode(vec![7; 1_600_000])).unwrap();
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
