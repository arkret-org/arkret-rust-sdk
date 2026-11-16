use std::sync::{Arc, Mutex};

use arkret_identity::{RealmAuthorityFreshness, RealmAuthorityKeyMap};
use arkret_signatures::PublicKeyMaterial;
use arkret_signatures::detached_object::sign_detached_object;
use arkret_test_kit::SignedEventFixtureBuilder;
use arkret_test_kit::authority_objects::signed_commit;
use arkret_test_kit::service_identity::ServiceIdentityFixture;
use arkret_wire::{
    ActorId, Base64UrlString, CommitStreamHead, CommittedEventFullView, DetachedSignatureContext,
    RealmAuthorityBundle, RealmAuthorityCurrentAssertion,
};
use chrono::Duration;
use serde_json::json;

use super::super::{OwnStationSessionSnapshot, OwnStationSessionSource};
use super::*;
use crate::{Auth, ClientBuilder, Error};

struct Source(Mutex<OwnStationSessionSnapshot>);
impl OwnStationSessionSource for Source {
    fn snapshot(&self) -> Result<OwnStationSessionSnapshot> {
        Ok(self.0.lock().unwrap().clone())
    }
}

fn now() -> DateTime<Utc> {
    DateTime::from_timestamp(Utc::now().timestamp(), 0).unwrap()
}

fn station_fixture(seed: u8) -> ServiceIdentityFixture {
    ServiceIdentityFixture::webvh(
        &url::Url::parse(&format!("https://station-{seed}.example/")).unwrap(),
        seed.into(),
        [seed; 32],
        "consent-authority",
        now() - Duration::days(1),
        now(),
    )
    .unwrap()
}

fn holder(station: &ServiceIdentityFixture) -> AccountId {
    AccountId::new(
        "ak:did_core:web:holder.example".parse().unwrap(),
        station.service_id.clone(),
    )
}

fn client(station: &ServiceIdentityFixture) -> (OwnStationStateClient, Arc<Source>) {
    client_at(station, "https://station.example/".into())
}

fn client_at(
    station: &ServiceIdentityFixture,
    base_url: String,
) -> (OwnStationStateClient, Arc<Source>) {
    let binding = arkret_models_discovery::StationConnectionBinding {
        service_id: station.service_id.clone(),
        base_url,
        trust_domain: "ak:trust_domain:station.example".parse().unwrap(),
        authentication_metadata: arkret_models_discovery::AuthenticationMetadata::minimal(),
    };
    let snapshot = OwnStationSessionSnapshot::new(
        binding.clone(),
        holder(station),
        station.service_id.clone(),
        arkret_wire::SessionGrantRef::new(
            station.service_id.clone(),
            arkret_wire::SessionGrantId::new(
                "ak:session_grant:0190c6aa-1234-7000-8000-000000000001",
            )
            .unwrap(),
        ),
        0,
        "token".into(),
    )
    .unwrap()
    .with_provider_identity(Default::default());
    let source = Arc::new(Source(Mutex::new(snapshot)));
    let raw = ClientBuilder::new(url::Url::parse(&binding.base_url).unwrap())
        .allow_insecure_localhost()
        .auth(Auth::Bearer("token".into()))
        .build()
        .unwrap();
    (
        OwnStationStateClient::new(raw, binding, source.clone()).unwrap(),
        source,
    )
}

fn genesis(station: &ServiceIdentityFixture, human: bool) -> CommittedEventFullView {
    if !human {
        return organization_genesis(station).0;
    }
    let account = holder(station);
    let did = "did:web:holder.example".parse().unwrap();
    let method = arkret_wire::DidUrl::new(
        "did:web:holder.example#ak:device:01904100-0000-7000-8000-bbbbbbbbbbbb",
    )
    .unwrap();
    let signer = arkret_test_kit::seeded_signer(did, method);
    let event = SignedEventFixtureBuilder::new(
        "ak.realm.create",
        ScopeRef::RealmGenesis,
        ActorId::account(account),
        json!({"object":{"purpose":"principal_control",
            "governance_station_id":station.service_id}}),
    )
    .with_created_at(now() - Duration::minutes(1))
    .build_unsigned()
    .unwrap();
    let event = arkret_test_kit::sign_verifiable_event(
        event,
        &signer,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap()
    .expect_verifiable();
    let commit = signed_commit(
        &station.verification_method,
        &station.signing_key,
        &event,
        0,
        None,
        event.event_id.clone(),
        None,
    )
    .unwrap();
    CommittedEventFullView { event, commit }
}

/// A pure, genuinely signed Org inception/finite vote/Service producer closure.
/// It establishes no live native admission or Organization shared session.
fn organization_genesis(
    station: &ServiceIdentityFixture,
) -> (
    CommittedEventFullView,
    arkret_models_collaboration::authority_commit::OrganizationGenesisSignerFact,
) {
    use arkret_models_collaboration::authority_commit::{
        AuthorityForwardBranch, PeerAuthorityForwardEventRequestBody,
    };
    use arkret_models_collaboration::events_payloads::realm::{RealmGenesis, RealmPurpose};
    use arkret_signatures::Ed25519DetachedJwsSigner;
    use arkret_wire::{
        ApprovalContext, ApprovalSignature, ApprovalSignatureInput, ApprovalSignatureProof,
        ApprovalSignatureProofKind, ApprovalTarget, CapabilityActionId, Did, DidUrl,
        EventAdmissionSubmission, GenesisSalt, ServiceOperationId,
    };

    let at = now() - Duration::minutes(1);
    let control = ed25519_dalek::SigningKey::from_bytes(&[103; 32]);
    let next_root = ed25519_dalek::SigningKey::from_bytes(&[102; 32]);
    let next_multibase =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(next_root.verifying_key().as_bytes());
    let org = arkret_signatures::webvh::prepare_organization_inception(
        &arkret_signatures::webvh::OrganizationInceptionInput {
            provider_endpoint: &url::Url::parse("https://organization-consent.example/").unwrap(),
            local_id: "organization",
            version_created_at: at - Duration::days(1),
            root_seed: &[101; 32],
            next_root_public_key_multibase: &next_multibase,
            control_public_key: &control.verifying_key().to_bytes(),
        },
    )
    .unwrap();
    let org_did = Did::new(&org.did).unwrap();
    let account = AccountId::new(
        arkret_wire::project_did_to_core_id(&org_did).unwrap(),
        station.service_id.clone(),
    );
    let object = RealmGenesis::new(
        RealmPurpose::PrincipalControl,
        GenesisSalt::new(arkret_canonical::base64url_encode([104; 32])).unwrap(),
        "ak:trust_domain:organization-consent".parse().unwrap(),
        arkret_wire::SecurityClass::HighAssurance,
        station.service_id.clone(),
        arkret_wire::JoinRule::Closed,
        arkret_wire::HistoryAccess::SinceJoin,
        arkret_wire::Discoverability::Secret,
        None,
        Some(arkret_models_identity::ResolutionCommitment {
            did: org_did.clone(),
            method_history_head: arkret_canonical::canonical_sha256(&org.log_entry).unwrap(),
            version_id: org.log_entry["versionId"].as_str().unwrap().to_owned(),
        }),
    )
    .unwrap();
    let mut event = SignedEventFixtureBuilder::new(
        "ak.realm.create",
        ScopeRef::RealmGenesis,
        ActorId::account(account),
        json!({"object": object}),
    )
    .with_created_at(at)
    .build_unsigned()
    .unwrap();
    let control_method = DidUrl::new(format!("{org_did}#organization-control")).unwrap();
    event.executed_by = Some(ActorId::service(station.service_id.clone()));
    event.authorization_ref = Some(control_method.clone().into());
    let producer = arkret_test_kit::seeded_signer_for_seed(
        station.signing_key.to_bytes(),
        station.resolution.normalized_did_document.id.clone(),
        station.verification_method.clone(),
    );
    let event = arkret_test_kit::sign_verifiable_event(
        event,
        &producer,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap()
    .expect_verifiable();
    let mut approval = ApprovalSignature {
        input: ApprovalSignatureInput {
            approval_context: ApprovalContext::RealmGovernance {},
            approval_target: ApprovalTarget::Event {
                event_id: event.event_id.clone(),
            },
            request_canonical_digest: arkret_wire::Hash::new(
                arkret_canonical::canonical_sha256(&event).unwrap(),
            )
            .unwrap(),
            operation: ServiceOperationId::PEER_EVENTS_COMMAND_SUBMIT_V1.into(),
            action: CapabilityActionId::RealmCreate,
            realm_id: event.realm_id.clone(),
            initiating_actor_id: event.actor_id.clone(),
            approver_did: org_did,
            approved_at: at,
            nonce: arkret_canonical::base64url_encode([105; 32]),
        },
        proof: ApprovalSignatureProof {
            kind: ApprovalSignatureProofKind::DetachedJws,
            verification_method: control_method,
            jws: String::new(),
        },
    };
    approval.proof.jws = Ed25519DetachedJwsSigner::from_seed(
        control.to_bytes(),
        approval.proof.verification_method.as_str(),
    )
    .sign_detached_jws(
        &arkret_signatures::approval_signature::approval_signature_signing_bytes(&approval)
            .unwrap(),
    );
    let mut submission = EventAdmissionSubmission::new(event.clone());
    submission.approval_signatures = Some(vec![approval]);
    let request = PeerAuthorityForwardEventRequestBody {
        branch: AuthorityForwardBranch::AuthorityForward,
        event_submission: submission,
        mls_group_state_material: None,
        content_backup_sources: None,
        producer_device_evidence: None,
        producer_agent_evidence: None,
        successor_device_evidence: None,
    };
    let (_, fact) =
        arkret_identity::organization_pcr_genesis::verify_organization_pcr_genesis_source(
            &request,
            &station.service_id,
            std::slice::from_ref(&org.log_entry),
            &[],
            Some(&station.resolution),
            at,
        )
        .unwrap();
    let commit = signed_commit(
        &station.verification_method,
        &station.signing_key,
        &event,
        0,
        None,
        event.event_id.clone(),
        Some(fact.digest().unwrap()),
    )
    .unwrap();
    let full = CommittedEventFullView { event, commit };
    arkret_identity::organization_pcr_genesis::verify_organization_genesis_signer_fact(
        &full, &fact,
    )
    .unwrap();
    assert_eq!(
        full.commit.producer_signer_fact_digest.as_ref(),
        Some(&fact.digest().unwrap())
    );
    (full, fact)
}

fn request(station: &ServiceIdentityFixture) -> ConsentCurrentReadRequestBody {
    serde_json::from_value(json!({
        "holder_account_id":holder(station),
        "peer":{"kind":"actor","actor_id":ActorId::account(holder(station))},
        "audience_actor_id":ActorId::service(station.service_id.clone()),
        "nonce":arkret_canonical::base64url_encode([19;32]),
    }))
    .unwrap()
}

fn outcome(
    station: &ServiceIdentityFixture,
    request: &ConsentCurrentReadRequestBody,
    realm: &RealmId,
    generation: u64,
) -> ConsentCurrentReadResponseBody {
    let mut outcome = serde_json::from_value(json!({
        "request_digest":arkret_models_collaboration::call_invitation::canonical_request_digest(request).unwrap(),
        "realm_id":realm,"governance_generation":(generation).to_string(),
        "effective_stream_head":{"stream_ref":{"kind":"realm","realm_id":realm},
            "stream_position":2,"commit_id":arkret_wire::RealmCommitId::from_digest([47;32])},
        "current":{"state":"never_written"},
        "evaluated_at":arkret_canonical::format_timestamp_canonical(now()),
        "expires_at":arkret_canonical::format_timestamp_canonical(now()+Duration::seconds(30)),
        "proof":{"verification_method":station.verification_method,"jws":"pending"},
    })).unwrap();
    arkret_signatures::call_invitation::sign_consent_current_read(
        &mut outcome,
        &station.signing_key,
    )
    .unwrap();
    outcome
}

#[test]
fn human_consent_authority_requires_exact_live_original_and_initial_tenure() {
    let station = station_fixture(71);
    let (client, source) = client(&station);
    let full = genesis(&station, true);
    let pcr = full.event.realm_id.clone();
    let bound = client
        .bind(
            full.event.event_id.clone(),
            CommittedEventView::Full(full.clone()),
        )
        .unwrap();
    let authority =
        ConsentCurrentReadAuthority::from_human_genesis(&holder(&station), &pcr, &bound).unwrap();
    assert_eq!(authority.generation(), 0);
    let request = request(&station);
    let signed = outcome(&station, &request, &pcr, 0);
    authority.validate_client(&client, &request, &pcr).unwrap();
    authority
        .verify_outcome(
            &request,
            &signed,
            &station.resolution.normalized_did_document,
            now(),
        )
        .unwrap();

    // There is no known-generation cache at this cold read. A real signature
    // at a nonzero Human tenure still cannot establish a new authority.
    let future = outcome(&station, &request, &pcr, 1);
    assert!(
        authority
            .verify_outcome(
                &request,
                &future,
                &station.resolution.normalized_did_document,
                now()
            )
            .is_err()
    );
    let other_realm = RealmId::from_event_id(&EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [21; 32],
    ));
    assert!(
        ConsentCurrentReadAuthority::from_human_genesis(&holder(&station), &other_realm, &bound)
            .is_err()
    );
    let nonhuman = genesis(&station, false);
    let nonhuman_bound = client
        .bind(
            nonhuman.event.event_id.clone(),
            CommittedEventView::Full(nonhuman.clone()),
        )
        .unwrap();
    assert!(
        ConsentCurrentReadAuthority::from_human_genesis(
            &holder(&station),
            &nonhuman.event.realm_id,
            &nonhuman_bound
        )
        .is_err()
    );
    let mut wrong_tenure = full;
    wrong_tenure.commit.governance_generation = 1;
    wrong_tenure.commit.commit_id = arkret_wire::RealmCommitId::from_digest(
        arkret_canonical::sha256_bytes(wrong_tenure.commit.canonical_id_bytes().unwrap()),
    );
    wrong_tenure.commit.signature = sign_detached_object(
        &arkret_canonical::unsigned_value(&wrong_tenure.commit, &["signature"]).unwrap(),
        DetachedSignatureContext::RealmCommit,
        station.verification_method.clone(),
        now(),
        &station.signing_key,
    )
    .unwrap();
    wrong_tenure.commit.validate_content_address().unwrap();
    let wrong = client
        .bind(
            wrong_tenure.event.event_id.clone(),
            CommittedEventView::Full(wrong_tenure),
        )
        .unwrap();
    assert!(
        ConsentCurrentReadAuthority::from_human_genesis(&holder(&station), &pcr, &wrong).is_err()
    );
    source.0.lock().unwrap().epoch += 1;
    assert!(authority.validate_client(&client, &request, &pcr).is_err());
    assert!(
        ConsentCurrentReadAuthority::from_human_genesis(&holder(&station), &pcr, &bound).is_err()
    );
}

#[test]
fn own_station_result_rejects_another_issuer_with_the_same_local_grant_id() {
    let station = station_fixture(72);
    let (client, source) = client(&station);
    let full = genesis(&station, true);
    let bound = client
        .bind(full.event.event_id.clone(), CommittedEventView::Full(full))
        .unwrap();
    let original = source.snapshot().unwrap();
    source.0.lock().unwrap().grant_ref.issuer_id =
        "ak:did_core:web:another-issuer.example".parse().unwrap();
    let changed = source.snapshot().unwrap();
    assert_eq!(original.grant_ref().id, changed.grant_ref().id);
    assert_ne!(original.grant_ref(), changed.grant_ref());
    assert!(matches!(
        bound.value(),
        Err(Error::OwnStationSessionChanged)
    ));
}

#[test]
fn consent_production_verifier_rejects_bad_proof_nonce_method_key_pcr_and_generation() {
    let station = station_fixture(73);
    let (client, _) = client(&station);
    let full = genesis(&station, true);
    let pcr = full.event.realm_id.clone();
    let bound = client
        .bind(full.event.event_id.clone(), CommittedEventView::Full(full))
        .unwrap();
    let authority =
        ConsentCurrentReadAuthority::from_human_genesis(&holder(&station), &pcr, &bound).unwrap();
    let request = request(&station);
    let signed = outcome(&station, &request, &pcr, 0);
    let document = &station.resolution.normalized_did_document;
    authority
        .verify_outcome(&request, &signed, document, now())
        .unwrap();
    for mutation in 0..5 {
        let mut changed = signed.clone();
        match mutation {
            0 => changed.proof.jws = "invalid".into(),
            1 => {
                changed.proof.verification_method =
                    arkret_wire::DidUrl::new("did:web:elsewhere.example#consent-authority").unwrap()
            }
            2 => changed.governance_generation = 1,
            3 => {
                changed.realm_id = RealmId::from_event_id(&EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [91; 32],
                ))
            }
            _ => {
                changed.proof.jws = arkret_signatures::sign_ed25519_detached_jws(
                    &ed25519_dalek::SigningKey::from_bytes(&[99; 32]),
                    &changed.signature_input().unwrap(),
                )
                .unwrap()
            }
        }
        assert!(
            authority
                .verify_outcome(&request, &changed, document, now())
                .is_err(),
            "accepted mutation {mutation}"
        );
    }
    let mut replay = request.clone();
    replay.nonce = arkret_canonical::base64url_encode([23; 32]);
    assert!(
        authority
            .verify_outcome(&replay, &signed, document, now())
            .is_err()
    );
    let mut without_relationship = document.clone();
    without_relationship
        .raw_properties
        .remove("assertionMethod");
    without_relationship
        .raw_properties
        .remove("assertion_methods");
    assert!(
        authority
            .verify_outcome(&request, &signed, &without_relationship, now())
            .is_err()
    );
    let wrong_document = station_fixture(79);
    assert!(
        authority
            .verify_outcome(
                &request,
                &signed,
                &wrong_document.resolution.normalized_did_document,
                now()
            )
            .is_err()
    );
}

fn verified_nonhuman(station: &ServiceIdentityFixture) -> (VerifiedRealmAuthority, AccountId) {
    let (full, fact) = organization_genesis(station);
    let account = full.event.actor_id.as_account_id().unwrap().clone();
    let realm = full.event.realm_id.clone();
    let head = CommitStreamHead {
        stream_ref: full.commit.stream_ref.clone(),
        stream_position: 2,
        commit_id: arkret_wire::RealmCommitId::from_digest([47; 32]),
    };
    let nonce = Base64UrlString::new(arkret_canonical::base64url_encode([97; 32])).unwrap();
    let mut assertion = RealmAuthorityCurrentAssertion {
        realm_id: realm.clone(),
        current_generation: 0,
        current_service_id: station.service_id.clone(),
        last_handoff_ref: None,
        realm_stream_head: head.clone(),
        nonce: nonce.clone(),
        expires_at: now() + Duration::minutes(2),
        signature: full.commit.signature.clone(),
    };
    assertion.signature = sign_detached_object(
        &arkret_canonical::unsigned_value(&assertion, &["signature"]).unwrap(),
        DetachedSignatureContext::RealmAuthorityCurrentAssertion,
        station.verification_method.clone(),
        now(),
        &station.signing_key,
    )
    .unwrap();
    let bundle = RealmAuthorityBundle {
        realm_id: realm,
        genesis_event: full.event,
        genesis_commit: full.commit,
        producer_signer_fact: Some(serde_json::to_value(fact).unwrap()),
        authority_transitions: vec![],
        current_generation: 0,
        current_service_id: station.service_id.clone(),
        current_route_record: serde_json::to_value(&station.resolution).unwrap(),
        realm_stream_head: head,
        bundle_issued_at: now(),
        current_assertion: assertion,
    };
    let keys = RealmAuthorityKeyMap::new().with_key(
        &station.verification_method,
        PublicKeyMaterial::Ed25519Raw {
            bytes: station.signing_key.verifying_key().to_bytes().to_vec(),
        },
    );
    let verified = arkret_identity::verify_realm_authority_bundle(
        &bundle,
        &RealmAuthorityFreshness::new(now(), nonce.clone()),
        &keys,
    )
    .unwrap();
    assert!(matches!(
        GenesisGovernance::from_genesis(&bundle.genesis_event).unwrap(),
        GenesisGovernance::Organization,
    ));
    let mut missing = bundle.clone();
    missing.producer_signer_fact = None;
    assert!(
        arkret_identity::verify_realm_authority_bundle(
            &missing,
            &RealmAuthorityFreshness::new(now(), nonce),
            &keys,
        )
        .is_err()
    );
    (verified, account)
}

#[test]
fn nonhuman_consent_uses_verified_authority_and_retains_current_assertion_deadline() {
    let station = station_fixture(81);
    let (verified, organization) = verified_nonhuman(&station);
    let mut authority =
        ConsentCurrentReadAuthority::from_verified_realm(&verified, &station.resolution).unwrap();
    assert!(
        ConsentCurrentReadAuthority::from_verified_realm_at(
            &verified,
            &station.resolution,
            verified.current_assertion_expires_at().unwrap() + Duration::seconds(1),
        )
        .is_err()
    );
    let mut request = request(&station);
    request.holder_account_id = organization.clone();
    request.peer =
        serde_json::from_value(json!({"kind":"actor","actor_id":ActorId::account(organization)}))
            .unwrap();
    let signed = outcome(
        &station,
        &request,
        verified.realm_id(),
        verified.current_generation(),
    );
    let document = &station.resolution.normalized_did_document;
    authority
        .verify_outcome(&request, &signed, document, now())
        .unwrap();
    for mutation in ["older", "fork", "stream"] {
        let mut stale = signed.clone();
        match mutation {
            "older" => stale.effective_stream_head.stream_position -= 1,
            "fork" => {
                stale.effective_stream_head.commit_id =
                    arkret_wire::RealmCommitId::from_digest([101; 32])
            }
            _ => {
                stale.effective_stream_head.stream_ref = CommitStreamRef::Realm {
                    realm_id: RealmId::from_event_id(&EventId::from_digest(
                        arkret_canonical::DigestSuite::Sha256,
                        [103; 32],
                    )),
                }
            }
        }
        arkret_signatures::call_invitation::sign_consent_current_read(
            &mut stale,
            &station.signing_key,
        )
        .unwrap();
        if mutation != "stream" {
            // These remain valid request-bound JWS assertions. Independent
            // authority head monotonicity, not a broken signature, rejects them.
            arkret_signatures::call_invitation::verify_consent_current_read(
                &stale,
                &request,
                &station.verification_method,
                &PublicKeyMaterial::Ed25519Raw {
                    bytes: station.signing_key.verifying_key().to_bytes().to_vec(),
                },
                stale.governance_generation,
                now(),
            )
            .unwrap();
        }
        assert!(
            authority
                .verify_outcome(&request, &stale, document, now())
                .is_err(),
            "accepted {mutation} authority cut"
        );
    }
    let wrong_authority = station_fixture(83);
    assert!(
        ConsentCurrentReadAuthority::from_verified_realm(&verified, &wrong_authority.resolution)
            .is_err()
    );
    let forged = outcome(
        &wrong_authority,
        &request,
        verified.realm_id(),
        verified.current_generation(),
    );
    assert!(
        authority
            .verify_outcome(
                &request,
                &forged,
                &wrong_authority.resolution.normalized_did_document,
                now()
            )
            .is_err()
    );
    authority.authority_expires_at = Some(now() - Duration::seconds(1));
    assert!(
        authority
            .verify_outcome(&request, &signed, document, now())
            .is_err()
    );

    let (client, _) = client(&station);
    let mut bound = client.bind(request, signed).unwrap();
    bound.valid_until = Some(now() - Duration::seconds(1));
    assert!(bound.value().is_err());
    assert!(bound.into_value().is_err());
}

#[tokio::test]
async fn consent_http_cannot_bind_a_structurally_valid_bad_authority_proof() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let station = station_fixture(89);
    // This document is independently authenticated fixture material, not a
    // key or method learned from either HTTP Consent response.
    arkret_identity::verify_authenticated_service_resolution_history(
        &station.resolution,
        &station.service_id,
        now(),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (client, _) = client_at(
        &station,
        format!("http://{}/", listener.local_addr().unwrap()),
    );
    let full = genesis(&station, true);
    let pcr = full.event.realm_id.clone();
    let bound = client
        .bind(full.event.event_id.clone(), CommittedEventView::Full(full))
        .unwrap();
    let authority =
        ConsentCurrentReadAuthority::from_human_genesis(&holder(&station), &pcr, &bound).unwrap();
    let request = request(&station);
    let positive = outcome(&station, &request, &pcr, 0);
    let mut negative = positive.clone();
    negative.proof.jws = "invalid".into();
    let server = tokio::spawn(async move {
        for value in [positive, negative] {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            loop {
                let mut chunk = [0_u8; 8192];
                let count = socket.read(&mut chunk).await.unwrap();
                assert_ne!(count, 0);
                bytes.extend_from_slice(&chunk[..count]);
                let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n")
                else {
                    continue;
                };
                let headers = String::from_utf8_lossy(&bytes[..header_end]).to_ascii_lowercase();
                let length: usize = headers
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .unwrap()
                    .trim()
                    .parse()
                    .unwrap();
                if bytes.len() >= header_end + 4 + length {
                    break;
                }
            }
            let wire = String::from_utf8_lossy(&bytes);
            assert!(wire.contains("/_arkret/self/consent/current"));
            assert!(
                wire.to_ascii_lowercase()
                    .contains("authorization: bearer token")
            );
            let body = serde_json::to_vec(&value).unwrap();
            socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes()).await.unwrap();
            socket.write_all(&body).await.unwrap();
        }
    });
    let document = &station.resolution.normalized_did_document;
    let accepted = client
        .consent_current_with_document(&request, &pcr, &authority, document)
        .await
        .unwrap();
    assert_eq!(accepted.value().unwrap().governance_generation, 0);
    assert!(
        client
            .consent_current_with_document(&request, &pcr, &authority, document)
            .await
            .is_err()
    );
    server.await.unwrap();
}
