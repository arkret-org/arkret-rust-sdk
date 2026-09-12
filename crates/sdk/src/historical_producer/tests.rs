use arkret_models_crypto::{
    DeviceAuthorizationWindow, DeviceProjectionAttestationCore, DeviceStatus,
};
use arkret_signatures::webvh::{ServiceInceptionInput, prepare_service_inception};
use arkret_wire::{
    AccountId, DeviceId, Did, DidCoreId, DidKey, Hash, Hlc, NonEmptyString, RealmId, ScopeRef,
};
use chrono::{Duration, TimeZone as _};
use ed25519_dalek::SigningKey;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng as _;

use super::*;

struct Fixture {
    root: Evidence,
    dependency: Evidence,
    actor: ActorId,
    device_key: SigningKey,
    at: DateTime<Utc>,
}

impl Fixture {
    fn new() -> Self {
        let at = Utc.with_ymd_and_hms(2026, 9, 12, 0, 0, 0).unwrap();
        let endpoint = "https://producer-source.example/".parse().unwrap();
        let mut rng = ChaChaRng::seed_from_u64(991);
        let inception = prepare_service_inception(
            &mut rng,
            &ServiceInceptionInput {
                principal_endpoint: &endpoint,
                local_id: "station",
                also_known_as: &[],
                version_time: at,
                did_key_fragment: Some("assertion-1"),
            },
        )
        .unwrap();
        let station_did = Did::new(inception.did.clone()).unwrap();
        let station = arkret_wire::project_did_to_core_id(&station_did).unwrap();
        let document = serde_json::from_value(inception.log_entry["state"].clone()).unwrap();
        let resolution = arkret_identity::build_authenticated_webvh_service_resolution(
            station.clone(),
            "station".to_owned(),
            document,
            vec![inception.log_entry.clone()],
            Vec::new(),
            at,
        )
        .unwrap();
        let method = DidUrl::new(inception.did_key_id.clone()).unwrap();
        let dependency = Evidence::Service {
            signer_id: station.clone(),
            verification_method: method.clone(),
            authenticated_resolution: resolution,
        };
        let account = AccountId::new(
            DidCoreId::new("ak:did_core:webvh:zdeviceholder").unwrap(),
            station,
        );
        let device = DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001").unwrap();
        let device_key = SigningKey::from_bytes(&[33; 32]);
        let core = DeviceProjectionAttestationCore {
            account_id: account.clone(),
            device_id: device.clone(),
            device_signing_key_did: DidKey::new(format!(
                "did:key:{}",
                arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                    &device_key.verifying_key().to_bytes()
                )
            ))
            .unwrap(),
            hpke_key: NonEmptyString::new("hpke-key").unwrap(),
            device_authorize_event_id: EventId::from_digest(DigestSuite::Sha256, [1; 32]),
            authorized_generation_ref: 7,
            device_status: DeviceStatus::Active,
            authorization_window: DeviceAuthorizationWindow {
                not_before: at,
                expires_at: Some(at + Duration::hours(1)),
            },
            attested_at: at,
            expires_at: at + Duration::minutes(5),
        };
        let attestation = arkret_signatures::device_projection::sign_device_projection_attestation(
            core,
            method,
            &SigningKey::from_bytes(&inception.did_key_seed),
        )
        .unwrap();
        let root = Evidence::AccountDevice {
            signer_id: account.principal_id.clone(),
            verification_method: DidUrl::new(format!(
                "did:webvh:zdeviceholder:holder.example#{device}"
            ))
            .unwrap(),
            device_projection_attestation: attestation,
            attester_signer_evidence_ref: dependency.evidence_ref().unwrap(),
        };
        Self {
            root,
            dependency,
            actor: ActorId::account(account),
            device_key,
            at,
        }
    }
    fn source(&self) -> AuthenticatedHistoricalProducerSource {
        AuthenticatedHistoricalProducerSource::authenticate(
            &self.root.evidence_ref().unwrap(),
            &self.actor,
            &self.root,
            std::slice::from_ref(&self.dependency),
            self.at,
        )
        .unwrap()
    }
    fn event(&self, at: DateTime<Utc>) -> Event {
        let mut event = arkret_wire::test_support::raw_event_for_actor_at(
            "ak.message.create",
            ScopeRef::Realm {
                realm_id: RealmId::new("ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir")
                    .unwrap(),
            },
            self.actor.clone(),
            0,
            Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
            serde_json::json!({"message_id":"m1","content":{"type":"text","body":"hello"}}),
            at,
        )
        .unwrap();
        let digest = Hash::new(
            event
                .event_digest_with_digest_suite(DigestSuite::Sha256)
                .unwrap(),
        )
        .unwrap();
        event.event_id = EventId::from_event_digest(&digest).unwrap();
        let mut proof = arkret_wire::ProducerEventProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            verification_method: self.root.verification_method().clone(),
            event_digest: digest,
            signer_resolution_evidence_ref: Some(self.root.evidence_ref().unwrap()),
            created_at: at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: String::new(),
        };
        proof.jws = arkret_signatures::jws::sign_jws_ed25519(
            &proof.canonical_binding_bytes(&event.actor_id).unwrap(),
            &self.device_key,
        )
        .unwrap();
        event.proofs = vec![proof];
        event
    }
}

#[test]
fn verified_source_survives_cache_expiry_but_not_original_grant_expiry() {
    let fixture = Fixture::new();
    let source = fixture.source();
    source
        .verify_event(
            &fixture.event(fixture.at + Duration::minutes(10)),
            DigestSuite::Sha256,
        )
        .unwrap();
    assert!(
        source
            .verify_event(
                &fixture.event(fixture.at + Duration::hours(1)),
                DigestSuite::Sha256
            )
            .is_err()
    );
    // A cold receiver with the same immutable source closure authenticates the
    // same publication without using its arrival time or refreshing the source.
    let cold_receiver = AuthenticatedHistoricalProducerSource::authenticate(
        &fixture.root.evidence_ref().unwrap(),
        &fixture.actor,
        &fixture.root,
        std::slice::from_ref(&fixture.dependency),
        fixture.at + Duration::minutes(10),
    )
    .unwrap();
    let event = fixture.event(fixture.at + Duration::minutes(10));
    assert_eq!(
        source
            .verify_event(&event, DigestSuite::Sha256)
            .unwrap()
            .key(),
        cold_receiver
            .verify_event(&event, DigestSuite::Sha256)
            .unwrap()
            .key()
    );
}

#[test]
fn raw_projection_tampering_and_wrong_full_account_cannot_create_authenticated_source() {
    let mut fixture = Fixture::new();
    let Evidence::AccountDevice {
        device_projection_attestation,
        ..
    } = &mut fixture.root
    else {
        unreachable!()
    };
    device_projection_attestation
        .attestation
        .authorized_generation_ref += 1;
    assert!(
        AuthenticatedHistoricalProducerSource::authenticate(
            &fixture.root.evidence_ref().unwrap(),
            &fixture.actor,
            &fixture.root,
            std::slice::from_ref(&fixture.dependency),
            fixture.at
        )
        .is_err()
    );
    let fixture = Fixture::new();
    let mut wrong = fixture.actor.as_account_id().unwrap().clone();
    wrong.station_id = DidCoreId::new("ak:did_core:web:other.example").unwrap();
    assert!(
        AuthenticatedHistoricalProducerSource::authenticate(
            &fixture.root.evidence_ref().unwrap(),
            &ActorId::account(wrong),
            &fixture.root,
            &[fixture.dependency],
            fixture.at
        )
        .is_err()
    );
}

#[test]
fn event_id_does_not_allow_replacing_original_proof_or_evidence_reference() {
    let fixture = Fixture::new();
    let source = fixture.source();
    let event = fixture.event(fixture.at);
    let verified = source.verify_event(&event, DigestSuite::Sha256).unwrap();
    let mut modified = event.clone();
    modified.proofs[0].jws = "AA".to_owned();
    assert_eq!(modified.event_id, event.event_id);
    assert!(!verified.matches_event(&modified));
    assert!(source.verify_event(&modified, DigestSuite::Sha256).is_err());
    modified = event;
    modified.proofs[0].signer_resolution_evidence_ref =
        Some(fixture.dependency.evidence_ref().unwrap());
    assert!(source.verify_event(&modified, DigestSuite::Sha256).is_err());
}

#[test]
fn exact_attester_ref_and_native_history_are_mandatory() {
    let fixture = Fixture::new();
    assert!(
        AuthenticatedHistoricalProducerSource::authenticate(
            &fixture.root.evidence_ref().unwrap(),
            &fixture.actor,
            &fixture.root,
            &[],
            fixture.at
        )
        .is_err()
    );
    let mut corrupt = fixture.dependency.clone();
    let Evidence::Service {
        authenticated_resolution,
        ..
    } = &mut corrupt
    else {
        unreachable!()
    };
    let arkret_models_identity::ResolutionMethodHistoryEvidence::WebvhLog { log_entries, .. } =
        &mut authenticated_resolution.method_history_evidence
    else {
        unreachable!()
    };
    log_entries[0]["proof"] = serde_json::json!([]);
    let mut root = fixture.root.clone();
    let Evidence::AccountDevice {
        attester_signer_evidence_ref,
        ..
    } = &mut root
    else {
        unreachable!()
    };
    *attester_signer_evidence_ref = corrupt.evidence_ref().unwrap();
    assert!(
        AuthenticatedHistoricalProducerSource::authenticate(
            &root.evidence_ref().unwrap(),
            &fixture.actor,
            &root,
            &[corrupt],
            fixture.at
        )
        .is_err()
    );
}
