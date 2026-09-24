use arkret_canonical::DigestSuite;
use arkret_identity::account_device_signer_evidence::{
    verify_current_account_device_signer_evidence, verify_forwarded_human_producer,
    verify_historical_account_device_signer_evidence,
};
use arkret_identity::build_authenticated_webvh_service_resolution;
use arkret_models_crypto::{
    DeviceAuthorizationWindow, DeviceProjectionAttestation, DeviceProjectionAttestationCore,
    DeviceStatus,
};
use arkret_models_identity::AccountDeviceSignerEvidence;
use arkret_models_identity::service_identity::{CanonicalServiceUrl, ServiceRegistrationKey};
use arkret_signatures::device_projection::sign_device_projection_attestation;
use arkret_signatures::webvh::{
    ServiceRegistrationInceptionInput, prepare_service_registration_inception,
};
use arkret_signatures::{
    Ed25519DetachedJwsSigner, SignEventOptions, sign_ed25519_detached_jws, sign_event,
};
use arkret_wire::{
    AccountId, ActorId, AuthoredEvent, DeviceId, Did, DidCoreId, DidKey, DidUrl, ErrorCode, Event,
    EventId, NonEmptyString, ProtocolSignature, RealmId, ScopeRef, ServiceKind,
};
use chrono::{DateTime, Duration, TimeZone as _, Utc};
use ed25519_dalek::SigningKey;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::json;

const DEVICE: &str = "ak:device:0196419b-0000-7000-8000-000000000001";
const PRINCIPAL_DID: &str = "did:webvh:z6mkfixture:alice.example";
const DEVICE_SEED: [u8; 32] = [7; 32];

/// One registered Station together with the key that signs its attestations.
struct Station {
    service_id: DidCoreId,
    method: DidUrl,
    signing_key: SigningKey,
    service_resolution: arkret_models_identity::AuthenticatedServiceResolution,
    registered_at: DateTime<Utc>,
}

fn station(seed: u8, host: &str) -> Station {
    let registered_at = Utc.with_ymd_and_hms(2026, 9, 24, 0, 0, 0).unwrap();
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let registration = ServiceRegistrationKey::new(
        ServiceKind::Station,
        CanonicalServiceUrl::new(format!("https://{host}/")).unwrap(),
    )
    .unwrap();
    let inception = prepare_service_registration_inception(
        &mut rng,
        &ServiceRegistrationInceptionInput {
            provider_endpoint: &"https://identity.example/".parse().unwrap(),
            registration_key: &registration,
            also_known_as: &[],
            version_time: registered_at,
            did_key_fragment: None,
        },
    )
    .unwrap();
    let did = Did::new(inception.did.clone()).unwrap();
    let service_id = arkret_wire::project_did_to_core_id(&did).unwrap();
    let service_resolution = build_authenticated_webvh_service_resolution(
        service_id.clone(),
        "station".into(),
        serde_json::from_value(inception.log_entry["state"].clone()).unwrap(),
        vec![inception.log_entry.clone()],
        vec![],
        registered_at + Duration::seconds(10),
    )
    .unwrap();
    Station {
        service_id,
        method: DidUrl::new(inception.did_key_id.clone()).unwrap(),
        signing_key: SigningKey::from_bytes(&inception.did_key_seed),
        service_resolution,
        registered_at,
    }
}

fn device_key_did() -> DidKey {
    let public = SigningKey::from_bytes(&DEVICE_SEED)
        .verifying_key()
        .to_bytes();
    DidKey::new(format!(
        "did:key:{}",
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(&public)
    ))
    .unwrap()
}

fn account(station: &Station) -> AccountId {
    AccountId::new(
        arkret_wire::project_did_to_core_id(&Did::new(PRINCIPAL_DID).unwrap()).unwrap(),
        station.service_id.clone(),
    )
}

fn core(station: &Station) -> DeviceProjectionAttestationCore {
    let attested_at = station.registered_at + Duration::seconds(10);
    DeviceProjectionAttestationCore {
        account_id: account(station),
        device_id: DeviceId::new(DEVICE).unwrap(),
        device_signing_key_did: device_key_did(),
        hpke_key: NonEmptyString::new("hpke-1").unwrap(),
        device_authorize_event_id: EventId::new(
            "ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e",
        )
        .unwrap(),
        authorized_generation_ref: 1,
        device_status: DeviceStatus::Active,
        authorization_window: DeviceAuthorizationWindow {
            not_before: station.registered_at,
            expires_at: None,
        },
        attested_at,
        expires_at: attested_at + Duration::minutes(5),
    }
}

/// Sign any attestation core with the Station key, bypassing the producer-side
/// guards so a verifier can be fed what a compromised or buggy origin emits.
fn sign_raw(
    core: DeviceProjectionAttestationCore,
    method: &DidUrl,
    key: &SigningKey,
) -> DeviceProjectionAttestation {
    let mut attestation = DeviceProjectionAttestation {
        proof: ProtocolSignature {
            verification_method: method.clone(),
            created_at: core.attested_at,
            jws: "eyJhbGciOiJFZDI1NTE5In0..AA".to_owned(),
        },
        attestation: core,
    };
    attestation.proof.jws =
        sign_ed25519_detached_jws(key, &attestation.proof_signing_bytes().unwrap()).unwrap();
    attestation
}

fn evidence_with(
    station: &Station,
    edit: impl FnOnce(&mut DeviceProjectionAttestationCore),
) -> AccountDeviceSignerEvidence {
    let mut core = core(station);
    edit(&mut core);
    AccountDeviceSignerEvidence {
        device_projection_attestation: sign_raw(core, &station.method, &station.signing_key),
        service_resolution: station.service_resolution.clone(),
    }
}

fn signed_root() -> AccountDeviceSignerEvidence {
    let station = station(74, "station.example");
    let attestation = sign_device_projection_attestation(
        core(&station),
        station.method.clone(),
        &station.signing_key,
    )
    .unwrap();
    AccountDeviceSignerEvidence {
        device_projection_attestation: attestation,
        service_resolution: station.service_resolution,
    }
}

fn device_event(
    actor: ActorId,
    fragment: &str,
    created_at: DateTime<Utc>,
    seed: [u8; 32],
) -> Event {
    let event = arkret_wire::test_support::raw_event_for_actor_at(
        "ak.realm.policy",
        ScopeRef::Realm {
            realm_id: RealmId::from_event_id(&EventId::from_digest(
                DigestSuite::Sha256,
                [0x41; 32],
            )),
        },
        actor,
        json!({"policy": "fixture"}),
        created_at,
    )
    .unwrap();
    let mut authored =
        AuthoredEvent::finalize_with_digest_suite(event, DigestSuite::Sha256).unwrap();
    sign_event(
        &mut authored,
        &Ed25519DetachedJwsSigner::from_seed(seed, format!("{PRINCIPAL_DID}#{fragment}")),
        SignEventOptions::new().with_created_at(created_at),
    )
    .unwrap();
    authored.into_event()
}

fn human_event(station: &Station) -> Event {
    device_event(
        ActorId::account(account(station)),
        DEVICE,
        station.registered_at + Duration::seconds(30),
        DEVICE_SEED,
    )
}

fn now(station: &Station) -> DateTime<Utc> {
    station.registered_at + Duration::minutes(1)
}

fn rejection(
    evidence: &AccountDeviceSignerEvidence,
    event: &Event,
    source: &DidCoreId,
    now: DateTime<Utc>,
) -> Option<ErrorCode> {
    verify_forwarded_human_producer(evidence, event, source, DigestSuite::Sha256, now)
        .unwrap_err()
        .error_code()
}

#[test]
fn complete_signed_root_verifies_current_and_historical_use() {
    let root = signed_root();
    let core = &root.device_projection_attestation.attestation;
    verify_current_account_device_signer_evidence(
        &root,
        &core.account_id,
        &core.device_id,
        core.attested_at + Duration::seconds(1),
    )
    .unwrap();
    assert!(
        verify_current_account_device_signer_evidence(
            &root,
            &core.account_id,
            &core.device_id,
            core.expires_at,
        )
        .is_err()
    );
    verify_historical_account_device_signer_evidence(&root, &core.account_id, &core.device_id)
        .unwrap();

    let mut wrong_ref_preimage = root.clone();
    wrong_ref_preimage.service_resolution.service_kind = "media".into();
    assert!(
        !wrong_ref_preimage
            .matches_ref(&root.signer_evidence_ref().unwrap())
            .unwrap()
    );
    let mut wrong_generation = root.clone();
    wrong_generation
        .device_projection_attestation
        .attestation
        .authorized_generation_ref = 2;
    assert!(
        verify_historical_account_device_signer_evidence(
            &wrong_generation,
            &core.account_id,
            &core.device_id,
        )
        .is_err()
    );
    let mut wrong_service = root.clone();
    wrong_service.service_resolution.service_id =
        DidCoreId::new("ak:did_core:web:other.example").unwrap();
    assert!(
        verify_historical_account_device_signer_evidence(
            &wrong_service,
            &core.account_id,
            &core.device_id,
        )
        .is_err()
    );
}

#[test]
fn fresh_forwarded_evidence_admits_the_human_device_producer() {
    let station = station(74, "station.example");
    let evidence = evidence_with(&station, |_| {});
    let event = human_event(&station);
    let producer = verify_forwarded_human_producer(
        &evidence,
        &event,
        &station.service_id,
        DigestSuite::Sha256,
        now(&station),
    )
    .unwrap();
    assert_eq!(producer.account_id, account(&station));
    assert_eq!(producer.device_id.as_str(), DEVICE);
}

#[test]
fn source_station_and_attestation_signature_bind_the_origin() {
    let station = station(74, "station.example");
    let evidence = evidence_with(&station, |_| {});
    let event = human_event(&station);
    let now = now(&station);

    // Step 1: the authenticated peer is not the Account Station.
    let other = DidCoreId::new("ak:did_core:web:other.example").unwrap();
    assert_eq!(
        rejection(&evidence, &event, &other, now),
        Some(ErrorCode::SignatureInvalid)
    );

    // Step 2: attestation signed by a key the Station never published.
    let rogue = SigningKey::from_bytes(&[9; 32]);
    let mut forged = evidence.clone();
    forged.device_projection_attestation = sign_raw(core(&station), &station.method, &rogue);
    assert_eq!(
        rejection(&forged, &event, &station.service_id, now),
        Some(ErrorCode::SignatureInvalid)
    );

    // Step 2: attestation signed by another Station's registered key.
    let foreign = crate::station(75, "foreign.example");
    let mut foreign_signed = evidence.clone();
    foreign_signed.device_projection_attestation =
        sign_raw(core(&station), &foreign.method, &foreign.signing_key);
    assert_eq!(
        rejection(&foreign_signed, &event, &station.service_id, now),
        Some(ErrorCode::SignatureInvalid)
    );

    // Step 2: the carried Service history belongs to another Station.
    let mut foreign_history = evidence.clone();
    foreign_history.service_resolution = foreign.service_resolution;
    assert_eq!(
        rejection(&foreign_history, &event, &station.service_id, now),
        Some(ErrorCode::SignatureInvalid)
    );

    // Step 2: the Service history does not yet contain the method at attested_at.
    let before_registration = evidence_with(&station, |core| {
        core.attested_at = station.registered_at - Duration::seconds(1);
        core.authorization_window.not_before = core.attested_at;
    });
    assert_eq!(
        rejection(&before_registration, &event, &station.service_id, now),
        Some(ErrorCode::SignatureInvalid)
    );

    // Step 2: any altered attested member breaks the Station signature.
    let mut tampered = evidence;
    tampered
        .device_projection_attestation
        .attestation
        .expires_at += Duration::hours(1);
    assert_eq!(
        rejection(&tampered, &event, &station.service_id, now),
        Some(ErrorCode::SignatureInvalid)
    );
}

#[test]
fn stale_or_out_of_window_evidence_is_unauthorized() {
    let station = station(74, "station.example");
    let evidence = evidence_with(&station, |_| {});
    let event = human_event(&station);
    let core = core(&station);

    // Step 3: the attestation cache deadline has passed.
    assert_eq!(
        rejection(&evidence, &event, &station.service_id, core.expires_at),
        Some(ErrorCode::DeviceUnauthorized)
    );

    // Step 4: the original window does not yet cover the Event.
    let early_event = device_event(
        ActorId::account(account(&station)),
        DEVICE,
        station.registered_at - Duration::seconds(1),
        DEVICE_SEED,
    );
    assert_eq!(
        rejection(&evidence, &early_event, &station.service_id, now(&station)),
        Some(ErrorCode::DeviceUnauthorized)
    );

    // Step 4: the original window ended before the Event was created.
    let ended = evidence_with(&station, |core| {
        core.expires_at = core.attested_at + Duration::seconds(15);
        core.authorization_window.expires_at = Some(core.expires_at);
    });
    assert_eq!(
        rejection(
            &ended,
            &event,
            &station.service_id,
            station.registered_at + Duration::seconds(20),
        ),
        Some(ErrorCode::DeviceUnauthorized)
    );

    // Step 4: an origin-signed cache deadline beyond the original window
    // never extends the window past now.
    let overlong = evidence_with(&station, |core| {
        core.authorization_window.expires_at = Some(core.attested_at + Duration::seconds(40));
    });
    verify_forwarded_human_producer(
        &overlong,
        &event,
        &station.service_id,
        DigestSuite::Sha256,
        station.registered_at + Duration::seconds(45),
    )
    .unwrap();
    assert_eq!(
        rejection(
            &overlong,
            &event,
            &station.service_id,
            station.registered_at + Duration::seconds(50),
        ),
        Some(ErrorCode::DeviceUnauthorized)
    );

    // Step 4: a revoked device, even when signed by the origin.
    let revoked = evidence_with(&station, |core| core.device_status = DeviceStatus::Revoked);
    assert_eq!(
        rejection(&revoked, &event, &station.service_id, now(&station)),
        Some(ErrorCode::DeviceRevoked)
    );
}

#[test]
fn attested_device_must_be_the_producer_and_verify_its_proof() {
    let station = station(74, "station.example");
    let evidence = evidence_with(&station, |_| {});
    let now = now(&station);

    // Step 5: the proof fragment names another device.
    let other_device = device_event(
        ActorId::account(account(&station)),
        "ak:device:0196419b-0000-7000-8000-000000000002",
        station.registered_at + Duration::seconds(30),
        DEVICE_SEED,
    );
    assert_eq!(
        rejection(&evidence, &other_device, &station.service_id, now),
        Some(ErrorCode::SignatureInvalid)
    );

    // Step 5: the producer is another Account of the same Station.
    let other_account = device_event(
        ActorId::account(AccountId::new(
            DidCoreId::new("ak:did_core:webvh:z6mkother").unwrap(),
            station.service_id.clone(),
        )),
        DEVICE,
        station.registered_at + Duration::seconds(30),
        DEVICE_SEED,
    );
    assert_eq!(
        rejection(&evidence, &other_account, &station.service_id, now),
        Some(ErrorCode::SignatureInvalid)
    );

    // Step 5: the producer proof was made by a key other than the attested one.
    let other_key = device_event(
        ActorId::account(account(&station)),
        DEVICE,
        station.registered_at + Duration::seconds(30),
        [8; 32],
    );
    assert_eq!(
        rejection(&evidence, &other_key, &station.service_id, now),
        Some(ErrorCode::SignatureInvalid)
    );
}

#[test]
fn non_device_producer_has_no_forwarded_evidence_to_verify() {
    let station = station(74, "station.example");
    let evidence = evidence_with(&station, |_| {});
    let service_actor = device_event(
        ActorId::service(station.service_id.clone()),
        DEVICE,
        station.registered_at + Duration::seconds(30),
        DEVICE_SEED,
    );
    assert_eq!(
        rejection(
            &evidence,
            &service_actor,
            &station.service_id,
            now(&station)
        ),
        Some(ErrorCode::SchemaViolation)
    );
    let agent_key = device_event(
        ActorId::account(account(&station)),
        "agent-runtime-1",
        station.registered_at + Duration::seconds(30),
        DEVICE_SEED,
    );
    assert_eq!(
        rejection(&evidence, &agent_key, &station.service_id, now(&station)),
        Some(ErrorCode::SchemaViolation)
    );
}
