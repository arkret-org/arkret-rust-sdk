use arkret_identity::account_device_signer_evidence::{
    verify_current_account_device_signer_evidence, verify_historical_account_device_signer_evidence,
};
use arkret_identity::build_authenticated_webvh_service_resolution;
use arkret_models_crypto::{
    DeviceAuthorizationWindow, DeviceProjectionAttestationCore, DeviceStatus,
};
use arkret_models_identity::AccountDeviceSignerEvidence;
use arkret_models_identity::service_identity::{CanonicalServiceUrl, ServiceRegistrationKey};
use arkret_signatures::device_projection::sign_device_projection_attestation;
use arkret_signatures::webvh::{
    ServiceRegistrationInceptionInput, prepare_service_registration_inception,
};
use arkret_wire::{
    AccountId, DeviceId, DidCoreId, DidKey, DidUrl, EventId, NonEmptyString, ServiceKind,
};
use chrono::{Duration, TimeZone as _, Utc};
use ed25519_dalek::SigningKey;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn signed_root() -> AccountDeviceSignerEvidence {
    let at = Utc.with_ymd_and_hms(2026, 9, 24, 0, 0, 0).unwrap();
    let mut rng = ChaCha20Rng::from_seed([74; 32]);
    let registration = ServiceRegistrationKey::new(
        ServiceKind::Station,
        CanonicalServiceUrl::new("https://station.example/").unwrap(),
    )
    .unwrap();
    let inception = prepare_service_registration_inception(
        &mut rng,
        &ServiceRegistrationInceptionInput {
            provider_endpoint: &"https://identity.example/".parse().unwrap(),
            registration_key: &registration,
            also_known_as: &[],
            version_time: at,
            did_key_fragment: None,
        },
    )
    .unwrap();
    let did = arkret_wire::Did::new(inception.did.clone()).unwrap();
    let service_id = arkret_wire::project_did_to_core_id(&did).unwrap();
    let attested_at = at + Duration::seconds(10);
    let service_resolution = build_authenticated_webvh_service_resolution(
        service_id.clone(),
        "station".into(),
        serde_json::from_value(inception.log_entry["state"].clone()).unwrap(),
        vec![inception.log_entry.clone()],
        vec![],
        attested_at,
    )
    .unwrap();
    let account_id = AccountId::new(
        DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
        service_id,
    );
    let core = DeviceProjectionAttestationCore {
        account_id,
        device_id: DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001").unwrap(),
        device_signing_key_did: DidKey::new(
            "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuVkhY7g94pVQyG98x",
        )
        .unwrap(),
        hpke_key: NonEmptyString::new("hpke-1").unwrap(),
        device_authorize_event_id: EventId::new(
            "ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e",
        )
        .unwrap(),
        authorized_generation_ref: 1,
        device_status: DeviceStatus::Active,
        authorization_window: DeviceAuthorizationWindow {
            not_before: at,
            expires_at: None,
        },
        attested_at,
        expires_at: attested_at + Duration::minutes(5),
    };
    let attestation = sign_device_projection_attestation(
        core,
        DidUrl::new(inception.did_key_id.clone()).unwrap(),
        &SigningKey::from_bytes(&inception.did_key_seed),
    )
    .unwrap();
    AccountDeviceSignerEvidence {
        device_projection_attestation: attestation,
        service_resolution,
    }
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
