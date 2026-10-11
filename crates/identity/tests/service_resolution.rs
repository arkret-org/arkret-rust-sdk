use arkret_identity::{
    build_authenticated_webvh_service_resolution, verify_authenticated_service_resolution_history,
    verify_current_service_resolution, verify_service_resolution_floor,
};
use arkret_models_identity::service_identity::{CanonicalServiceUrl, ServiceRegistrationKey};
use arkret_models_identity::{
    AuthenticatedServiceResolution, DidDocument, ResolutionDidBindingEvidenceKind,
    ResolutionDidBindingEvidenceReceipt, ResolutionMethodEvidenceBoundary,
    ResolutionMethodHistoryEvidence, ServiceMethodState,
};
use arkret_signatures::webvh::{
    ServiceRegistrationInceptionInput, ServiceRotationInput,
    prepare_service_registration_inception, prepare_service_rotation,
};
use arkret_wire::{Did, ServiceKind};
use chrono::{DateTime, Duration, Utc};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::json;

fn now() -> DateTime<Utc> {
    "2026-09-08T00:00:00Z".parse().unwrap()
}
fn key(seed: &[u8; 32]) -> String {
    arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        ed25519_dalek::SigningKey::from_bytes(seed)
            .verifying_key()
            .as_bytes(),
    )
}
fn fixture() -> (
    AuthenticatedServiceResolution,
    AuthenticatedServiceResolution,
) {
    let mut rng = ChaCha20Rng::from_seed([42; 32]);
    let registration = ServiceRegistrationKey::new(
        ServiceKind::Station,
        CanonicalServiceUrl::new("https://old.example/").unwrap(),
    )
    .unwrap();
    let endpoint = "https://identity.example/".parse().unwrap();
    let inception = prepare_service_registration_inception(
        &mut rng,
        &ServiceRegistrationInceptionInput {
            provider_endpoint: &endpoint,
            registration_key: &registration,
            also_known_as: &[],
            version_time: now(),
            did_key_fragment: None,
        },
    )
    .unwrap();
    let did = Did::new(inception.did.clone()).unwrap();
    let service_id = arkret_wire::project_did_to_core_id(&did).unwrap();
    let mut logs = vec![inception.log_entry.clone()];
    let original = build_authenticated_webvh_service_resolution(
        service_id.clone(),
        "station".to_owned(),
        serde_json::from_value(logs[0]["state"].clone()).unwrap(),
        logs.clone(),
        vec![],
        now(),
    )
    .unwrap();
    let mut state = logs[0]["state"].clone();
    state["service"][0]["serviceEndpoint"] = json!("https://middle.example/");
    let next = prepare_service_rotation(&ServiceRotationInput {
        did: did.as_str(),
        previous_entries: &logs,
        state: &state,
        current_update_seed: &inception.next_update_key_seed,
        next_update_public_key_multibase: &key(&[43; 32]),
        version_time: now() + Duration::seconds(1),
    })
    .unwrap();
    logs.push(next.log_entry);
    state["service"][0]["serviceEndpoint"] = json!("https://new.example/");
    let next = prepare_service_rotation(&ServiceRotationInput {
        did: did.as_str(),
        previous_entries: &logs,
        state: &state,
        current_update_seed: &[43; 32],
        next_update_public_key_multibase: &key(&[44; 32]),
        version_time: now() + Duration::seconds(2),
    })
    .unwrap();
    logs.push(next.log_entry);
    let updated = build_authenticated_webvh_service_resolution(
        service_id,
        "station".to_owned(),
        serde_json::from_value(state).unwrap(),
        logs,
        vec![],
        now() + Duration::days(1),
    )
    .unwrap();
    (original, updated)
}
fn floor(resolution: &AuthenticatedServiceResolution) -> ServiceMethodState {
    let projection = resolution.projection().unwrap();
    ServiceMethodState {
        service_id: projection.service_id,
        service_kind: projection.service_kind,
        did: projection.did,
        method_history_head: projection.method_history_head,
        version_id: projection.version_id,
        verified_at: now(),
    }
}
fn current(resolution: &AuthenticatedServiceResolution) -> arkret_identity::ResolvedDid {
    let document = resolution.normalized_did_document.clone();
    let method_evidence = match &resolution.method_history_evidence {
        ResolutionMethodHistoryEvidence::WebvhLog {
            boundary, evidence, ..
        } => arkret_identity::MethodEvidence {
            proofs: vec![arkret_identity::MethodEvidenceProof::WebvhLog(
                arkret_identity::WebvhLogEvidence {
                    history_head: boundary.to_version_id.clone(),
                    witnesses: vec![],
                    witness_proofs_digest: evidence.method_proofs[0].witness_proofs_digest.clone(),
                },
            )],
            history_head: Some(boundary.to_version_id.clone()),
            version_id: Some(boundary.to_version_id.clone()),
        },
        _ => arkret_identity::MethodEvidence::none(),
    };
    arkret_identity::ResolvedDid::new(document, method_evidence)
}
#[test]
fn offline_route_skips_updates_and_persists_only_native_state() {
    let (old, new) = fixture();
    let saved: ServiceMethodState =
        serde_json::from_slice(&serde_json::to_vec(&floor(&old)).unwrap()).unwrap();
    verify_service_resolution_floor(&new, &saved).unwrap();
    let route = verify_current_service_resolution(
        &new,
        &new.service_id,
        "station",
        &current(&new),
        now() + Duration::days(90),
    )
    .unwrap();
    assert_eq!(route.base_url, "https://new.example/");
    assert!(verify_service_resolution_floor(&old, &floor(&new)).is_err());
    assert!(
        verify_current_service_resolution(&old, &old.service_id, "station", &current(&new), now())
            .is_err()
    );
    verify_current_service_resolution(
        &old,
        &old.service_id,
        "station",
        &current(&old),
        now() + Duration::days(90),
    )
    .unwrap();
}
#[test]
fn missing_native_history_wrong_role_and_endpoint_tampering_are_rejected() {
    let (_, new) = fixture();
    assert!(
        verify_current_service_resolution(
            &new,
            &new.service_id,
            "identity_registry",
            &current(&new),
            now()
        )
        .is_err()
    );
    let mut missing = new.clone();
    if let ResolutionMethodHistoryEvidence::WebvhLog { log_entries, .. } =
        &mut missing.method_history_evidence
    {
        log_entries.remove(1);
    }
    assert!(
        verify_authenticated_service_resolution_history(&missing, &new.service_id, now()).is_err()
    );
    let mut altered = new.clone();
    altered
        .normalized_did_document
        .raw_properties
        .get_mut("service")
        .unwrap()[0]["serviceEndpoint"] = json!("https://attacker.example/");
    assert!(
        verify_authenticated_service_resolution_history(&altered, &new.service_id, now()).is_err()
    );
}
fn web_resolution(endpoint: &str) -> AuthenticatedServiceResolution {
    let did = Did::new("did:web:station.example").unwrap();
    let document:DidDocument=serde_json::from_value(json!({"id":did,"verificationMethod":[],"service":[{"id":format!("{did}#service"),"type":"ArkretService","serviceKind":"station","serviceEndpoint":endpoint}]})).unwrap();
    let digest = arkret_models_identity::normalized_did_document_digest(&document).unwrap();
    let version = format!(
        "synthetic-jcs-sha256:{}",
        digest.as_str().trim_start_matches("sha256:")
    );
    AuthenticatedServiceResolution {
        service_id: arkret_wire::project_did_to_core_id(&did).unwrap(),
        service_kind: "station".to_owned(),
        method_history_evidence: ResolutionMethodHistoryEvidence::DidWebDocument {
            boundary: ResolutionMethodEvidenceBoundary {
                from_method_history_head: digest.to_string(),
                to_method_history_head: digest.to_string(),
                from_version_id: version.clone(),
                to_version_id: version,
            },
            evidence: ResolutionDidBindingEvidenceReceipt {
                kind: ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
                method: "web".to_owned(),
                document_digest: digest,
                method_proofs: vec![],
            },
        },
        normalized_did_document: document,
    }
}
#[test]
fn did_web_endpoint_updates_do_not_claim_historical_authority() {
    let old = web_resolution("https://old.example/");
    let new = web_resolution("https://new.example/");
    verify_service_resolution_floor(&new, &floor(&old)).unwrap();
    verify_current_service_resolution(&new, &new.service_id, "station", &current(&new), now())
        .unwrap();
    assert!(verify_authenticated_service_resolution_history(&new, &new.service_id, now()).is_err());
    let mut duplicate = new.clone();
    let entries = duplicate
        .normalized_did_document
        .raw_properties
        .get_mut("service")
        .unwrap()
        .as_array_mut()
        .unwrap();
    let mut other = entries[0].clone();
    other["id"] = json!(format!("{}#other", new.normalized_did_document.id));
    entries.push(other);
    if let ResolutionMethodHistoryEvidence::DidWebDocument { evidence, .. } =
        &mut duplicate.method_history_evidence
    {
        evidence.document_digest = arkret_models_identity::normalized_did_document_digest(
            &duplicate.normalized_did_document,
        )
        .unwrap();
    }
    assert!(duplicate.projection().is_err());
}

#[test]
fn portable_method_relocation_preserves_the_accepted_service_state() {
    use arkret_signatures::webvh::{WebvhRelocationInput, prepare_webvh_relocation};
    let (old, current) = fixture();
    let ResolutionMethodHistoryEvidence::WebvhLog {
        mut log_entries, ..
    } = current.method_history_evidence.clone()
    else {
        unreachable!()
    };
    let old_did = current.normalized_did_document.id.to_string();
    let scid = old_did.split(':').nth(2).unwrap();
    let target = format!("did:webvh:{scid}:moved.example:webvh:service");
    let mut state: serde_json::Value = serde_json::from_str(
        &serde_json::to_string(&log_entries.last().unwrap()["state"])
            .unwrap()
            .replace(&old_did, &target),
    )
    .unwrap();
    state["alsoKnownAs"] = json!([old_did]);
    let relocation = prepare_webvh_relocation(&WebvhRelocationInput {
        current_did: &old_did,
        target_did: &target,
        previous_entries: &log_entries,
        version_time: now() + Duration::seconds(3),
        current_update_seed: &[44; 32],
        next_update_public_key_multibase: &key(&[45; 32]),
        state: &state,
    })
    .unwrap();
    log_entries.push(relocation.log_entry);
    let raw_log = log_entries
        .iter()
        .map(|entry| serde_json::to_string(entry).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(
        arkret_identity::discover_webvh_current_did(&current.service_id, raw_log.as_bytes())
            .unwrap()
            .as_str(),
        target
    );
    let moved = build_authenticated_webvh_service_resolution(
        current.service_id,
        "station".to_owned(),
        serde_json::from_value(state).unwrap(),
        log_entries,
        vec![],
        now() + Duration::days(1),
    )
    .unwrap();
    verify_service_resolution_floor(&moved, &floor(&old)).unwrap();
    assert_eq!(moved.projection().unwrap().did.as_str(), target);
    assert!(verify_service_resolution_floor(&old, &floor(&moved)).is_err());
}

#[test]
fn normalized_wire_roundtrip_retains_native_authority_and_rejects_raw_documents() {
    let (_, resolution) = fixture();
    let mut wire = serde_json::to_value(&resolution).unwrap();
    assert!(wire["normalized_did_document"].get("did").is_some());
    assert!(wire["normalized_did_document"].get("id").is_none());
    let parsed: AuthenticatedServiceResolution = serde_json::from_value(wire.clone()).unwrap();
    verify_current_service_resolution(
        &parsed,
        &resolution.service_id,
        "station",
        &current(&resolution),
        now(),
    )
    .unwrap();
    assert_eq!(
        parsed.projection().unwrap(),
        resolution.projection().unwrap()
    );
    wire["normalized_did_document"] =
        serde_json::to_value(&resolution.normalized_did_document).unwrap();
    assert!(serde_json::from_value::<AuthenticatedServiceResolution>(wire).is_err());
    let mut stale_current = current(&resolution);
    stale_current.method_evidence.version_id = Some("99-different-native-entry".into());
    assert!(
        verify_current_service_resolution(
            &resolution,
            &resolution.service_id,
            "station",
            &stale_current,
            now()
        )
        .is_err()
    );
}

#[test]
fn independently_valid_native_forks_cannot_replace_an_accepted_branch() {
    let (_, current) = fixture();
    let ResolutionMethodHistoryEvidence::WebvhLog { log_entries, .. } =
        &current.method_history_evidence
    else {
        unreachable!()
    };
    let fork = |endpoint: &str, seed: &[u8; 32]| {
        let mut state = log_entries.last().unwrap()["state"].clone();
        state["service"][0]["serviceEndpoint"] = json!(endpoint);
        let next = prepare_service_rotation(&ServiceRotationInput {
            did: current.normalized_did_document.id.as_str(),
            previous_entries: log_entries,
            state: &state,
            current_update_seed: &[44; 32],
            next_update_public_key_multibase: &key(seed),
            version_time: now() + Duration::seconds(3),
        })
        .unwrap();
        let mut entries = log_entries.clone();
        entries.push(next.log_entry);
        build_authenticated_webvh_service_resolution(
            current.service_id.clone(),
            "station".to_owned(),
            serde_json::from_value(state).unwrap(),
            entries,
            vec![],
            now(),
        )
        .unwrap()
    };
    let accepted = fork("https://accepted.example/", &[46; 32]);
    let rival = fork("https://rival.example/", &[47; 32]);
    assert!(verify_service_resolution_floor(&rival, &floor(&accepted)).is_err());
}
