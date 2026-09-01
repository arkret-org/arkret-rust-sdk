use arkret_identity::verify_did_webvh_v1_log;
use arkret_signatures::webvh::{
    PrincipalInceptionInput, PrincipalRotationInput, WebvhRelocationInput,
    prepare_portable_principal_inception, prepare_principal_inception,
    prepare_principal_portability_update, prepare_webvh_relocation, validate_webvh_history_at,
};
use arkret_wire::Did;
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};

fn public_key(seed: &[u8; 32]) -> String {
    arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        &SigningKey::from_bytes(seed).verifying_key().to_bytes(),
    )
}

#[test]
fn portable_relocation_preserves_scid_and_requires_direct_predecessor_link() {
    let current_seed = [9u8; 32];
    let next_seed = [11u8; 32];
    let current_key = public_key(&current_seed);
    let next_key = public_key(&next_seed);
    let endpoint = "https://old.example.com/".parse().unwrap();
    let inception = prepare_portable_principal_inception(&PrincipalInceptionInput {
        provider_endpoint: &endpoint,
        principal_endpoint: &endpoint,
        local_id: "alice",
        also_known_as: &[],
        version_time: DateTime::parse_from_rfc3339("2026-05-06T00:00:00.000Z")
            .unwrap()
            .with_timezone(&Utc),
        root_seed: &[7u8; 32],
        next_root_public_key_multibase: &current_key,
        witness_policy: None,
    })
    .unwrap();
    let scid = inception.did.split(':').nth(2).unwrap();
    let target_did = format!("did:webvh:{scid}:new.example.com:webvh:alice");
    let mut successor_state: Value = serde_json::from_str(
        &serde_json::to_string(&inception.log_entry["state"])
            .unwrap()
            .replace(&inception.did, &target_did),
    )
    .unwrap();
    successor_state["alsoKnownAs"] = json!([inception.did.clone()]);
    let relocation = prepare_webvh_relocation(&WebvhRelocationInput {
        current_did: &inception.did,
        target_did: &target_did,
        previous_entries: std::slice::from_ref(&inception.log_entry),
        version_time: DateTime::parse_from_rfc3339("2026-05-07T00:00:00.000Z")
            .unwrap()
            .with_timezone(&Utc),
        current_update_seed: &current_seed,
        next_update_public_key_multibase: &next_key,
        state: &successor_state,
    })
    .unwrap();
    let entries = vec![inception.log_entry.clone(), relocation.log_entry];
    let target = Did::new(target_did.clone()).unwrap();
    let verified = verify_did_webvh_v1_log(&target, &entries).unwrap();
    assert_eq!(verified.head_state["id"], target_did);
    assert!(verify_did_webvh_v1_log(&Did::new(inception.did.clone()).unwrap(), &entries).is_err());

    let mut missing_link = successor_state.clone();
    missing_link["alsoKnownAs"] = json!([]);
    assert!(
        prepare_webvh_relocation(&WebvhRelocationInput {
            current_did: &inception.did,
            target_did: target.as_str(),
            previous_entries: std::slice::from_ref(&inception.log_entry),
            version_time: DateTime::parse_from_rfc3339("2026-05-07T00:00:00.000Z")
                .unwrap()
                .with_timezone(&Utc),
            current_update_seed: &current_seed,
            next_update_public_key_multibase: &next_key,
            state: &missing_link,
        })
        .is_err()
    );
    let different_core = target_did.replacen(scid, "QmDifferentScid", 1);
    assert!(
        prepare_webvh_relocation(&WebvhRelocationInput {
            current_did: &inception.did,
            target_did: &different_core,
            previous_entries: std::slice::from_ref(&inception.log_entry),
            version_time: DateTime::parse_from_rfc3339("2026-05-07T00:00:00.000Z")
                .unwrap()
                .with_timezone(&Utc),
            current_update_seed: &current_seed,
            next_update_public_key_multibase: &next_key,
            state: &successor_state,
        })
        .is_err()
    );
}

fn at(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .unwrap()
        .with_timezone(&Utc)
}

fn relocated_state(inception: &Value, predecessor: &str, target: &str) -> Value {
    let mut state: Value = serde_json::from_str(
        &serde_json::to_string(inception)
            .unwrap()
            .replace(predecessor, target),
    )
    .unwrap();
    state["alsoKnownAs"] = json!([predecessor]);
    state
}

#[test]
fn predecessor_effective_portability_is_shared_and_survives_restart() {
    let enable_seed = [41u8; 32];
    let relocation_seed = [42u8; 32];
    let next_seed = [43u8; 32];
    let endpoint = "https://old-transition.example/".parse().unwrap();
    let inception = prepare_principal_inception(&PrincipalInceptionInput {
        provider_endpoint: &endpoint,
        principal_endpoint: &endpoint,
        local_id: "alice",
        also_known_as: &[],
        version_time: at("2026-06-01T00:00:00Z"),
        root_seed: &[40u8; 32],
        next_root_public_key_multibase: &public_key(&enable_seed),
        witness_policy: None,
    })
    .unwrap();
    let enabled = prepare_principal_portability_update(
        &PrincipalRotationInput {
            did: &inception.did,
            local_id: &inception.local_id,
            previous_entries: std::slice::from_ref(&inception.log_entry),
            version_time: at("2026-06-02T00:00:00Z"),
            current_root_seed: &enable_seed,
            next_root_public_key_multibase: &public_key(&relocation_seed),
            state: &inception.log_entry["state"],
        },
        true,
    )
    .unwrap();

    let scid = inception.did.split(':').nth(2).unwrap();
    let target_did = format!("did:webvh:{scid}:new-transition.example:webvh:alice");
    let target_state = relocated_state(&inception.log_entry["state"], &inception.did, &target_did);
    let predecessor_entries = vec![inception.log_entry.clone(), enabled.log_entry.clone()];
    let relocation = prepare_webvh_relocation(&WebvhRelocationInput {
        current_did: &inception.did,
        target_did: &target_did,
        previous_entries: &predecessor_entries,
        version_time: at("2026-06-03T00:00:00Z"),
        current_update_seed: &relocation_seed,
        next_update_public_key_multibase: &public_key(&next_seed),
        state: &target_state,
    })
    .unwrap();
    let accepted = vec![
        inception.log_entry.clone(),
        enabled.log_entry.clone(),
        relocation.log_entry,
    ];
    let target = Did::new(target_did.clone()).unwrap();
    verify_did_webvh_v1_log(&target, &accepted).unwrap();
    validate_webvh_history_at(&target, &accepted, at("2026-06-03T00:00:01Z")).unwrap();

    let restarted: Vec<Value> =
        serde_json::from_slice(&serde_json::to_vec(&accepted).unwrap()).unwrap();
    verify_did_webvh_v1_log(&target, &restarted).unwrap();
    validate_webvh_history_at(&target, &restarted, at("2026-06-03T00:00:01Z")).unwrap();

    let mut same_transition_enable = enabled.log_entry.clone();
    same_transition_enable["state"] = target_state.clone();
    let illegal_enable = vec![inception.log_entry.clone(), same_transition_enable];
    assert!(verify_did_webvh_v1_log(&target, &illegal_enable).is_err());
    assert!(
        validate_webvh_history_at(&target, &illegal_enable, at("2026-06-02T00:00:01Z")).is_err()
    );

    let disable_seed = [52u8; 32];
    let disabled_relocation_seed = [53u8; 32];
    let portable_inception = prepare_portable_principal_inception(&PrincipalInceptionInput {
        provider_endpoint: &endpoint,
        principal_endpoint: &endpoint,
        local_id: "bob",
        also_known_as: &[],
        version_time: at("2026-07-01T00:00:00Z"),
        root_seed: &[51u8; 32],
        next_root_public_key_multibase: &public_key(&disable_seed),
        witness_policy: None,
    })
    .unwrap();
    let disabled = prepare_principal_portability_update(
        &PrincipalRotationInput {
            did: &portable_inception.did,
            local_id: &portable_inception.local_id,
            previous_entries: std::slice::from_ref(&portable_inception.log_entry),
            version_time: at("2026-07-02T00:00:00Z"),
            current_root_seed: &disable_seed,
            next_root_public_key_multibase: &public_key(&disabled_relocation_seed),
            state: &portable_inception.log_entry["state"],
        },
        false,
    )
    .unwrap();
    let disabled_scid = portable_inception.did.split(':').nth(2).unwrap();
    let disabled_target_did = format!("did:webvh:{disabled_scid}:disabled.example:webvh:bob");
    let disabled_target_state = relocated_state(
        &portable_inception.log_entry["state"],
        &portable_inception.did,
        &disabled_target_did,
    );
    let disabled_predecessors = vec![
        portable_inception.log_entry.clone(),
        disabled.log_entry.clone(),
    ];
    assert!(
        prepare_webvh_relocation(&WebvhRelocationInput {
            current_did: &portable_inception.did,
            target_did: &disabled_target_did,
            previous_entries: &disabled_predecessors,
            version_time: at("2026-07-03T00:00:00Z"),
            current_update_seed: &disabled_relocation_seed,
            next_update_public_key_multibase: &public_key(&[54u8; 32]),
            state: &disabled_target_state,
        })
        .is_err()
    );

    let mut illegal_disabled_relocation = disabled.log_entry.clone();
    illegal_disabled_relocation["versionId"] = Value::String("3-placeholder".to_owned());
    illegal_disabled_relocation["state"] = disabled_target_state;
    let illegal_disabled = vec![
        portable_inception.log_entry,
        disabled.log_entry,
        illegal_disabled_relocation,
    ];
    let disabled_target = Did::new(disabled_target_did).unwrap();
    assert!(verify_did_webvh_v1_log(&disabled_target, &illegal_disabled).is_err());
    assert!(
        validate_webvh_history_at(
            &disabled_target,
            &illegal_disabled,
            at("2026-07-03T00:00:01Z")
        )
        .is_err()
    );
}
