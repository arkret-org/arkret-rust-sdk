use arkret_identity::verify_did_webvh_v1_log;
use arkret_signatures::webvh::{
    PrincipalInceptionInput, WebvhRelocationInput, prepare_portable_principal_inception,
    prepare_webvh_relocation,
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
