use arkret_wire::{Did, Hash, Proof, proof_kind};
use chrono::{TimeZone, Timelike, Utc};

fn proof_with_submillisecond_created_at() -> Proof {
    Proof {
        kind: proof_kind::DETACHED_JWS.to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method: "did:web:alice.example#key-1".to_owned(),
        event_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
        created_at: Utc
            .with_ymd_and_hms(2026, 7, 21, 12, 34, 56)
            .unwrap()
            .with_nanosecond(123_456_789)
            .unwrap(),
        domain: None,
        audience: None,
        jws: "header..signature".to_owned(),
    }
}

#[test]
fn proof_wire_and_binding_use_the_same_canonical_millisecond_timestamp() {
    let proof = proof_with_submillisecond_created_at();
    let actor_id = Did::new("did:web:alice.example").unwrap();

    let wire = serde_json::to_value(&proof).unwrap();
    let binding = proof.binding_object(&actor_id);

    assert_eq!(wire["created_at"], "2026-07-21T12:34:56.123Z");
    assert_eq!(binding["created_at"], wire["created_at"]);
}

#[test]
fn proof_ingress_rejects_noncanonical_timestamp_before_verification() {
    let proof = proof_with_submillisecond_created_at();
    let mut wire = serde_json::to_value(&proof).unwrap();
    wire["created_at"] = "2026-07-21T12:34:56Z".into();

    assert!(serde_json::from_value::<Proof>(wire).is_err());
}
