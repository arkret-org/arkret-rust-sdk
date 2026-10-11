//! Shared serialization and detached-signature KAT for authority objects.
//! This material does not prove stream provenance or a live handoff import.
use arkret_wire::{RealmAuthorityHandoff, RealmCommit};

pub const FIXTURE: &str = include_str!("../fixtures/authority-object-canonical.json");

pub fn assert_canonical_objects(commit: &RealmCommit, handoff: &RealmAuthorityHandoff) {
    let fixture: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    let bytes = |name: &str| {
        arkret_canonical::base64url::base64url_decode(fixture[name].as_str().unwrap()).unwrap()
    };
    assert_eq!(
        arkret_canonical::canonical_json_bytes(commit).unwrap(),
        bytes("commit_canonical_b64")
    );
    assert_eq!(
        arkret_canonical::canonical_json_bytes(handoff).unwrap(),
        bytes("handoff_canonical_b64")
    );
    commit.validate_content_address().unwrap();
    handoff.validate_shape().unwrap();
    let unsigned_commit = arkret_canonical::unsigned_value(commit, &["signature"]).unwrap();
    let unsigned_handoff = arkret_canonical::unsigned_value(
        handoff,
        &[
            "old_authority_signature",
            "new_authority_acceptance_signature",
        ],
    )
    .unwrap();
    for (proof, body, expected, key) in [
        (
            &commit.signature,
            &unsigned_commit,
            "commit_signing_b64",
            "old_public_key_b64",
        ),
        (
            &handoff.old_authority_signature,
            &unsigned_handoff,
            "handoff_old_signing_b64",
            "old_public_key_b64",
        ),
        (
            &handoff.new_authority_acceptance_signature,
            &unsigned_handoff,
            "handoff_new_signing_b64",
            "new_public_key_b64",
        ),
    ] {
        assert_eq!(
            arkret_signatures::detached_object::detached_object_signing_bytes(
                proof.context,
                &proof.verification_method,
                &proof.signed_digest,
                proof.created_at,
            )
            .unwrap(),
            bytes(expected)
        );
        arkret_signatures::detached_object::verify_detached_object_signature(
            proof,
            body,
            proof.context,
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw { bytes: bytes(key) },
        )
        .unwrap();
    }
}

pub fn objects() -> (RealmCommit, RealmAuthorityHandoff) {
    let fixture: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    (
        serde_json::from_value(fixture["commit"].clone()).unwrap(),
        serde_json::from_value(fixture["handoff"].clone()).unwrap(),
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn authority_objects_reproduce_independent_canonical_and_signature_bytes() {
        let (commit, handoff) = super::objects();
        super::assert_canonical_objects(&commit, &handoff);
    }
}
