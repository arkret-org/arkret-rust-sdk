//! Shared serialization and detached-signature KAT for authority objects.
//! This material does not prove stream provenance or a live handoff import.
use anyhow::Result;
use arkret_wire::{
    CommitStreamRef, Event, EventId, Hash, RealmAuthorityHandoff, RealmCommit, RealmCommitId,
};
use serde_json::json;

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

/// Real generation-zero authority Commit material for an explicit independent
/// stream coordinate. This checks signatures and shape, not live admission or
/// stream provenance. Callers verify each successor against its actual head.
pub fn signed_commit(
    verification_method: &arkret_wire::DidUrl,
    signing_key: &ed25519_dalek::SigningKey,
    event: &Event,
    position: u64,
    predecessor: Option<RealmCommitId>,
    genesis: EventId,
    fact: Option<Hash>,
) -> Result<RealmCommit> {
    let mut value = RealmCommit {
        commit_id: RealmCommitId::from_digest([0; 32]),
        realm_id: event.realm_id.clone(),
        stream_ref: CommitStreamRef::from_scope(&event.scope_ref, Some(event.realm_id.clone()))?,
        stream_position: position,
        previous_commit_ref: predecessor,
        event_ref: event.event_id.clone(),
        governance_generation: 0,
        authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(genesis),
        committed_at: event.created_at,
        producer_signer_fact_digest: fact,
        signature: arkret_signatures::detached_object::sign_detached_object(
            &json!({}),
            arkret_wire::DetachedSignatureContext::RealmCommit,
            verification_method.clone(),
            event.created_at,
            signing_key,
        )?,
    };
    value.commit_id = RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
        &arkret_canonical::canonical_json_bytes(&arkret_canonical::unsigned_value(
            &value,
            &["commit_id", "signature"],
        )?)?,
    ));
    value.signature = arkret_signatures::detached_object::sign_detached_object(
        &arkret_canonical::unsigned_value(&value, &["signature"])?,
        arkret_wire::DetachedSignatureContext::RealmCommit,
        verification_method.clone(),
        event.created_at,
        signing_key,
    )?;
    value.validate_shape()?;
    value.verify_commit_id_matches_content()?;
    arkret_signatures::detached_object::verify_detached_object_signature(
        &value.signature,
        &arkret_canonical::unsigned_value(&value, &["signature"])?,
        arkret_wire::DetachedSignatureContext::RealmCommit,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: signing_key.verifying_key().to_bytes().to_vec(),
        },
    )?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    #[test]
    fn exhausted_generation_cannot_form_a_handoff_successor() {
        let (_, mut handoff) = super::objects();
        handoff.from_generation = u64::MAX;
        handoff.to_generation = u64::MAX;
        assert!(handoff.validate_shape().is_err());
        handoff.from_generation = u64::MAX - 1;
        handoff.validate_shape().unwrap();
    }

    #[test]
    fn authority_objects_reproduce_independent_canonical_and_signature_bytes() {
        let (commit, handoff) = super::objects();
        super::assert_canonical_objects(&commit, &handoff);
    }
}
