//! Snapshot v1 signing and consumer verification helpers.

use chrono::{DateTime, Utc};
use cokret_core::{
    DETACHED_JWS_ALG_EDDSA, DETACHED_JWS_PROOF_KIND, DetachedJwsProof, Hash, SnapshotChunkPayload,
    SnapshotManifest, SnapshotValidationCode, SnapshotValidationError, SnapshotVerifyOptions,
    SnapshotVerifyReport,
};
use ed25519_dalek::SigningKey;

use crate::identity::DidResolver;
use crate::{Error, Result};

/// Sign the unsigned `ck.schema.snapshot.v1` manifest transcript and attach
/// the resulting detached JWS proof to the manifest.
pub fn sign_snapshot_manifest_ed25519(
    manifest: &mut SnapshotManifest,
    signing_key: &SigningKey,
    verification_method: impl Into<String>,
    created_at: DateTime<Utc>,
) -> Result<DetachedJwsProof> {
    let canonical_bytes = manifest.unsigned_canonical_bytes()?;
    let payload_digest = Hash::new(cokret_core::canonical::sha256_digest(&canonical_bytes))?;
    let jws =
        crate::jws::sign_jws_ed25519(&canonical_bytes, signing_key).map_err(Error::Protocol)?;
    let proof =
        DetachedJwsProof::eddsa(verification_method.into(), payload_digest, created_at, jws);
    manifest.signature = proof.clone();
    Ok(proof)
}

/// Verify the detached JWS proof over the unsigned manifest transcript.
pub fn verify_snapshot_manifest_signature(
    manifest: &SnapshotManifest,
    resolver: &dyn DidResolver,
) -> std::result::Result<(), SnapshotValidationError> {
    if manifest.signature.kind != DETACHED_JWS_PROOF_KIND
        || manifest.signature.alg != DETACHED_JWS_ALG_EDDSA
        || manifest.signature.verification_method.trim().is_empty()
        || manifest.signature.jws.trim().is_empty()
    {
        return Err(SnapshotValidationError::new(
            SnapshotValidationCode::SnapshotAuthorityUnverified,
            "snapshot signature is not an EdDSA detached JWS proof",
        ));
    }
    if manifest.authority_binding.issuer != manifest.created_by {
        return Err(SnapshotValidationError::new(
            SnapshotValidationCode::SnapshotAuthorityUnverified,
            "snapshot authority_binding.issuer does not match created_by",
        ));
    }

    let canonical_bytes = manifest.unsigned_canonical_bytes().map_err(|err| {
        SnapshotValidationError::new(
            SnapshotValidationCode::DigestMismatch,
            format!("snapshot signature transcript could not be canonicalized: {err}"),
        )
    })?;
    let expected_digest = Hash::new(cokret_core::canonical::sha256_digest(&canonical_bytes))
        .map_err(|err| {
            SnapshotValidationError::new(
                SnapshotValidationCode::DigestMismatch,
                format!("snapshot signature payload digest could not be computed: {err}"),
            )
        })?;
    if manifest.signature.payload_digest != expected_digest {
        return Err(SnapshotValidationError::new(
            SnapshotValidationCode::DigestMismatch,
            "snapshot signature payload_digest does not match manifest canonical bytes",
        ));
    }

    crate::jws::verify_jws_ed25519(
        &canonical_bytes,
        &manifest.signature.jws,
        &manifest.signature.verification_method,
        manifest.created_by.as_str(),
        resolver,
    )
    .map_err(|err| {
        SnapshotValidationError::new(
            SnapshotValidationCode::SnapshotAuthorityUnverified,
            format!("snapshot signature verification failed: {err}"),
        )
    })
}

/// Verify the signed manifest plus decoded chunk payloads.
pub fn verify_snapshot_manifest(
    manifest: &SnapshotManifest,
    chunks: &[SnapshotChunkPayload],
    options: &SnapshotVerifyOptions,
    resolver: &dyn DidResolver,
) -> std::result::Result<SnapshotVerifyReport, SnapshotValidationError> {
    verify_snapshot_manifest_signature(manifest, resolver)?;
    cokret_core::verify_snapshot_manifest(manifest, chunks, options)
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use cokret_core::{
        AuthorityBinding, Did, EventId, EventSetCommitmentAlgorithm, EventSetLeaf, Hlc, RealmId,
        SNAPSHOT_REDUCER_PROFILE_V1, SnapshotAuthorityKind, SnapshotFrontier,
        SnapshotMaterializedItem, SnapshotSecurityClass, SnapshotVerificationHints,
        build_snapshot_chunks, event_set_commitment, state_digest_from_items,
    };
    use serde_json::json;

    use super::*;
    use crate::identity::{DidDocument, DidWebResolver};

    fn did() -> Did {
        Did::new("did:web:generator.example".to_owned()).unwrap()
    }

    fn realm() -> RealmId {
        RealmId::new("ck:realm:0196419b-0000-7000-8000-00000000014a".to_owned()).unwrap()
    }

    fn event_id(suffix: &str) -> EventId {
        EventId::new(format!("ck:event:01904100-0000-7000-8000-{suffix}")).unwrap()
    }

    fn hash(seed: u8) -> Hash {
        Hash::new(format!("sha256:{}", format!("{seed:02x}").repeat(32))).unwrap()
    }

    fn snapshot_id() -> cokret_core::SnapshotId {
        cokret_core::SnapshotId::new("ck:snapshot:01904100-0000-7000-8000-000000000001").unwrap()
    }

    fn resolver_for(signing_key: &SigningKey) -> DidWebResolver {
        let did = did();
        let verification_method = format!("{did}#snapshot-key-1");
        let public_key = cokret_core::ed25519_pubkey_to_did_key_multibase(
            signing_key.verifying_key().as_bytes(),
        );
        let mut resolver = DidWebResolver::new();
        resolver
            .insert(DidDocument::new(did, verification_method, public_key))
            .unwrap();
        resolver
    }

    fn manifest_fixture(
        signing_key: &SigningKey,
    ) -> (SnapshotManifest, Vec<SnapshotChunkPayload>, DidWebResolver) {
        let item = SnapshotMaterializedItem {
            kind: "strand".to_owned(),
            id: "ck:strand:01904100-0000-7000-8000-000000000001".to_owned(),
            object: json!({
                "id": "ck:strand:01904100-0000-7000-8000-000000000001",
                "kind": "strand",
                "schema": "ck.schema.test.v1"
            }),
            source_event_id: event_id("000000000001"),
        };
        let items = vec![item];
        let state_digest = state_digest_from_items(&items).unwrap();
        let built = build_snapshot_chunks(&snapshot_id(), SNAPSHOT_REDUCER_PROFILE_V1, items, 4096)
            .unwrap();
        let chunks = built
            .iter()
            .map(|chunk| chunk.payload.clone())
            .collect::<Vec<_>>();
        let descriptors = built
            .into_iter()
            .map(|chunk| chunk.descriptor)
            .collect::<Vec<_>>();
        let covered_event = event_id("000000000001");
        let event_leaf = EventSetLeaf {
            event_id: covered_event.clone(),
            event_digest: hash(8),
            actor_id: did(),
            actor_seq: 1,
            hlc: Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
        };
        let event_set = event_set_commitment(
            EventSetCommitmentAlgorithm::MerkleEventSetV1,
            &[event_leaf],
            vec![covered_event.clone()],
        )
        .unwrap();
        let created_at = "2026-06-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let mut manifest = SnapshotManifest {
            id: snapshot_id(),
            realm_id: realm(),
            reducer_profile: SNAPSHOT_REDUCER_PROFILE_V1.to_owned(),
            schema_profile_refs: vec!["ck.profile.core_event_store.v1".to_owned()],
            state_digest,
            frontier: SnapshotFrontier {
                event_ids: vec![covered_event.clone()],
                timeline_hlc: Hlc::new("01970e589d21-0002-a13f9c2e").unwrap(),
            },
            event_set_commitment: event_set,
            chunks: descriptors,
            security_class: SnapshotSecurityClass::Standard,
            verification_hints: Some(SnapshotVerificationHints {
                verification_profile: SnapshotSecurityClass::Standard,
                inclusion_proof_url: None,
                challenge_window_seconds: None,
                witness_quorum: None,
                conflict_records_digest: None,
                soft_failed_digest: None,
                quarantined_digest: None,
            }),
            created_by: did(),
            created_at,
            authority_binding: AuthorityBinding {
                issuer: did(),
                authority_kind: SnapshotAuthorityKind::RealmPolicySnapshotIssuer,
                auth_state_digest: hash(1),
                auth_frontier: vec![covered_event],
                checked_at: created_at,
                witness_attestations: Vec::new(),
            },
            signature: DetachedJwsProof::eddsa(
                format!("{}#snapshot-key-1", did()),
                hash(2),
                created_at,
                "header..signature".to_owned(),
            ),
        };
        sign_snapshot_manifest_ed25519(
            &mut manifest,
            signing_key,
            format!("{}#snapshot-key-1", did()),
            created_at,
        )
        .unwrap();
        (manifest, chunks, resolver_for(signing_key))
    }

    #[test]
    fn signed_snapshot_manifest_verifies_with_did_resolver() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let (manifest, chunks, resolver) = manifest_fixture(&signing_key);
        let report = verify_snapshot_manifest(
            &manifest,
            &chunks,
            &SnapshotVerifyOptions::standard(
                manifest.created_at + Duration::days(1),
                SNAPSHOT_REDUCER_PROFILE_V1,
            ),
            &resolver,
        )
        .unwrap();

        assert_eq!(report.item_count, 1);
        assert_eq!(report.chunk_count, 1);
    }

    #[test]
    fn manifest_tamper_rejects_on_signature_digest() {
        let signing_key = SigningKey::from_bytes(&[8u8; 32]);
        let (mut manifest, _chunks, resolver) = manifest_fixture(&signing_key);
        manifest.reducer_profile = "ck.reducer.other.v1".to_owned();

        let err = verify_snapshot_manifest_signature(&manifest, &resolver).unwrap_err();
        assert_eq!(err.code, SnapshotValidationCode::DigestMismatch);
    }

    #[test]
    fn recomputed_digest_cannot_hide_jws_tamper() {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let (mut manifest, _chunks, resolver) = manifest_fixture(&signing_key);
        manifest.frontier.timeline_hlc = Hlc::new("01970e589d21-0003-a13f9c2e").unwrap();
        manifest.signature.payload_digest = manifest.expected_signature_digest().unwrap();

        let err = verify_snapshot_manifest_signature(&manifest, &resolver).unwrap_err();
        assert_eq!(
            err.code,
            SnapshotValidationCode::SnapshotAuthorityUnverified
        );
    }

    #[test]
    fn signed_manifest_still_rejects_tampered_chunk_state() {
        let signing_key = SigningKey::from_bytes(&[10u8; 32]);
        let (manifest, mut chunks, resolver) = manifest_fixture(&signing_key);
        chunks[0].items[0].object["schema"] = json!("ck.schema.tampered.v1");

        let err = verify_snapshot_manifest(
            &manifest,
            &chunks,
            &SnapshotVerifyOptions::standard(
                manifest.created_at + Duration::days(1),
                SNAPSHOT_REDUCER_PROFILE_V1,
            ),
            &resolver,
        )
        .unwrap_err();
        assert_eq!(err.code, SnapshotValidationCode::DigestMismatch);
    }
}
