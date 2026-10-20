//! Verify independent Realm actor native identity and control possession.
use arkret_models_integration::RealmActorCreatePayload;
use arkret_wire::{DetachedSignatureContext, ErrorCode};
use chrono::{DateTime, Utc};

use crate::{DidVerificationRelationship, Result};
fn rejected(code: ErrorCode, message: &str) -> crate::IdentityError {
    arkret_wire::WireError::Protocol(format!("{}: {message}", code.as_str())).into()
}
pub fn verify_realm_actor_initial_resolution(
    payload: &RealmActorCreatePayload,
    accepted_at: DateTime<Utc>,
) -> Result<crate::DidDocument> {
    payload.validate()?;
    let did = &payload.initial_resolution.did;
    let (receipt, entries, witnesses) = payload.method_history_evidence.webvh_material();
    crate::verify_realm_actor_native_history(
        &payload.actor_id,
        &payload.initial_resolution,
        entries,
        &payload.control_method_kid,
        accepted_at,
    )?;
    let mut log_bytes = Vec::new();
    for entry in entries {
        log_bytes.extend(arkret_canonical::canonical_json_bytes(entry)?);
        log_bytes.push(b'\n');
    }
    let witness_bytes = arkret_canonical::canonical_json_bytes(witnesses)?;
    let verified =
        crate::verify_did_webvh_v1_chain_and_witness_bytes(did, &log_bytes, Some(&witness_bytes))
            .map_err(|error| {
            rejected(
                ErrorCode::SignatureInvalid,
                &format!("managed Principal native history does not verify: {error}",),
            )
        })?;
    let terminal = verified.log.raw_entries.last().ok_or_else(|| {
        rejected(
            ErrorCode::SignatureInvalid,
            "managed Principal native history has no terminal entry",
        )
    })?;
    if verified.log.head_version_id != payload.initial_resolution.version_id
        || arkret_canonical::canonical_sha256(terminal)?
            != payload.initial_resolution.method_history_head
    {
        return Err(rejected(
            ErrorCode::SignatureInvalid,
            "managed Principal native terminal differs from its original resolution",
        ));
    }
    let effective = arkret_signatures::webvh::validate_webvh_history_at(did, entries, accepted_at)
        .map_err(|error| {
            rejected(
                ErrorCode::SignatureInvalid,
                &format!("managed Principal original effective history does not verify: {error}",),
            )
        })?;
    // Managed Principals carry an independent operational controller. Human
    // identity-anchor document restrictions do not apply, but no history root
    // may appear in any of their operational DID documents.
    let roots = entries
        .iter()
        .filter_map(|entry| {
            entry
                .pointer("/parameters/updateKeys")
                .and_then(serde_json::Value::as_array)
        })
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .collect::<Vec<_>>();
    for entry in entries {
        let state = entry.get("state").ok_or_else(|| {
            rejected(
                ErrorCode::SignatureInvalid,
                "managed Principal history omits its document",
            )
        })?;
        let document: crate::DidDocument = serde_json::from_value(state.clone())?;
        document.validate()?;
        let encoded = serde_json::to_string(state)?;
        if roots.iter().any(|root| encoded.contains(root)) {
            return Err(rejected(
                ErrorCode::SignatureInvalid,
                "managed Principal operational document exposes a history root",
            ));
        }
    }
    if effective.version_id != payload.initial_resolution.version_id {
        return Err(rejected(
            ErrorCode::SignatureInvalid,
            "managed Principal initial resolution was not effective at its original acceptance",
        ));
    }
    let document: crate::DidDocument = serde_json::from_value(verified.log.head_state)?;
    if arkret_models_identity::normalized_did_document_digest(&document)? != receipt.document_digest
    {
        return Err(rejected(
            ErrorCode::SignatureInvalid,
            "managed Principal method receipt names a different original document",
        ));
    }
    let first = verified.log.entries.first().ok_or_else(|| {
        rejected(
            ErrorCode::SignatureInvalid,
            "managed Principal native history has no inception",
        )
    })?;
    let complete = arkret_models_identity::ResolutionMethodEvidenceBoundary {
        from_method_history_head: arkret_canonical::canonical_sha256(&entries[0])?,
        from_version_id: first.version_id.clone(),
        to_method_history_head: payload.initial_resolution.method_history_head.clone(),
        to_version_id: payload.initial_resolution.version_id.clone(),
    };
    crate::service_resolution_evidence::verify_webvh_history(
        did,
        &document,
        &complete,
        receipt,
        entries,
        witnesses,
        &payload.initial_resolution.method_history_head,
        &payload.initial_resolution.version_id,
    )
    .map_err(|error| {
        rejected(
            ErrorCode::SignatureInvalid,
            &format!("managed Principal original method receipt does not verify: {error}",),
        )
    })?;
    if verified.log.active_update_keys.len() != 1
        || entries
            .iter()
            .rev()
            .find_map(|entry| {
                entry
                    .pointer("/parameters/nextKeyHashes")
                    .and_then(serde_json::Value::as_array)
            })
            .is_none_or(|keys| keys.len() != 1)
    {
        return Err(rejected(
            ErrorCode::SignatureInvalid,
            "Realm actor requires one active and one committed next native update key",
        ));
    }
    crate::validate_verification_method_relationship(
        &document,
        &payload.control_method_kid,
        &document.id,
        DidVerificationRelationship::AssertionMethod,
    )
    .map_err(|error| rejected(ErrorCode::SignatureInvalid, &error.to_string()))?;
    let key = crate::public_key_material_from_document(&document, &payload.control_method_kid)
        .map_err(|error| rejected(ErrorCode::SignatureInvalid, &error.to_string()))?;
    let control_bytes = key
        .ed25519_bytes()
        .map_err(|error| rejected(ErrorCode::SignatureInvalid, &error.to_string()))?;
    let control_multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(&control_bytes);
    let commitment = arkret_signatures::webvh::webvh_next_key_hash_value(&control_multibase);
    if roots.iter().any(|root| *root == control_multibase)
        || entries
            .iter()
            .filter_map(|entry| {
                entry
                    .pointer("/parameters/nextKeyHashes")
                    .and_then(serde_json::Value::as_array)
            })
            .flatten()
            .any(|value| value.as_str() == Some(commitment.as_str()))
    {
        return Err(rejected(
            ErrorCode::SignatureInvalid,
            "Realm actor control key must be distinct from native update keys and commitments",
        ));
    }
    arkret_signatures::detached_object::verify_detached_object_signature(
        &payload.control_signature,
        &payload.creation_transcript(),
        DetachedSignatureContext::RealmActorCreation,
        &key,
    )
    .map_err(|error| rejected(ErrorCode::SignatureInvalid, &error.to_string()))?;
    if accepted_at < payload.control_signature.created_at || accepted_at >= payload.expires_at {
        return Err(rejected(
            ErrorCode::SignatureInvalid,
            "Realm actor creation proof is outside its validity interval",
        ));
    }
    Ok(document)
}

/// Verify normal control rotation without granting Realm authority. The caller
/// still checks the old-method Event signature, current CAS and live native head.
pub fn verify_realm_actor_control_successor(
    actor: &arkret_wire::ActorId,
    current: &arkret_models_identity::PrincipalResolutionProjection,
    current_method: &arkret_wire::DidUrl,
    payload: &arkret_models_integration::RealmActorControlUpdatePayload,
    accepted_at: DateTime<Utc>,
) -> Result<crate::DidDocument> {
    let invalid = |message: &str| rejected(ErrorCode::SignatureInvalid, message);
    payload.method_history_evidence.validate_shape()?;
    let (receipt, entries, witnesses) = payload.method_history_evidence.webvh_material();
    let document = crate::verify_realm_actor_native_history(
        actor,
        &payload.next_resolution,
        entries,
        &payload.next_control_method_kid,
        accepted_at,
    )?;
    let anchor = entries
        .iter()
        .find(|entry| {
            entry.get("versionId").and_then(serde_json::Value::as_str)
                == Some(current.version_id.as_str())
        })
        .ok_or_else(|| invalid("control successor omits the accepted native anchor"))?;
    if arkret_wire::project_did_to_core_id(&current.did)? != *actor.signing_principal_id()
        || arkret_canonical::canonical_sha256(anchor)? != current.method_history_head
        || payload.next_method_signature.verification_method != payload.next_control_method_kid
        || payload.next_method_signature.created_at > accepted_at
    {
        return Err(invalid(
            "control successor anchor or possession signature differs",
        ));
    }
    let previous: crate::DidDocument = serde_json::from_value(anchor["state"].clone())?;
    if previous.id != current.did {
        return Err(invalid("accepted native anchor DID differs"));
    }
    let old_key = crate::public_key_material_from_document(&previous, current_method)
        .map_err(|error| invalid(&error.to_string()))?;
    crate::validate_verification_method_relationship(
        &document,
        current_method,
        &document.id,
        DidVerificationRelationship::AssertionMethod,
    )
    .map_err(|error| invalid(&error.to_string()))?;
    let retained_key = crate::public_key_material_from_document(&document, current_method)
        .map_err(|error| invalid(&error.to_string()))?;
    if old_key
        .ed25519_bytes()
        .map_err(|error| invalid(&error.to_string()))?
        != retained_key
            .ed25519_bytes()
            .map_err(|error| invalid(&error.to_string()))?
    {
        return Err(invalid(
            "normal rotation must retain the old valid control method until acceptance",
        ));
    }
    crate::service_resolution_evidence::verify_webvh_history(
        &payload.next_resolution.did,
        &document,
        payload.method_history_evidence.boundary(),
        receipt,
        entries,
        witnesses,
        &payload.next_resolution.method_history_head,
        &payload.next_resolution.version_id,
    )?;
    let transcript = arkret_models_integration::RealmActorControlAcceptanceTranscript {
        actor_id: actor.clone(),
        expected_revision: payload.expected_revision.clone(),
        next_resolution: payload.next_resolution.clone(),
        method_history_evidence: payload.method_history_evidence.clone(),
        next_control_method_kid: payload.next_control_method_kid.clone(),
    };
    let next_key =
        crate::public_key_material_from_document(&document, &payload.next_control_method_kid)
            .map_err(|error| invalid(&error.to_string()))?;
    arkret_signatures::detached_object::verify_detached_object_signature(
        &payload.next_method_signature,
        &transcript,
        DetachedSignatureContext::RealmActorControlAcceptance,
        &next_key,
    )
    .map_err(|error| invalid(&error.to_string()))?;
    Ok(document)
}
