//! Method-native recovery verification for an accepted Realm-owned identity.
use arkret_models_identity::{PrincipalResolutionProjection, ResolutionCommitment};
use arkret_models_integration::{
    AppletManagedActorMethodHistoryEvidence, RealmActorRecoveryAcceptanceTranscript,
    RealmActorRecoveryBeginPayload,
};
use arkret_wire::{ActorId, AppletId, DetachedSignatureContext, DidCoreId, DidUrl};
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::{DidDocument, DidVerificationRelationship, IdentityError, Result};

fn invalid(message: impl std::fmt::Display) -> IdentityError {
    IdentityError::Protocol(format!("signature_invalid: {message}"))
}

/// Verifies the native chain and control-key separation for the complete history.
/// The returned document is not a Realm authorization: the caller must also
/// compare the locked current revisions, manager, recovery policy and gates.
pub fn verify_realm_actor_native_history(
    actor: &ActorId,
    resolution: &ResolutionCommitment,
    entries: &[Value],
    control_method: &DidUrl,
    at: DateTime<Utc>,
) -> Result<DidDocument> {
    let subject = actor
        .as_realm_actor_id()
        .ok_or_else(|| invalid("Realm actor required"))?;
    if resolution.did.method() != "webvh"
        || arkret_wire::project_did_to_core_id(&resolution.did)? != subject.principal_id
        || entries.is_empty()
        || entries.len() > 4096
        || arkret_canonical::canonical_json_bytes(entries)?.len() > 1024 * 1024
    {
        return Err(invalid("native recovery identity or history bounds differ"));
    }
    let log = crate::verify_did_webvh_v1_chain(&resolution.did, entries)?;
    if log.head_version_id != resolution.version_id
        || arkret_canonical::canonical_sha256(
            entries.last().ok_or_else(|| invalid("empty history"))?,
        )? != resolution.method_history_head
        || log.entries.iter().any(|entry| entry.version_time > at)
    {
        return Err(invalid("native history terminal or effective time differs"));
    }
    let mut active = Vec::<String>::new();
    let mut next = Vec::<String>::new();
    let mut all_roots = std::collections::BTreeSet::new();
    let mut all_commitments = std::collections::BTreeSet::new();
    for entry in &log.entries {
        if let Some(keys) = entry.parameters.get("updateKeys") {
            active = serde_json::from_value(keys.clone())?;
        }
        if let Some(keys) = entry.parameters.get("nextKeyHashes") {
            next = serde_json::from_value(keys.clone())?;
        }
        if active.len() != 1
            || next.len() != 1
            || next[0] == arkret_signatures::webvh::webvh_next_key_hash_value(&active[0])
        {
            return Err(invalid(
                "each native generation requires one distinct next commitment",
            ));
        }
        all_roots.extend(active.iter().cloned());
        all_commitments.extend(next.iter().cloned());
    }
    for entry in &log.entries {
        let document: DidDocument = serde_json::from_value(entry.state.clone())?;
        document.validate()?;
        // Decode every operational key, including JWK representations. A textual
        // search for multibase would miss the same native key encoded as a JWK.
        for method in document.verification_methods.keys() {
            let method = DidUrl::new(method.clone()).map_err(invalid)?;
            let Ok(key) = crate::public_key_material_from_document(&document, &method) else {
                continue;
            };
            let key = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                &key.ed25519_bytes().map_err(invalid)?,
            );
            if all_roots.contains(&key)
                || all_commitments
                    .contains(&arkret_signatures::webvh::webvh_next_key_hash_value(&key))
            {
                return Err(invalid(
                    "operational document exposes native update key material",
                ));
            }
        }
    }
    let document: DidDocument = serde_json::from_value(log.head_state)?;
    crate::validate_verification_method_relationship(
        &document,
        control_method,
        &document.id,
        DidVerificationRelationship::AssertionMethod,
    )
    .map_err(invalid)?;
    Ok(document)
}

fn verify_witnesses(
    did: &arkret_wire::Did,
    entries: &[Value],
    records: &[Value],
    required_through: usize,
) -> Result<()> {
    let log = crate::verify_did_webvh_v1_chain(did, entries)?;
    let mut by_version = std::collections::BTreeMap::new();
    if arkret_canonical::canonical_json_bytes(&(entries, records))?.len() > 1024 * 1024 {
        return Err(invalid("native method evidence exceeds its byte budget"));
    }
    for record in records {
        let version = record
            .get("versionId")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("witness lacks versionId"))?;
        if by_version.insert(version, record).is_some() {
            return Err(invalid("duplicate witness version"));
        }
    }
    let mut policy = None;
    for (index, entry) in log.entries.iter().enumerate() {
        if let Some(next) =
            crate::parse_did_webvh_witness_policy(&entry.parameters).map_err(invalid)?
        {
            policy = Some(next);
        }
        match (
            policy.as_ref(),
            by_version.remove(entry.version_id.as_str()),
        ) {
            (Some(policy), Some(record)) => {
                crate::verify_did_webvh_witness_record(&entry.version_id, policy, record)
                    .map_err(invalid)?;
            }
            (Some(policy), None) if index <= required_through && policy.threshold > 0 => {
                return Err(invalid("accepted prefix witness is unavailable"));
            }
            (None, Some(_)) => return Err(invalid("witness has no native policy")),
            _ => {}
        }
    }
    if !by_version.is_empty() {
        return Err(invalid("witness names a version outside the exact chain"));
    }
    Ok(())
}

/// Begin accepts a proposed, controller-signed native successor. Witnesses for
/// the already accepted prefix are mandatory; any supplied successor witness
/// is verified, while missing successor witnesses may be supplied at finish.
pub fn verify_realm_actor_recovery_plan(
    applet: &AppletId,
    service: &DidCoreId,
    current: &PrincipalResolutionProjection,
    current_method: &DidUrl,
    payload: &RealmActorRecoveryBeginPayload,
    created_at: DateTime<Utc>,
    accepted_at: DateTime<Utc>,
) -> Result<DidDocument> {
    if current.did != payload.next_resolution.did
        || payload.next_control_method_kid == *current_method
        || payload.expires_at <= accepted_at
        || payload.expires_at > created_at + chrono::Duration::minutes(10)
        || payload.control_signature.created_at > accepted_at
        || payload.control_signature.created_at < created_at - chrono::Duration::minutes(10)
        || payload.control_signature.verification_method != payload.next_control_method_kid
        || payload.expected_generation.checked_add(1) != Some(payload.new_generation)
        || payload.expected_generation == 0
        || !(22..=128).contains(&payload.request_id.len())
        || !payload
            .request_id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
    {
        return Err(invalid(
            "recovery intent identity, generation or lifetime differs",
        ));
    }
    let entries = &payload.method_history_evidence.log_entries;
    let document = verify_realm_actor_native_history(
        &payload.target_actor_id,
        &payload.next_resolution,
        entries,
        &payload.next_control_method_kid,
        accepted_at,
    )?;
    let anchor = entries
        .iter()
        .position(|entry| {
            entry.get("versionId").and_then(Value::as_str) == Some(current.version_id.as_str())
        })
        .ok_or_else(|| invalid("accepted native anchor is missing"))?;
    if anchor + 1 >= entries.len()
        || arkret_canonical::canonical_sha256(&entries[anchor])? != current.method_history_head
    {
        return Err(invalid(
            "recovery must extend the exact accepted native anchor",
        ));
    }
    verify_witnesses(
        &current.did,
        entries,
        &payload.method_history_evidence.witness_records,
        anchor,
    )?;
    let old_document: DidDocument = serde_json::from_value(entries[anchor]["state"].clone())?;
    let old_key =
        crate::public_key_material_from_document(&old_document, current_method).map_err(invalid)?;
    let new_key =
        crate::public_key_material_from_document(&document, &payload.next_control_method_kid)
            .map_err(invalid)?;
    if old_key.ed25519_bytes().map_err(invalid)? == new_key.ed25519_bytes().map_err(invalid)?
        || crate::public_key_material_from_document(&document, current_method).is_ok()
    {
        return Err(invalid(
            "recovery must replace and remove the old control method",
        ));
    }
    let mut unsigned = serde_json::to_value(payload)?;
    unsigned
        .as_object_mut()
        .ok_or_else(|| invalid("recovery payload must be an object"))?
        .remove("control_signature");
    let transcript = RealmActorRecoveryAcceptanceTranscript {
        applet_id: applet.clone(),
        service_id: service.clone(),
        payload_without_control_signature: serde_json::from_value(unsigned)?,
    };
    arkret_signatures::detached_object::verify_detached_object_signature(
        &payload.control_signature,
        &transcript,
        DetachedSignatureContext::RealmActorRecoveryAcceptance,
        &new_key,
    )
    .map_err(invalid)?;
    Ok(document)
}

/// Finish verifies the exact plan logs, with complete published witness and
/// receipt material. The durable begin's freshness is not re-evaluated here.
pub fn verify_realm_actor_recovery_publication(
    begin: &RealmActorRecoveryBeginPayload,
    published: &AppletManagedActorMethodHistoryEvidence,
    accepted_at: DateTime<Utc>,
) -> Result<DidDocument> {
    published.validate_shape()?;
    let (receipt, entries, records) = published.webvh_material();
    if entries != begin.method_history_evidence.log_entries {
        return Err(invalid(
            "published recovery chain differs from the accepted exact plan",
        ));
    }
    let document = verify_realm_actor_native_history(
        &begin.target_actor_id,
        &begin.next_resolution,
        entries,
        &begin.next_control_method_kid,
        accepted_at,
    )?;
    verify_witnesses(
        &begin.next_resolution.did,
        entries,
        records,
        entries.len() - 1,
    )?;
    let first = entries[0]
        .get("versionId")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("native inception has no version"))?;
    let boundary = arkret_models_identity::ResolutionMethodEvidenceBoundary {
        from_method_history_head: arkret_canonical::canonical_sha256(&entries[0])?,
        from_version_id: first.to_owned(),
        to_method_history_head: begin.next_resolution.method_history_head.clone(),
        to_version_id: begin.next_resolution.version_id.clone(),
    };
    if published.boundary() != &boundary {
        return Err(invalid(
            "published method boundary differs from exact recovery plan",
        ));
    }
    crate::service_resolution_evidence::verify_webvh_history(
        &begin.next_resolution.did,
        &document,
        &boundary,
        receipt,
        entries,
        records,
        &begin.next_resolution.method_history_head,
        &begin.next_resolution.version_id,
    )?;
    Ok(document)
}
