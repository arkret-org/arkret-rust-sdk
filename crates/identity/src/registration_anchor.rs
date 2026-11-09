//! Authoritative derivation for the closed `principal_registration_anchor`.
//!
//! One dispatch, one answer. Every consumer of a human registration anchor -
//! the Account Authority at registration and the Station at PCR genesis -
//! derives the DID, the method history coordinates and the root control key
//! here, from the anchor branch alone. Nothing in this module reads a current resolver, a
//! database row or an Account-Authority receipt, so the whole derivation runs
//! offline.
//!
//! `did:web` has no branch: it is not a registered human principal anchor, so
//! an ineligible method fails closed at the union's own deserialization before
//! any method parser runs.

use arkret_canonical::canonical;
use arkret_canonical::multibase::decode_ed25519_multibase;
use arkret_models_identity::{
    PrincipalRegistrationAnchor, ValidatedRegistrationAnchor, WEBVH_REGISTRATION_ANCHOR_KIND,
};
use arkret_wire::{DidUrl, Hash, project_did_to_core_id};
use serde_json::Value;

use crate::error::{IdentityError, Result};
use crate::resolvers::verify_did_webvh_v1_log_and_witness_records;

fn protocol(message: impl Into<String>) -> IdentityError {
    IdentityError::Protocol(message.into())
}

/// Validate a registration anchor and derive its authenticated coordinates.
pub fn validate_principal_registration_anchor(
    anchor: &PrincipalRegistrationAnchor,
) -> Result<ValidatedRegistrationAnchor> {
    anchor.validate()?;
    let did = anchor.did().clone();
    let principal_id = project_did_to_core_id(&did)?;
    let registration_anchor_digest = anchor.canonical_digest()?;
    match anchor {
        PrincipalRegistrationAnchor::WebvhRegistration {
            log_entries,
            witness_records,
            normalized_did_document,
            ..
        } => {
            let raw_entries = log_entries
                .iter()
                .map(|entry| serde_json::to_value(entry).map_err(IdentityError::from))
                .collect::<Result<Vec<Value>>>()?;
            let raw_records = witness_records
                .iter()
                .map(|record| serde_json::to_value(record).map_err(IdentityError::from))
                .collect::<Result<Vec<Value>>>()?;
            let verified =
                verify_did_webvh_v1_log_and_witness_records(&did, &raw_entries, &raw_records)
                    .map_err(|error| protocol(error.to_string()))?;
            let terminal = raw_entries
                .last()
                .ok_or_else(|| protocol("verified did:webvh log has no terminal entry"))?;
            let terminal_entry = verified
                .log
                .entries
                .last()
                .ok_or_else(|| protocol("verified did:webvh log has no terminal entry"))?;
            if verified.log.head_version_id != terminal_entry.version_id {
                return Err(protocol(
                    "verified did:webvh head is not the registration entry",
                ));
            }
            if verified.log.active_update_keys.len() != 1 {
                return Err(protocol(
                    "a human registration anchor must declare exactly one active update key",
                ));
            }
            let root_public_key_multibase = verified.log.active_update_keys[0].clone();
            // The principal's own published document must not republish the
            // method-native update key as a business key.
            arkret_signatures::webvh::validate_principal_did_document_profile(
                did.as_str(),
                &verified.log.head_state,
                &[root_public_key_multibase.as_str()],
            )
            .map_err(|error| protocol(error.to_string()))?;
            // The anchor's normalized document is a restatement, never an
            // authority: recompute the projection from the verified terminal
            // state and require byte equality.
            let derived_document: arkret_models_identity::DidDocument =
                serde_json::from_value(verified.log.head_state.clone())?;
            if arkret_models_identity::normalized_did_document(&derived_document)?
                != arkret_models_identity::normalized_did_document(normalized_did_document)?
            {
                return Err(protocol(
                    "registration anchor document is not the normalized terminal state",
                ));
            }
            let root_verification_method = terminal
                .pointer("/proof/0/verificationMethod")
                .and_then(Value::as_str)
                .ok_or_else(|| protocol("registration entry proof omits verificationMethod"))?;
            if root_verification_method
                != format!("did:key:{root_public_key_multibase}#{root_public_key_multibase}")
            {
                return Err(protocol(
                    "registration entry was not signed by its own active update key",
                ));
            }
            let next_root_key_hash = terminal
                .pointer("/parameters/nextKeyHashes")
                .and_then(Value::as_array)
                .filter(|hashes| hashes.len() == 1)
                .and_then(|hashes| hashes[0].as_str())
                .ok_or_else(|| {
                    protocol("registration entry must declare exactly one next root commitment")
                })?
                .to_owned();
            Ok(ValidatedRegistrationAnchor {
                anchor_kind: WEBVH_REGISTRATION_ANCHOR_KIND,
                did,
                principal_id,
                registration_anchor_digest,
                did_version_id: terminal_entry.version_id.clone(),
                method_history_head: Hash::new(canonical::canonical_sha256(terminal)?)?,
                did_version_time: Some(terminal_entry.version_created_at),
                control_key_digest: control_key_digest(&root_public_key_multibase)?,
                root_public_key_multibase,
                root_verification_method: DidUrl::new(root_verification_method.to_owned())
                    .map_err(protocol)?,
                next_root_key_hash: Some(next_root_key_hash),
            })
        }
    }
}

/// Recover the exact historical registration anchor named by an authenticated
/// PCR Genesis commitment. Native log bytes and witness proofs may come from
/// retained server evidence; current documents or keys are never substitutes.
/// This reconstructs public verification material, not identity or read authority.
pub fn recover_principal_registration_anchor(
    target: &arkret_models_identity::ResolutionCommitment,
    history: &[Value],
    witness_history: &[Value],
) -> Result<PrincipalRegistrationAnchor> {
    if target.did.method() != "webvh" {
        return Err(protocol("historical Human anchor requires did:webvh"));
    }
    let expected_head = Hash::new(target.method_history_head.clone())?;
    let matching = history
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| {
            (entry.get("versionId").and_then(Value::as_str) == Some(target.version_id.as_str()))
                .then_some(index)
        })
        .collect::<Vec<_>>();
    let [terminal_index] = matching.as_slice() else {
        return Err(protocol(
            "historical registration version is missing or ambiguous",
        ));
    };
    let terminal = &history[*terminal_index];
    if canonical::canonical_sha256(terminal)? != expected_head.as_str() {
        return Err(protocol(
            "historical registration log differs from the committed head",
        ));
    }
    let prefix = &history[..=*terminal_index];
    let versions = prefix
        .iter()
        .filter_map(|entry| entry.get("versionId").and_then(Value::as_str))
        .collect::<std::collections::BTreeSet<_>>();
    let log_entries = prefix
        .iter()
        .cloned()
        .map(serde_json::from_value)
        .collect::<std::result::Result<Vec<std::collections::BTreeMap<String, Value>>, _>>()?;
    let witness_records = witness_history
        .iter()
        .filter(|record| {
            record
                .get("versionId")
                .and_then(Value::as_str)
                .is_some_and(|version| versions.contains(version))
        })
        .cloned()
        .map(serde_json::from_value)
        .collect::<std::result::Result<Vec<std::collections::BTreeMap<String, Value>>, _>>()?;
    let operation = log_entries
        .last()
        .ok_or_else(|| protocol("historical registration prefix is empty"))?
        .clone();
    let normalized_did_document = serde_json::from_value(
        terminal
            .get("state")
            .ok_or_else(|| protocol("historical registration entry has no document"))?
            .clone(),
    )?;
    let anchor = PrincipalRegistrationAnchor::WebvhRegistration {
        registration_did_operation: Box::new(
            arkret_models_identity::DidOperationSubmitRequestBody {
                did: target.did.clone(),
                did_method: arkret_models_identity::DidMethodName::Webvh,
                sequence: Some(
                    u64::try_from(log_entries.len())
                        .map_err(|_| protocol("historical registration sequence overflow"))?,
                ),
                previous_event_digest: None,
                operation,
            },
        ),
        log_entries,
        witness_records,
        normalized_did_document,
    };
    let verified = validate_principal_registration_anchor(&anchor)?;
    if verified.did != target.did
        || verified.did_version_id != target.version_id
        || verified.method_history_head != expected_head
    {
        return Err(protocol(
            "verified registration anchor differs from the original commitment",
        ));
    }
    Ok(anchor)
}

fn control_key_digest(root_public_key_multibase: &str) -> Result<Hash> {
    let bytes = decode_ed25519_multibase(root_public_key_multibase)
        .map_err(|error| protocol(error.to_string()))?;
    Ok(Hash::new(format!(
        "sha256:{}",
        arkret_canonical::sha256_hex(bytes)
    ))?)
}

#[cfg(test)]
mod tests {
    use arkret_models_identity::{DidDocument, DidOperationSubmitRequestBody};
    use arkret_signatures::webvh::{PrincipalInceptionInput, prepare_principal_inception};
    use chrono::{TimeZone, Utc};
    use ed25519_dalek::{SECRET_KEY_LENGTH, SigningKey};
    use url::Url;

    use super::*;

    fn entry_map(entry: &Value) -> std::collections::BTreeMap<String, Value> {
        serde_json::from_value(entry.clone()).unwrap()
    }

    fn webvh_anchor() -> (
        PrincipalRegistrationAnchor,
        DidOperationSubmitRequestBody,
        Value,
        String,
    ) {
        let root_seed = [0x51; SECRET_KEY_LENGTH];
        let next_root_public_key_multibase =
            arkret_canonical::multibase::ed25519_pubkey_to_did_key_multibase(
                &SigningKey::from_bytes(&[0x52; SECRET_KEY_LENGTH])
                    .verifying_key()
                    .to_bytes(),
            );
        let prepared = prepare_principal_inception(&PrincipalInceptionInput {
            provider_endpoint: &Url::parse("https://registration.example/").unwrap(),
            principal_endpoint: &Url::parse("https://registration.example/").unwrap(),
            local_id: "alice",
            also_known_as: &[],
            version_created_at: Utc.with_ymd_and_hms(2026, 8, 11, 2, 0, 0).unwrap(),
            root_seed: &root_seed,
            next_root_public_key_multibase: &next_root_public_key_multibase,
            witness_policy: None,
        })
        .unwrap();
        let document: DidDocument =
            serde_json::from_value(prepared.log_entry["state"].clone()).unwrap();
        let anchor = PrincipalRegistrationAnchor::WebvhRegistration {
            registration_did_operation: Box::new(prepared.submit_body.clone()),
            log_entries: vec![entry_map(&prepared.log_entry)],
            witness_records: Vec::new(),
            normalized_did_document: document,
        };
        (
            anchor,
            prepared.submit_body,
            prepared.log_entry,
            prepared.version_id,
        )
    }

    #[test]
    fn webvh_anchor_derives_every_coordinate_from_its_verified_terminal_entry() {
        let (anchor, submit_body, log_entry, version_id) = webvh_anchor();
        let validated = validate_principal_registration_anchor(&anchor).unwrap();

        assert_eq!(validated.anchor_kind, WEBVH_REGISTRATION_ANCHOR_KIND);
        assert_eq!(validated.did, submit_body.did);
        assert_eq!(
            validated.principal_id,
            project_did_to_core_id(&submit_body.did).unwrap()
        );
        assert_eq!(validated.did_version_id, version_id);
        assert_eq!(
            validated.method_history_head.as_str(),
            canonical::canonical_sha256(&log_entry).unwrap()
        );
        assert_eq!(
            validated.root_verification_method.as_str(),
            log_entry["proof"][0]["verificationMethod"]
                .as_str()
                .unwrap()
        );
        assert_eq!(
            validated.root_public_key_multibase,
            log_entry["parameters"]["updateKeys"][0].as_str().unwrap()
        );
        assert_eq!(
            validated.registration_anchor_digest,
            anchor.canonical_digest().unwrap()
        );
        assert!(validated.did_version_time.is_some());
        assert!(validated.next_root_key_hash.is_some());
    }

    #[test]
    fn webvh_anchor_rejects_a_substituted_terminal_entry() {
        let (anchor, submit_body, log_entry, _) = webvh_anchor();
        let PrincipalRegistrationAnchor::WebvhRegistration {
            normalized_did_document,
            ..
        } = anchor;
        let mut tampered = log_entry;
        tampered["versionTime"] = Value::String("2026-08-12T02:00:00Z".to_owned());
        let mut operation = submit_body;
        operation.operation = entry_map(&tampered);
        validate_principal_registration_anchor(&PrincipalRegistrationAnchor::WebvhRegistration {
            registration_did_operation: Box::new(operation),
            log_entries: vec![entry_map(&tampered)],
            witness_records: Vec::new(),
            normalized_did_document,
        })
        .unwrap_err();
    }

    #[test]
    fn webvh_anchor_rejects_a_document_that_is_not_the_terminal_state() {
        let (anchor, _, log_entry, _) = webvh_anchor();
        let PrincipalRegistrationAnchor::WebvhRegistration {
            registration_did_operation,
            log_entries,
            witness_records,
            ..
        } = anchor;
        let mut state = log_entry["state"].clone();
        state["alsoKnownAs"] = serde_json::json!(["acct:substituted@example"]);
        validate_principal_registration_anchor(&PrincipalRegistrationAnchor::WebvhRegistration {
            registration_did_operation,
            log_entries,
            witness_records,
            normalized_did_document: serde_json::from_value(state).unwrap(),
        })
        .unwrap_err();
    }

    #[test]
    fn recovered_registration_uses_the_original_root_after_native_rotation() {
        let (anchor, operation, entry, version_id) = webvh_anchor();
        let target = arkret_models_identity::ResolutionCommitment {
            did: operation.did.clone(),
            method_history_head: canonical::canonical_sha256(&entry).unwrap(),
            version_id,
        };
        let next = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            SigningKey::from_bytes(&[0x53; 32])
                .verifying_key()
                .as_bytes(),
        );
        let rotation = arkret_signatures::webvh::prepare_principal_rotation(
            &arkret_signatures::webvh::PrincipalRotationInput {
                did: operation.did.as_str(),
                local_id: "alice",
                previous_entries: std::slice::from_ref(&entry),
                version_created_at: Utc.with_ymd_and_hms(2026, 8, 12, 2, 0, 0).unwrap(),
                current_root_seed: &[0x52; 32],
                next_root_public_key_multibase: &next,
                state: &entry["state"],
            },
        )
        .unwrap();
        let history = vec![entry, rotation.log_entry];
        let recovered = recover_principal_registration_anchor(&target, &history, &[]).unwrap();
        assert_eq!(
            recovered.canonical_digest().unwrap(),
            anchor.canonical_digest().unwrap()
        );
        let original = validate_principal_registration_anchor(&recovered).unwrap();
        let current = crate::resolvers::verify_did_webvh_v1_log(&operation.did, &history).unwrap();
        assert_ne!(
            original.root_public_key_multibase,
            current.active_update_keys[0]
        );
    }

    #[test]
    fn historical_registration_rejects_changed_coordinates_or_native_proof() {
        let (_, operation, entry, version_id) = webvh_anchor();
        let target = arkret_models_identity::ResolutionCommitment {
            did: operation.did,
            method_history_head: canonical::canonical_sha256(&entry).unwrap(),
            version_id,
        };
        assert!(recover_principal_registration_anchor(&target, &[], &[]).is_err());
        assert!(
            recover_principal_registration_anchor(&target, &[entry.clone(), entry.clone()], &[])
                .is_err()
        );
        let mut wrong = target.clone();
        wrong.method_history_head = format!("sha256:{}", "00".repeat(32));
        assert!(
            recover_principal_registration_anchor(&wrong, std::slice::from_ref(&entry), &[])
                .is_err()
        );
        wrong = target.clone();
        wrong.version_id = "2-unknown".into();
        assert!(
            recover_principal_registration_anchor(&wrong, std::slice::from_ref(&entry), &[])
                .is_err()
        );
        wrong = target.clone();
        wrong.did = arkret_wire::Did::new(target.did.as_str().replace("alice", "bob")).unwrap();
        assert!(
            recover_principal_registration_anchor(&wrong, std::slice::from_ref(&entry), &[])
                .is_err()
        );
        let mut forged = entry;
        forged["proof"][0]["proofValue"] = serde_json::json!("zForged");
        wrong = target;
        wrong.method_history_head = canonical::canonical_sha256(&forged).unwrap();
        assert!(recover_principal_registration_anchor(&wrong, &[forged], &[]).is_err());
    }
}
