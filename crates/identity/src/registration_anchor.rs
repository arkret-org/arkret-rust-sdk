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
                did_version_time: Some(terminal_entry.version_time),
                control_key_digest: control_key_digest(&root_public_key_multibase)?,
                root_public_key_multibase,
                root_verification_method: DidUrl::new(root_verification_method.to_owned())
                    .map_err(protocol)?,
                next_root_key_hash: Some(next_root_key_hash),
            })
        }
    }
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
            version_time: Utc.with_ymd_and_hms(2026, 8, 11, 2, 0, 0).unwrap(),
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
}
