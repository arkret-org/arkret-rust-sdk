//! Purpose-separated Recovery signatures over the original native objects.
//!
//! Keys and expected methods must come from verified Session / authority state.
//! These functions authenticate bytes, not current policy, grants or storage.

use arkret_models_crypto::{RecoveryReceipt, RecoveryTransactionCompletion};
use arkret_wire::{DetachedSignatureContext, DidUrl, RealmCommit};
use ed25519_dalek::{Signer, SigningKey};

use crate::{Error, EventProofBuilder, PublicKeyMaterial, Result};

fn raw(bytes: &[u8], signature: &str, key: &PublicKeyMaterial) -> Result<()> {
    crate::proof::verify_ed25519_raw_transcript_signature(bytes, signature, key)
        .map_err(|error| Error::Protocol(format!("Recovery signature is invalid: {error}")))
}

pub fn sign_recovery_receipt(receipt: &mut RecoveryReceipt, key: &SigningKey) -> Result<()> {
    let signature = key.sign(&receipt.signature_transcript_bytes()?);
    receipt.signature_proof.signature =
        arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(signature.to_bytes()))
            .map_err(|error| Error::Protocol(error.to_owned()))?;
    Ok(())
}

/// Candidate verification never looks in the accepted-device directory: the
/// caller provides the key/method frozen by its verified RecoverySession.
pub fn verify_recovery_receipt(
    receipt: &RecoveryReceipt,
    expected_method: &DidUrl,
    candidate_key: &PublicKeyMaterial,
) -> Result<()> {
    receipt.validate()?;
    if receipt.signature_proof.verification_method != *expected_method {
        return Err(Error::Protocol(
            "Recovery receipt uses another candidate method".into(),
        ));
    }
    raw(
        &receipt.signature_transcript_bytes()?,
        receipt.signature_proof.signature.as_str(),
        candidate_key,
    )?;
    for slot in &receipt.recovery_unit.events {
        let event = &slot.event;
        let proof = event
            .producer_proof
            .as_ref()
            .ok_or_else(|| Error::Protocol("Recovery Event has no producer proof".into()))?;
        if proof.verification_method != *expected_method {
            return Err(Error::Protocol(
                "Recovery Event uses another candidate method".into(),
            ));
        }
        let transcript = EventProofBuilder::new().envelope_bytes(event)?;
        crate::verify_ed25519_detached_jws_proof_with_digest_suite(
            proof,
            &transcript,
            &event.actor_id,
            candidate_key,
            arkret_canonical::DigestSuite::Sha256,
        )
        .map_err(|error| Error::Protocol(error.to_string()))?;
    }
    let payload = serde_json::to_value(&receipt.recovery_unit.events[1].event.payload)?;
    let key_did = payload["device_public_key_did"]
        .as_str()
        .and_then(|value| value.strip_prefix("did:key:"))
        .ok_or_else(|| {
            Error::Protocol("Recovery authorize payload has no candidate did:key".into())
        })?;
    let declared = PublicKeyMaterial::Ed25519Multibase {
        value: key_did.into(),
    };
    if declared.ed25519_bytes()? != candidate_key.ed25519_bytes()? {
        return Err(Error::Protocol(
            "Recovery authorize key differs from the verified Session candidate".into(),
        ));
    }
    let mut possession = payload
        .as_object()
        .ok_or_else(|| Error::Protocol("Recovery authorization must be an object".into()))?
        .clone();
    let signature = possession
        .remove("device_signature")
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| {
            Error::Protocol("Recovery authorize payload lacks device possession proof".into())
        })?;
    possession.insert(
        "account_id".into(),
        serde_json::to_value(&receipt.account_id)?,
    );
    possession
        .entry("expires_at")
        .or_insert(serde_json::Value::Null);
    possession
        .entry("scopes")
        .or_insert(serde_json::Value::Null);
    let mut bytes = b"ak.device_authorize_recovery_possession_proof.v1\n".to_vec();
    bytes.extend(arkret_canonical::canonical_json_bytes(&possession)?);
    raw(&bytes, &signature, candidate_key)
}

/// Verify C and both real native Commits. The authority key/method must be
/// independently resolved at the accepted historical authority cut; this does
/// not replace full chain/current-authority qualification by the caller.
pub fn verify_recovery_completion(
    completed: &RecoveryTransactionCompletion,
    commits: &[RealmCommit; 2],
    expected_method: &DidUrl,
    station_key: &PublicKeyMaterial,
) -> Result<()> {
    completed.validate_structural()?;
    let completion = &completed.completion_attestation;
    if completion.signature_proof.verification_method != *expected_method {
        return Err(Error::Protocol(
            "Recovery C uses another Station method".into(),
        ));
    }
    raw(
        &completion.signing_bytes()?,
        &completion.signature_proof.signature,
        station_key,
    )?;
    for (index, commit) in commits.iter().enumerate() {
        commit.validate_content_address()?;
        let reference = if index == 0 {
            &completion.reanchor_event_ref
        } else {
            &completion.device_authorization_event_ref
        };
        if reference.commit_id != commit.commit_id
            || reference.event_id != commit.event_ref
            || reference.stream_ref != commit.stream_ref
            || reference.stream_position != commit.stream_position
            || commit.signature.verification_method != *expected_method
        {
            return Err(Error::Protocol(
                "Recovery C reference differs from its native Commit".into(),
            ));
        }
        let mut body = serde_json::to_value(commit)?;
        body.as_object_mut()
            .ok_or_else(|| Error::Protocol("Commit must be an object".into()))?
            .remove("signature");
        crate::detached_object::verify_detached_object_signature(
            &commit.signature,
            &body,
            DetachedSignatureContext::RealmCommit,
            station_key,
        )?;
    }
    if commits[0].previous_commit_ref.as_ref()
        != Some(&completed.recovery_receipt.recovery_unit.predecessor_ref)
        || commits[1].previous_commit_ref.as_ref() != Some(&commits[0].commit_id)
    {
        return Err(Error::Protocol(
            "Recovery native Commit pair does not extend the independent accepted predecessor"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(any(
    feature = "collaboration",
    feature = "service-identity",
    feature = "webvh"
))]
pub fn verify_recovery_completion_holder(
    request: &arkret_models_identity::RecoveryCompletionGrantRequestBody,
    accepted_device_method: &DidUrl,
    accepted_device_key: &PublicKeyMaterial,
) -> Result<()> {
    request.validate_structural()?;
    let proof = &request.accepted_device_possession_proof;
    if proof.verification_method != *accepted_device_method {
        return Err(Error::Protocol(
            "completion holder proof uses another accepted device method".into(),
        ));
    }
    raw(
        &proof.canonical_signing_bytes()?,
        proof.signature.as_str(),
        accepted_device_key,
    )
}

#[cfg(test)]
mod tests;
