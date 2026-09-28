//! Approval signature verification for one exact producer-authored Event.
//!
//! The caller resolves the approver method at `approved_at`, checks its
//! revocation status, and supplies that method's public key. Grant, governance
//! and List WIP qualification plus atomic nonce consumption remain the
//! governing Station's same-cut responsibilities.

use arkret_wire::{ApprovalSignature, ApprovalTarget, CapabilityActionId, Event, WireError};
use chrono::{DateTime, Utc};

use crate::{Ed25519DetachedJwsVerifier, PublicKeyMaterial};

/// Distinguishes a stale binding from a bad proof without guessing a wire
/// error code before the caller's ingress and authority policy are known.
#[derive(Debug, thiserror::Error)]
pub enum ApprovalEventVerificationError {
    #[error("approval timestamp is outside the registered future guard: {0}")]
    Time(String),
    #[error("approval does not bind the exact Event and execution")]
    Binding,
    #[error("approval digest does not bind the complete Event")]
    Digest,
    #[error("approval signature is invalid")]
    Signature,
    #[error("approval canonical input cannot be encoded: {0}")]
    Canonical(String),
}

/// The exact bytes covered by `ak.schema.approval_signature.v1`.
pub fn approval_signature_signing_bytes(
    signature: &ApprovalSignature,
) -> arkret_wire::Result<Vec<u8>> {
    let mut bytes = b"ak.approval.signature.v1\n".to_vec();
    bytes.extend(
        arkret_canonical::canonical::canonical_json_bytes(&signature.input)
            .map_err(|error| WireError::Protocol(error.to_string()))?,
    );
    Ok(bytes)
}

/// Verify the detached signature and exact Event binding at the caller's
/// proposed accepting time. This does not authorize the initiator, prove
/// DID-method validity at `approved_at`, or consume the signature's nonce.
pub fn verify_event_approval_signature(
    signature: &ApprovalSignature,
    event: &Event,
    operation: &str,
    action: CapabilityActionId,
    verification_time: DateTime<Utc>,
    approver_public_key: &PublicKeyMaterial,
) -> Result<(), ApprovalEventVerificationError> {
    signature
        .input
        .validate_approved_at(verification_time)
        .map_err(|error| ApprovalEventVerificationError::Time(error.to_string()))?;
    let method_did = signature
        .proof
        .verification_method
        .as_str()
        .split_once('#')
        .map(|(did, _)| did);
    if method_did != Some(signature.input.approver_did.as_str())
        || !matches!(
            &signature.input.approval_target,
            ApprovalTarget::Event { event_id } if event_id == &event.event_id
        )
        || signature.input.operation != operation
        || signature.input.action != action
        || signature.input.realm_id != event.realm_id
        || signature.input.initiating_actor_id != event.actor_id
    {
        return Err(ApprovalEventVerificationError::Binding);
    }
    let event_digest = arkret_canonical::canonical::canonical_sha256(event)
        .map_err(|error| ApprovalEventVerificationError::Canonical(error.to_string()))?;
    if signature.input.request_canonical_digest.as_str() != event_digest {
        return Err(ApprovalEventVerificationError::Digest);
    }
    let signing_bytes = approval_signature_signing_bytes(signature)
        .map_err(|error| ApprovalEventVerificationError::Canonical(error.to_string()))?;
    Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(&signature.proof.jws, &signing_bytes, approver_public_key)
        .map_err(|_| ApprovalEventVerificationError::Signature)
}

#[cfg(test)]
mod tests {
    use arkret_wire::{
        ApprovalContext, ApprovalSignatureInput, ApprovalSignatureProof,
        ApprovalSignatureProofKind, Did, DidCoreId, DidUrl, EventId, Hash, ProducerEventProof,
        RealmId, ScopeRef, test_support,
    };
    use chrono::TimeZone;
    use serde_json::json;

    use super::*;
    use crate::Ed25519DetachedJwsSigner;

    #[test]
    fn exact_event_approval_verifies_and_rejects_changed_binding() {
        let at = Utc.timestamp_opt(1_800_000_000, 0).unwrap();
        let realm = RealmId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [3; 32],
        ));
        let mut event = test_support::raw_event_at(
            "ak.strand.move",
            ScopeRef::Realm {
                realm_id: realm.clone(),
            },
            DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            json!({"board_space_id":"board","strand_id":"strand","target_space_id":"list","rank":"a"}),
            at,
        )
        .unwrap();
        event.producer_proof = Some(ProducerEventProof {
            kind: "detached_jws".to_owned(),
            verification_method: DidUrl::new("did:web:alice.example#device-1").unwrap(),
            event_digest: Hash::new(format!("sha256:{}", "22".repeat(32))).unwrap(),
            created_at: at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "producer-proof".to_owned(),
        });
        let method = DidUrl::new("did:web:manager.example#key-1").unwrap();
        let signer = Ed25519DetachedJwsSigner::from_seed([23; 32], method.as_str());
        let key = PublicKeyMaterial::Ed25519Raw {
            bytes: signer.verifying_key().to_bytes().to_vec(),
        };
        let input = ApprovalSignatureInput {
            approval_context: ApprovalContext::RealmGovernance {},
            approval_target: ApprovalTarget::Event {
                event_id: event.event_id.clone(),
            },
            request_canonical_digest: Hash::new(
                arkret_canonical::canonical::canonical_sha256(&event).unwrap(),
            )
            .unwrap(),
            operation: "ak.self.events.command.submit.v1".to_owned(),
            action: CapabilityActionId::StrandMove,
            realm_id: realm,
            initiating_actor_id: event.actor_id.clone(),
            approver_did: Did::new("did:web:manager.example").unwrap(),
            approved_at: at,
            nonce: "ABCDEFGHIJKLMNOPQRSTUV".to_owned(),
        };
        let mut signature = ApprovalSignature {
            input,
            proof: ApprovalSignatureProof {
                kind: ApprovalSignatureProofKind::DetachedJws,
                verification_method: method,
                jws: String::new(),
            },
        };
        signature.proof.jws =
            signer.sign_detached_jws(&approval_signature_signing_bytes(&signature).unwrap());
        assert!(
            verify_event_approval_signature(
                &signature,
                &event,
                "ak.self.events.command.submit.v1",
                CapabilityActionId::StrandMove,
                at,
                &key,
            )
            .is_ok()
        );
        let mut tampered = signature.clone();
        tampered.input.nonce.push('X');
        assert!(matches!(
            verify_event_approval_signature(
                &tampered,
                &event,
                "ak.self.events.command.submit.v1",
                CapabilityActionId::StrandMove,
                at,
                &key
            ),
            Err(ApprovalEventVerificationError::Signature)
        ));
        assert!(matches!(
            verify_event_approval_signature(
                &signature,
                &event,
                "ak.peer.events.command.submit.v1",
                CapabilityActionId::StrandMove,
                at,
                &key
            ),
            Err(ApprovalEventVerificationError::Binding)
        ));
        let mut changed_event = event.clone();
        changed_event.producer_proof.as_mut().unwrap().jws.push('X');
        assert!(matches!(
            verify_event_approval_signature(
                &signature,
                &changed_event,
                "ak.self.events.command.submit.v1",
                CapabilityActionId::StrandMove,
                at,
                &key
            ),
            Err(ApprovalEventVerificationError::Digest)
        ));
    }
}
