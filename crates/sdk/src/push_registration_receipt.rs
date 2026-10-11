//! Public Push Gateway installation-receipt verification.

use arkret_models_integration::{
    PushRegistrationHandoffRequestBody, PushRegistrationInstallationReceipt,
};
use arkret_signatures::{Ed25519DetachedJwsVerifier, PublicKeyMaterial};
use arkret_wire::{DidCoreId, WireError};
use ed25519_dalek::VerifyingKey;

/// Verify a Gateway's durable receipt for one exact registration handoff.
///
/// The caller resolves `receipt.proof.verification_method` through the
/// authenticated Gateway DID history effective at `receipt.stored_at` and
/// supplies that exact Ed25519 key. This helper first validates every closed
/// request/receipt/proof binding and only then checks the detached JWS. Keeping
/// that order prevents a valid signature from authenticating a receipt whose
/// echoed request, source Station, destination Gateway, or proof metadata has
/// drifted.
pub fn verify_push_registration_installation_receipt(
    receipt: &PushRegistrationInstallationReceipt,
    request: &PushRegistrationHandoffRequestBody,
    source_station_id: &DidCoreId,
    destination_gateway_id: &DidCoreId,
    verifying_key: &VerifyingKey,
) -> Result<(), WireError> {
    receipt.validate_for_handoff(request, source_station_id, destination_gateway_id)?;
    let binding = receipt.proof_binding_bytes()?;
    Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(
            &receipt.proof.jws,
            &binding,
            &PublicKeyMaterial::Ed25519Raw {
                bytes: verifying_key.to_bytes().to_vec(),
            },
        )
        .map_err(|_| {
            WireError::Protocol(
                "push registration installation receipt signature is invalid".to_owned(),
            )
        })
}

#[cfg(test)]
mod tests {
    use arkret_models_integration::{PushRegistrationHandoffState, PushRegistrationId};
    use arkret_signatures::sign_ed25519_detached_jws;
    use arkret_wire::{Audience, Did, DidUrl, Hash, PayloadProof, project_did_to_core_id};
    use chrono::{DateTime, Utc};
    use ed25519_dalek::SigningKey;
    use serde_json::json;

    use super::*;

    fn fixture() -> (
        PushRegistrationHandoffRequestBody,
        PushRegistrationInstallationReceipt,
        DidCoreId,
        DidCoreId,
        SigningKey,
    ) {
        let request: PushRegistrationHandoffRequestBody = serde_json::from_value(json!({
            "registration_id": "registration_0123456789abcdef",
            "push_target_id": "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
            "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
            "state": "active",
            "push_key": "provider-secret",
            "platform": "apns",
            "visible_notification_opt_in": false
        }))
        .unwrap();
        let source_station_id =
            project_did_to_core_id(&Did::new("did:web:source.example").unwrap()).unwrap();
        let destination_gateway_id =
            project_did_to_core_id(&Did::new("did:web:gateway.example").unwrap()).unwrap();
        let stored_at = DateTime::parse_from_rfc3339("2026-09-20T12:34:56Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut receipt = PushRegistrationInstallationReceipt {
            registration_id: request.registration_id().clone(),
            push_target_id: request.push_target_id().clone(),
            device_id: request.device_id().clone(),
            state: PushRegistrationHandoffState::Active,
            request_digest: request.request_digest().unwrap(),
            source_station_id: source_station_id.clone(),
            destination_gateway_id: destination_gateway_id.clone(),
            stored_at,
            proof: PayloadProof {
                kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
                verification_method: DidUrl::new("did:web:gateway.example#push-receipt-key")
                    .unwrap(),
                payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                created_at: stored_at,
                domain: None,
                audience: Some(Audience::Single(source_station_id.as_str().to_owned())),
                proof_purpose: None,
                jws: "pending..signature".to_owned(),
            },
        };
        receipt.proof.payload_digest = receipt.expected_payload_digest().unwrap();
        let signing_key = SigningKey::from_bytes(&[61; 32]);
        receipt.proof.jws =
            sign_ed25519_detached_jws(&signing_key, &receipt.proof_binding_bytes().unwrap())
                .unwrap();
        (
            request,
            receipt,
            source_station_id,
            destination_gateway_id,
            signing_key,
        )
    }

    #[test]
    fn verifies_exact_handoff_before_accepting_gateway_signature() {
        let (request, receipt, source, destination, signing_key) = fixture();
        verify_push_registration_installation_receipt(
            &receipt,
            &request,
            &source,
            &destination,
            &signing_key.verifying_key(),
        )
        .unwrap();
    }

    #[test]
    fn rejects_binding_tampering_before_detached_jws_verification() {
        let (request, mut receipt, source, destination, signing_key) = fixture();
        receipt.registration_id = PushRegistrationId::new("other_registration_0123456789").unwrap();
        let last = receipt.proof.jws.pop().unwrap();
        receipt.proof.jws.push(if last == 'A' { 'B' } else { 'A' });
        receipt.proof.payload_digest = receipt.expected_payload_digest().unwrap();
        let error = verify_push_registration_installation_receipt(
            &receipt,
            &request,
            &source,
            &destination,
            &signing_key.verifying_key(),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not bind the exact handoff"),
            "binding validation must fail before JWS verification: {error}"
        );
    }

    #[test]
    fn rejects_signature_tampering_and_wrong_gateway_key() {
        let (request, mut receipt, source, destination, signing_key) = fixture();
        let last = receipt.proof.jws.pop().unwrap();
        receipt.proof.jws.push(if last == 'A' { 'B' } else { 'A' });
        assert!(
            verify_push_registration_installation_receipt(
                &receipt,
                &request,
                &source,
                &destination,
                &signing_key.verifying_key(),
            )
            .is_err()
        );

        let (_, receipt, ..) = fixture();
        let wrong_key = SigningKey::from_bytes(&[62; 32]);
        assert!(
            verify_push_registration_installation_receipt(
                &receipt,
                &request,
                &source,
                &destination,
                &wrong_key.verifying_key(),
            )
            .is_err()
        );
    }
}
