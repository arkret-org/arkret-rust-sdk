//! Contact source-service receipt signing inputs and verification.

use arkret_models_collaboration::contact_operations::RequestAcceptanceReceipt;
use arkret_wire::{EventId, Hash, Result, WireError};
use ed25519_dalek::Signature;
use serde::Serialize;

/// Canonical bytes signed by the source service for a Contact request
/// acceptance receipt. The non-recursive `receipt_digest` covers `core`; the
/// signature then covers both values.
pub fn contact_request_acceptance_receipt_signing_bytes(
    receipt: &RequestAcceptanceReceipt,
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct SignedValue<'a> {
        core: &'a arkret_models_collaboration::contact_operations::RequestAcceptanceReceiptCore,
        receipt_digest: &'a Hash,
    }
    arkret_canonical::canonical_json_bytes(&SignedValue {
        core: &receipt.core,
        receipt_digest: &receipt.receipt_digest,
    })
    .map_err(Into::into)
}

/// Verify a pending-incoming Contact receipt after the caller has resolved the
/// issuer service key at `receipt.core.accepted_at`.
///
/// `expected_request_event_ref` must come from the exact request Event, not
/// from the list projection's summary alone. Its digest is encoded in the
/// suite-tagged full-digest EventId.
pub fn verify_contact_request_acceptance_receipt(
    receipt: &RequestAcceptanceReceipt,
    expected_request_event_ref: &EventId,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<()> {
    receipt.validate_shape()?;
    if &receipt.core.request_event_ref != expected_request_event_ref {
        return Err(WireError::Protocol(
            "Contact request receipt does not bind the exact request Event".to_owned(),
        ));
    }
    let signature_bytes = arkret_canonical::base64url_decode(receipt.signature.jws.as_str())
        .map_err(|error| {
            WireError::Protocol(format!("invalid Contact receipt signature: {error}"))
        })?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|_| {
        WireError::Protocol(
            "Contact receipt signature must contain exactly 64 Ed25519 bytes".to_owned(),
        )
    })?;
    verifying_key
        .verify_strict(
            &contact_request_acceptance_receipt_signing_bytes(receipt)?,
            &signature,
        )
        .map_err(|_| WireError::Protocol("Contact request receipt signature is invalid".to_owned()))
}

#[cfg(test)]
mod tests {
    use arkret_models_collaboration::contact_operations::{
        ContactPeer, RequestAcceptanceReceiptCore,
    };
    use arkret_wire::{Base64UrlString, DidCoreId, DidUrl, ProtocolSignature};
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use chrono::{DateTime, Utc};
    use ed25519_dalek::Signer as _;

    use super::*;

    const REQUEST_EVENT_REF: &str = "ak:event:AQJmSg1s9QyzppFeJL40dN92YVHZeLdBBt3UWHa9XNOD";
    const CORE_DIGEST: &str =
        "sha256:954956d6a6cff74c828d11f7f2d03d8f1dafb28de93f823444caaa392a2e2b98";

    fn hash(fill: char) -> Hash {
        Hash::new(format!("sha256:{}", fill.to_string().repeat(64))).unwrap()
    }

    fn signed_receipt(signing_key: &ed25519_dalek::SigningKey) -> RequestAcceptanceReceipt {
        let accepted_at = DateTime::parse_from_rfc3339("2026-08-08T00:00:00.000Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut receipt = RequestAcceptanceReceipt {
            core: RequestAcceptanceReceiptCore {
                holder: ContactPeer::Human {
                    principal_id: DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap(),
                },
                peer: ContactPeer::Human {
                    principal_id: DidCoreId::new("ak:did_core:webvh:z6mkfixturebob").unwrap(),
                },
                slot_version: 1,
                slot_predecessor: None,
                previous_terminal_contact_round_id: None,
                request_event_ref: EventId::new(REQUEST_EVENT_REF).unwrap(),
                source_checkpoint: hash('b'),
                accepted_at,
                issuer: DidCoreId::new("ak:did_core:web:ps.example").unwrap(),
            },
            receipt_digest: hash('0'),
            signature: ProtocolSignature {
                verification_method: DidUrl::new("did:web:ps.example#key-1").unwrap(),
                created_at: accepted_at,
                jws: Base64UrlString::new("AA").unwrap(),
            },
        };
        receipt.receipt_digest = receipt.computed_core_digest().unwrap();
        let signature =
            signing_key.sign(&contact_request_acceptance_receipt_signing_bytes(&receipt).unwrap());
        receipt.signature.jws =
            Base64UrlString::new(URL_SAFE_NO_PAD.encode(signature.to_bytes())).unwrap();
        receipt
    }

    #[test]
    fn contact_receipt_known_signing_fixture_verifies() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[23_u8; 32]);
        let receipt = signed_receipt(&signing_key);
        assert_eq!(receipt.receipt_digest.as_str(), CORE_DIGEST);
        assert_eq!(
            receipt.core.request_digest().as_str(),
            "sha256:02664a0d6cf50cb3a6915e24be3474df766151d978b74106ddd45876bd5cd383"
        );
        assert_eq!(
            String::from_utf8(contact_request_acceptance_receipt_signing_bytes(&receipt).unwrap())
                .unwrap(),
            concat!(
                "{\"core\":{\"accepted_at\":\"2026-08-08T00:00:00.000Z\",",
                "\"holder\":{\"kind\":\"human\",\"principal_id\":\"ak:did_core:webvh:z6mkfixturealice\"},",
                "\"issuer\":\"ak:did_core:web:ps.example\",",
                "\"peer\":{\"kind\":\"human\",\"principal_id\":\"ak:did_core:webvh:z6mkfixturebob\"},",
                "\"request_event_ref\":\"ak:event:AQJmSg1s9QyzppFeJL40dN92YVHZeLdBBt3UWHa9XNOD\",",
                "\"slot_version\":1,",
                "\"source_checkpoint\":\"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"},",
                "\"receipt_digest\":\"sha256:954956d6a6cff74c828d11f7f2d03d8f1dafb28de93f823444caaa392a2e2b98\"}"
            )
        );
        verify_contact_request_acceptance_receipt(
            &receipt,
            &receipt.core.request_event_ref,
            &signing_key.verifying_key(),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(&receipt).unwrap()["core"]["slot_version"],
            1
        );
    }

    #[test]
    fn contact_receipt_rejects_wrong_request_tampering_and_signer() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[24_u8; 32]);
        let receipt = signed_receipt(&signing_key);
        let wrong_event =
            EventId::new("ak:event:AWi7O9JH8Ib3wHJrt01Tl7Gf67pixYPhAmufRLOXFoBA").unwrap();
        assert!(
            verify_contact_request_acceptance_receipt(
                &receipt,
                &wrong_event,
                &signing_key.verifying_key(),
            )
            .is_err()
        );

        let mut signature_tampered = receipt.clone();
        let mut signature = URL_SAFE_NO_PAD
            .decode(signature_tampered.signature.jws.as_str())
            .unwrap();
        signature[0] ^= 1;
        signature_tampered.signature.jws =
            Base64UrlString::new(URL_SAFE_NO_PAD.encode(signature)).unwrap();
        assert!(
            verify_contact_request_acceptance_receipt(
                &signature_tampered,
                &signature_tampered.core.request_event_ref,
                &signing_key.verifying_key(),
            )
            .is_err()
        );

        let mut wrong_signer = receipt;
        wrong_signer.signature.verification_method =
            DidUrl::new("did:web:attacker.example#key-1").unwrap();
        assert!(wrong_signer.validate_shape().is_err());
    }
}
