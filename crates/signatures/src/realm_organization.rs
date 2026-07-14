//! Organization-side statement signing helper (A3).
//!
//! The verifier (soland's `verify_realm_organization_proof_signature`) decodes
//! `authorization.proof` with base64url (no padding) and runs
//! `verify_strict(signing_bytes, signature)` where `signing_bytes` come from
//! [`arkret_core::models::realm_organization_statement_signing_bytes`]. This
//! helper produces the byte-symmetric counterpart: a detached Ed25519 signature
//! over those same `signing_bytes`, base64url-unpadded encoded, set as the
//! `authorization.proof` `SignatureMaterial::NonEmptyString`.

use arkret_canonical::base64url::base64url_encode;
use arkret_core::models::{NonEmptyString, RealmOrganizationPayload, SignatureMaterial};
use arkret_core::{Error, Result};
use ed25519_dalek::{Signer, SigningKey};

/// Sign `payload` with `signing_key` and return a clone whose
/// `authorization.proof` carries the detached Ed25519 signature.
///
/// The signature is computed over
/// [`arkret_core::models::realm_organization_statement_signing_bytes`] and
/// encoded with base64url (no padding), so it round-trips through soland's
/// `verify_realm_organization_proof_signature` (which decodes with
/// `URL_SAFE_NO_PAD` and calls `verify_strict` over the same bytes).
///
/// `signing_key` MUST correspond to the verification method named in
/// `payload.authorization.verification_method` and resolvable from the
/// `organization_id` DID document; this helper does not check that binding —
/// the verifier does.
pub fn realm_organization_statement_sign(
    payload: &RealmOrganizationPayload,
    signing_key: &SigningKey,
) -> Result<RealmOrganizationPayload> {
    let signing_bytes = arkret_core::models::realm_organization_statement_signing_bytes(payload)?;
    let signature = signing_key.sign(&signing_bytes);
    let proof = NonEmptyString::new(base64url_encode(signature.to_bytes()))
        .map_err(|reason| Error::Protocol(reason.to_owned()))?;
    let mut signed = payload.clone();
    signed.authorization.proof = SignatureMaterial::NonEmptyString(
        NonEmptyString::new(proof)
            .map_err(|error| Error::Protocol(format!("invalid organization proof: {error}")))?,
    );
    Ok(signed)
}

#[cfg(test)]
mod tests {
    use arkret_canonical::base64url::base64url_decode;
    use arkret_core::identifiers::{Did, RealmId};
    use arkret_core::models::{
        RealmOrganizationAuthorization, RealmOrganizationControlScope, RealmOrganizationIssuerRole,
        RealmOrganizationRelationship, RealmOrganizationStatus,
    };
    use chrono::{DateTime, TimeZone, Utc};

    use super::*;

    fn realm_id() -> RealmId {
        RealmId::new("ak:realm:0196419b-0000-7000-8000-000000000010").unwrap()
    }

    fn org_did() -> Did {
        Did::new("did:webvh:example.test:orgs:org1".to_owned()).unwrap()
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 25, 12, 0, 0).unwrap()
    }

    fn payload() -> RealmOrganizationPayload {
        RealmOrganizationPayload {
            statement_id: "org-stmt-1".to_owned(),
            realm_id: realm_id(),
            organization_id: org_did(),
            relationship: RealmOrganizationRelationship::Owner,
            status: RealmOrganizationStatus::Active,
            control_scopes: vec![
                RealmOrganizationControlScope::OfficialBadge,
                RealmOrganizationControlScope::RealmAdmin,
            ],
            issued_at: now(),
            not_before: None,
            expires_at: None,
            supersedes_statement_id: None,
            revokes_statement_id: None,
            realm_frontier_digest: None,
            organization_policy_ref: None,
            authorization: RealmOrganizationAuthorization {
                issuer: org_did(),
                issuer_role: RealmOrganizationIssuerRole::OrganizationDid,
                verification_method: arkret_core::models::DidUrl::new(
                    "did:webvh:example.test:orgs:org1#k1",
                )
                .unwrap(),
                delegation_ref: None,
                executed_by: None,
                signed_at: now(),
                // Placeholder proof; replaced by the signer.
                proof: SignatureMaterial::NonEmptyString(
                    NonEmptyString::new("placeholder").unwrap(),
                ),
            },
        }
    }

    /// Sign, then re-derive the signing bytes and verify with `verify_strict`
    /// over the verifying key — exactly the path soland's verifier runs.
    #[test]
    fn sign_round_trips_through_soland_verifier_shape() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key = signing_key.verifying_key();

        let signed = realm_organization_statement_sign(&payload(), &signing_key).expect("sign ok");

        let proof_b64 = match &signed.authorization.proof {
            SignatureMaterial::NonEmptyString(value) => value.clone(),
            SignatureMaterial::Variant1(_) => panic!("expected detached signature string"),
        };
        let sig_bytes = base64url_decode(proof_b64.trim()).expect("base64url decode");
        let signature = ed25519_dalek::Signature::from_slice(&sig_bytes).expect("64-byte sig");

        let signing_bytes =
            arkret_core::models::realm_organization_statement_signing_bytes(&signed)
                .expect("signing bytes");
        verifying_key
            .verify_strict(&signing_bytes, &signature)
            .expect("verify_strict must pass");
    }

    #[test]
    fn proof_is_unpadded_url_safe_base64() {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let signed = realm_organization_statement_sign(&payload(), &signing_key).unwrap();
        let proof = match &signed.authorization.proof {
            SignatureMaterial::NonEmptyString(value) => value.clone(),
            SignatureMaterial::Variant1(_) => unreachable!(),
        };
        assert!(!proof.contains('='), "base64url is unpadded");
        assert!(
            !proof.contains('+') && !proof.contains('/'),
            "URL-safe alphabet"
        );
        // A 64-byte signature encodes to 86 base64url chars (no padding).
        assert_eq!(proof.len(), 86);
    }

    #[test]
    fn signing_does_not_mutate_input_except_proof() {
        let signing_key = SigningKey::from_bytes(&[3u8; 32]);
        let original = payload();
        let signed = realm_organization_statement_sign(&original, &signing_key).unwrap();
        assert_eq!(signed.statement_id, original.statement_id);
        assert_eq!(signed.realm_id, original.realm_id);
        assert_eq!(
            signed.authorization.verification_method,
            original.authorization.verification_method
        );
    }
}
