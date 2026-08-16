//! Canonical Account Status authority-evidence proof signing and verification.

use arkret_models_collaboration::account_lifecycle::{
    AccountStatusAuthorityEvidence, UnsignedAccountStatusAuthorityEvidence,
};
use ed25519_dalek::SigningKey;

use crate::{Ed25519DetachedJwsVerifier, PublicKeyMaterial, Result, sign_ed25519_detached_jws};

pub fn sign_account_status_authority_evidence(
    unsigned: UnsignedAccountStatusAuthorityEvidence,
    signing_key: &SigningKey,
) -> Result<AccountStatusAuthorityEvidence> {
    let metadata = unsigned.proof_metadata()?;
    let binding = unsigned.canonical_proof_binding_bytes(&metadata)?;
    let jws = sign_ed25519_detached_jws(signing_key, &binding)?;
    let proof = metadata.finalize(jws)?;
    unsigned.attach_proof(proof).map_err(Into::into)
}

pub fn verify_account_status_authority_evidence(
    evidence: &AccountStatusAuthorityEvidence,
    public_key: &PublicKeyMaterial,
) -> Result<()> {
    evidence.validate_shape()?;
    Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(
            &evidence.proof.jws,
            &evidence.canonical_proof_binding_bytes()?,
            public_key,
        )
        .map(|_| ())
        .map_err(|_| {
            crate::Error::Protocol(
                "account status authority evidence signature is invalid".to_owned(),
            )
        })
}

#[cfg(test)]
mod tests {
    use arkret_models_collaboration::account_lifecycle::UnsignedAccountStatusAuthorityEvidence;
    use arkret_wire::{DidCoreId, DidUrl, NonEmptyString, RealmId};

    use super::*;

    fn unsigned() -> UnsignedAccountStatusAuthorityEvidence {
        UnsignedAccountStatusAuthorityEvidence {
            account_authority_id: DidCoreId::new("ak:did_core:web:authority.example").unwrap(),
            issuer_service_id: DidCoreId::new("ak:did_core:web:issuer.example").unwrap(),
            principal_control_realm_id: RealmId::new(
                "ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir",
            )
            .unwrap(),
            account_id: NonEmptyString::new("account-1").unwrap(),
            principal_id: DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            binding_version: 7,
            issued_at: "2026-08-16T00:00:00.000Z".parse().unwrap(),
            expires_at: "2026-08-16T00:05:00.000Z".parse().unwrap(),
            verification_method: DidUrl::new("did:web:authority.example#account-status-key")
                .unwrap(),
        }
    }

    #[test]
    fn canonical_helper_signs_and_verifies_exact_evidence() {
        let key = SigningKey::from_bytes(&[23; 32]);
        let evidence = sign_account_status_authority_evidence(unsigned(), &key).unwrap();
        verify_account_status_authority_evidence(
            &evidence,
            &PublicKeyMaterial::Ed25519Raw {
                bytes: key.verifying_key().to_bytes().to_vec(),
            },
        )
        .unwrap();
    }

    #[test]
    fn signature_does_not_survive_binding_version_mutation() {
        let key = SigningKey::from_bytes(&[29; 32]);
        let mut evidence = sign_account_status_authority_evidence(unsigned(), &key).unwrap();
        evidence.binding_version += 1;
        assert!(
            verify_account_status_authority_evidence(
                &evidence,
                &PublicKeyMaterial::Ed25519Raw {
                    bytes: key.verifying_key().to_bytes().to_vec(),
                },
            )
            .is_err()
        );
    }

    #[test]
    fn evidence_rejects_removed_authority_ref_field() {
        let key = SigningKey::from_bytes(&[31; 32]);
        let evidence = sign_account_status_authority_evidence(unsigned(), &key).unwrap();
        let mut encoded = serde_json::to_value(evidence).unwrap();
        encoded.as_object_mut().unwrap().insert(
            "authority_ref".to_owned(),
            serde_json::json!("did:web:authority.example#obsolete-delegation"),
        );

        assert!(serde_json::from_value::<AccountStatusAuthorityEvidence>(encoded).is_err());
    }
}
