//! Canonical Account Authority issuer-record signing and verification.

use arkret_models_collaboration::account_lifecycle::{
    AccountStatusReceipt, AccountStatusRecord, UnsignedAccountStatusReceipt,
    UnsignedAccountStatusRecord,
};
use arkret_wire::DidUrl;
use ed25519_dalek::SigningKey;

use crate::{Ed25519DetachedJwsVerifier, PublicKeyMaterial, Result, sign_ed25519_detached_jws};

pub fn sign_account_status_record(
    unsigned: UnsignedAccountStatusRecord,
    verification_method: DidUrl,
    signing_key: &SigningKey,
) -> Result<AccountStatusRecord> {
    let metadata = unsigned.proof_metadata(verification_method)?;
    let binding = unsigned.canonical_proof_binding_bytes(&metadata)?;
    let jws = sign_ed25519_detached_jws(signing_key, &binding)?;
    let proof = metadata.finalize(jws)?;
    unsigned.attach_proof(proof).map_err(Into::into)
}

pub fn verify_account_status_record(
    record: &AccountStatusRecord,
    public_key: &PublicKeyMaterial,
) -> Result<()> {
    record.validate_shape()?;
    Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(
            &record.proof.jws,
            &record.canonical_proof_binding_bytes()?,
            public_key,
        )
        .map(|_| ())
        .map_err(|_| {
            crate::Error::Protocol("account status record signature is invalid".to_owned())
        })
}

pub fn sign_account_status_receipt(
    unsigned: UnsignedAccountStatusReceipt,
    signing_key: &SigningKey,
) -> Result<AccountStatusReceipt> {
    let metadata = unsigned.proof_metadata()?;
    let binding = unsigned.canonical_proof_binding_bytes(&metadata)?;
    let jws = sign_ed25519_detached_jws(signing_key, &binding)?;
    let proof = metadata.finalize(jws)?;
    unsigned.attach_proof(proof).map_err(Into::into)
}

pub fn verify_account_status_receipt(
    receipt: &AccountStatusReceipt,
    public_key: &PublicKeyMaterial,
) -> Result<()> {
    receipt.validate_shape()?;
    Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(
            &receipt.proof.jws,
            &receipt.canonical_proof_binding_bytes()?,
            public_key,
        )
        .map(|_| ())
        .map_err(|_| {
            crate::Error::Protocol("account status receipt signature is invalid".to_owned())
        })
}

#[cfg(test)]
mod tests {
    use arkret_models_collaboration::account_lifecycle::{
        AccountStatusPrincipalAuthority, UnsignedAccountStatusReceipt, UnsignedAccountStatusRecord,
    };
    use arkret_models_collaboration::objects::account_status::AccountStatus;
    use arkret_wire::{DidCoreId, DidUrl, RealmId, ReceiptId, SchemaId, ServiceAccountId};

    use super::*;

    fn unsigned() -> UnsignedAccountStatusRecord {
        UnsignedAccountStatusRecord {
            schema: SchemaId::ACCOUNT_STATUS_RECORD_V1.to_owned(),
            account_authority_id: DidCoreId::new("ak:did_core:web:authority.example").unwrap(),
            account_id: ServiceAccountId::new("account-1").unwrap(),
            principal_authority: AccountStatusPrincipalAuthority {
                principal_id: DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                principal_server_id: DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
            },
            principal_control_realm_id: RealmId::new(
                "ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir",
            )
            .unwrap(),
            binding_version: 7,
            status_seq: 1,
            previous_account_status_record_id: None,
            status: AccountStatus::Active,
            reason_code: None,
            reason: None,
            issued_at: "2026-08-16T00:00:00.000Z".parse().unwrap(),
            effective_at: "2026-08-16T00:00:00.000Z".parse().unwrap(),
            expires_at: None,
        }
    }

    fn authority_method() -> DidUrl {
        DidUrl::new("did:web:authority.example#account-status-key").unwrap()
    }

    #[test]
    fn canonical_helper_signs_and_verifies_exact_evidence() {
        let key = SigningKey::from_bytes(&[23; 32]);
        let record = sign_account_status_record(unsigned(), authority_method(), &key).unwrap();
        verify_account_status_record(
            &record,
            &PublicKeyMaterial::Ed25519Raw {
                bytes: key.verifying_key().to_bytes().to_vec(),
            },
        )
        .unwrap();
    }

    #[test]
    fn signature_does_not_survive_binding_version_mutation() {
        let key = SigningKey::from_bytes(&[29; 32]);
        let mut record = sign_account_status_record(unsigned(), authority_method(), &key).unwrap();
        record.binding_version += 1;
        assert!(
            verify_account_status_record(
                &record,
                &PublicKeyMaterial::Ed25519Raw {
                    bytes: key.verifying_key().to_bytes().to_vec(),
                },
            )
            .is_err()
        );
    }

    #[test]
    fn receipt_signature_and_record_binding_are_both_required() {
        let authority_key = SigningKey::from_bytes(&[33; 32]);
        let receiver_key = SigningKey::from_bytes(&[35; 32]);
        let record =
            sign_account_status_record(unsigned(), authority_method(), &authority_key).unwrap();
        let receipt = sign_account_status_receipt(
            UnsignedAccountStatusReceipt {
                receipt_id: ReceiptId::new("ak:receipt:01904100-0000-7000-8000-000000000035")
                    .unwrap(),
                account_status_record_id: record.account_status_record_id.clone(),
                record_digest: record.payload_digest().unwrap(),
                account_authority_id: record.account_authority_id.clone(),
                account_id: record.account_id.clone(),
                status_seq: record.status_seq,
                receiver_id: DidCoreId::new("ak:did_core:web:receiver.example").unwrap(),
                accepted_at: "2026-08-16T00:00:01.000Z".parse().unwrap(),
                verification_method: DidUrl::new("did:web:receiver.example#notary-key").unwrap(),
            },
            &receiver_key,
        )
        .unwrap();
        verify_account_status_receipt(
            &receipt,
            &PublicKeyMaterial::Ed25519Raw {
                bytes: receiver_key.verifying_key().to_bytes().to_vec(),
            },
        )
        .unwrap();
        receipt.validate_for_record(&record).unwrap();

        let mut other_record = record;
        other_record.status_seq += 1;
        assert!(receipt.validate_for_record(&other_record).is_err());
    }

    #[test]
    fn record_rejects_unknown_authority_ref_field() {
        let key = SigningKey::from_bytes(&[31; 32]);
        let record = sign_account_status_record(unsigned(), authority_method(), &key).unwrap();
        let mut encoded = serde_json::to_value(record).unwrap();
        encoded.as_object_mut().unwrap().insert(
            "authority_ref".to_owned(),
            serde_json::json!("did:web:authority.example#invalid-delegation"),
        );

        assert!(serde_json::from_value::<AccountStatusRecord>(encoded).is_err());
    }
}
