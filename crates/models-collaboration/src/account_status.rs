//! Signed Account Authority status records and replication receipts.

use arkret_wire::{
    AccountId, AccountStatusRecordId, AuditReasonText, Did, DidCoreId, DidUrl, Hash, PayloadProof,
    RealmId, ReceiptId, Result, SchemaId, UnsignedPayloadProof, WireError, canonical,
    project_did_to_core_id,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::objects::account_status::AccountStatus;

pub const ACCOUNT_STATUS_RECORD_CONTEXT: &str =
    arkret_wire::ProofContextId::ACCOUNT_STATUS_RECORD_PROOF_V1;
pub const ACCOUNT_STATUS_RECEIPT_CONTEXT: &str =
    arkret_wire::ProofContextId::ACCOUNT_STATUS_REPLICATION_RECEIPT_PROOF_V1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedAccountStatusRecord {
    pub schema: String,
    pub account_authority_id: DidCoreId,
    pub account_id: AccountId,
    pub principal_control_realm_id: RealmId,
    pub binding_version: u64,
    pub status_seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_account_status_record_id: Option<AccountStatusRecordId>,
    pub status: AccountStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<AuditReasonText>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub effective_at: DateTime<Utc>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
}

impl UnsignedAccountStatusRecord {
    pub fn validate(&self) -> Result<()> {
        if self.schema != SchemaId::ACCOUNT_STATUS_RECORD_V1 {
            return Err(WireError::Protocol(
                "account status record schema mismatch".into(),
            ));
        }
        self.account_id.validate()?;
        if self.binding_version == 0 || self.status_seq == 0 {
            return Err(WireError::Protocol(
                "account status record bounds are invalid".into(),
            ));
        }
        if self.status_seq == 1 {
            if self.previous_account_status_record_id.is_some()
                || self.status != AccountStatus::Active
            {
                return Err(WireError::Protocol(
                    "account status genesis must be active without a predecessor".into(),
                ));
            }
        } else if self.previous_account_status_record_id.is_none() {
            return Err(WireError::Protocol(
                "account status successor requires previous_account_status_record_id".into(),
            ));
        }
        if let Some(code) = &self.reason_code {
            let valid = code.len() <= 64
                && code
                    .bytes()
                    .next()
                    .is_some_and(|byte| byte.is_ascii_lowercase())
                && code
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
            if !valid {
                return Err(WireError::Protocol(
                    "account status reason_code is invalid".into(),
                ));
            }
        }
        if self
            .reason
            .as_ref()
            .is_some_and(|reason| reason.as_str().chars().count() > 1024)
        {
            return Err(WireError::Protocol(
                "account status reason exceeds 1024 characters".into(),
            ));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        canonical::canonical_json_bytes(self).map_err(Into::into)
    }

    pub fn record_id(&self) -> Result<AccountStatusRecordId> {
        Ok(AccountStatusRecordId::from_record_digest(
            canonical::sha256_bytes(&self.canonical_bytes()?),
        ))
    }

    pub fn payload_digest(&self) -> Result<Hash> {
        Hash::new(canonical::sha256_digest(&self.canonical_bytes()?)).map_err(Into::into)
    }

    pub fn proof_metadata(&self, verification_method: DidUrl) -> Result<UnsignedPayloadProof> {
        Ok(UnsignedPayloadProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            verification_method,
            payload_digest: self.payload_digest()?,
            created_at: self.issued_at,
            domain: None,
            audience: None,
            proof_purpose: None,
        })
    }

    pub fn canonical_proof_binding_bytes(&self, proof: &UnsignedPayloadProof) -> Result<Vec<u8>> {
        proof.validate_production()?;
        if proof.payload_digest != self.payload_digest()?
            || proof.created_at != self.issued_at
            || proof.domain.is_some()
            || proof.audience.is_some()
            || proof.proof_purpose.is_some()
        {
            return Err(WireError::Protocol(
                "account status record proof metadata does not match its unsigned core".into(),
            ));
        }
        canonical::canonical_json_bytes(&json!({
            "context": ACCOUNT_STATUS_RECORD_CONTEXT,
            "payload_digest": proof.payload_digest,
            "verification_method": proof.verification_method,
            "created_at": arkret_canonical::format_timestamp_canonical(proof.created_at),
        }))
        .map_err(Into::into)
    }

    pub fn attach_proof(self, proof: PayloadProof) -> Result<AccountStatusRecord> {
        self.canonical_proof_binding_bytes(&proof.unsigned())?;
        let record = AccountStatusRecord {
            account_status_record_id: self.record_id()?,
            schema: self.schema,
            account_authority_id: self.account_authority_id,
            account_id: self.account_id,
            principal_control_realm_id: self.principal_control_realm_id,
            binding_version: self.binding_version,
            status_seq: self.status_seq,
            previous_account_status_record_id: self.previous_account_status_record_id,
            status: self.status,
            reason_code: self.reason_code,
            reason: self.reason,
            issued_at: self.issued_at,
            effective_at: self.effective_at,
            expires_at: self.expires_at,
            proof,
        };
        record.validate_shape()?;
        Ok(record)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AccountStatusRecord {
    pub schema: String,
    pub account_status_record_id: AccountStatusRecordId,
    pub account_authority_id: DidCoreId,
    pub account_id: AccountId,
    pub principal_control_realm_id: RealmId,
    pub binding_version: u64,
    pub status_seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_account_status_record_id: Option<AccountStatusRecordId>,
    pub status: AccountStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<AuditReasonText>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub effective_at: DateTime<Utc>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    pub proof: PayloadProof,
}

impl AccountStatusRecord {
    pub fn unsigned(&self) -> UnsignedAccountStatusRecord {
        UnsignedAccountStatusRecord {
            schema: self.schema.clone(),
            account_authority_id: self.account_authority_id.clone(),
            account_id: self.account_id.clone(),
            principal_control_realm_id: self.principal_control_realm_id.clone(),
            binding_version: self.binding_version,
            status_seq: self.status_seq,
            previous_account_status_record_id: self.previous_account_status_record_id.clone(),
            status: self.status,
            reason_code: self.reason_code.clone(),
            reason: self.reason.clone(),
            issued_at: self.issued_at,
            effective_at: self.effective_at,
            expires_at: self.expires_at,
        }
    }

    pub fn payload_digest(&self) -> Result<Hash> {
        let value = canonical::unsigned_value(self, &["account_status_record_id", "proof"])?;
        Hash::new(canonical::canonical_sha256(&value)?).map_err(Into::into)
    }

    pub fn validate_shape(&self) -> Result<()> {
        self.unsigned().validate()?;
        if self.account_status_record_id != self.unsigned().record_id()? {
            return Err(WireError::Protocol(
                "account status account_status_record_id mismatch".into(),
            ));
        }
        self.proof.validate_production()?;
        self.unsigned()
            .canonical_proof_binding_bytes(&self.proof.unsigned())?;
        if self.proof.payload_digest != self.payload_digest()? {
            return Err(WireError::Protocol(
                "account status record proof digest mismatch".into(),
            ));
        }
        if proof_controller(&self.proof.verification_method).as_ref()
            != Some(&self.account_authority_id)
        {
            return Err(WireError::Protocol(
                "account status record proof controller mismatch".into(),
            ));
        }
        Ok(())
    }

    pub fn canonical_proof_binding_bytes(&self) -> Result<Vec<u8>> {
        self.unsigned()
            .canonical_proof_binding_bytes(&self.proof.unsigned())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AccountStatusReceipt {
    pub receipt_id: ReceiptId,
    pub account_status_record_id: AccountStatusRecordId,
    pub record_digest: Hash,
    pub account_authority_id: DidCoreId,
    pub account_id: AccountId,
    pub status_seq: u64,
    pub receiver_id: DidCoreId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    pub proof: PayloadProof,
}

#[derive(Clone, Debug)]
pub struct UnsignedAccountStatusReceipt {
    pub receipt_id: ReceiptId,
    pub account_status_record_id: AccountStatusRecordId,
    pub record_digest: Hash,
    pub account_authority_id: DidCoreId,
    pub account_id: AccountId,
    pub status_seq: u64,
    pub receiver_id: DidCoreId,
    pub accepted_at: DateTime<Utc>,
    pub verification_method: DidUrl,
}

impl UnsignedAccountStatusReceipt {
    pub fn payload_digest(&self) -> Result<Hash> {
        Hash::new(canonical::canonical_sha256(&json!({
            "receipt_id": self.receipt_id,
            "account_status_record_id": self.account_status_record_id,
            "record_digest": self.record_digest,
            "account_authority_id": self.account_authority_id,
            "account_id": self.account_id,
            "status_seq": self.status_seq,
            "receiver_id": self.receiver_id,
            "accepted_at": arkret_canonical::format_timestamp_canonical(self.accepted_at),
        }))?)
        .map_err(Into::into)
    }

    pub fn proof_metadata(&self) -> Result<UnsignedPayloadProof> {
        Ok(UnsignedPayloadProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            verification_method: self.verification_method.clone(),
            payload_digest: self.payload_digest()?,
            created_at: self.accepted_at,
            domain: None,
            audience: None,
            proof_purpose: None,
        })
    }

    pub fn canonical_proof_binding_bytes(&self, proof: &UnsignedPayloadProof) -> Result<Vec<u8>> {
        proof.validate_production()?;
        if proof.payload_digest != self.payload_digest()?
            || proof.verification_method != self.verification_method
            || proof.created_at != self.accepted_at
            || proof.domain.is_some()
            || proof.audience.is_some()
            || proof.proof_purpose.is_some()
        {
            return Err(WireError::Protocol(
                "account status receipt proof metadata does not match its unsigned core".into(),
            ));
        }
        canonical::canonical_json_bytes(&json!({
            "context": ACCOUNT_STATUS_RECEIPT_CONTEXT,
            "payload_digest": proof.payload_digest,
            "verification_method": proof.verification_method,
            "created_at": arkret_canonical::format_timestamp_canonical(proof.created_at),
        }))
        .map_err(Into::into)
    }

    pub fn attach_proof(self, proof: PayloadProof) -> Result<AccountStatusReceipt> {
        self.canonical_proof_binding_bytes(&proof.unsigned())?;
        let receipt = AccountStatusReceipt {
            receipt_id: self.receipt_id,
            account_status_record_id: self.account_status_record_id,
            record_digest: self.record_digest,
            account_authority_id: self.account_authority_id,
            account_id: self.account_id,
            status_seq: self.status_seq,
            receiver_id: self.receiver_id,
            accepted_at: self.accepted_at,
            proof,
        };
        receipt.validate_shape()?;
        Ok(receipt)
    }
}

impl AccountStatusReceipt {
    pub fn payload_digest(&self) -> Result<Hash> {
        let value = canonical::unsigned_value(self, &["proof"])?;
        Hash::new(canonical::canonical_sha256(&value)?).map_err(Into::into)
    }

    pub fn validate_shape(&self) -> Result<()> {
        self.account_id.validate()?;
        if self.status_seq == 0 {
            return Err(WireError::Protocol(
                "account status receipt status_seq must be positive".into(),
            ));
        }
        self.proof.validate_production()?;
        if self.proof.payload_digest != self.payload_digest()? {
            return Err(WireError::Protocol(
                "account status receipt proof digest mismatch".into(),
            ));
        }
        if proof_controller(&self.proof.verification_method).as_ref() != Some(&self.receiver_id) {
            return Err(WireError::Protocol(
                "account status receipt proof controller mismatch".into(),
            ));
        }
        Ok(())
    }

    pub fn canonical_proof_binding_bytes(&self) -> Result<Vec<u8>> {
        UnsignedAccountStatusReceipt {
            receipt_id: self.receipt_id.clone(),
            account_status_record_id: self.account_status_record_id.clone(),
            record_digest: self.record_digest.clone(),
            account_authority_id: self.account_authority_id.clone(),
            account_id: self.account_id.clone(),
            status_seq: self.status_seq,
            receiver_id: self.receiver_id.clone(),
            accepted_at: self.accepted_at,
            verification_method: self.proof.verification_method.clone(),
        }
        .canonical_proof_binding_bytes(&self.proof.unsigned())
    }

    pub fn validate_for_record(&self, record: &AccountStatusRecord) -> Result<()> {
        self.validate_shape()?;
        record.validate_shape()?;
        if self.account_status_record_id != record.account_status_record_id
            || self.record_digest != record.payload_digest()?
            || self.account_authority_id != record.account_authority_id
            || self.account_id != record.account_id
            || self.status_seq != record.status_seq
        {
            return Err(WireError::Protocol(
                "account status receipt binding mismatch".into(),
            ));
        }
        Ok(())
    }
}

fn proof_controller(method: &DidUrl) -> Option<DidCoreId> {
    method
        .as_str()
        .rsplit_once('#')
        .map(|(controller, _)| controller)
        .and_then(|controller| Did::new(controller.to_owned()).ok())
        .and_then(|controller| project_did_to_core_id(&controller).ok())
}
