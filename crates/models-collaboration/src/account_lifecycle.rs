//! Account consent-cell, lifecycle-proof, register/view, and session-revoke
//! wire models relocated from the `arkret` umbrella.
//!
//! These shapes bind cross-domain types: consent cells (`ConsentScope`,
//! `arkret-wire`), session-grant selectors (`ScopeRef`, `arkret-wire`),
//! profile patches (`ProfilePatch` = `arkret_wire::patch::Patch`), account
//! status rollups (`AccountStatus`), handle claims (`HandleClaim`,
//! `arkret-models-identity`), and the identity-face registration evidence /
//! audit shapes. They live here in the collaboration/governance domain, which
//! reaches all of them within its layering edge. the `arkret` umbrella re-exports them
//! for path stability.

use arkret_models_identity::account::{
    AccountBindingReceipt, AccountDeviceSummary, AccountRegistrationAudit,
    AccountRegistrationControlProof, AccountRegistrationPolicyEvidence,
    IdentityCreationRegistration,
};
use arkret_models_identity::actor_profile::{AccountMaterializedProfile, ActorProfile};
use arkret_wire::{
    ActorProfileId, AppletId, AppletRevokeMode, ConsentScope, Cursor, DeviceId, DidCoreId,
    DidFullId, DidUrl, EventBatchReceipt, EventInitialSubmission, EventKind, Hash, NonEmptyString,
    PayloadProof, ProofContextId, RealmId, ReasonCode, ReceiptId, Result, SchemaId, ScopeRef,
    ServiceOperationId, SessionGrantId, UnsignedPayloadProof, canonical,
    project_full_id_to_core_id,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::governance::handle_claim::HandleClaim;
use crate::objects::account_status::AccountStatus;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ConsentState {
    Active,
    NoConsent,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ConsentCellView {
    pub ok: bool,
    pub cell_id: String,
    pub holder_principal_id: DidCoreId,
    pub peer_principal_id: DidCoreId,
    pub consent_scope: ConsentScope,
    pub state: ConsentState,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub requested_at: Option<DateTime<Utc>>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub updated_at: DateTime<Utc>,
    #[serde(default)]
    pub active_grant_dots: Vec<String>,
    #[serde(default)]
    pub grant_dots: Vec<String>,
    #[serde(default)]
    pub revoked_dots: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ConsentCellList {
    pub ok: bool,
    #[serde(default)]
    pub cells: Vec<ConsentCellView>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ConsentGrantRequestBody {
    /// Initial publication of the caller-signed `ak.consent.grant` Control Move.
    ///
    /// `consent_id`, `peer`, `consent_scope`, `not_before` and `expires_at` all
    /// live in `grant_event.event.payload`; the holder comes from the path.
    /// `consent_id` is producer-allocated, so the caller mints it: it is the cell
    /// subject, and the or_set add dot is
    /// `ak:event:<enclosing event_id>:<write_index>` (spec
    /// `zh/identity/consent-model.md` section 3.2). A service that wrote this
    /// element itself would be putting consent into replicated cell state that no
    /// Event in the log explains.
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub grant_event: EventInitialSubmission,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ConsentRevokeRequestBody {
    /// Initial publication of the caller-signed `ak.consent.revoke` Control Move.
    ///
    /// Its `payload.observed_dots` names the exact dots being removed, read back
    /// from [`ConsentCellView::active_grant_dots`]: an observe-remove OR-Set
    /// revoker has to enumerate them or two concurrent revokes race, one removing
    /// the old dot and the other the new one while the UI reports success. A
    /// `consent_scope=any` cascade is no exception.
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub revoke_event: EventInitialSubmission,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ConsentRequestRequestBody {
    pub holder_principal_id: DidCoreId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_principal_id: Option<DidCoreId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consent_scope: Option<ConsentScope>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ConsentRequestOutcome {
    pub ok: bool,
    pub accepted_for_processing: bool,
}

#[cfg(test)]
mod consent_request_tests {
    use super::{ConsentRequestOutcome, ConsentState};

    #[test]
    fn opaque_request_outcome_is_closed_and_minimal() {
        let value = serde_json::json!({
            "ok": true,
            "accepted_for_processing": true
        });
        let outcome: ConsentRequestOutcome =
            serde_json::from_value(value.clone()).expect("registered opaque outcome");
        assert_eq!(serde_json::to_value(outcome).unwrap(), value);

        let mut extra = value;
        extra["cell_id"] = serde_json::json!(
            "ak:cell:ak.component.consent.grant.v1:ak:consent:01964137-0000-7000-8000-000000000041"
        );
        assert!(serde_json::from_value::<ConsentRequestOutcome>(extra).is_err());
        assert_eq!(
            serde_json::to_value(ConsentState::NoConsent).unwrap(),
            serde_json::json!("no_consent")
        );
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AccountLifecycleProof {
    pub proof_kind: String,
    pub challenge: String,
    pub request_canonical_digest: Hash,
    pub audience: DidCoreId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_method: Option<DidUrl>,
    pub signature: String,
}

pub const ACCOUNT_LIFECYCLE_PROOF_SCHEMA: &str = SchemaId::ACCOUNT_OPERATIONS_V1;
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionGrantAppletSelector {
    pub applet_id: String,
    pub effective_scope: ScopeRef,
    pub registration_epoch: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_grant_refs: Vec<String>,
}

impl AccountLifecycleProof {
    pub fn session_revoke_request_digest(
        actor_id: &DidCoreId,
        service_id: &DidCoreId,
        session_device_id: &DeviceId,
        target_session_grant_id: Option<&SessionGrantId>,
        target_device_id: Option<&DeviceId>,
        all_sessions: bool,
        applet_selector: Option<&SessionGrantAppletSelector>,
    ) -> Result<Hash> {
        let request = json!({
            "schema": SchemaId::ACCOUNT_OPERATIONS_V1,
            "operation": ServiceOperationId::GATE_ACCOUNT_COMMAND_REVOKE_SESSION,
            "actor_id": actor_id,
            "service_id": service_id,
            "session_device_id": session_device_id,
            "target_session_grant_id": target_session_grant_id,
            "target_device_id": target_device_id,
            "all_sessions": all_sessions,
            "applet_selector": applet_selector,
        });
        Ok(Hash::new(canonical::canonical_sha256(&request)?)?)
    }

    pub fn canonical_signing_bytes(&self) -> Result<Vec<u8>> {
        let signing_input = json!({
            "schema": ACCOUNT_LIFECYCLE_PROOF_SCHEMA,
            "proof_kind": &self.proof_kind,
            "challenge": &self.challenge,
            "request_canonical_digest": &self.request_canonical_digest,
            "audience": &self.audience,
            "issued_at": &self.issued_at,
            "expires_at": &self.expires_at,
            "verification_method": &self.verification_method,
        });
        Ok(canonical::canonical_json_bytes(&signing_input)?)
    }
}

pub const ACCOUNT_STATUS_RECORD_CONTEXT: &str = ProofContextId::ACCOUNT_STATUS_RECORD_PROOF_V1;
pub const ACCOUNT_STATUS_RECEIPT_CONTEXT: &str =
    ProofContextId::ACCOUNT_STATUS_REPLICATION_RECEIPT_PROOF_V1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AccountStatusPrincipalAuthority {
    pub principal_id: DidCoreId,
    pub principal_server_id: DidCoreId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedAccountStatusRecord {
    pub schema: String,
    pub account_authority_id: DidCoreId,
    pub account_id: NonEmptyString,
    pub principal_authority: AccountStatusPrincipalAuthority,
    pub principal_control_realm_id: RealmId,
    pub binding_version: u64,
    pub status_seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_account_status_record_id: Option<arkret_wire::AccountStatusRecordId>,
    pub status: AccountStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<NonEmptyString>,
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
    pub verification_method: DidUrl,
}

impl UnsignedAccountStatusRecord {
    pub fn validate(&self) -> Result<()> {
        if self.schema != SchemaId::ACCOUNT_STATUS_RECORD_V1 {
            return Err(arkret_wire::Error::Protocol(
                "account status record schema mismatch".to_owned(),
            ));
        }
        if self.account_id.as_str().chars().count() > 255
            || self.binding_version == 0
            || self.status_seq == 0
        {
            return Err(arkret_wire::Error::Protocol(
                "account status record bounds are invalid".to_owned(),
            ));
        }
        if self.status_seq == 1 {
            if self.previous_account_status_record_id.is_some()
                || self.status != AccountStatus::Active
            {
                return Err(arkret_wire::Error::Protocol(
                    "account status genesis must be active without a predecessor".to_owned(),
                ));
            }
        } else if self.previous_account_status_record_id.is_none() {
            return Err(arkret_wire::Error::Protocol(
                "account status successor requires previous_account_status_record_id".to_owned(),
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
                return Err(arkret_wire::Error::Protocol(
                    "account status reason_code is invalid".to_owned(),
                ));
            }
        }
        if self
            .reason
            .as_ref()
            .is_some_and(|reason| reason.as_str().chars().count() > 1024)
        {
            return Err(arkret_wire::Error::Protocol(
                "account status reason exceeds 1024 characters".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        canonical::canonical_json_bytes(self).map_err(Into::into)
    }

    pub fn record_id(&self) -> Result<arkret_wire::AccountStatusRecordId> {
        Ok(arkret_wire::AccountStatusRecordId::from_record_digest(
            canonical::sha256_bytes(&self.canonical_bytes()?),
        ))
    }

    pub fn payload_digest(&self) -> Result<Hash> {
        Hash::new(canonical::sha256_digest(&self.canonical_bytes()?)).map_err(Into::into)
    }

    pub fn proof_metadata(&self) -> Result<UnsignedPayloadProof> {
        Ok(UnsignedPayloadProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            verification_method: self.verification_method.clone(),
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
            || proof.verification_method != self.verification_method
            || proof.created_at != self.issued_at
            || proof.domain.is_some()
            || proof.audience.is_some()
            || proof.proof_purpose.is_some()
        {
            return Err(arkret_wire::Error::Protocol(
                "account status record proof metadata does not match its unsigned core".to_owned(),
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
        let account_status_record_id = self.record_id()?;
        let record = AccountStatusRecord {
            schema: self.schema,
            account_status_record_id,
            account_authority_id: self.account_authority_id,
            account_id: self.account_id,
            principal_authority: self.principal_authority,
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
            verification_method: self.verification_method,
            proof,
        };
        record.validate_shape()?;
        Ok(record)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AccountStatusRecord {
    pub schema: String,
    pub account_status_record_id: arkret_wire::AccountStatusRecordId,
    pub account_authority_id: DidCoreId,
    pub account_id: NonEmptyString,
    pub principal_authority: AccountStatusPrincipalAuthority,
    pub principal_control_realm_id: RealmId,
    pub binding_version: u64,
    pub status_seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_account_status_record_id: Option<arkret_wire::AccountStatusRecordId>,
    pub status: AccountStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<NonEmptyString>,
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
    pub verification_method: DidUrl,
    pub proof: PayloadProof,
}

impl AccountStatusRecord {
    pub fn unsigned(&self) -> UnsignedAccountStatusRecord {
        UnsignedAccountStatusRecord {
            schema: self.schema.clone(),
            account_authority_id: self.account_authority_id.clone(),
            account_id: self.account_id.clone(),
            principal_authority: self.principal_authority.clone(),
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
            verification_method: self.verification_method.clone(),
        }
    }

    pub fn payload_digest(&self) -> Result<Hash> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .expect("AccountStatusRecord serializes as an object")
            .remove("account_status_record_id");
        value
            .as_object_mut()
            .expect("AccountStatusRecord serializes as an object")
            .remove("proof");
        Hash::new(canonical::canonical_sha256(&value)?).map_err(Into::into)
    }

    pub fn validate_shape(&self) -> Result<()> {
        self.unsigned().validate()?;
        if self.account_status_record_id != self.unsigned().record_id()? {
            return Err(arkret_wire::Error::Protocol(
                "account status account_status_record_id mismatch".to_owned(),
            ));
        }
        if self.verification_method != self.proof.verification_method {
            return Err(arkret_wire::Error::Protocol(
                "account status verification_method mismatch".to_owned(),
            ));
        }
        self.proof.validate_production()?;
        self.unsigned()
            .canonical_proof_binding_bytes(&self.proof.unsigned())?;
        if self.proof.payload_digest != self.payload_digest()? {
            return Err(arkret_wire::Error::Protocol(
                "account status record proof digest mismatch".to_owned(),
            ));
        }
        let proof_controller = self
            .proof
            .verification_method
            .as_str()
            .rsplit_once('#')
            .map(|(controller, _)| controller)
            .and_then(|controller| DidFullId::new(controller.to_owned()).ok())
            .and_then(|controller| project_full_id_to_core_id(&controller).ok());
        if proof_controller.as_ref() != Some(&self.account_authority_id) {
            return Err(arkret_wire::Error::Protocol(
                "account status record proof controller mismatch".to_owned(),
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
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AccountStatusResolveRequestBody {
    pub account_authority_id: DidCoreId,
    pub account_id: NonEmptyString,
    pub from_status_seq: u64,
    pub limit: u16,
}

impl AccountStatusResolveRequestBody {
    pub fn validate(&self) -> Result<()> {
        if self.account_id.as_str().chars().count() > 255
            || self.from_status_seq == 0
            || !(1..=128).contains(&self.limit)
        {
            return Err(arkret_wire::Error::Protocol(
                "account status resolve bounds are invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AccountStatusResolveOutcome {
    pub account_authority_id: DidCoreId,
    pub account_id: NonEmptyString,
    pub records: Vec<AccountStatusRecord>,
    pub has_more: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_status_seq: Option<u64>,
}

impl AccountStatusResolveOutcome {
    pub fn validate_for_request(&self, request: &AccountStatusResolveRequestBody) -> Result<()> {
        request.validate()?;
        if self.account_authority_id != request.account_authority_id
            || self.account_id != request.account_id
            || self.records.len() > usize::from(request.limit)
        {
            return Err(arkret_wire::Error::Protocol(
                "account status resolve binding mismatch".to_owned(),
            ));
        }
        for (offset, record) in self.records.iter().enumerate() {
            record.validate_shape()?;
            if record.account_authority_id != self.account_authority_id
                || record.account_id != self.account_id
                || record.status_seq != request.from_status_seq + offset as u64
            {
                return Err(arkret_wire::Error::Protocol(
                    "account status resolve range is not contiguous".to_owned(),
                ));
            }
        }
        let expected_next = self.records.last().map(|record| record.status_seq + 1);
        if self.has_more != self.next_status_seq.is_some()
            || self
                .next_status_seq
                .is_some_and(|next| Some(next) != expected_next)
        {
            return Err(arkret_wire::Error::Protocol(
                "account status resolve continuation is invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AccountStatusReceipt {
    pub receipt_id: ReceiptId,
    pub account_status_record_id: arkret_wire::AccountStatusRecordId,
    pub record_digest: Hash,
    pub account_authority_id: DidCoreId,
    pub account_id: NonEmptyString,
    pub status_seq: u64,
    pub receiver_service_id: DidCoreId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    pub proof: PayloadProof,
}

#[derive(Clone, Debug)]
pub struct UnsignedAccountStatusReceipt {
    pub receipt_id: ReceiptId,
    pub account_status_record_id: arkret_wire::AccountStatusRecordId,
    pub record_digest: Hash,
    pub account_authority_id: DidCoreId,
    pub account_id: NonEmptyString,
    pub status_seq: u64,
    pub receiver_service_id: DidCoreId,
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
            "receiver_service_id": self.receiver_service_id,
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
            return Err(arkret_wire::Error::Protocol(
                "account status receipt proof metadata does not match its unsigned core".to_owned(),
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
            receiver_service_id: self.receiver_service_id,
            accepted_at: self.accepted_at,
            proof,
        };
        receipt.validate_shape()?;
        Ok(receipt)
    }
}

impl AccountStatusReceipt {
    pub fn payload_digest(&self) -> Result<Hash> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .expect("AccountStatusReceipt serializes as an object")
            .remove("proof");
        Hash::new(canonical::canonical_sha256(&value)?).map_err(Into::into)
    }

    pub fn validate_shape(&self) -> Result<()> {
        if self.account_id.as_str().chars().count() > 255 || self.status_seq == 0 {
            return Err(arkret_wire::Error::Protocol(
                "account status receipt account_id exceeds 255 characters".to_owned(),
            ));
        }
        self.proof.validate_production()?;
        if self.proof.payload_digest != self.payload_digest()? {
            return Err(arkret_wire::Error::Protocol(
                "account status receipt proof digest mismatch".to_owned(),
            ));
        }
        let proof_controller = self
            .proof
            .verification_method
            .as_str()
            .rsplit_once('#')
            .map(|(controller, _)| controller)
            .and_then(|controller| DidFullId::new(controller.to_owned()).ok())
            .and_then(|controller| project_full_id_to_core_id(&controller).ok());
        if proof_controller.as_ref() != Some(&self.receiver_service_id) {
            return Err(arkret_wire::Error::Protocol(
                "account status receipt proof controller mismatch".to_owned(),
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
            receiver_service_id: self.receiver_service_id.clone(),
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
            return Err(arkret_wire::Error::Protocol(
                "account status receipt binding mismatch".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AccountStatusInitialPublication {
    pub record: AccountStatusRecord,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AccountStatusReceiptedPublication {
    pub record: AccountStatusRecord,
    pub account_status_receipts: Vec<AccountStatusReceipt>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AccountStatusPublication {
    Receipted(AccountStatusReceiptedPublication),
    Initial(AccountStatusInitialPublication),
}

impl AccountStatusPublication {
    pub fn record(&self) -> &AccountStatusRecord {
        match self {
            Self::Receipted(publication) => &publication.record,
            Self::Initial(publication) => &publication.record,
        }
    }

    pub fn receipts(&self) -> &[AccountStatusReceipt] {
        match self {
            Self::Receipted(publication) => &publication.account_status_receipts,
            Self::Initial(_) => &[],
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AccountStatusPublicationRequestBody {
    pub publication: AccountStatusPublication,
}

impl AccountStatusPublicationRequestBody {
    pub fn validate_shape(&self) -> Result<()> {
        let record = self.publication.record();
        record.validate_shape()?;
        for receipt in self.publication.receipts() {
            receipt.validate_for_record(record)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AccountStatusPublicationStatus {
    Accepted,
    Duplicate,
    DependencyMissing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AccountStatusPropagationState {
    NotRequired,
    Scheduled,
    Complete,
    Incomplete,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AccountStatusPublicationOutcome {
    pub status: AccountStatusPublicationStatus,
    pub account_status_record_id: arkret_wire::AccountStatusRecordId,
    pub status_seq: u64,
    pub account_id: NonEmptyString,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_account_status_record_id: Option<arkret_wire::AccountStatusRecordId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_status_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_status_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub barrier_cursor: Option<Cursor>,
    pub propagation_state: AccountStatusPropagationState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_destination_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<AccountStatusReceipt>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountView {
    pub principal_id: DidCoreId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub primary_handle_claim: Option<HandleClaim>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_handle_claim_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub handle_claim_digests: Vec<Hash>,
    pub state: AccountStatus,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub devices: Vec<AccountDeviceSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub profile: Option<AccountMaterializedProfile>,
    /// True when the authenticated principal is a deployment server
    /// administrator (the server's configured admin principal set). Operator-only
    /// product surfaces (e.g. organization creation) gate their UI on this.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_server_admin: bool,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountRegisterRequestBody {
    pub principal_id: DidCoreId,
    pub full_id: DidFullId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<AccountRegistrationControlProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub identity_creation: Option<IdentityCreationRegistration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub policy_evidence: Option<AccountRegistrationPolicyEvidence>,
}

impl AccountRegisterRequestBody {
    pub fn validate(&self) -> Result<()> {
        if self.proof.is_some() == self.identity_creation.is_some() {
            return Err(arkret_wire::Error::Protocol(
                "account register requires exactly one proof or identity_creation branch"
                    .to_owned(),
            ));
        }
        if project_full_id_to_core_id(&self.full_id)? != *self.principal_id.as_core_id() {
            return Err(arkret_wire::Error::Protocol(
                "account register full_id does not project to principal_id".to_owned(),
            ));
        }
        if let Some(proof) = &self.proof {
            proof.validate_shape()?;
            if proof.principal_id != self.principal_id || proof.full_id != self.full_id {
                return Err(arkret_wire::Error::Protocol(
                    "account register published-DID proof binding mismatch".to_owned(),
                ));
            }
        }
        if let Some(identity_creation) = &self.identity_creation {
            identity_creation.validate()?;
            if self.device_id.is_some() {
                return Err(arkret_wire::Error::Protocol(
                    "top-level device_id is not used by identity creation".to_owned(),
                ));
            }
            if identity_creation.control_proof.principal_id != self.principal_id {
                return Err(arkret_wire::Error::Protocol(
                    "account register identity creation does not match principal".to_owned(),
                ));
            }
            if identity_creation.full_id != self.full_id {
                return Err(arkret_wire::Error::Protocol(
                    "account register identity creation full_id mismatch".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountRegisterOutcome {
    pub principal_id: DidCoreId,
    pub state: AccountStatus,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub devices: Vec<AccountDeviceSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub primary_handle_claim: Option<HandleClaim>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_handle_claim_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub handle_claim_digests: Vec<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub profile: Option<AccountMaterializedProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub registration_audit: Option<AccountRegistrationAudit>,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub binding_receipt: AccountBindingReceipt,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub pcr_genesis_receipt: Option<EventBatchReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub session_grant_outcome: Option<crate::session_grant_bodies::SessionGrantOutcome>,
}

impl AccountRegisterOutcome {
    pub fn validate_against_request(&self, request: &AccountRegisterRequestBody) -> Result<()> {
        request.validate()?;
        if self.principal_id != request.principal_id {
            return Err(arkret_wire::Error::Protocol(
                "account register outcome principal_id mismatch".to_owned(),
            ));
        }
        if let Some(identity_creation) = &request.identity_creation {
            let binding_receipt = &self.binding_receipt;
            binding_receipt.validate_shape()?;
            let receipt = self.pcr_genesis_receipt.as_ref().ok_or_else(|| {
                arkret_wire::Error::Protocol(
                    "identity creation outcome omits pcr_genesis_receipt".to_owned(),
                )
            })?;
            receipt.validate()?;
            let receipt_scope = receipt.pcr_genesis_scope()?;
            let grant = self.session_grant_outcome.as_ref().ok_or_else(|| {
                arkret_wire::Error::Protocol(
                    "identity creation outcome omits session_grant_outcome".to_owned(),
                )
            })?;
            let initial = &identity_creation.initial_session;
            let constraints = [
                (
                    "grant principal_id",
                    grant.principal_id == request.principal_id,
                ),
                (
                    "grant device_id",
                    grant.device_id.as_ref() == Some(&initial.device_id),
                ),
                (
                    "grant session_public_key",
                    grant.session_public_key == initial.session_public_key,
                ),
                ("grant audience", grant.audience == initial.audience),
                (
                    "grant scope ceiling",
                    grant
                        .granted_scope
                        .iter()
                        .all(|scope| initial.allows_scope(scope)),
                ),
                (
                    "receipt principal_id",
                    receipt_scope.principal_id == request.principal_id,
                ),
                (
                    "receipt realm_id",
                    receipt_scope.realm_id == identity_creation.control_proof.pcr_realm_id,
                ),
                (
                    "receipt accepted_device_id",
                    receipt_scope.accepted_device_id == initial.device_id,
                ),
                (
                    "binding receipt principal_id",
                    binding_receipt.principal_id == request.principal_id,
                ),
                (
                    "binding receipt operation_digest",
                    binding_receipt.operation_digest
                        == identity_creation.control_proof.operation_digest,
                ),
                (
                    "binding receipt lease",
                    binding_receipt.identity_creation_lease_id
                        == Some(identity_creation.identity_creation_lease_id.clone())
                        && binding_receipt.lease_fence == Some(identity_creation.lease_fence),
                ),
                (
                    "receipt did log pins",
                    receipt_scope.did_version_id == identity_creation.control_proof.did_version_id
                        && receipt_scope.log_head_digest
                            == identity_creation.control_proof.log_head_digest
                        && receipt_scope.control_key_digest
                            == identity_creation.control_proof.control_key_digest,
                ),
            ];
            if let Some((constraint, _)) = constraints.iter().find(|(_, valid)| !valid) {
                return Err(arkret_wire::Error::Protocol(format!(
                    "initial session grant outcome does not match its registration request: \
                         {constraint}"
                )));
            }
        }
        self.binding_receipt.validate_shape()?;
        if self.binding_receipt.principal_id != self.principal_id
            || self.binding_receipt.full_id != request.full_id
        {
            return Err(arkret_wire::Error::Protocol(
                "account register outcome binding receipt mismatch".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountUpdateProfileRequestBody {
    /// Complete caller-authored and caller-signed `ak.profile.create` or
    /// `ak.profile.update` Event. The service submits these exact bytes through
    /// ordinary Event admission and never authors the profile Event itself.
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub profile_event: EventInitialSubmission,
}

/// Accepted projection facts used only to validate authoring context.
///
/// This is not part of [`AccountUpdateProfileRequestBody`]. Producers must
/// obtain it from an accepted profile projection or equivalent verified view;
/// an optional `ActorProfile.id` must never be guessed into this basis.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountProfileAcceptedBasis {
    pub profile_id: ActorProfileId,
    pub principal_id: DidCoreId,
    pub principal_control_realm_id: RealmId,
}

impl AccountUpdateProfileRequestBody {
    /// Validate constraints carried entirely inside the signed request.
    pub fn validate(&self) -> Result<()> {
        self.profile_event.validate_structural()?;
        let event = &self.profile_event.event;
        if event.executed_by.is_some()
            || event.authorization_ref.is_some()
            || event.applet_id.is_some()
            || event.external_ref.is_some()
        {
            return Err(arkret_wire::Error::Protocol(
                "account profile self-service requires a direct holder-authored Event".to_owned(),
            ));
        }
        if !event.preconditions.is_empty() {
            return Err(arkret_wire::Error::Protocol(
                "account profile self-service does not accept extra Event preconditions".to_owned(),
            ));
        }
        match &event.kind {
            EventKind::ProfileCreate => {
                let payload: crate::events_payloads::ActorProfileCreatePayload =
                    crate::events_payloads::event_wire::decode_payload_after_kind_validation(
                        event,
                    )?;
                validate_account_profile_create_payload(&payload)
            }
            EventKind::ProfileUpdate => {
                let payload: crate::events_payloads::ActorProfileUpdatePayload =
                    crate::events_payloads::event_wire::decode_payload_after_kind_validation(
                        event,
                    )?;
                payload.validate_for_account_self_service()
            }
            _ => Err(arkret_wire::Error::Protocol(
                "account profile self-service requires ak.profile.create or ak.profile.update"
                    .to_owned(),
            )),
        }
    }

    /// Bind a structurally valid request to the authenticated principal, its
    /// exact Principal Control Realm and the current accepted profile basis.
    pub fn validate_authoring_context(
        &self,
        session_principal_id: &DidCoreId,
        principal_control_realm_id: &RealmId,
        accepted_basis: Option<&AccountProfileAcceptedBasis>,
    ) -> Result<()> {
        self.validate()?;
        let event = &self.profile_event.event;
        if &event.actor_id != session_principal_id
            || &event.realm_id != principal_control_realm_id
            || event.scope_ref
                != (ScopeRef::Realm {
                    realm_id: principal_control_realm_id.clone(),
                })
        {
            return Err(arkret_wire::Error::Protocol(
                "account profile Event does not match the authenticated principal's exact PCR"
                    .to_owned(),
            ));
        }
        match &event.kind {
            EventKind::ProfileCreate => {
                if accepted_basis.is_some() {
                    return Err(arkret_wire::Error::Protocol(
                        "ak.profile.create is allowed only when no accepted profile exists"
                            .to_owned(),
                    ));
                }
                let payload: crate::events_payloads::ActorProfileCreatePayload =
                    crate::events_payloads::event_wire::decode_payload_after_kind_validation(
                        event,
                    )?;
                if &payload.object.principal_id != session_principal_id
                    || payload
                        .object
                        .realm_id
                        .as_ref()
                        .is_some_and(|realm_id| realm_id != principal_control_realm_id)
                {
                    return Err(arkret_wire::Error::Protocol(
                        "ak.profile.create payload does not match the authenticated principal's exact PCR"
                            .to_owned(),
                    ));
                }
            }
            EventKind::ProfileUpdate => {
                let basis = accepted_basis.ok_or_else(|| {
                    arkret_wire::Error::Protocol(
                        "ak.profile.update requires an accepted create-derived profile basis"
                            .to_owned(),
                    )
                })?;
                if &basis.principal_id != session_principal_id
                    || &basis.principal_control_realm_id != principal_control_realm_id
                {
                    return Err(arkret_wire::Error::Protocol(
                        "accepted profile basis does not match the authenticated principal's exact PCR"
                            .to_owned(),
                    ));
                }
                let payload: crate::events_payloads::ActorProfileUpdatePayload =
                    crate::events_payloads::event_wire::decode_payload_after_kind_validation(
                        event,
                    )?;
                if payload.target_ref != basis.profile_id {
                    return Err(arkret_wire::Error::Protocol(
                        "ak.profile.update target_ref does not match the accepted create-derived profile id"
                            .to_owned(),
                    ));
                }
            }
            _ => unreachable!("validate pins the profile Event kind"),
        }
        Ok(())
    }

    /// Return the profile identity selected by this signed Event. Create IDs
    /// are a byte-for-byte retype of the signed create Event ID.
    pub fn profile_id(&self) -> Result<ActorProfileId> {
        self.validate()?;
        match &self.profile_event.event.kind {
            EventKind::ProfileCreate => Ok(ActorProfileId::from_event_id(
                &self.profile_event.event.event_id,
            )),
            EventKind::ProfileUpdate => {
                let payload: crate::events_payloads::ActorProfileUpdatePayload =
                    crate::events_payloads::event_wire::decode_payload_after_kind_validation(
                        &self.profile_event.event,
                    )?;
                Ok(payload.target_ref)
            }
            _ => unreachable!("validate pins the profile Event kind"),
        }
    }
}

fn validate_account_profile_create_payload(
    payload: &crate::events_payloads::ActorProfileCreatePayload,
) -> Result<()> {
    let object = &payload.object;
    if object.id.is_some()
        || object.schema != ActorProfile::SCHEMA
        || object.handle.is_some()
        || object.agent_slug.is_some()
        || object.status.is_some()
        || !object.accountable_principal_ids.is_empty()
        || object.resolution.is_some()
        || object.updated_by.is_some()
        || object.updated_at.is_some()
    {
        return Err(arkret_wire::Error::Protocol(
            "account self-service ak.profile.create contains non-authorable profile fields"
                .to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod account_update_profile_request_tests {
    use arkret_wire::{
        CellRef, DidUrl, Hlc, Precondition, Predicate, PredicateOp, Proof, SealBasis, SealId,
        proof_kind,
    };
    use chrono::{DateTime, Utc};
    use serde_json::json;

    use super::{
        AccountProfileAcceptedBasis, AccountUpdateProfileRequestBody, ActorProfileId, DidCoreId,
        EventInitialSubmission, Hash, RealmId,
    };

    const ACTOR: &str = "ak:did_core:webvh:z6mkfixture";
    const OTHER_ACTOR: &str = "ak:did_core:webvh:z6mkother";
    const PCR: &str = "ak:realm:AfTcej7ZFNg8uTbkOiUJT0KN1F_c9l1fmtil65CUwncm";
    const OTHER_PCR: &str = "ak:realm:ARmJMvTcKFyiF-V_8oL4mIoHfnlqERCrcgNBONtY4HQD";

    fn actor() -> DidCoreId {
        DidCoreId::new(ACTOR).unwrap()
    }

    fn pcr() -> RealmId {
        RealmId::new(PCR).unwrap()
    }

    fn signed_control_event(kind: &str, payload: serde_json::Value) -> arkret_wire::Event {
        let created_at: DateTime<Utc> = "2026-08-11T00:00:00.000Z".parse().unwrap();
        let mut event = arkret_wire::test_support::raw_event_at(
            kind,
            arkret_wire::ScopeRef::Realm { realm_id: pcr() },
            actor(),
            DidCoreId::new("ak:did_core:webvh:z6mkfixtureps").unwrap(),
            7,
            Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            payload,
            created_at,
        )
        .unwrap();
        event.seal_basis = Some(SealBasis {
            leaves: vec![SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64))).unwrap()],
        });
        event.refresh_content_bound_identity().unwrap();
        let event_digest = Hash::new(event.event_digest().unwrap()).unwrap();
        event.proofs = vec![
            Proof {
                kind: proof_kind::DETACHED_JWS.to_owned(),
                verification_method: DidUrl::new("did:webvh:z6mkfixture:fixture.example#device-1")
                    .unwrap(),
                event_digest,
                created_at,
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: "a..b".to_owned(),
            }
            .into(),
        ];
        event
    }

    fn create_request() -> AccountUpdateProfileRequestBody {
        AccountUpdateProfileRequestBody {
            profile_event: EventInitialSubmission::online(signed_control_event(
                "ak.profile.create",
                json!({
                    "object": {
                        "schema": "ak.schema.actor_profile.v1",
                        "realm_id": PCR,
                        "principal_id": ACTOR,
                        "actor_kind": "user",
                        "display_name": "Fixture User",
                        "profile_fields": {"bio": "hello"},
                        "created_at": "2026-08-11T00:00:00.000Z"
                    }
                }),
            )),
        }
    }

    fn update_request(
        profile_id: &ActorProfileId,
        patch: serde_json::Value,
    ) -> AccountUpdateProfileRequestBody {
        AccountUpdateProfileRequestBody {
            profile_event: EventInitialSubmission::online(signed_control_event(
                "ak.profile.update",
                json!({
                    "target_ref": profile_id,
                    "patch": patch
                }),
            )),
        }
    }

    fn accepted_basis(profile_id: ActorProfileId) -> AccountProfileAcceptedBasis {
        AccountProfileAcceptedBasis {
            profile_id,
            principal_id: actor(),
            principal_control_realm_id: pcr(),
        }
    }

    #[test]
    fn valid_create_has_only_the_retyped_signed_event_id() {
        let request = create_request();
        request.validate().unwrap();
        request
            .validate_authoring_context(&actor(), &pcr(), None)
            .unwrap();
        assert_eq!(
            request.profile_id().unwrap(),
            ActorProfileId::from_event_id(&request.profile_event.event.event_id)
        );
    }

    #[test]
    fn valid_update_requires_the_exact_accepted_basis() {
        let profile_id = create_request().profile_id().unwrap();
        let basis = accepted_basis(profile_id.clone());
        let request = update_request(
            &profile_id,
            json!({"display_name": {"$op": "set", "value": "Updated"}}),
        );
        request.validate().unwrap();
        request
            .validate_authoring_context(&actor(), &pcr(), Some(&basis))
            .unwrap();
        assert_eq!(request.profile_id().unwrap(), profile_id);
    }

    #[test]
    fn create_and_update_are_gated_by_accepted_profile_presence() {
        let create = create_request();
        let basis = accepted_basis(create.profile_id().unwrap());
        assert!(
            create
                .validate_authoring_context(&actor(), &pcr(), Some(&basis))
                .is_err()
        );

        let update = update_request(&basis.profile_id, json!({"display_name": "Updated"}));
        assert!(
            update
                .validate_authoring_context(&actor(), &pcr(), None)
                .is_err()
        );
    }

    #[test]
    fn update_rejects_wrong_target_pcr_and_actor() {
        let profile_id = create_request().profile_id().unwrap();
        let wrong_profile_id =
            ActorProfileId::new("ak:actor_profile:AdP2S6y0Ms7yp9-GNvXZ3sVfvTEo8mtnV3G_RfApIOn0")
                .unwrap();
        let basis = accepted_basis(wrong_profile_id);
        let request = update_request(&profile_id, json!({"display_name": "Updated"}));
        assert!(
            request
                .validate_authoring_context(&actor(), &pcr(), Some(&basis))
                .is_err()
        );

        let basis = accepted_basis(profile_id);
        assert!(
            request
                .validate_authoring_context(
                    &actor(),
                    &RealmId::new(OTHER_PCR).unwrap(),
                    Some(&basis),
                )
                .is_err()
        );
        assert!(
            request
                .validate_authoring_context(
                    &DidCoreId::new(OTHER_ACTOR).unwrap(),
                    &pcr(),
                    Some(&basis),
                )
                .is_err()
        );
    }

    #[test]
    fn request_rejects_forbidden_patch_provenance_and_precondition() {
        let profile_id = create_request().profile_id().unwrap();
        let forbidden_patch = update_request(&profile_id, json!({"handle": "fixture.example"}));
        assert!(forbidden_patch.validate().is_err());

        let mut delegated = create_request();
        delegated.profile_event.event.executed_by = Some(actor());
        assert!(delegated.validate().is_err());

        let mut guarded = create_request();
        guarded.profile_event.event.preconditions = vec![Precondition {
            cell: CellRef::new(format!(
                "ak:cell:ak.component.profile.create.v1:{profile_id}"
            ))
            .unwrap(),
            predicate: Predicate {
                op: PredicateOp::HeadEq,
                value: Some(json!(null)),
                values: None,
                predicate_id: None,
            },
        }];
        assert!(guarded.validate().is_err());
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRevokeRequestBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_session_grant_id: Option<SessionGrantId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_device_id: Option<DeviceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub all_sessions: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applet_id: Option<AppletId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_scope: Option<ScopeRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_epoch: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_grant_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<AccountLifecycleProof>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionRevokeOutcome {
    pub revoked_count: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revoked_session_grant_ids: Vec<SessionGrantId>,
}

/// `ak.self.applet.command.revoke` request body. Binds the account-lifecycle
/// proof (`AccountLifecycleProof`) alongside the applet revoke mode
/// (`AppletRevokeMode`, `arkret-wire`), so it lives in the collaboration domain
/// which reaches both. the `arkret` umbrella re-exports it for path stability.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletRevokeRequestBody {
    pub revoke_plan_digest: Hash,
    pub effective_scope: ScopeRef,
    pub reason_code: ReasonCode,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub revoke_mode: AppletRevokeMode,
    pub capability_revoke_events: Vec<EventInitialSubmission>,
    pub membership_state_events: Vec<EventInitialSubmission>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<AccountLifecycleProof>,
}

#[cfg(test)]
mod applet_revoke_request_tests {
    use super::AppletRevokeRequestBody;

    #[test]
    fn signed_revoke_carrier_requires_plan_and_both_event_arrays() {
        let complete = serde_json::json!({
            "revoke_plan_digest": format!("sha256:{}", "a".repeat(64)),
            "effective_scope": {"kind": "realm_genesis"},
            "reason_code": "requested_by_admin",
            "revoke_mode": "revoke_runtime_only",
            "capability_revoke_events": [],
            "membership_state_events": []
        });
        let parsed: AppletRevokeRequestBody =
            serde_json::from_value(complete.clone()).expect("closed revoke carrier");
        assert_eq!(serde_json::to_value(parsed).unwrap(), complete);

        for required in [
            "revoke_plan_digest",
            "capability_revoke_events",
            "membership_state_events",
        ] {
            let mut missing = complete.clone();
            missing.as_object_mut().unwrap().remove(required);
            assert!(
                serde_json::from_value::<AppletRevokeRequestBody>(missing).is_err(),
                "{required} must not become optional"
            );
        }
    }
}
