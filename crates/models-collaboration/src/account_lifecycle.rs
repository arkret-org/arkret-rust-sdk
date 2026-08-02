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
    AccountRegistrationPolicyEvidence, IdentityCreationRegistration,
};
use arkret_models_identity::actor_profile::ActorProfile;
use arkret_wire::patch::Patch;
use arkret_wire::{
    AppletId, AppletRevokeMode, ConsentScope, DeviceId, Did, DidUrl, GrantId, Hash, ReasonCode,
    Result, ScopeRef, ServiceOperationId, canonical,
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
    Pending,
    Revoked,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ConsentCellView {
    pub ok: bool,
    pub cell_id: String,
    pub holder_did: Did,
    pub peer_did: Did,
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
pub struct ConsentUpdateRequestBody {
    pub peer_did: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consent_scope: Option<ConsentScope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ConsentRequestRequestBody {
    pub holder_did: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_did: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consent_scope: Option<ConsentScope>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AccountLifecycleProof {
    pub proof_kind: String,
    pub challenge: String,
    pub request_canonical_digest: Hash,
    pub audience: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_method: Option<DidUrl>,
    pub signature: String,
}

pub const ACCOUNT_LIFECYCLE_PROOF_SCHEMA: &str = "ak.schema.account_lifecycle_proof.v1";
pub const SESSION_REVOKE_LIFECYCLE_PROOF_KIND: &str =
    "ak.account.lifecycle_proof.session_revoke.v1";
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionGrantAppletSelector {
    pub applet_id: String,
    pub effective_scope: ScopeRef,
    pub registration_epoch: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_grant_refs: Vec<String>,
}

impl AccountLifecycleProof {
    pub fn session_revoke_request_digest(
        actor_id: &Did,
        service_id: &Did,
        session_device_id: &DeviceId,
        target_grant_id: Option<&GrantId>,
        target_device_id: Option<&DeviceId>,
        all_sessions: bool,
        applet_selector: Option<&SessionGrantAppletSelector>,
    ) -> Result<Hash> {
        let request = json!({
            "schema": "ak.schema.session_revoke.request.v1",
            "operation": ServiceOperationId::GATE_ACCOUNT_COMMAND_REVOKE_SESSION,
            "actor_id": actor_id,
            "service_id": service_id,
            "session_device_id": session_device_id,
            "target_grant_id": target_grant_id,
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

pub const ACCOUNT_STATUS_AUTHORITY_EVIDENCE_CONTEXT: &str =
    "ak.account_status.authority_evidence.v1";
pub const ACCOUNT_STATUS_RECEIPT_CONTEXT: &str = "ak.account_status.ingress_receipt.v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AccountStatusAuthorityEvidence {
    pub account_authority_id: Did,
    pub issuer_service_id: Did,
    pub principal_control_realm_id: RealmId,
    pub account_id: NonEmptyString,
    pub principal_id: Did,
    pub binding_version: u64,
    pub authority_ref: DidUrl,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub proof: PayloadProof,
}

impl AccountStatusAuthorityEvidence {
    pub fn payload_digest(&self) -> Result<Hash> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .expect("AccountStatusAuthorityEvidence serializes as an object")
            .remove("proof");
        Hash::new(canonical::canonical_sha256(&value)?).map_err(Into::into)
    }

    pub fn validate_shape(&self) -> Result<()> {
        if self.binding_version == 0 {
            return Err(arkret_wire::Error::Protocol(
                "account status authority binding_version must be at least 1".to_owned(),
            ));
        }
        if self.account_id.as_str().chars().count() > 255 {
            return Err(arkret_wire::Error::Protocol(
                "account status authority account_id exceeds 255 characters".to_owned(),
            ));
        }
        if self.expires_at <= self.issued_at {
            return Err(arkret_wire::Error::Protocol(
                "account status authority evidence expires_at must follow issued_at".to_owned(),
            ));
        }
        self.proof.validate_production()?;
        if self.proof.payload_digest != self.payload_digest()? {
            return Err(arkret_wire::Error::Protocol(
                "account status authority evidence proof digest mismatch".to_owned(),
            ));
        }
        if !self
            .proof
            .verification_method
            .as_str()
            .starts_with(&format!("{}#", self.account_authority_id))
        {
            return Err(arkret_wire::Error::Protocol(
                "account status authority evidence proof controller mismatch".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AccountStatusReceipt {
    pub receipt_id: ReceiptId,
    pub event_id: EventId,
    pub event_digest: Hash,
    pub account_id: NonEmptyString,
    pub principal_id: Did,
    pub principal_control_realm_id: RealmId,
    pub receiver_service_id: Did,
    pub account_status_frontier_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    pub proof: PayloadProof,
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
        if self.account_id.as_str().chars().count() > 255 {
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
        if !self
            .proof
            .verification_method
            .as_str()
            .starts_with(&format!("{}#", self.receiver_service_id))
        {
            return Err(arkret_wire::Error::Protocol(
                "account status receipt proof controller mismatch".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AccountStatusInitialPublication {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub event: Event,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AccountStatusReceiptedPublication {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub event: Event,
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
    pub fn event(&self) -> &Event {
        match self {
            Self::Receipted(publication) => &publication.event,
            Self::Initial(publication) => &publication.event,
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
    pub authority_evidence: AccountStatusAuthorityEvidence,
    pub publication: AccountStatusPublication,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Vec<serde_json::Value>)))]
    pub cba_proof_bundles: Vec<CbaProofBundle>,
}

impl AccountStatusPublicationRequestBody {
    pub fn validate_shape(&self) -> Result<()> {
        self.authority_evidence.validate_shape()?;
        let event = self.publication.event();
        if event.kind.as_str() != "ak.account.status" {
            return Err(arkret_wire::Error::Protocol(
                "account status publication must carry ak.account.status".to_owned(),
            ));
        }
        if event.actor_id != self.authority_evidence.issuer_service_id
            || event.realm_id != self.authority_evidence.principal_control_realm_id
            || event.scope_ref.circle_id().is_some()
            || event.scope_ref.realm_id() != &self.authority_evidence.principal_control_realm_id
        {
            return Err(arkret_wire::Error::Protocol(
                "account status publication Event authority or PCR mismatch".to_owned(),
            ));
        }
        let payload_account_id = event
            .payload
            .get("account_id")
            .and_then(|value| value.as_str());
        let payload_principal_id = event
            .payload
            .get("principal_id")
            .and_then(|value| value.as_str());
        if payload_account_id != Some(self.authority_evidence.account_id.as_str())
            || payload_principal_id != Some(self.authority_evidence.principal_id.as_str())
        {
            return Err(arkret_wire::Error::Protocol(
                "account status publication payload binding mismatch".to_owned(),
            ));
        }
        event.validate_proof_bindings()?;
        let event_digest = Hash::new(event.event_digest()?)?;
        for receipt in self.publication.receipts() {
            receipt.validate_shape()?;
            if receipt.event_id != event.event_id
                || receipt.event_digest != event_digest
                || receipt.account_id != self.authority_evidence.account_id
                || receipt.principal_id != self.authority_evidence.principal_id
                || receipt.principal_control_realm_id
                    != self.authority_evidence.principal_control_realm_id
            {
                return Err(arkret_wire::Error::Protocol(
                    "account status receipt binding mismatch".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AccountStatusPublicationStatus {
    PendingSeal,
    Accepted,
    Duplicate,
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
    pub event_id: EventId,
    pub account_id: NonEmptyString,
    pub principal_id: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_status_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_status_frontier_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub barrier_cursor: Option<Cursor>,
    pub propagation_state: AccountStatusPropagationState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_destination_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountView {
    pub principal_id: Did,
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
    pub profile: Option<ActorProfile>,
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
    pub principal_id: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<AccountLifecycleProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub identity_creation: Option<IdentityCreationRegistration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub policy_evidence: Option<AccountRegistrationPolicyEvidence>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountRegisterOutcome {
    pub principal_id: Did,
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
    pub profile: Option<ActorProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub registration_audit: Option<AccountRegistrationAudit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub binding_receipt: Option<AccountBindingReceipt>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountUpdateProfileRequestBody {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub patch: Patch,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRevokeRequestBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_grant_id: Option<GrantId>,
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
    pub service_id: Option<Did>,
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
    pub revoked_grant_ids: Vec<GrantId>,
}

/// `ak.self.applet.command.revoke` request body. Binds the account-lifecycle
/// proof (`AccountLifecycleProof`) alongside the applet revoke mode
/// (`AppletRevokeMode`, `arkret-wire`), so it lives in the collaboration domain
/// which reaches both. the `arkret` umbrella re-exports it for path stability.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletRevokeRequestBody {
    pub effective_scope: ScopeRef,
    pub reason_code: ReasonCode,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub revoke_mode: AppletRevokeMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<AccountLifecycleProof>,
}
