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
use arkret_models_identity::actor_profile::ActorProfile;
use arkret_wire::patch::Patch;
use arkret_wire::{
    AppletId, AppletRevokeMode, CbaProofBundle, ConsentScope, CoreId, Cursor, DeviceId, Did,
    DidUrl, Event, EventBatchReceipt, EventId, EventInitialSubmission, FullId, Hash,
    NonEmptyString, PayloadProof, RealmId, ReasonCode, ReceiptId, Result, ScopeRef,
    ServiceOperationId, SessionGrantId, canonical, project_full_id_to_core_id,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::event_sync::{
    ControlGovernanceHealthStatus, RealmActorFrontierView, RealmSealFrontierView,
};
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
    pub holder_did: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_did: Option<Did>,
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
        target_grant_id: Option<&SessionGrantId>,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AccountStatusAuthoringEventKind {
    #[serde(rename = "ak.account.status")]
    AccountStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AccountStatusAuthoringBasisRequestBody {
    pub authority_evidence: AccountStatusAuthorityEvidence,
    pub event_kind: AccountStatusAuthoringEventKind,
}

impl AccountStatusAuthoringBasisRequestBody {
    pub fn validate(&self) -> Result<()> {
        self.authority_evidence.validate_shape()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AccountStatusAuthoringBasisOutcome {
    pub account_id: NonEmptyString,
    pub principal_id: Did,
    pub principal_control_realm_id: RealmId,
    pub issuer_service_id: Did,
    pub actor_frontier: RealmActorFrontierView,
    pub seal_frontier: RealmSealFrontierView,
}

impl AccountStatusAuthoringBasisOutcome {
    /// Validate the response against the signed authority evidence before the
    /// returned frontiers are used to author an account-status Event.
    pub fn validate_for_request(
        &self,
        request: &AccountStatusAuthoringBasisRequestBody,
    ) -> Result<()> {
        request.validate()?;
        let evidence = &request.authority_evidence;
        if self.account_id != evidence.account_id
            || self.principal_id != evidence.principal_id
            || self.principal_control_realm_id != evidence.principal_control_realm_id
            || self.issuer_service_id != evidence.issuer_service_id
            || self.actor_frontier.realm_id != evidence.principal_control_realm_id
            || self.actor_frontier.actor_id != evidence.issuer_service_id
            || self.seal_frontier.realm_id != evidence.principal_control_realm_id
        {
            return Err(arkret_wire::Error::Protocol(
                "account-status authoring basis does not match authority evidence".to_owned(),
            ));
        }
        self.actor_frontier.validate()?;
        self.seal_frontier.validate_protocol_bounds()?;
        if self.seal_frontier.governance_health.status != ControlGovernanceHealthStatus::Healthy {
            return Err(arkret_wire::Error::Protocol(
                "account-status authoring basis requires a healthy Seal frontier".to_owned(),
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
        if event.actor_id
            != arkret_wire::ActorId::from(project_full_id_to_core_id(
                &self.authority_evidence.issuer_service_id,
            )?)
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
    pub principal_id: CoreId,
    pub full_id: FullId,
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
        if project_full_id_to_core_id(&self.full_id)? != self.principal_id {
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
    pub principal_id: CoreId,
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
                ("grant principal_id", grant.principal_id == request.full_id),
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
                        .all(|scope| initial.requested_scope.contains(scope)),
                ),
                (
                    "receipt principal_id",
                    receipt_scope.principal_id == request.full_id,
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
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub patch: Patch,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRevokeRequestBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_grant_id: Option<SessionGrantId>,
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
    pub revoked_grant_ids: Vec<SessionGrantId>,
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
