//! Current account registration, projection, and profile-write DTOs.

use arkret_models_identity::{
    AccountBindingReceipt, AccountDeviceSummary, AccountMaterializedProfile,
    AccountRegistrationAudit, AccountRegistrationControlProof, AccountRegistrationPolicyEvidence,
    HandleClaim, IdentityCreationRegistration, PublishedIdentityRegistration,
};
use arkret_wire::{
    Did, DidCoreId, EventAdmissionSubmission, EventKind, Hash, RealmCommit, Result, WireError,
    project_did_to_core_id,
};
use serde::{Deserialize, Serialize};

use crate::objects::account_status::AccountStatus;
use crate::session_grants::SessionGrantResponseBody;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountView {
    pub principal_id: DidCoreId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_handle_claim: Option<HandleClaim>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_handle_claim_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub handle_claim_digests: Vec<Hash>,
    pub state: AccountStatus,

    pub devices: Vec<AccountDeviceSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<AccountMaterializedProfile>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_server_admin: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountRegisterRequestBody {
    pub principal_id: DidCoreId,
    pub did: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published_identity: Option<PublishedIdentityRegistration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<AccountRegistrationControlProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_creation: Option<IdentityCreationRegistration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_evidence: Option<AccountRegistrationPolicyEvidence>,
}

impl AccountRegisterRequestBody {
    pub fn validate(&self) -> Result<()> {
        match (
            &self.identity_creation,
            &self.published_identity,
            &self.proof,
        ) {
            (Some(creation), None, None) => {
                creation.validate()?;
                if creation.did != self.did {
                    return Err(WireError::Protocol(
                        "account registration identity creation DID differs".into(),
                    ));
                }
            }
            (None, Some(published), Some(proof)) => {
                published.validate_against(proof)?;
                if published.did != self.did {
                    return Err(WireError::Protocol(
                        "account registration published DID differs".into(),
                    ));
                }
            }
            _ => {
                return Err(WireError::Protocol(
                    "account register requires identity_creation or proof with published_identity"
                        .into(),
                ));
            }
        }
        if project_did_to_core_id(&self.did)? != self.principal_id {
            return Err(WireError::Protocol(
                "account register DID does not match principal_id".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountRegisterResponseBody {
    pub principal_id: DidCoreId,
    pub state: AccountStatus,

    pub devices: Vec<AccountDeviceSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_handle_claim: Option<HandleClaim>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_handle_claim_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub handle_claim_digests: Vec<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<AccountMaterializedProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_audit: Option<AccountRegistrationAudit>,
    pub binding_receipt: AccountBindingReceipt,
    pub pcr_genesis_commits: [RealmCommit; 2],
    pub issued_session: SessionGrantResponseBody,
}

impl AccountRegisterResponseBody {
    pub fn validate_against_request(&self, request: &AccountRegisterRequestBody) -> Result<()> {
        request.validate()?;
        if self.principal_id != request.principal_id
            || self.binding_receipt.principal_id != self.principal_id
            || self.binding_receipt.did != request.did
        {
            return Err(WireError::Protocol(
                "account register outcome does not match request".into(),
            ));
        }
        self.binding_receipt.validate_shape()?;
        let [create, authorize] = &self.pcr_genesis_commits;
        create.validate_shape()?;
        authorize.validate_successor_of(create)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountUpdateProfileRequestBody {
    pub profile_event: EventAdmissionSubmission,
}

impl AccountUpdateProfileRequestBody {
    /// `account-operations.schema.json#/$defs/account_profile_event_submission`:
    /// one holder-signed profile Event with direct proof, no delegation or
    /// Applet provenance, a create carrying only the self-service display
    /// members for the actor's own principal, and an update patch limited to
    /// display name, avatar and `profile_fields.<key>`.
    pub fn validate(&self) -> Result<()> {
        let event = &self.profile_event.event;
        if self.profile_event.approval_signatures.is_some()
            || event.executed_by.is_some()
            || event.authorization_ref.is_some()
            || event.applet_id.is_some()
            || event.external_ref.is_some()
        {
            return Err(WireError::Protocol(
                "account profile Event must be a direct holder-authored Event".into(),
            ));
        }
        let account = event.actor_id.as_account_id().ok_or_else(|| {
            WireError::Protocol("account profile Event actor must be an account".into())
        })?;
        match event.kind {
            EventKind::ProfileCreate => {
                let payload: crate::events_payloads::ActorProfileCreatePayload =
                    crate::events_payloads::event_wire::decode_payload_after_kind_validation(
                        event,
                    )?;
                let object = &payload.object;
                object.validate()?;
                if object.handle.is_some()
                    || object.agent_slug.is_some()
                    || object
                        .accountable_principal_ids
                        .as_ref()
                        .is_some_and(|ids| !ids.is_empty())
                {
                    return Err(WireError::Protocol(
                        "account profile create carries a member outside the self-service surface"
                            .into(),
                    ));
                }
                if object.principal_id.as_ref() != Some(&account.principal_id)
                    || object.actor_id.is_some()
                {
                    return Err(WireError::Protocol(
                        "account profile create principal_id must equal the Event actor".into(),
                    ));
                }
            }
            EventKind::ProfileUpdate => {
                let payload: crate::events_payloads::ActorProfileUpdatePayload =
                    crate::events_payloads::event_wire::decode_payload_after_kind_validation(
                        event,
                    )?;
                payload.validate_for_account_self_service()?;
            }
            _ => {
                return Err(WireError::Protocol(
                    "account profile update requires a profile create/update Event".into(),
                ));
            }
        }
        event.validate_for_submit_structural()
    }
}
