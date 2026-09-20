//! Current account registration, projection, and profile-write DTOs.

use arkret_models_identity::{
    AccountBindingReceipt, AccountDeviceSummary, AccountMaterializedProfile,
    AccountRegistrationAudit, AccountRegistrationControlProof, AccountRegistrationPolicyEvidence,
    HandleClaim, IdentityCreationRegistration,
};
use arkret_wire::{
    Did, DidCoreId, EventCommitSubmission, EventKind, Hash, RealmCommit, Result, WireError,
    project_did_to_core_id,
};
use serde::{Deserialize, Serialize};

use crate::objects::account_status::AccountStatus;
use crate::session_grants::SessionGrantOutcome;

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
    #[serde(default)]
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
    pub device_id: Option<arkret_wire::DeviceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<AccountRegistrationControlProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_creation: Option<IdentityCreationRegistration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_evidence: Option<AccountRegistrationPolicyEvidence>,
}

impl AccountRegisterRequestBody {
    pub fn validate(&self) -> Result<()> {
        if self.proof.is_some() == self.identity_creation.is_some() {
            return Err(WireError::Protocol(
                "account register requires exactly one registration authority branch".into(),
            ));
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
pub struct AccountRegisterOutcome {
    pub principal_id: DidCoreId,
    pub state: AccountStatus,
    #[serde(default)]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pcr_genesis_commits: Option<[RealmCommit; 2]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_grant_outcome: Option<SessionGrantOutcome>,
}

impl AccountRegisterOutcome {
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
        if let Some([create, authorize]) = &self.pcr_genesis_commits {
            create.validate_shape()?;
            authorize.validate_successor_of(create)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountUpdateProfileRequestBody {
    pub profile_event: EventCommitSubmission,
}

impl AccountUpdateProfileRequestBody {
    pub fn validate(&self) -> Result<()> {
        if !matches!(
            self.profile_event.event.kind,
            EventKind::ProfileCreate | EventKind::ProfileUpdate
        ) {
            return Err(WireError::Protocol(
                "account profile update requires a profile create/update Event".into(),
            ));
        }
        self.profile_event.event.validate_for_submit_structural()
    }
}
