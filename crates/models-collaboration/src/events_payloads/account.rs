//! Account-status event payloads.

use arkret_wire::{DidCoreId, DidFullId};

use crate::internal_prelude::*;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/account_status_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountStatusPayload {
    pub account_id: String,
    pub principal_id: DidCoreId,
    pub status: AccountStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub effective_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<NullableTimestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_status_event_id: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_proof: Option<SignatureMaterial>,
}

pub struct AccountStatusServiceBinding<'a> {
    pub actor_id: &'a DidCoreId,
    pub proof_controller: &'a DidFullId,
    pub signature_kid_controller: &'a DidFullId,
    pub authoritative_service_id: &'a DidCoreId,
    pub bound_account_id: &'a str,
    pub bound_principal_id: &'a DidCoreId,
    pub signing_key_valid_at_effective_at: bool,
    pub delegation_covers_account_status: bool,
}

impl AccountStatusPayload {
    pub fn validate_service_binding(
        &self,
        binding: &AccountStatusServiceBinding<'_>,
    ) -> Result<()> {
        if self.account_id.is_empty() || self.account_id.len() > 255 {
            return Err(Error::Protocol(
                "account status account_id must be 1..=255 bytes".to_owned(),
            ));
        }
        if binding.actor_id.as_core_id() != binding.authoritative_service_id.as_core_id()
            || project_full_id_to_core_id(binding.proof_controller)?
                != *binding.authoritative_service_id.as_core_id()
            || project_full_id_to_core_id(binding.signature_kid_controller)?
                != *binding.authoritative_service_id.as_core_id()
        {
            return Err(Error::Protocol(
                "account status issuer service binding mismatch".to_owned(),
            ));
        }
        if self.account_id != binding.bound_account_id
            || &self.principal_id != binding.bound_principal_id
        {
            return Err(Error::Protocol(
                "account status account/principal binding mismatch".to_owned(),
            ));
        }
        if !binding.signing_key_valid_at_effective_at || !binding.delegation_covers_account_status {
            return Err(Error::Protocol(
                "account status signing authority is not valid at effective_at".to_owned(),
            ));
        }
        Ok(())
    }
}
