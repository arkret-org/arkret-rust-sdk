//! Finite, unsigned owner-transfer intent shared by key lookup and Event DTOs.

use arkret_wire::{
    AccountId, ActorId, DetachedObjectSignature, DetachedSignatureContext, DeviceId, Did, Hash,
    RealmId, ScopeRef, WireError,
};
use serde::{Deserialize, Serialize};

include!("generated/realm_owner_transfer_contracts.rs");

impl RealmOwnerTransferAcceptanceIntent {
    /// Byte-local invariants only. Account classification and current native
    /// root eligibility are established by their authoritative current source.
    pub fn validate(&self) -> arkret_wire::Result<()> {
        let payload = &self.payload_without_successor_acceptance;
        self.actor_id.validate()?;
        payload.patch.controller_actor_id.validate()?;
        if !matches!(&self.scope_ref, ScopeRef::Realm {realm_id} if realm_id==&payload.realm_id)
            || self.actor_id.as_account_id().is_none()
            || payload.patch.controller_actor_id.as_account_id().is_none()
            || !payload
                .expected_state_digest
                .as_str()
                .starts_with("sha256:")
        {
            return Err(WireError::Protocol(
                "owner transfer requires exact Realm scope and native Account identities".into(),
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> arkret_wire::Result<Hash> {
        self.validate()?;
        Ok(Hash::new(arkret_canonical::canonical_sha256(self)?)?)
    }

    pub fn successor_account(&self) -> arkret_wire::Result<&AccountId> {
        self.payload_without_successor_acceptance
            .patch
            .controller_actor_id
            .as_account_id()
            .ok_or_else(|| WireError::Protocol("owner transfer successor is not an Account".into()))
    }

    pub fn successor_device(
        &self,
        acceptance: &DetachedObjectSignature,
    ) -> arkret_wire::Result<DeviceId> {
        let (did, fragment) = acceptance
            .verification_method
            .as_str()
            .split_once('#')
            .ok_or_else(|| WireError::Protocol("successor method has no Device fragment".into()))?;
        if arkret_wire::project_did_to_core_id(&Did::new(did.to_owned())?)?
            != self.successor_account()?.principal_id
        {
            return Err(WireError::Protocol(
                "successor acceptance method addresses another Account".into(),
            ));
        }
        Ok(DeviceId::new(fragment)?)
    }

    pub fn validate_acceptance(
        &self,
        acceptance: &DetachedObjectSignature,
    ) -> arkret_wire::Result<()> {
        if acceptance.context != DetachedSignatureContext::RealmOwnerTransferAcceptance
            || acceptance.signed_digest != self.digest()?
        {
            return Err(WireError::Protocol(
                "successor acceptance does not bind the finite owner-transfer intent".into(),
            ));
        }
        self.successor_device(acceptance)?;
        Ok(())
    }
}

impl RealmOwnerTransferAcceptance {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        self.intent.validate_acceptance(&self.acceptance)
    }
}

#[cfg(test)]
mod tests;
