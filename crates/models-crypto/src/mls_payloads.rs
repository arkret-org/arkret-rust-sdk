//! MLS governance and Commit Event payloads for the authority-commit protocol.

use arkret_wire::{
    BlobRef, CircleId, EventId, Hash, RealmId, Result, ScopeRef, SidecarId, WireError,
};
use serde::{Deserialize, Serialize};

use crate::mls_envelopes::MlsCommitEnvelope;

/// Authority-selected MLS group state coordinates carried in every transition.
///
/// Superseded frontier, reducer, archive, and sidecar-proof carriers are
/// deliberately absent. The accepted
/// `RealmCommit` is the ordering and governance authority.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsGovernanceBindingPayload {
    effective_scope: ScopeRef,
    #[serde(default)]
    base_group_state_ref: Option<EventId>,
    previous_epoch: u64,
    next_epoch: u64,
    key_access_revision: u64,
}

impl MlsGovernanceBindingPayload {
    pub fn realm(
        realm_id: RealmId,
        base_group_state_ref: Option<EventId>,
        previous_epoch: u64,
        next_epoch: u64,
        key_access_revision: u64,
    ) -> Result<Self> {
        Self::new(
            ScopeRef::Realm { realm_id },
            base_group_state_ref,
            previous_epoch,
            next_epoch,
            key_access_revision,
        )
    }

    pub fn circle(
        realm_id: RealmId,
        circle_id: CircleId,
        base_group_state_ref: Option<EventId>,
        previous_epoch: u64,
        next_epoch: u64,
        key_access_revision: u64,
    ) -> Result<Self> {
        Self::new(
            ScopeRef::Circle {
                realm_id,
                circle_id,
            },
            base_group_state_ref,
            previous_epoch,
            next_epoch,
            key_access_revision,
        )
    }

    pub fn sidecar(
        realm_id: RealmId,
        sidecar_id: SidecarId,
        base_group_state_ref: Option<EventId>,
        previous_epoch: u64,
        next_epoch: u64,
        key_access_revision: u64,
    ) -> Result<Self> {
        Self::new(
            ScopeRef::Sidecar {
                realm_id,
                sidecar_id,
            },
            base_group_state_ref,
            previous_epoch,
            next_epoch,
            key_access_revision,
        )
    }

    pub fn new(
        effective_scope: ScopeRef,
        base_group_state_ref: Option<EventId>,
        previous_epoch: u64,
        next_epoch: u64,
        key_access_revision: u64,
    ) -> Result<Self> {
        let value = Self {
            effective_scope,
            base_group_state_ref,
            previous_epoch,
            next_epoch,
            key_access_revision,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<()> {
        if self.next_epoch == 0 {
            if self.previous_epoch != 0 || self.base_group_state_ref.is_some() {
                return protocol("MLS genesis binding must be epoch zero without a base state");
            }
        } else if self.base_group_state_ref.is_none()
            || self.next_epoch != self.previous_epoch.saturating_add(1)
        {
            return protocol("MLS transition binding requires its immediate base group state");
        }
        Ok(())
    }

    /// Validation for consumers whose MLS history surface is intentionally
    /// restricted to Realm and Circle groups.
    pub fn validate_realm_or_circle_scope(&self) -> Result<()> {
        self.validate()?;
        if !matches!(
            self.effective_scope,
            ScopeRef::Realm { .. } | ScopeRef::Circle { .. }
        ) {
            return protocol("MLS history scope must be Realm or Circle");
        }
        Ok(())
    }

    pub fn effective_scope(&self) -> &ScopeRef {
        &self.effective_scope
    }
    pub fn base_group_state_ref(&self) -> Option<&EventId> {
        self.base_group_state_ref.as_ref()
    }
    pub const fn previous_epoch(&self) -> u64 {
        self.previous_epoch
    }
    pub const fn next_epoch(&self) -> u64 {
        self.next_epoch
    }
    pub const fn key_access_revision(&self) -> u64 {
        self.key_access_revision
    }

    pub fn mls_group_id(&self) -> Result<String> {
        self.effective_scope.canonical_mls_group_id()
    }
}

/// Compact `ak.mls.commit` Event payload.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MlsCommitPayload {
    base_group_state_ref: EventId,
    previous_epoch: u64,
    next_epoch: u64,
    covers_key_access_revision: u64,
    commit_bytes_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    commit_message_ref: Option<BlobRef>,
    #[serde(skip)]
    commit_digest: Hash,
    governance_binding: MlsGovernanceBindingPayload,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MlsCommitPayloadWire {
    base_group_state_ref: EventId,
    previous_epoch: u64,
    next_epoch: u64,
    covers_key_access_revision: u64,
    commit_bytes_b64: String,
    #[serde(default)]
    commit_message_ref: Option<BlobRef>,
    governance_binding: MlsGovernanceBindingPayload,
}

impl<'de> Deserialize<'de> for MlsCommitPayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = MlsCommitPayloadWire::deserialize(deserializer)?;
        let commit_bytes = arkret_wire::base64url::base64url_decode(&wire.commit_bytes_b64)
            .map_err(serde::de::Error::custom)?;
        let commit_digest = Hash::new(arkret_wire::canonical::sha256_digest(&commit_bytes))
            .map_err(serde::de::Error::custom)?;
        let payload = Self {
            base_group_state_ref: wire.base_group_state_ref,
            previous_epoch: wire.previous_epoch,
            next_epoch: wire.next_epoch,
            covers_key_access_revision: wire.covers_key_access_revision,
            commit_bytes_b64: wire.commit_bytes_b64,
            commit_message_ref: wire.commit_message_ref,
            commit_digest,
            governance_binding: wire.governance_binding,
        };
        payload.validate().map_err(serde::de::Error::custom)?;
        Ok(payload)
    }
}

impl MlsCommitPayload {
    pub fn new(
        base_group_state_ref: EventId,
        covers_key_access_revision: u64,
        commit: &MlsCommitEnvelope,
        governance_binding: MlsGovernanceBindingPayload,
    ) -> Result<Self> {
        governance_binding.validate()?;
        if governance_binding.base_group_state_ref() != Some(&base_group_state_ref)
            || commit.group_id != governance_binding.mls_group_id()?
            || commit.epoch != governance_binding.next_epoch()
        {
            return protocol("MLS Commit envelope differs from its governance binding");
        }
        let payload = Self {
            base_group_state_ref,
            previous_epoch: governance_binding.previous_epoch(),
            next_epoch: governance_binding.next_epoch(),
            covers_key_access_revision,
            commit_bytes_b64: commit.commit.clone(),
            commit_message_ref: None,
            commit_digest: commit.commit_digest.clone(),
            governance_binding,
        };
        payload.validate()?;
        Ok(payload)
    }

    pub fn validate(&self) -> Result<()> {
        self.governance_binding.validate()?;
        if self.previous_epoch != self.governance_binding.previous_epoch()
            || self.next_epoch != self.governance_binding.next_epoch()
            || self.governance_binding.base_group_state_ref() != Some(&self.base_group_state_ref)
            || self.covers_key_access_revision < self.governance_binding.key_access_revision()
        {
            return protocol("MLS Commit coordinates differ from governance_binding");
        }
        let bytes = arkret_wire::base64url::base64url_decode(&self.commit_bytes_b64)
            .map_err(|error| WireError::Protocol(error.to_string()))?;
        if arkret_wire::canonical::sha256_digest(&bytes) != self.commit_digest.as_str() {
            return protocol("MLS Commit digest does not match commit bytes");
        }
        if let Some(reference) = &self.commit_message_ref {
            let expected = reference
                .as_str()
                .strip_prefix("ak:blob:")
                .ok_or_else(|| WireError::Protocol("invalid Commit blob ref".to_owned()))?;
            arkret_wire::canonical::verify_digest(&bytes, expected).map_err(|_| {
                WireError::Protocol("Commit blob ref does not address bytes".to_owned())
            })?;
        }
        Ok(())
    }

    pub fn event_kind(&self) -> &'static str {
        arkret_wire::event_kind_str::MLS_COMMIT
    }
    pub fn base_group_state_ref(&self) -> &EventId {
        &self.base_group_state_ref
    }
    pub const fn base_epoch(&self) -> u64 {
        self.previous_epoch
    }
    pub const fn next_epoch(&self) -> u64 {
        self.next_epoch
    }
    pub const fn covers_key_access_revision(&self) -> u64 {
        self.covers_key_access_revision
    }
    pub fn commit_bytes_b64(&self) -> &str {
        &self.commit_bytes_b64
    }
    pub fn commit_message_ref(&self) -> Option<&BlobRef> {
        self.commit_message_ref.as_ref()
    }
    pub fn commit_digest(&self) -> &Hash {
        &self.commit_digest
    }
    pub fn governance_binding(&self) -> &MlsGovernanceBindingPayload {
        &self.governance_binding
    }
    pub fn mls_group_id(&self) -> Result<String> {
        self.governance_binding.mls_group_id()
    }

    pub fn commit_envelope(&self) -> Result<MlsCommitEnvelope> {
        Ok(MlsCommitEnvelope {
            group_id: self.mls_group_id()?,
            epoch: self.next_epoch,
            commit: self.commit_bytes_b64.clone(),
            commit_digest: self.commit_digest.clone(),
            ratchet_tree: None,
        })
    }
}

fn protocol<T>(message: &str) -> Result<T> {
    Err(WireError::Protocol(message.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(byte: u8) -> EventId {
        EventId::from_event_digest(
            &Hash::new(arkret_wire::canonical::sha256_digest([byte])).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn history_scope_validator_rejects_sidecar_without_rejecting_sidecar_mls() {
        let binding = MlsGovernanceBindingPayload::sidecar(
            RealmId::new("ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-").unwrap(),
            SidecarId::new("ak:sidecar:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml").unwrap(),
            Some(event(1)),
            1,
            2,
            0,
        )
        .unwrap();
        binding.validate().unwrap();
        assert!(binding.validate_realm_or_circle_scope().is_err());
    }
}
