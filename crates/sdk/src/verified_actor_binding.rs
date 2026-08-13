use arkret_models_identity::{
    AuthenticatedServiceResolution, OrganizationRegistrationReceipt,
    OrganizationRegistrationStatus, validate_organization_registration_authorization_at,
};
use arkret_policy::{AgentMlsSignerClaim, AgentMlsSignerView, verify_ordinary_agent_mls_binding};
use arkret_signatures::VerifiedPrincipalDevice;
use arkret_signatures::agent_evidence::VerifiedAgentSigningKey;
use arkret_wire::{ActorKind, DidCoreId, EventId, Hash, PrincipalAuthorityKey};
use chrono::{DateTime, Utc};

use crate::{Error, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrganizationAuthorityRef {
    organization_id: DidCoreId,
    governance_service_id: DidCoreId,
    evidence_digest: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentAuthorityRef {
    agent_id: DidCoreId,
    authority_service_id: DidCoreId,
    authorization_ref: EventId,
    snapshot_digest: Hash,
    admission_evidence_digest: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceAuthorityRef {
    service_id: DidCoreId,
    resolution_record_digest: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsLeafBindingRef {
    actor_id: DidCoreId,
    group_id: String,
    epoch: u64,
    group_state_ref: String,
    leaf_index: u32,
    authorization_ref: EventId,
}

/// Closed authority proof selected for one actor authorization decision.
///
/// Each branch is purpose-scoped and contains only data produced by its
/// corresponding verifier. The human branch pins the public account authority pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActorAuthority {
    Human(PrincipalAuthorityKey),
    Organization(OrganizationAuthorityRef),
    ManagedAgent(AgentAuthorityRef),
    Service(ServiceAuthorityRef),
    EphemeralMls(MlsLeafBindingRef),
}

/// Actor identity paired with the exact verified principal authority pair
/// accepted for one authorization decision.
///
/// No constructor accepts only a [`DidCoreId`] or caller-declared
/// [`ActorKind`]. Every public constructor consumes an opaque verifier output
/// or runs the corresponding service/MLS verifier itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedActorBinding {
    actor_id: DidCoreId,
    actor_kind: ActorKind,
    authority: ActorAuthority,
}

impl VerifiedActorBinding {
    pub fn from_verified_principal_device(evidence: &VerifiedPrincipalDevice) -> Self {
        Self {
            actor_id: evidence.principal_id().clone(),
            actor_kind: ActorKind::User,
            authority: ActorAuthority::Human(evidence.authority().clone()),
        }
    }

    pub fn verify_organization(
        receipt: &OrganizationRegistrationReceipt,
        current_generation: u64,
        current_status: OrganizationRegistrationStatus,
        now: DateTime<Utc>,
        verify_receipt_proof: &dyn Fn(&OrganizationRegistrationReceipt) -> Result<()>,
    ) -> Result<Self> {
        validate_organization_registration_authorization_at(
            receipt,
            current_generation,
            current_status,
            now,
        )?;
        verify_receipt_proof(receipt)?;
        let evidence_digest = Hash::new(arkret_canonical::canonical_sha256(receipt)?)?;
        Ok(Self {
            actor_id: receipt.organization_id.clone(),
            actor_kind: ActorKind::Org,
            authority: ActorAuthority::Organization(OrganizationAuthorityRef {
                organization_id: receipt.organization_id.clone(),
                governance_service_id: receipt.issuer_service_id.clone(),
                evidence_digest,
            }),
        })
    }

    pub fn from_verified_agent(signing_key: &VerifiedAgentSigningKey) -> Self {
        Self {
            actor_id: signing_key.signer().clone(),
            actor_kind: ActorKind::Agent,
            authority: ActorAuthority::ManagedAgent(AgentAuthorityRef {
                agent_id: signing_key.signer().clone(),
                authority_service_id: signing_key.authority_service_id().clone(),
                authorization_ref: signing_key.authorization_ref().clone(),
                snapshot_digest: signing_key.snapshot_digest().clone(),
                admission_evidence_digest: signing_key.admission_evidence_digest().clone(),
            }),
        }
    }

    pub fn verify_service(
        resolution: &AuthenticatedServiceResolution,
        expected_service_id: &DidCoreId,
        now: DateTime<Utc>,
    ) -> Result<Self> {
        arkret_signatures::service_resolution::verify_authenticated_service_resolution(
            resolution,
            expected_service_id,
            now,
        )?;
        let resolution_record_digest = Hash::new(arkret_canonical::canonical_sha256(
            &resolution.service_resolution_record,
        )?)?;
        Ok(Self {
            actor_id: expected_service_id.clone(),
            actor_kind: ActorKind::Service,
            authority: ActorAuthority::Service(ServiceAuthorityRef {
                service_id: expected_service_id.clone(),
                resolution_record_digest,
            }),
        })
    }

    pub fn verify_ephemeral_mls(
        view: &AgentMlsSignerView,
        claim: &AgentMlsSignerClaim<'_>,
    ) -> Result<Self> {
        let leaf_index = verify_ordinary_agent_mls_binding(view, claim)
            .map_err(|error| Error::Protocol(error.to_string()))?;
        Ok(Self {
            actor_id: claim.signer_id.clone(),
            actor_kind: ActorKind::Agent,
            authority: ActorAuthority::EphemeralMls(MlsLeafBindingRef {
                actor_id: claim.signer_id.clone(),
                group_id: claim.group_id.to_owned(),
                epoch: claim.epoch,
                group_state_ref: claim.group_state_ref.to_owned(),
                leaf_index,
                authorization_ref: claim.agent_key_authorize_event_id.clone(),
            }),
        })
    }

    pub fn actor_id(&self) -> &DidCoreId {
        &self.actor_id
    }

    pub const fn actor_kind(&self) -> &ActorKind {
        &self.actor_kind
    }

    pub const fn authority(&self) -> &ActorAuthority {
        &self.authority
    }

    pub fn has_same_authority(&self, other: &Self) -> bool {
        self.actor_id == other.actor_id
            && self.actor_kind == other.actor_kind
            && self.authority == other.authority
    }
}

impl OrganizationAuthorityRef {
    pub fn organization_id(&self) -> &DidCoreId {
        &self.organization_id
    }

    pub fn governance_service_id(&self) -> &DidCoreId {
        &self.governance_service_id
    }

    pub fn evidence_digest(&self) -> &Hash {
        &self.evidence_digest
    }
}

impl AgentAuthorityRef {
    pub fn agent_id(&self) -> &DidCoreId {
        &self.agent_id
    }

    pub fn authority_service_id(&self) -> &DidCoreId {
        &self.authority_service_id
    }

    pub fn authorization_ref(&self) -> &EventId {
        &self.authorization_ref
    }

    pub fn snapshot_digest(&self) -> &Hash {
        &self.snapshot_digest
    }

    pub fn admission_evidence_digest(&self) -> &Hash {
        &self.admission_evidence_digest
    }
}

impl ServiceAuthorityRef {
    pub fn service_id(&self) -> &DidCoreId {
        &self.service_id
    }

    pub fn resolution_record_digest(&self) -> &Hash {
        &self.resolution_record_digest
    }
}

impl MlsLeafBindingRef {
    pub fn actor_id(&self) -> &DidCoreId {
        &self.actor_id
    }

    pub fn group_id(&self) -> &str {
        &self.group_id
    }

    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn group_state_ref(&self) -> &str {
        &self.group_state_ref
    }

    pub const fn leaf_index(&self) -> u32 {
        self.leaf_index
    }

    pub fn authorization_ref(&self) -> &EventId {
        &self.authorization_ref
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    fn did(value: &str) -> DidCoreId {
        DidCoreId::new(format!("ak:did_core:web:{value}.example")).unwrap()
    }

    fn human_binding(server: &str) -> VerifiedActorBinding {
        let principal_id = did("alice");
        VerifiedActorBinding {
            actor_id: principal_id.clone(),
            actor_kind: ActorKind::User,
            authority: ActorAuthority::Human(PrincipalAuthorityKey::new(principal_id, did(server))),
        }
    }

    #[test]
    fn same_core_cannot_substitute_a_different_pcr_lineage() {
        let pcr_a = human_binding("server-a");
        let pcr_b = human_binding("server-b");
        assert_eq!(pcr_a.actor_id(), pcr_b.actor_id());
        assert!(!pcr_a.has_same_authority(&pcr_b));
    }
}
