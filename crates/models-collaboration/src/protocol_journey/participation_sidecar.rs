use std::collections::BTreeSet;

use arkret_wire::{
    Base64UrlString, CircleId, Did, DidUrl, Event, EventId, EventInitialSubmission, Hash, RealmId,
    RelationId, SidecarId, StrandId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{ProtocolOpaqueId, ProtocolOperationId, ProtocolSignature, string_marker};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ParticipationBits {
    pub reply_message: bool,
    pub reaction_add: bool,
    pub reaction_remove: bool,
    pub accept_third_party_mention: bool,
    pub act_on_behalf: bool,
}

impl ParticipationBits {
    pub fn is_subset_of(self, ceiling: Self) -> bool {
        (!self.reply_message || ceiling.reply_message)
            && (!self.reaction_add || ceiling.reaction_add)
            && (!self.reaction_remove || ceiling.reaction_remove)
            && (!self.accept_third_party_mention || ceiling.accept_third_party_mention)
            && (!self.act_on_behalf || ceiling.act_on_behalf)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ParticipationScope {
    Realm {
        realm_id: RealmId,
    },
    Circle {
        realm_id: RealmId,
        circle_id: CircleId,
    },
    Strand {
        realm_id: RealmId,
        strand_id: StrandId,
    },
}

impl ParticipationScope {
    pub fn realm_id(&self) -> &RealmId {
        match self {
            Self::Realm { realm_id }
            | Self::Circle { realm_id, .. }
            | Self::Strand { realm_id, .. } => realm_id,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ParticipationScopeEvidencePrepareRequestBody {
    pub base_batch_digest: Hash,
    pub caller_id: Did,
    pub agent_id: Did,
    pub target_scope: ParticipationScope,
    pub target_service_id: Did,
    pub verifier_id: Did,
    pub audience: ProtocolOpaqueId,
    pub idempotency_key: ProtocolOpaqueId,
}

string_marker!(
    ParticipationChallengeDomain,
    V1,
    "ak.participation.scope-evidence-challenge.v1"
);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ParticipationScopeEvidenceChallenge {
    pub domain: ParticipationChallengeDomain,
    pub challenge_id: ProtocolOpaqueId,
    pub base_batch_digest: Hash,
    pub caller_id: Did,
    pub agent_id: Did,
    pub target_scope: ParticipationScope,
    pub target_service_id: Did,
    pub verifier_id: Did,
    pub audience: ProtocolOpaqueId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub signature: ProtocolSignature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ParticipationScopeEvidence {
    InlineEncrypted {
        challenge: ParticipationScopeEvidenceChallenge,
        suite_id: ProtocolOpaqueId,
        recipient_key_ref: DidUrl,
        enc: Base64UrlString,
        ciphertext: Base64UrlString,
        plaintext_digest: Hash,
    },
    AcceptedTargetReceipt {
        receipt_id: ProtocolOpaqueId,
        disclosure_digest: Hash,
        commitment: Hash,
        agent_id: Did,
        target_scope: ParticipationScope,
        target_service_id: Did,
        verifier_id: Did,
        audience: ProtocolOpaqueId,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        issued_at: DateTime<Utc>,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        expires_at: DateTime<Utc>,
        binding_digest: Hash,
        signature: ProtocolSignature,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ParticipationReplacementBatch {
    pub agent_id: Did,
    pub target_scope: ParticipationScope,
    pub selection: ParticipationBits,
    pub scope_evidence: ParticipationScopeEvidence,
    pub expected_version: u64,
    pub basis: Vec<EventId>,
    pub grant_events: Vec<EventInitialSubmission>,
    pub revoke_events: Vec<EventInitialSubmission>,
    pub idempotency_key: ProtocolOpaqueId,
    pub controller_signature: ProtocolSignature,
}

impl ParticipationReplacementBatch {
    /// Digest of the controller batch before private evidence and the outer
    /// signature are attached (RFC 8785/JCS).
    pub fn base_batch_digest(&self) -> arkret_wire::Result<Hash> {
        #[derive(Serialize)]
        struct BaseBatch<'a> {
            agent_id: &'a Did,
            target_scope: &'a ParticipationScope,
            selection: ParticipationBits,
            expected_version: u64,
            basis: &'a [EventId],
            grant_events: &'a [EventInitialSubmission],
            revoke_events: &'a [EventInitialSubmission],
            idempotency_key: &'a ProtocolOpaqueId,
        }
        let base = BaseBatch {
            agent_id: &self.agent_id,
            target_scope: &self.target_scope,
            selection: self.selection,
            expected_version: self.expected_version,
            basis: &self.basis,
            grant_events: &self.grant_events,
            revoke_events: &self.revoke_events,
            idempotency_key: &self.idempotency_key,
        };
        let bytes = arkret_canonical::canonical_json_bytes(&base)?;
        Hash::new(arkret_canonical::canonical::sha256_digest(bytes))
            .map_err(|error| arkret_wire::Error::Protocol(error.to_string()))
    }

    pub fn validate(&self) -> arkret_wire::Result<()> {
        if self.basis.is_empty()
            || self.basis.iter().collect::<BTreeSet<_>>().len() != self.basis.len()
        {
            return Err(arkret_wire::Error::Protocol(
                "participation replacement basis must be non-empty and unique".to_owned(),
            ));
        }
        match &self.scope_evidence {
            ParticipationScopeEvidence::InlineEncrypted { challenge, .. } => {
                if challenge.base_batch_digest != self.base_batch_digest()?
                    || challenge.agent_id != self.agent_id
                    || challenge.target_scope != self.target_scope
                    || challenge.issued_at >= challenge.expires_at
                {
                    return Err(arkret_wire::Error::Protocol(
                        "inline participation evidence does not bind the replacement batch"
                            .to_owned(),
                    ));
                }
            }
            ParticipationScopeEvidence::AcceptedTargetReceipt {
                agent_id,
                target_scope,
                issued_at,
                expires_at,
                ..
            } if agent_id != &self.agent_id
                || target_scope != &self.target_scope
                || issued_at >= expires_at =>
            {
                return Err(arkret_wire::Error::Protocol(
                    "accepted participation evidence does not bind the replacement batch"
                        .to_owned(),
                ));
            }
            ParticipationScopeEvidence::AcceptedTargetReceipt { .. } => {}
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ParticipationReplaceRelayRequestBody {
    pub original_signed_batch_bytes: Base64UrlString,
    pub target_service_id: Did,
    pub transport_digest: Hash,
    pub idempotency_key: ProtocolOpaqueId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ParticipationReplaceReceipt {
    pub batch_digest: Hash,
    pub scope_evidence_digest: Hash,
    pub deployment_ceiling_digest: Hash,
    pub deployment_ceiling_version: u64,
    pub accepted_version: u64,
    pub target_service_id: Did,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    pub signature: ProtocolSignature,
}

impl ParticipationReplaceReceipt {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        if self.deployment_ceiling_version == 0 || self.accepted_version == 0 {
            return Err(arkret_wire::Error::Protocol(
                "participation receipt versions must be at least one".to_owned(),
            ));
        }
        Ok(())
    }
}

string_marker!(
    DeploymentCeilingDomain,
    V1,
    "ak.participation.deployment-ceiling.v1"
);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DeploymentCeilingCore {
    pub domain: DeploymentCeilingDomain,
    pub slot_id: ProtocolOpaqueId,
    pub target_service_id: Did,
    pub issuer: Did,
    pub issuer_verification_method: DidUrl,
    pub version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predecessor_digest: Option<Hash>,
    pub ceiling: ParticipationBits,
    pub policy_basis: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

impl DeploymentCeilingCore {
    pub fn digest(&self) -> arkret_wire::Result<Hash> {
        if self.version == 0
            || (self.version == 1) == self.predecessor_digest.is_some()
            || self.issued_at >= self.expires_at
        {
            return Err(arkret_wire::Error::Protocol(
                "deployment ceiling predecessor/version mismatch".to_owned(),
            ));
        }
        let bytes = arkret_canonical::canonical_json_bytes(self)?;
        Hash::new(arkret_canonical::canonical::sha256_digest(bytes))
            .map_err(|error| arkret_wire::Error::Protocol(error.to_string()))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DeploymentCeilingSignedHead {
    pub head_digest: Hash,
    pub core: DeploymentCeilingCore,
    pub signature: ProtocolSignature,
}

impl DeploymentCeilingSignedHead {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        if self.head_digest != self.core.digest()?
            || self.signature.verification_method != self.core.issuer_verification_method
        {
            return Err(arkret_wire::Error::Protocol(
                "deployment ceiling head digest mismatch".to_owned(),
            ));
        }
        Ok(())
    }
}

string_marker!(
    DeploymentCompletenessDomain,
    V1,
    "ak.participation.deployment-ceiling-completeness.v1"
);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DeploymentCeilingCompletenessCore {
    pub domain: DeploymentCompletenessDomain,
    pub slot_id: ProtocolOpaqueId,
    pub target_service_id: Did,
    pub checkpoint_issuer: Did,
    pub checkpoint_verification_method: DidUrl,
    pub checkpoint_seq: u64,
    pub covered_through_version: u64,
    pub covered_through_head_digest: Hash,
    pub fork_heads: Vec<DeploymentCeilingSignedHead>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

impl DeploymentCeilingCompletenessCore {
    pub fn root(&self) -> arkret_wire::Result<Hash> {
        if self.checkpoint_seq == 0
            || self.covered_through_version == 0
            || self.fork_heads.len() < 2
            || self.issued_at >= self.expires_at
        {
            return Err(arkret_wire::Error::Protocol(
                "deployment completeness core is incomplete".to_owned(),
            ));
        }
        let mut previous_digest: Option<&Hash> = None;
        let mut covered_head_seen = false;
        for head in &self.fork_heads {
            head.validate()?;
            if head.core.slot_id != self.slot_id
                || head.core.target_service_id != self.target_service_id
                || head.core.version > self.covered_through_version
            {
                return Err(arkret_wire::Error::Protocol(
                    "deployment completeness head is outside the checkpoint domain".to_owned(),
                ));
            }
            if previous_digest.is_some_and(|previous| {
                previous.as_str().as_bytes() >= head.head_digest.as_str().as_bytes()
            }) {
                return Err(arkret_wire::Error::Protocol(
                    "deployment completeness fork heads must be strictly UTF-8 sorted and unique"
                        .to_owned(),
                ));
            }
            covered_head_seen |= head.core.version == self.covered_through_version
                && head.head_digest == self.covered_through_head_digest;
            previous_digest = Some(&head.head_digest);
        }
        if !covered_head_seen {
            return Err(arkret_wire::Error::Protocol(
                "covered-through deployment head is absent from the completeness frontier"
                    .to_owned(),
            ));
        }
        let bytes = arkret_canonical::canonical_json_bytes(self)?;
        Hash::new(arkret_canonical::canonical::sha256_digest(bytes))
            .map_err(|error| arkret_wire::Error::Protocol(error.to_string()))
    }
}

string_marker!(
    DeploymentForkRepairDomain,
    V1,
    "ak.participation.deployment-ceiling-fork-repair.v1"
);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DeploymentCeilingForkRepair {
    pub domain: DeploymentForkRepairDomain,
    pub completeness_core: DeploymentCeilingCompletenessCore,
    pub completeness_root: Hash,
    pub predecessor_set: Vec<Hash>,
    pub successor: DeploymentCeilingCore,
    pub successor_digest: Hash,
    pub target_authority: Did,
    pub target_verification_method: DidUrl,
    pub signature: ProtocolSignature,
}

impl DeploymentCeilingForkRepair {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        let root = self.completeness_core.root()?;
        let mut expected = self
            .completeness_core
            .fork_heads
            .iter()
            .map(|head| head.head_digest.clone())
            .collect::<Vec<_>>();
        expected.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        if self.completeness_root != root
            || self.predecessor_set != expected
            || self.successor.version != self.completeness_core.covered_through_version + 1
            || self.successor.predecessor_digest.as_ref() != Some(&self.completeness_root)
            || self.successor_digest != self.successor.digest()?
            || self.successor.slot_id != self.completeness_core.slot_id
            || self.successor.target_service_id != self.completeness_core.target_service_id
            || self.target_authority != self.successor.issuer
            || self.target_verification_method != self.successor.issuer_verification_method
            || self.signature.verification_method != self.target_verification_method
        {
            return Err(arkret_wire::Error::Protocol(
                "deployment fork repair cross-binding mismatch".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum SidecarContextRef {
    Relation { relation_id: RelationId },
    Strand { strand_id: StrandId },
}

string_marker!(SidecarPreparePhase, Prepare, "prepare");
string_marker!(SidecarCommitPhase, Commit, "commit");
string_marker!(SidecarAttachPhase, Attach, "attach");

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct SidecarEnsurePrepareRequestBody {
    pub phase: SidecarPreparePhase,
    pub operation_id: ProtocolOperationId,
    pub idempotency_key: ProtocolOpaqueId,
    pub source_realm_id: RealmId,
    pub controller_id: Did,
    pub context_ref: SidecarContextRef,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct SidecarEnsureCommitRequestBody {
    pub phase: SidecarCommitPhase,
    pub operation_id: ProtocolOperationId,
    pub idempotency_key: ProtocolOpaqueId,
    pub reservation_handle: ProtocolOpaqueId,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub create_event: Event,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub context_attach_event: Event,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct SidecarEnsureAttachRequestBody {
    pub phase: SidecarAttachPhase,
    pub operation_id: ProtocolOperationId,
    pub idempotency_key: ProtocolOpaqueId,
    pub reservation_handle: ProtocolOpaqueId,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub context_attach_event: Event,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum SidecarEnsureRequestBody {
    Prepare(SidecarEnsurePrepareRequestBody),
    Commit(SidecarEnsureCommitRequestBody),
    Attach(SidecarEnsureAttachRequestBody),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum SidecarAccessReadiness {
    Opening,
    AccessReconciliationPending,
    KeyMaterialPending,
    EpochUpdateRequired,
    Ready,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum SidecarProvisioningPhase {
    BackingScopeMembership,
    MlsWelcome,
    MlsRemove,
    EpochRotation,
    DeviceKeyMaterial,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct SidecarPendingAccessReconciliation {
    pub agent_id: Did,
    pub provisioning_phase: SidecarProvisioningPhase,
    pub reason: ProtocolOpaqueId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum SidecarAcceptedPhase {
    Commit,
    Attach,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SidecarAcceptedOk;

impl Serialize for SidecarAcceptedOk {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bool(true)
    }
}

impl<'de> Deserialize<'de> for SidecarAcceptedOk {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if !bool::deserialize(deserializer)? {
            return Err(serde::de::Error::custom(
                "accepted Sidecar outcome requires ok=true",
            ));
        }
        Ok(Self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct SidecarPreparedEventDraft {
    pub event_id: EventId,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub kind: arkret_wire::EventKind,
    pub unsigned_event_bytes: Base64UrlString,
    pub event_digest: Hash,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "branch", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum SidecarPreparedOutcome {
    New {
        operation_id: ProtocolOperationId,
        reservation_handle: ProtocolOpaqueId,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        expires_at: DateTime<Utc>,
        sidecar_id: SidecarId,
        backing_circle_id: CircleId,
        private_strand_id: StrandId,
        private_relation_id: RelationId,
        create_event_id: EventId,
        context_attach_event_id: EventId,
        create_event_draft: SidecarPreparedEventDraft,
        context_attach_event_draft: SidecarPreparedEventDraft,
    },
    Existing {
        operation_id: ProtocolOperationId,
        reservation_handle: ProtocolOpaqueId,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        expires_at: DateTime<Utc>,
        sidecar_id: SidecarId,
        backing_circle_id: CircleId,
        private_strand_id: StrandId,
        private_relation_id: RelationId,
        context_attach_event_id: EventId,
        context_attach_event_draft: SidecarPreparedEventDraft,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum SidecarEnsureOutcome {
    Prepared {
        #[serde(flatten)]
        prepared: SidecarPreparedOutcome,
    },
    Accepted {
        operation_id: ProtocolOperationId,
        accepted_phase: SidecarAcceptedPhase,
        #[cfg_attr(feature = "openapi", salvo(schema(value_type = bool)))]
        ok: SidecarAcceptedOk,
        sidecar_id: SidecarId,
        private_strand_id: StrandId,
        private_relation_id: RelationId,
        access_readiness: SidecarAccessReadiness,
        pending_access_reconciliations: Vec<SidecarPendingAccessReconciliation>,
    },
}

impl SidecarEnsureOutcome {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        if let Self::Accepted {
            access_readiness,
            pending_access_reconciliations,
            ..
        } = self
            && ((*access_readiness == SidecarAccessReadiness::Ready
                && !pending_access_reconciliations.is_empty())
                || pending_access_reconciliations
                    .iter()
                    .collect::<BTreeSet<_>>()
                    .len()
                    != pending_access_reconciliations.len())
        {
            return Err(arkret_wire::Error::Protocol(
                "invalid accepted Sidecar readiness outcome".to_owned(),
            ));
        }
        Ok(())
    }
}

string_marker!(SidecarScopeKind, Circle, "circle");

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct SidecarScopeRef {
    pub kind: SidecarScopeKind,
    pub realm_id: RealmId,
    pub circle_id: CircleId,
}

string_marker!(
    SidecarAccessReplaceKind,
    Replace,
    "ak.sidecar.access.replace"
);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct SidecarAccessReplace {
    pub kind: SidecarAccessReplaceKind,
    pub realm_id: RealmId,
    pub scope_ref: SidecarScopeRef,
    pub sidecar_id: SidecarId,
    pub selected_agent_ids: Vec<Did>,
    pub version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predecessor_event_ref: Option<EventId>,
    pub controller_signature: ProtocolSignature,
}

impl SidecarAccessReplace {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        if self.version == 0
            || (self.version == 1) == self.predecessor_event_ref.is_some()
            || self.scope_ref.realm_id != self.realm_id
            || self
                .selected_agent_ids
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != self.selected_agent_ids.len()
            || !self
                .selected_agent_ids
                .windows(2)
                .all(|pair| pair[0].as_str().as_bytes() < pair[1].as_str().as_bytes())
        {
            return Err(arkret_wire::Error::Protocol(
                "invalid Sidecar access replacement".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum SidecarMembershipPolarity {
    Positive,
    Negative,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct SidecarMembershipRef {
    pub polarity: SidecarMembershipPolarity,
    pub event_ref: EventId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct SidecarControlFrontier {
    pub create_event_ref: EventId,
    pub access_event_ref: EventId,
    pub membership_refs: Vec<SidecarMembershipRef>,
}

impl SidecarControlFrontier {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        if self.membership_refs.is_empty()
            || !self.membership_refs.windows(2).all(|pair| {
                pair[0].event_ref.as_str().as_bytes() < pair[1].event_ref.as_str().as_bytes()
            })
        {
            return Err(arkret_wire::Error::Protocol(
                "Sidecar membership frontier must be non-empty, UTF-8 sorted and unique".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn accepted_sidecar_ok_is_const_true_at_decode() {
        serde_json::from_value::<SidecarAcceptedOk>(json!(true)).unwrap();
        assert!(serde_json::from_value::<SidecarAcceptedOk>(json!(false)).is_err());
        assert!(serde_json::from_value::<SidecarAcceptedOk>(json!("true")).is_err());
    }

    #[test]
    fn control_frontier_rejects_empty_and_unsorted_membership_refs() {
        let event = |suffix: &str| {
            EventId::new(format!("ak:event:01964137-0000-7000-8000-{suffix}")).unwrap()
        };
        let mut frontier = SidecarControlFrontier {
            create_event_ref: event("000000000001"),
            access_event_ref: event("000000000002"),
            membership_refs: Vec::new(),
        };
        assert!(frontier.validate().is_err());
        frontier.membership_refs = vec![
            SidecarMembershipRef {
                polarity: SidecarMembershipPolarity::Positive,
                event_ref: event("000000000004"),
            },
            SidecarMembershipRef {
                polarity: SidecarMembershipPolarity::Negative,
                event_ref: event("000000000003"),
            },
        ];
        assert!(frontier.validate().is_err());
    }
}
