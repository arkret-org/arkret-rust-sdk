use std::collections::BTreeSet;

use arkret_wire::{
    Base64UrlString, CircleId, Did, Event, EventId, Hash, RealmId, RelationId, SidecarId, StrandId,
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
    pub const NONE: Self = Self {
        reply_message: false,
        reaction_add: false,
        reaction_remove: false,
        accept_third_party_mention: false,
        act_on_behalf: false,
    };

    pub const ALL: Self = Self {
        reply_message: true,
        reaction_add: true,
        reaction_remove: true,
        accept_third_party_mention: true,
        act_on_behalf: true,
    };

    #[must_use]
    pub fn intersect(self, other: Self) -> Self {
        Self {
            reply_message: self.reply_message && other.reply_message,
            reaction_add: self.reaction_add && other.reaction_add,
            reaction_remove: self.reaction_remove && other.reaction_remove,
            accept_third_party_mention: self.accept_third_party_mention
                && other.accept_third_party_mention,
            act_on_behalf: self.act_on_behalf && other.act_on_behalf,
        }
    }

    #[must_use]
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

    /// Stable account-data key used by participation projections.
    #[must_use]
    pub fn scope_key(&self) -> String {
        match self {
            Self::Realm { realm_id } => format!("realm:{}", uuid_part(realm_id.as_str())),
            Self::Circle {
                realm_id,
                circle_id,
            } => format!(
                "circle:{}:{}",
                uuid_part(realm_id.as_str()),
                uuid_part(circle_id.as_str())
            ),
            Self::Strand {
                realm_id,
                strand_id,
            } => format!(
                "strand:{}:{}",
                uuid_part(realm_id.as_str()),
                uuid_part(strand_id.as_str())
            ),
        }
    }
}

fn uuid_part(typed_id: &str) -> &str {
    typed_id.rsplit(':').next().unwrap_or(typed_id)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ParticipationReplaceRequestBody {
    pub target_scope: ParticipationScope,
    pub selection: ParticipationBits,
    pub expected_version: u64,
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
