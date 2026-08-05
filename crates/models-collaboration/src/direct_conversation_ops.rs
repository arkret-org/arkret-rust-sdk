//! Direct Conversation resolver and single-sided founding carriers.
//!
//! Mirrors `schemas/direct-conversation-operations.schema.json`.
//!
//! Creation is never carried here. A Direct Conversation Realm is created only by the founder
//! derived from the pair's root Contact basis, through the `direct_conversation_genesis` (or
//! `direct_conversation_agent_genesis`) admission variant of `ak.realm.create`. This module only
//! carries the query-only resolver and the source-signed founding acceptance receipt.

use arkret_wire::{Did, EventId, Hash, ProtocolOpaqueId, ProtocolSignature, RealmId, StrandId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::contact_operations::ContactPeer;

/// Closed query body for `ak.self.direct_conversation.query.resolve`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DirectConversationResolveRequestBody {
    pub peer: ContactPeer,
}

/// Permanent Direct Conversation coordinates.
///
/// `binding_event_ref` appears only from `found`/`suspended` onward; it is absent while the pair is
/// still `provisional`, because no binding endorsement exists yet.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DirectConversationCoordinates {
    pub pair_key: Hash,
    pub realm_id: RealmId,
    pub main_strand_id: StrandId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_event_ref: Option<EventId>,
}

/// Closed machine-readable blocker set surfaced by the resolver.
///
/// Values never disclose peer presence to non-participants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DirectConversationSendBlocker {
    SessionMissing,
    PresenceOffline,
    KeypackageEmpty,
    GrantMissing,
    PolicyStale,
    ContactScopeStale,
    MlsReconcileRequired,
    PersonalBlocked,
    AgentRuntimeUnavailable,
    PeerNotJoinedMls,
    HistoryKeyUnavailable,
    PairMaterializationConflict,
    RealmTerminalFault,
    NotaryUnavailable,
    ProfileUnsupported,
}

/// Closed tagged outcome of `ak.self.direct_conversation.query.resolve`.
///
/// Evaluation order is fixed: `TemporarilyUnavailable` when the current basis or founder cannot be
/// verified; then `CreationBlocked`/`CreationRequired`/`AwaitingFounder` while no Realm exists; then
/// `Suspended` for identity, materialization, terminal or gate conflicts; then `Provisional` while
/// no binding endorsement exists; `Found` last.
///
/// `retry_after_ms` is a scheduling hint only. Waiting never grants create authority to the
/// non-founder: there is no timeout fallback or takeover in base v1.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DirectConversationResolveOutcome {
    /// No accepted Realm, and this principal is the derived founder.
    CreationRequired,
    /// No accepted Realm, this principal is the founder, but a current gate refuses creation.
    /// No coordinates are allocated in this state.
    CreationBlocked {
        blockers: Vec<DirectConversationSendBlocker>,
    },
    /// No accepted Realm and this principal is not the founder. Only the founder may create.
    AwaitingFounder {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retry_after_ms: Option<u64>,
    },
    /// The founding unit is accepted but no binding endorsement exists yet.
    Provisional {
        coordinates: DirectConversationCoordinates,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        active_mls_generation_ref: Option<EventId>,
    },
    Found {
        coordinates: DirectConversationCoordinates,
        active_mls_generation_ref: EventId,
        send_blockers: Vec<DirectConversationSendBlocker>,
    },
    Suspended {
        coordinates: DirectConversationCoordinates,
        blockers: Vec<DirectConversationSendBlocker>,
    },
    TemporarilyUnavailable {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retry_after_ms: Option<u64>,
    },
}

impl DirectConversationResolveOutcome {
    /// Coordinates, when the outcome carries them. Never hidden by presence, session, KeyPackage
    /// inventory or MLS reconcile state.
    #[must_use]
    pub fn coordinates(&self) -> Option<&DirectConversationCoordinates> {
        match self {
            Self::Provisional { coordinates, .. }
            | Self::Found { coordinates, .. }
            | Self::Suspended { coordinates, .. } => Some(coordinates),
            _ => None,
        }
    }

    /// Whether the caller may author the founding unit for this pair.
    #[must_use]
    pub fn is_founder_creation_point(&self) -> bool {
        matches!(self, Self::CreationRequired)
    }
}

/// Branch-specific authorization core of a founding acceptance receipt.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DirectConversationFoundingAuthorizationCore {
    /// human-to-human and Agent-to-third-party: founder derives from the Contact basis.
    Human {
        current_contact_basis_id: ProtocolOpaqueId,
        founder_basis_id: ProtocolOpaqueId,
        accepted_contact_evidence_digest: Hash,
    },
    /// controller-to-own-Agent: no Contact basis exists, founder is fixed to the controller.
    ControllerAgent {
        agent_provision_ref: EventId,
        agent_provision_digest: Hash,
        controller_binding_digest: Hash,
    },
}

/// Source-signed evidence that the founder's current Principal Server atomically accepted exactly
/// one founding unit and closed its local unique slot.
///
/// It creates no Realm, authorizes no Message and is not a global slot. A second receipt for the
/// same pair and founder but a different unit is `direct_conversation_pair_materialization_conflict`
/// evidence: implementations MUST NOT pick a winner by UUID or arrival order.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DirectConversationFoundingAcceptanceReceipt {
    pub pair_key: Hash,
    pub founder_id: Did,
    pub realm_id: RealmId,
    pub main_strand_id: StrandId,
    pub founding_unit_digest: Hash,
    pub authorization_core: DirectConversationFoundingAuthorizationCore,
    /// Always `true` on the wire: the receipt is only emitted inside the slot-committing
    /// transaction.
    pub slot_committed: bool,
    pub issuer_service_id: Did,
    pub issuer_service_binding_digest: Hash,
    pub accepted_at: DateTime<Utc>,
    pub proof: ProtocolSignature,
}

impl DirectConversationFoundingAcceptanceReceipt {
    /// Shape check that does not replace admission: `slot_committed` MUST be true, otherwise the
    /// receipt does not attest that the founder's unique slot was closed.
    pub fn validate_shape(&self) -> arkret_wire::Result<()> {
        if !self.slot_committed {
            return Err(arkret_wire::Error::Protocol(
                "direct conversation founding acceptance receipt must set slot_committed".to_owned(),
            ));
        }
        Ok(())
    }
}
