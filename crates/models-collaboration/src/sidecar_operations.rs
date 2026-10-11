//! Sidecar creation/attachment through the current Realm authority.
//!
//! The ensure operation is a three-phase prepare/commit/attach exchange: the
//! service prepares canonical unsigned Event drafts under a reservation, the
//! controller returns the signed Events, and the service replies with the
//! accepted Sidecar plus its MLS access readiness.

use arkret_wire::{
    AccountId, DidCoreId, Event, EventId, IdempotencyKey, ProtocolOperationId, RealmId,
    ReservationHandle, Result, SidecarId, WireError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::agent_sidecar::{AgentSidecarAccessReadiness, PendingSidecarAccessReconciliation};
use crate::prepared_event_draft::PreparedEventDraft;
use crate::string_marker;

/// Event kind of the Sidecar create Event carried by the commit phase.
pub const SIDECAR_CREATE_EVENT_KIND: &str = "ak.sidecar.create";
/// Event kind of the Sidecar context attach Event.
pub const SIDECAR_CONTEXT_ATTACH_EVENT_KIND: &str = "ak.sidecar.context.attach";

pub use arkret_wire::SidecarContextRef;

/// Accepted refs of one Sidecar's control stream. Circle membership and Sidecar
/// selection refs are forbidden here.
// Field declaration order is byte-for-byte the properties order of
// principal-operations.schema.json#/$defs/sidecar_stream_head.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct SidecarStreamHead {
    pub create_event_ref: EventId,
    /// Sorted ownership, Agent lifecycle, authorization, Realm participation
    /// and key-readiness refs.
    pub authority_refs: Vec<EventId>,
}

string_marker!(SidecarEnsurePreparePhase, Prepare, "prepare");
string_marker!(SidecarEnsureCommitPhase, Commit, "commit");
string_marker!(SidecarEnsureAttachPhase, Attach, "attach");
string_marker!(SidecarEnsurePreparedStatus, Prepared, "prepared");
string_marker!(SidecarEnsureAcceptedStatus, Accepted, "accepted");
string_marker!(SidecarEnsureNewBranch, New, "new");
string_marker!(SidecarEnsureExistingBranch, Existing, "existing");

// Field declaration order is byte-for-byte the properties order of
// principal-operations.schema.json#/$defs/sidecar_ensure_request (first
// branch).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct SidecarEnsurePrepareRequestBody {
    pub phase: SidecarEnsurePreparePhase,
    pub operation_id: ProtocolOperationId,
    pub idempotency_key: IdempotencyKey,
    pub source_realm_id: RealmId,
    pub controller_account_id: AccountId,
    pub context_ref: SidecarContextRef,
}

// Field declaration order is byte-for-byte the properties order of
// principal-operations.schema.json#/$defs/sidecar_ensure_request (second
// branch).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct SidecarEnsureCommitRequestBody {
    pub phase: SidecarEnsureCommitPhase,
    pub operation_id: ProtocolOperationId,
    pub idempotency_key: IdempotencyKey,
    pub reservation_handle: ReservationHandle,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub create_event: Event,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub context_attach_event: Event,
}

// Field declaration order is byte-for-byte the properties order of
// principal-operations.schema.json#/$defs/sidecar_ensure_request (third
// branch).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct SidecarEnsureAttachRequestBody {
    pub phase: SidecarEnsureAttachPhase,
    pub operation_id: ProtocolOperationId,
    pub idempotency_key: IdempotencyKey,
    pub reservation_handle: ReservationHandle,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub context_attach_event: Event,
}

/// The three closed phases of `ak.self.agent.sidecar.command.ensure.v1`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
// A one-shot HTTP body: it is built once per request, moved a handful of times,
// then dropped. Boxing the signed-Event variants would trade a free stack move
// for a heap allocation on every request.
#[allow(clippy::large_enum_variant)]
pub enum SidecarEnsureRequestBody {
    Prepare(SidecarEnsurePrepareRequestBody),
    Commit(SidecarEnsureCommitRequestBody),
    Attach(SidecarEnsureAttachRequestBody),
}

impl SidecarEnsureRequestBody {
    pub fn operation_id(&self) -> &ProtocolOperationId {
        match self {
            Self::Prepare(body) => &body.operation_id,
            Self::Commit(body) => &body.operation_id,
            Self::Attach(body) => &body.operation_id,
        }
    }

    pub fn idempotency_key(&self) -> &IdempotencyKey {
        match self {
            Self::Prepare(body) => &body.idempotency_key,
            Self::Commit(body) => &body.idempotency_key,
            Self::Attach(body) => &body.idempotency_key,
        }
    }

    /// The signed Events of this phase must carry their registered kinds; the
    /// service never re-authors them.
    pub fn validate_shape(&self) -> Result<()> {
        let expected: &[(&Event, &str)] = match self {
            Self::Prepare(_) => &[],
            Self::Commit(body) => &[
                (&body.create_event, SIDECAR_CREATE_EVENT_KIND),
                (
                    &body.context_attach_event,
                    SIDECAR_CONTEXT_ATTACH_EVENT_KIND,
                ),
            ],
            Self::Attach(body) => &[(
                &body.context_attach_event,
                SIDECAR_CONTEXT_ATTACH_EVENT_KIND,
            )],
        };
        for (event, kind) in expected {
            if event.kind.as_str() != *kind {
                return Err(WireError::Protocol(format!(
                    "sidecar ensure phase requires an Event of kind {kind}"
                )));
            }
        }
        Ok(())
    }
}

// Field declaration order is byte-for-byte the properties order of
// principal-operations.schema.json#/$defs/sidecar_ensure_outcome (first
// branch).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct SidecarEnsurePreparedNewOutcome {
    pub status: SidecarEnsurePreparedStatus,
    pub branch: SidecarEnsureNewBranch,
    pub operation_id: ProtocolOperationId,
    pub reservation_handle: ReservationHandle,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub create_event_draft: PreparedEventDraft,
    pub context_attach_event_draft: PreparedEventDraft,
}

// Field declaration order is byte-for-byte the properties order of
// principal-operations.schema.json#/$defs/sidecar_ensure_outcome (second
// branch).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct SidecarEnsurePreparedExistingOutcome {
    pub status: SidecarEnsurePreparedStatus,
    pub branch: SidecarEnsureExistingBranch,
    pub operation_id: ProtocolOperationId,
    pub reservation_handle: ReservationHandle,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub sidecar_id: SidecarId,
    pub context_attach_event_draft: PreparedEventDraft,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum SidecarEnsureAcceptedPhase {
    Commit,
    Attach,
}

// Field declaration order is byte-for-byte the properties order of
// principal-operations.schema.json#/$defs/sidecar_ensure_outcome (third
// branch).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct SidecarEnsureAcceptedOutcome {
    pub status: SidecarEnsureAcceptedStatus,
    pub operation_id: ProtocolOperationId,
    pub accepted_phase: SidecarEnsureAcceptedPhase,
    pub sidecar_id: SidecarId,
    pub source_context_ref: SidecarContextRef,
    pub access_readiness: AgentSidecarAccessReadiness,
    pub pending_access_reconciliations: Vec<PendingSidecarAccessReconciliation>,
}

/// Outcome of `ak.self.agent.sidecar.command.ensure.v1`: one prepared
/// reservation branch, or the accepted Sidecar.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum SidecarEnsureOutcome {
    Accepted(SidecarEnsureAcceptedOutcome),
    PreparedNew(SidecarEnsurePreparedNewOutcome),
    PreparedExisting(SidecarEnsurePreparedExistingOutcome),
}

impl SidecarEnsureOutcome {
    pub fn operation_id(&self) -> &ProtocolOperationId {
        match self {
            Self::Accepted(outcome) => &outcome.operation_id,
            Self::PreparedNew(outcome) => &outcome.operation_id,
            Self::PreparedExisting(outcome) => &outcome.operation_id,
        }
    }

    /// The accepted Sidecar identity, once the exchange has one.
    pub fn sidecar_id(&self) -> Option<&SidecarId> {
        match self {
            Self::Accepted(outcome) => Some(&outcome.sidecar_id),
            Self::PreparedNew(_) => None,
            Self::PreparedExisting(outcome) => Some(&outcome.sidecar_id),
        }
    }

    /// Agents still waiting on Welcome, removal, epoch rotation or device key
    /// material before the Sidecar MLS scope is usable.
    pub fn pending_agent_ids(&self) -> Vec<&DidCoreId> {
        match self {
            Self::Accepted(outcome) => outcome
                .pending_access_reconciliations
                .iter()
                .map(|item| &item.agent_id)
                .collect(),
            Self::PreparedNew(_) | Self::PreparedExisting(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::StrandId;
    use serde_json::json;

    use super::*;

    const OPERATION_ID: &str = "ak:operation:0198ff00-0000-7000-8000-000000000001";
    const AGENT_ID: &str = "ak:did_core:webvh:z6mkfixture:agent.example";

    fn event_id(byte: u8) -> EventId {
        EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [byte; 32])
    }

    fn sidecar_id() -> SidecarId {
        SidecarId::from_event_id(&event_id(2))
    }

    fn account_id() -> serde_json::Value {
        json!({
            "principal_id": "ak:did_core:webvh:z6mkfixture:alice.example",
            "station_id": "ak:did_core:web:station.example"
        })
    }

    fn prepared_event_draft() -> serde_json::Value {
        json!({
            "unsigned_event_bytes": "dW5zaWduZWQtZXZlbnQtYnl0ZXM",
            "event_digest": format!("sha256:{}", "ab".repeat(32))
        })
    }

    #[test]
    fn sidecar_stream_head_round_trips_and_is_closed() {
        let value = json!({
            "create_event_ref": event_id(1),
            "authority_refs": [event_id(2)]
        });
        let parsed: SidecarStreamHead = serde_json::from_value(value.clone()).expect("closed head");
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

        assert!(
            serde_json::from_value::<SidecarStreamHead>(json!({
                "create_event_ref": event_id(1),
                "circle_membership_refs": []
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<SidecarStreamHead>(json!({"authority_refs": []})).is_err()
        );
    }

    #[test]
    fn prepare_request_round_trips_and_is_closed() {
        let value = json!({
            "phase": "prepare",
            "operation_id": OPERATION_ID,
            "idempotency_key": "ensure-fixture-1",
            "source_realm_id": RealmId::from_event_id(&event_id(1)),
            "controller_account_id": account_id(),
            "context_ref": {"kind": "strand", "strand_id": StrandId::from_event_id(&event_id(3))}
        });
        let parsed: SidecarEnsureRequestBody =
            serde_json::from_value(value.clone()).expect("closed prepare body");
        parsed.validate_shape().expect("prepare carries no Events");
        assert_eq!(parsed.operation_id().as_str(), OPERATION_ID);
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

        let mut unknown = value.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("encryption_profile".to_owned(), json!("x"));
        assert!(serde_json::from_value::<SidecarEnsureRequestBody>(unknown).is_err());

        let mut missing = value;
        missing.as_object_mut().unwrap().remove("context_ref");
        assert!(serde_json::from_value::<SidecarEnsureRequestBody>(missing).is_err());
    }

    #[test]
    fn prepared_new_outcome_round_trips_and_is_closed() {
        let value = json!({
            "status": "prepared",
            "branch": "new",
            "operation_id": OPERATION_ID,
            "reservation_handle": "reservation-fixture-1",
            "expires_at": "2026-08-01T00:05:00.000Z",
            "create_event_draft": prepared_event_draft(),
            "context_attach_event_draft": prepared_event_draft()
        });
        let parsed: SidecarEnsureOutcome =
            serde_json::from_value(value.clone()).expect("closed prepared outcome");
        assert!(matches!(parsed, SidecarEnsureOutcome::PreparedNew(_)));
        assert!(parsed.sidecar_id().is_none());
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

        let mut unknown = value.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("sidecar_control_frontier".to_owned(), json!([]));
        assert!(serde_json::from_value::<SidecarEnsureOutcome>(unknown).is_err());

        let mut missing = value;
        missing
            .as_object_mut()
            .unwrap()
            .remove("context_attach_event_draft");
        assert!(serde_json::from_value::<SidecarEnsureOutcome>(missing).is_err());
    }

    #[test]
    fn prepared_existing_outcome_selects_its_own_branch() {
        let value = json!({
            "status": "prepared",
            "branch": "existing",
            "operation_id": OPERATION_ID,
            "reservation_handle": "reservation-fixture-1",
            "expires_at": "2026-08-01T00:05:00.000Z",
            "sidecar_id": sidecar_id(),
            "context_attach_event_draft": prepared_event_draft()
        });
        let parsed: SidecarEnsureOutcome =
            serde_json::from_value(value.clone()).expect("closed prepared outcome");
        assert!(matches!(parsed, SidecarEnsureOutcome::PreparedExisting(_)));
        assert_eq!(parsed.sidecar_id(), Some(&sidecar_id()));
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);
    }

    #[test]
    fn accepted_outcome_round_trips_and_is_closed() {
        let value = json!({
            "status": "accepted",
            "operation_id": OPERATION_ID,
            "accepted_phase": "commit",
            "sidecar_id": sidecar_id(),
            "source_context_ref": {
                "kind": "strand",
                "strand_id": StrandId::from_event_id(&event_id(3))
            },
            "access_readiness": "key_material_pending",
            "pending_access_reconciliations": [
                {"agent_id": AGENT_ID, "provisioning_phase": "mls_welcome"}
            ]
        });
        let parsed: SidecarEnsureOutcome =
            serde_json::from_value(value.clone()).expect("closed accepted outcome");
        assert!(matches!(parsed, SidecarEnsureOutcome::Accepted(_)));
        assert_eq!(parsed.pending_agent_ids().len(), 1);
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

        let mut unknown = value.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("accepted_frontier".to_owned(), json!([]));
        assert!(serde_json::from_value::<SidecarEnsureOutcome>(unknown).is_err());

        let mut missing = value;
        missing.as_object_mut().unwrap().remove("access_readiness");
        assert!(serde_json::from_value::<SidecarEnsureOutcome>(missing).is_err());
    }
}
