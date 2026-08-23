use arkret_wire::{
    DidCoreId, Event, EventId, IdempotencyKey, ProtocolOperationId, RealmId, RelationId,
    ReservationHandle, SidecarId, StrandId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::agent_operations::{
    AgentSidecarAccessReadiness, PendingSidecarAccessReconciliationItem,
};
use crate::string_marker;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum SidecarContextRef {
    Relation { relation_id: RelationId },
    Strand { strand_id: StrandId },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct SidecarContextAttachPayload {
    pub sidecar_id: SidecarId,
    pub source_context_ref: SidecarContextRef,
    pub version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predecessor_event_ref: Option<EventId>,
}

impl SidecarContextAttachPayload {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        if self.version == 0 || (self.version == 1) == self.predecessor_event_ref.is_some() {
            return Err(arkret_wire::WireError::Protocol(
                "Sidecar context attachment requires version>=1, no predecessor at version 1, and a predecessor after version 1".to_owned(),
            ));
        }
        Ok(())
    }
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
    pub idempotency_key: IdempotencyKey,
    pub source_realm_id: RealmId,
    pub controller_id: DidCoreId,
    pub context_ref: SidecarContextRef,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct SidecarEnsureCommitRequestBody {
    pub phase: SidecarCommitPhase,
    pub operation_id: ProtocolOperationId,
    pub idempotency_key: IdempotencyKey,
    pub reservation_handle: ReservationHandle,
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
    pub idempotency_key: IdempotencyKey,
    pub reservation_handle: ReservationHandle,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub context_attach_event: Event,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
// A one-shot HTTP body/aggregate: it is built once per request, moved a
// handful of times, then dropped. Boxing the large variant would trade a
// free stack move for a heap allocation on every request and break the
// constructor/pattern shape in every downstream repository, so the size
// skew is accepted deliberately.
#[allow(clippy::large_enum_variant)]
pub enum SidecarEnsureRequestBody {
    Prepare(SidecarEnsurePrepareRequestBody),
    Commit(SidecarEnsureCommitRequestBody),
    Attach(SidecarEnsureAttachRequestBody),
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

pub type SidecarPreparedEventDraft = crate::prepared_event_draft::PreparedEventDraft;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "branch", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum SidecarPreparedOutcome {
    New {
        operation_id: ProtocolOperationId,
        reservation_handle: ReservationHandle,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        expires_at: DateTime<Utc>,
        create_event_draft: SidecarPreparedEventDraft,
        context_attach_event_draft: SidecarPreparedEventDraft,
    },
    Existing {
        operation_id: ProtocolOperationId,
        reservation_handle: ReservationHandle,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        expires_at: DateTime<Utc>,
        sidecar_id: SidecarId,
        context_attach_event_draft: SidecarPreparedEventDraft,
    },
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
// A one-shot HTTP body/aggregate: it is built once per request, moved a
// handful of times, then dropped. Boxing the large variant would trade a
// free stack move for a heap allocation on every request and break the
// constructor/pattern shape in every downstream repository, so the size
// skew is accepted deliberately.
#[allow(clippy::large_enum_variant)]
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
        source_context_ref: SidecarContextRef,
        access_readiness: AgentSidecarAccessReadiness,
        pending_access_reconciliations: Vec<PendingSidecarAccessReconciliationItem>,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SidecarAcceptedOutcomePayload {
    operation_id: ProtocolOperationId,
    accepted_phase: SidecarAcceptedPhase,
    ok: SidecarAcceptedOk,
    sidecar_id: SidecarId,
    source_context_ref: SidecarContextRef,
    access_readiness: AgentSidecarAccessReadiness,
    pending_access_reconciliations: Vec<PendingSidecarAccessReconciliationItem>,
}

impl<'de> Deserialize<'de> for SidecarEnsureOutcome {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        let serde_json::Value::Object(mut object) = value else {
            return Err(serde::de::Error::custom(
                "Sidecar ensure outcome must be an object",
            ));
        };
        let status = match object.remove("status") {
            Some(serde_json::Value::String(status)) => status,
            Some(_) => {
                return Err(serde::de::Error::custom(
                    "Sidecar ensure outcome status must be a string",
                ));
            }
            None => {
                return Err(serde::de::Error::missing_field("status"));
            }
        };
        let payload = serde_json::Value::Object(object);
        match status.as_str() {
            "prepared" => serde_json::from_value(payload)
                .map(|prepared| Self::Prepared { prepared })
                .map_err(serde::de::Error::custom),
            "accepted" => {
                let accepted: SidecarAcceptedOutcomePayload =
                    serde_json::from_value(payload).map_err(serde::de::Error::custom)?;
                Ok(Self::Accepted {
                    operation_id: accepted.operation_id,
                    accepted_phase: accepted.accepted_phase,
                    ok: accepted.ok,
                    sidecar_id: accepted.sidecar_id,
                    source_context_ref: accepted.source_context_ref,
                    access_readiness: accepted.access_readiness,
                    pending_access_reconciliations: accepted.pending_access_reconciliations,
                })
            }
            _ => Err(serde::de::Error::unknown_variant(
                &status,
                &["prepared", "accepted"],
            )),
        }
    }
}

impl SidecarEnsureOutcome {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        if let Self::Accepted {
            access_readiness,
            pending_access_reconciliations,
            ..
        } = self
            && ((*access_readiness == AgentSidecarAccessReadiness::Ready
                && !pending_access_reconciliations.is_empty())
                || pending_access_reconciliations
                    .iter()
                    .enumerate()
                    .any(|(index, item)| {
                        pending_access_reconciliations[index + 1..].contains(item)
                    }))
        {
            return Err(arkret_wire::WireError::Protocol(
                "invalid accepted Sidecar readiness outcome".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct SidecarControlFrontier {
    pub create_event_ref: EventId,
    pub authority_refs: Vec<EventId>,
}

impl SidecarControlFrontier {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        if !self
            .authority_refs
            .windows(2)
            .all(|pair| pair[0].as_str().as_bytes() < pair[1].as_str().as_bytes())
        {
            return Err(arkret_wire::WireError::Protocol(
                "Sidecar authority frontier must be UTF-8 sorted and unique".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::Hash;
    use serde_json::json;

    use super::*;

    #[test]
    fn accepted_sidecar_ok_is_const_true_at_decode() {
        serde_json::from_value::<SidecarAcceptedOk>(json!(true)).unwrap();
        assert!(serde_json::from_value::<SidecarAcceptedOk>(json!(false)).is_err());
        assert!(serde_json::from_value::<SidecarAcceptedOk>(json!("true")).is_err());
    }

    #[test]
    fn prepared_sidecar_outcome_decodes_flattened_branch_and_stays_closed() {
        let value = json!({
            "status": "prepared",
            "branch": "existing",
            "operation_id": "ak:operation:sidecar.prepare",
            "reservation_handle": "reservation-1",
            "expires_at": "2026-08-03T00:00:00.000Z",
            "sidecar_id": "ak:sidecar:AaWlxNyGs0FzlOCJpyhjSRcmOcoYvk0qQ4X91NlGuKSZ",
            "context_attach_event_draft": {
                "unsigned_event_bytes": "e30",
                "event_digest": format!("sha256:{}", "00".repeat(32))
            }
        });

        let outcome: SidecarEnsureOutcome = serde_json::from_value(value.clone()).unwrap();
        assert!(matches!(
            outcome,
            SidecarEnsureOutcome::Prepared {
                prepared: SidecarPreparedOutcome::Existing { .. }
            }
        ));

        let mut unknown = value;
        unknown["unexpected"] = json!(true);
        assert!(serde_json::from_value::<SidecarEnsureOutcome>(unknown).is_err());
    }

    #[test]
    fn control_frontier_accepts_empty_and_rejects_unsorted_authority_refs() {
        let event = |suffix: &str| {
            EventId::from_event_digest(
                &Hash::new(arkret_canonical::sha256_digest(suffix.as_bytes())).unwrap(),
            )
            .unwrap()
        };
        let mut frontier = SidecarControlFrontier {
            create_event_ref: event("000000000001"),
            authority_refs: Vec::new(),
        };
        frontier.validate().unwrap();
        let mut unsorted = vec![event("000000000004"), event("000000000003")];
        unsorted.sort();
        unsorted.reverse();
        frontier.authority_refs = unsorted;
        assert!(frontier.validate().is_err());
    }
}
