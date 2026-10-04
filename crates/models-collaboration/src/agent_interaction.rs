//! Realm-local Agent interaction mode; capability and participation stay independent.
use arkret_wire::{AccountId, CommitStreamRef, CurrentRevision, RealmId, Result, WireError};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AgentInteractionMode {
    Private,
    Public,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_interaction_set_payload`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentInteractionSetPayload {
    pub agent_account_id: AccountId,
    pub controller_account_id: AccountId,
    pub interaction_mode: AgentInteractionMode,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub expected_revision: Option<CurrentRevision>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/typed-current-result.schema.json#/$defs/agent_interaction_value`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentInteractionCurrentValue {
    pub controller_account_id: AccountId,
    pub interaction_mode: AgentInteractionMode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AgentInteractionSelectorKind {
    #[serde(rename = "agent_interaction")]
    AgentInteraction,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/typed-current-result.schema.json#/$defs/agent_interaction_result/
/// properties/selector`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentInteractionExactCurrentSelector {
    pub kind: AgentInteractionSelectorKind,
    pub agent_account_id: AccountId,
}
impl AgentInteractionExactCurrentSelector {
    pub fn new(agent_account_id: AccountId) -> Self {
        Self {
            kind: AgentInteractionSelectorKind::AgentInteraction,
            agent_account_id,
        }
    }
}
/// Counterpart for
/// `spec/v1/artifacts/schemas/typed-current-result.schema.json#/$defs/agent_interaction_result`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentInteractionExactCurrentResult {
    pub selector: AgentInteractionExactCurrentSelector,
    pub source_stream_ref: CommitStreamRef,
    pub revision: CurrentRevision,
    pub value: AgentInteractionCurrentValue,
}

/// Only a verified same-cut read can yield a mode; a missing snapshot is unknown.
pub fn agent_interaction_from_verified_exact_read(
    outcome: &crate::exact_current_results::ExactCurrentResultsReadOutcome,
    realm_id: &RealmId,
    agent: &AccountId,
    controller: &AccountId,
    governance_generation: u64,
) -> Result<(AgentInteractionMode, Option<CurrentRevision>)> {
    use crate::exact_current_results::*;
    let selector = AgentInteractionExactCurrentSelector::new(agent.clone());
    let request = ExactCurrentResultsReadRequestBody {
        realm_id: realm_id.clone(),
        selector: ExactCurrentResultSelector::AgentInteraction(selector),
    };
    outcome.validate_for_request(&request, governance_generation)?;
    match outcome {
        ExactCurrentResultsReadOutcome::NeverWritten { .. } => {
            Ok((AgentInteractionMode::Private, None))
        }
        ExactCurrentResultsReadOutcome::Present {
            entry: ExactCurrentResultEntry::AgentInteraction(entry),
            ..
        } if &entry.value.controller_account_id == controller => {
            Ok((entry.value.interaction_mode, Some(entry.revision.clone())))
        }
        _ => Err(WireError::Protocol(
            "Agent interaction controller binding differs from current ownership".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    #[test]
    fn closed_mode_payload_rejects_null_partial_and_extra_authority() {
        let account = json!({"principal_id":"ak:did_core:web:agent.example", "station_id":"ak:did_core:web:station.example"});
        let value = json!({"agent_account_id":account, "controller_account_id":account, "interaction_mode":"public"});
        assert!(serde_json::from_value::<AgentInteractionSetPayload>(value.clone()).is_ok());
        for (key, field) in [
            ("expected_revision", serde_json::Value::Null),
            ("interaction_mode", json!("unknown")),
            ("scope_ref", json!({})),
            (
                "agent_account_id",
                json!({"principal_id":"ak:did_core:web:agent.example"}),
            ),
        ] {
            let mut bad = value.clone();
            bad[key] = field;
            assert!(serde_json::from_value::<AgentInteractionSetPayload>(bad).is_err());
        }
    }
}
