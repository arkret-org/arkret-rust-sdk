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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AgentInteractionSelectorKind {
    #[serde(rename = "agent_interaction")]
    AgentInteraction,
}

impl AgentInteractionExactCurrentSelector {
    pub fn new(agent_account_id: AccountId) -> Self {
        Self {
            kind: AgentInteractionSelectorKind::AgentInteraction,
            agent_account_id,
        }
    }
}

/// Only a verified same-cut read can yield a mode; a missing snapshot is unknown.
pub fn agent_interaction_from_verified_exact_read(
    outcome: &crate::exact_current_state::ExactCurrentStateReadResponseBody,
    realm_id: &RealmId,
    agent: &AccountId,
    controller: &AccountId,
    governance_generation: u64,
) -> Result<(AgentInteractionMode, Option<CurrentRevision>)> {
    use crate::exact_current_state::*;
    let selector = AgentInteractionExactCurrentSelector::new(agent.clone());
    let request = ExactCurrentStateReadRequestBody {
        realm_id: realm_id.clone(),
        selector: ExactCurrentStateSelector::AgentInteraction(selector),
    };
    outcome.validate_for_request(&request, governance_generation)?;
    match outcome {
        ExactCurrentStateReadResponseBody::NeverWritten { .. } => {
            Ok((AgentInteractionMode::Private, None))
        }
        ExactCurrentStateReadResponseBody::Present {
            current_state: ExactCurrentState::AgentInteraction(entry),
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

include!("generated/agent_interaction_contracts.rs");
