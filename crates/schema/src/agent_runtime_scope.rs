//! Typed consumer for the canonical Personal Agent runtime scope registry.
//!
//! The operation sets live only in the embedded spec artifact. Product code
//! selects capabilities and supplies the three accepted scope layers; this
//! module returns the exact migration reason and recovery class without a
//! second hand-maintained action list.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use thiserror::Error;

use crate::artifacts::embedded_json_artifact;

const REGISTRY_PATH: &str = "registry/agent-runtime-scope-registry.json";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AgentRuntimeCapability {
    InteractiveChat,
    E2ee,
}

impl AgentRuntimeCapability {
    const fn registry_key(self) -> &'static str {
        match self {
            Self::InteractiveChat => "interactive_chat",
            Self::E2ee => "e2ee",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRuntimeScopeLayer {
    Provision,
    KeyAuthorization,
    Session,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentRuntimeScopeDeficiency {
    pub layer: AgentRuntimeScopeLayer,
    pub missing_operations: Vec<String>,
    pub reason: String,
    pub recovery: String,
}

#[derive(Debug, Error)]
pub enum AgentRuntimeScopeError {
    #[error("agent runtime scope registry is invalid: {0}")]
    InvalidRegistry(String),
    #[error("agent runtime capability is absent from registry: {0}")]
    UnknownCapability(&'static str),
    #[error("agent runtime layer is absent from registry: {0:?}")]
    UnknownLayer(AgentRuntimeScopeLayer),
}

#[derive(Deserialize)]
struct Registry {
    layers: Vec<LayerRule>,
    capability_sets: BTreeMap<String, CapabilityRule>,
}

#[derive(Deserialize)]
struct LayerRule {
    layer: AgentRuntimeScopeLayer,
    missing_reason: String,
    recovery: String,
}

#[derive(Deserialize)]
struct CapabilityRule {
    mandatory_operations: Vec<String>,
}

fn registry() -> Result<Registry, AgentRuntimeScopeError> {
    let value = embedded_json_artifact(REGISTRY_PATH)
        .map_err(|error| AgentRuntimeScopeError::InvalidRegistry(error.to_string()))?;
    serde_json::from_value(value)
        .map_err(|error| AgentRuntimeScopeError::InvalidRegistry(error.to_string()))
}

pub fn required_agent_runtime_operations(
    capabilities: impl IntoIterator<Item = AgentRuntimeCapability>,
) -> Result<Vec<String>, AgentRuntimeScopeError> {
    let registry = registry()?;
    let mut required = BTreeSet::new();
    for capability in capabilities {
        let key = capability.registry_key();
        let rule = registry
            .capability_sets
            .get(key)
            .ok_or(AgentRuntimeScopeError::UnknownCapability(key))?;
        required.extend(rule.mandatory_operations.iter().cloned());
    }
    Ok(required.into_iter().collect())
}

pub fn assess_agent_runtime_scopes(
    capabilities: impl IntoIterator<Item = AgentRuntimeCapability>,
    provision_scope: impl IntoIterator<Item = impl AsRef<str>>,
    key_authorization_scope: impl IntoIterator<Item = impl AsRef<str>>,
    session_scope: impl IntoIterator<Item = impl AsRef<str>>,
) -> Result<Option<AgentRuntimeScopeDeficiency>, AgentRuntimeScopeError> {
    let required = required_agent_runtime_operations(capabilities)?;
    let registry = registry()?;
    let supplied = [
        (
            AgentRuntimeScopeLayer::Provision,
            provision_scope
                .into_iter()
                .map(|value| value.as_ref().to_owned())
                .collect::<BTreeSet<_>>(),
        ),
        (
            AgentRuntimeScopeLayer::KeyAuthorization,
            key_authorization_scope
                .into_iter()
                .map(|value| value.as_ref().to_owned())
                .collect::<BTreeSet<_>>(),
        ),
        (
            AgentRuntimeScopeLayer::Session,
            session_scope
                .into_iter()
                .map(|value| value.as_ref().to_owned())
                .collect::<BTreeSet<_>>(),
        ),
    ];

    for (layer, present) in supplied {
        let missing = required
            .iter()
            .filter(|operation| !present.contains(operation.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        if missing.is_empty() {
            continue;
        }
        let rule = registry
            .layers
            .iter()
            .find(|rule| rule.layer == layer)
            .ok_or(AgentRuntimeScopeError::UnknownLayer(layer))?;
        return Ok(Some(AgentRuntimeScopeDeficiency {
            layer,
            missing_operations: missing,
            reason: rule.missing_reason.clone(),
            recovery: rule.recovery.clone(),
        }));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn required() -> Vec<String> {
        required_agent_runtime_operations([
            AgentRuntimeCapability::InteractiveChat,
            AgentRuntimeCapability::E2ee,
        ])
        .unwrap()
    }

    #[test]
    fn registry_drives_all_three_failure_layers_without_silent_widening() {
        let required = required();
        assert!(
            required
                .iter()
                .any(|id| id == "ak.self.events.read.frontier")
        );
        assert!(
            required
                .iter()
                .any(|id| id == "ak.self.seals.read.frontier")
        );
        assert!(
            required
                .iter()
                .any(|id| id == "ak.self.keys.keypackages.upload.create")
        );

        for (layer, reason) in [
            (
                AgentRuntimeScopeLayer::Provision,
                "agent_provision_scope_migration_required",
            ),
            (
                AgentRuntimeScopeLayer::KeyAuthorization,
                "agent_key_scope_reauthorization_required",
            ),
            (
                AgentRuntimeScopeLayer::Session,
                "agent_session_scope_refresh_required",
            ),
        ] {
            let mut provision = required.clone();
            let mut key = required.clone();
            let mut session = required.clone();
            match layer {
                AgentRuntimeScopeLayer::Provision => provision.pop(),
                AgentRuntimeScopeLayer::KeyAuthorization => key.pop(),
                AgentRuntimeScopeLayer::Session => session.pop(),
            };
            let deficiency = assess_agent_runtime_scopes(
                [
                    AgentRuntimeCapability::InteractiveChat,
                    AgentRuntimeCapability::E2ee,
                ],
                &provision,
                &key,
                &session,
            )
            .unwrap()
            .unwrap();
            assert_eq!(deficiency.layer, layer);
            assert_eq!(deficiency.reason, reason);
        }
    }
}
