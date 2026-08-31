//! Typed consumer for the canonical Personal Agent runtime scope registry.
//!
//! The operation sets are generated from the canonical spec artifact. Product
//! code consumes static descriptors and never parses the registry at runtime.

use std::collections::BTreeSet;

use thiserror::Error;

pub use crate::generated::{AgentRuntimeCapability, AgentRuntimeScopeLayer};
use crate::generated::{agent_runtime_capability_descriptor, agent_runtime_scope_layer_descriptor};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentRuntimeScopeDeficiency {
    pub layer: AgentRuntimeScopeLayer,
    pub missing_operations: Vec<String>,
    pub reason: &'static str,
    pub recovery: &'static str,
}

#[derive(Debug, Error)]
pub enum AgentRuntimeScopeError {
    #[error("generated agent runtime scope descriptor is inconsistent")]
    InconsistentDescriptor,
}

pub fn required_agent_runtime_operations(
    capabilities: impl IntoIterator<Item = AgentRuntimeCapability>,
) -> Result<Vec<String>, AgentRuntimeScopeError> {
    let mut required = BTreeSet::new();
    for capability in capabilities {
        required.extend(
            agent_runtime_capability_descriptor(capability)
                .mandatory_operations
                .iter()
                .map(|operation| operation.as_str().to_owned()),
        );
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
        let rule = agent_runtime_scope_layer_descriptor(layer);
        if rule.layer != layer {
            return Err(AgentRuntimeScopeError::InconsistentDescriptor);
        }
        return Ok(Some(AgentRuntimeScopeDeficiency {
            layer,
            missing_operations: missing,
            reason: rule.missing_reason,
            recovery: rule.recovery,
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
                .any(|id| id == "ak.self.events.read.frontier.v1")
        );
        assert!(
            required
                .iter()
                .any(|id| id == "ak.self.seals.read.frontier.v1")
        );
        assert!(
            required
                .iter()
                .any(|id| id == "ak.self.keys.keypackages.upload.create.v1")
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
