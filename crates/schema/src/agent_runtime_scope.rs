//! Typed consumer for the canonical Agent runtime scope registry.
//!
//! The operation sets are generated from the canonical spec artifact. Product
//! code consumes static descriptors and never parses the registry at runtime.

use std::collections::BTreeSet;

use arkret_wire::error_codes::ReasonCode;
use thiserror::Error;

use crate::generated::{
    AGENT_RUNTIME_CAPABILITIES, agent_runtime_capability_descriptor,
    agent_runtime_scope_layer_descriptor,
};
pub use crate::generated::{
    AgentRuntimeCapability, AgentRuntimeCapabilitySelectionRule, AgentRuntimeScopeLayer,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentRuntimeScopeDeficiency {
    pub layer: AgentRuntimeScopeLayer,
    pub missing_operations: Vec<String>,
    pub reason: ReasonCode,
    pub recovery: &'static str,
}

#[derive(Debug, Error)]
pub enum AgentRuntimeScopeError {
    #[error("generated agent runtime scope descriptor is inconsistent")]
    InconsistentDescriptor,
}

pub fn selected_agent_runtime_capabilities(
    immutable_provision_actions: impl IntoIterator<Item = impl AsRef<str>>,
) -> Result<Vec<AgentRuntimeCapability>, AgentRuntimeScopeError> {
    let present = immutable_provision_actions
        .into_iter()
        .map(|operation| operation.as_ref().to_owned())
        .collect::<BTreeSet<_>>();
    let mut selected = Vec::new();
    for descriptor in AGENT_RUNTIME_CAPABILITIES {
        if descriptor
            .mandatory_operations
            .iter()
            .any(|operation| !descriptor.activation_operations.contains(operation))
        {
            return Err(AgentRuntimeScopeError::InconsistentDescriptor);
        }
        let is_selected = match descriptor.selection_rule {
            AgentRuntimeCapabilitySelectionRule::AnyActivationOperationPresentInImmutableProvisionActions => descriptor
                .activation_operations
                .iter()
                .any(|operation| present.contains(operation.as_str())),
        };
        if is_selected {
            selected.push(descriptor.capability);
        }
    }
    Ok(selected)
}

fn required_agent_runtime_operations(
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

pub fn complete_agent_runtime_scope(
    draft_actions: impl IntoIterator<Item = impl AsRef<str>>,
) -> Result<Vec<String>, AgentRuntimeScopeError> {
    let mut seen = BTreeSet::new();
    let draft = draft_actions
        .into_iter()
        .map(|operation| operation.as_ref().to_owned())
        .filter(|operation| seen.insert(operation.clone()))
        .collect::<Vec<_>>();
    let capabilities = selected_agent_runtime_capabilities(&draft)?;
    let mut completed = required_agent_runtime_operations(capabilities)?;
    for operation in draft {
        if !completed.contains(&operation) {
            completed.push(operation);
        }
    }
    Ok(completed)
}

pub fn assess_agent_runtime_scopes(
    provision_scope: impl IntoIterator<Item = impl AsRef<str>>,
    key_authorization_scope: impl IntoIterator<Item = impl AsRef<str>>,
    session_scope: impl IntoIterator<Item = impl AsRef<str>>,
) -> Result<Option<AgentRuntimeScopeDeficiency>, AgentRuntimeScopeError> {
    assess_agent_runtime_scope_layers(
        collect_scope(provision_scope),
        vec![
            (
                AgentRuntimeScopeLayer::KeyAuthorization,
                collect_scope(key_authorization_scope),
            ),
            (
                AgentRuntimeScopeLayer::Session,
                collect_scope(session_scope),
            ),
        ],
    )
}

pub fn assess_agent_runtime_provision_scope(
    provision_scope: impl IntoIterator<Item = impl AsRef<str>>,
) -> Result<Option<AgentRuntimeScopeDeficiency>, AgentRuntimeScopeError> {
    assess_agent_runtime_scope_layers(collect_scope(provision_scope), Vec::new())
}

pub fn assess_agent_runtime_key_scopes(
    provision_scope: impl IntoIterator<Item = impl AsRef<str>>,
    key_authorization_scope: impl IntoIterator<Item = impl AsRef<str>>,
) -> Result<Option<AgentRuntimeScopeDeficiency>, AgentRuntimeScopeError> {
    assess_agent_runtime_scope_layers(
        collect_scope(provision_scope),
        vec![(
            AgentRuntimeScopeLayer::KeyAuthorization,
            collect_scope(key_authorization_scope),
        )],
    )
}

fn collect_scope(scope: impl IntoIterator<Item = impl AsRef<str>>) -> BTreeSet<String> {
    scope
        .into_iter()
        .map(|value| value.as_ref().to_owned())
        .collect()
}

fn assess_agent_runtime_scope_layers(
    provision_scope: BTreeSet<String>,
    lower_layers: Vec<(AgentRuntimeScopeLayer, BTreeSet<String>)>,
) -> Result<Option<AgentRuntimeScopeDeficiency>, AgentRuntimeScopeError> {
    let capabilities = selected_agent_runtime_capabilities(&provision_scope)?;
    let required = required_agent_runtime_operations(capabilities)?;
    let supplied =
        std::iter::once((AgentRuntimeScopeLayer::Provision, provision_scope)).chain(lower_layers);

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
        let reason = reason_for_layer(layer);
        if reason.as_str() != rule.missing_reason {
            return Err(AgentRuntimeScopeError::InconsistentDescriptor);
        }
        return Ok(Some(AgentRuntimeScopeDeficiency {
            layer,
            missing_operations: missing,
            reason,
            recovery: rule.recovery,
        }));
    }
    Ok(None)
}

fn reason_for_layer(layer: AgentRuntimeScopeLayer) -> ReasonCode {
    match layer {
        AgentRuntimeScopeLayer::Provision => ReasonCode::AgentProvisionScopeMigrationRequired,
        AgentRuntimeScopeLayer::KeyAuthorization => {
            ReasonCode::AgentKeyScopeReauthorizationRequired
        }
        AgentRuntimeScopeLayer::Session => ReasonCode::AgentSessionScopeRefreshRequired,
    }
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
                ReasonCode::AgentProvisionScopeMigrationRequired,
            ),
            (
                AgentRuntimeScopeLayer::KeyAuthorization,
                ReasonCode::AgentKeyScopeReauthorizationRequired,
            ),
            (
                AgentRuntimeScopeLayer::Session,
                ReasonCode::AgentSessionScopeRefreshRequired,
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
            let deficiency = assess_agent_runtime_scopes(&provision, &key, &session)
                .unwrap()
                .unwrap();
            assert_eq!(deficiency.layer, layer);
            assert_eq!(deficiency.reason, reason);
        }
    }

    #[test]
    fn immutable_provision_actions_are_the_only_capability_authority() {
        for activation in [
            "ak.self.events.stream.subscribe.v1",
            "ak.self.events.read.scan.v1",
            "ak.self.events.read.frontier.v1",
            "ak.self.seals.read.frontier.v1",
            "ak.self.events.command.submit.v1",
        ] {
            let selected = selected_agent_runtime_capabilities([activation]).unwrap();
            assert!(selected.contains(&AgentRuntimeCapability::InteractiveChat));
        }
        for activation in [
            "ak.self.keys.keypackages.upload.create.v1",
            "ak.self.keys.keypackages.command.consume.v1",
            "ak.self.keys.keypackages.command.revoke.v1",
        ] {
            let selected = selected_agent_runtime_capabilities([activation]).unwrap();
            assert!(selected.contains(&AgentRuntimeCapability::E2ee));
        }
        let selected = selected_agent_runtime_capabilities([
            "ak.self.authz.read.check.v1",
            "ak.message.create",
            "ak.self.device_messages.read.list.v1",
        ])
        .unwrap();
        assert!(selected.is_empty());
    }

    #[test]
    fn authoring_completion_expands_selected_atomic_floors() {
        let completed = complete_agent_runtime_scope([
            "ak.self.events.read.scan.v1",
            "ak.self.keys.keypackages.command.consume.v1",
        ])
        .unwrap();
        for operation in required() {
            assert!(completed.contains(&operation));
        }
        assert!(
            completed
                .iter()
                .any(|operation| { operation == "ak.self.keys.keypackages.command.consume.v1" })
        );
    }

    #[test]
    fn old_scopes_reach_the_registered_migration_reasons() {
        let interactive_without_seal = [
            "ak.self.events.stream.subscribe.v1",
            "ak.self.events.read.scan.v1",
            "ak.self.events.read.frontier.v1",
            "ak.self.events.command.submit.v1",
        ];
        let deficiency = assess_agent_runtime_scopes(
            interactive_without_seal,
            interactive_without_seal,
            interactive_without_seal,
        )
        .unwrap()
        .unwrap();
        assert_eq!(deficiency.layer, AgentRuntimeScopeLayer::Provision);
        assert_eq!(
            deficiency.reason,
            ReasonCode::AgentProvisionScopeMigrationRequired
        );
        assert_eq!(
            deficiency.missing_operations,
            ["ak.self.seals.read.frontier.v1"]
        );

        for activation in [
            "ak.self.keys.keypackages.command.consume.v1",
            "ak.self.keys.keypackages.command.revoke.v1",
        ] {
            let deficiency = assess_agent_runtime_scopes([activation], [activation], [activation])
                .unwrap()
                .unwrap();
            assert_eq!(deficiency.layer, AgentRuntimeScopeLayer::Provision);
            assert_eq!(
                deficiency.missing_operations,
                ["ak.self.keys.keypackages.upload.create.v1"]
            );
        }
    }

    #[test]
    fn lower_layers_cannot_select_a_capability() {
        let provision = ["ak.self.authz.read.check.v1"];
        let lower_layer_activation = ["ak.self.events.stream.subscribe.v1"];
        assert!(
            assess_agent_runtime_scopes(provision, lower_layer_activation, lower_layer_activation,)
                .unwrap()
                .is_none()
        );
    }
}
