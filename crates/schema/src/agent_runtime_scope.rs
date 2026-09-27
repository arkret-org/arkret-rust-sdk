//! Typed consumer for the canonical Agent runtime scope registry.
//!
//! The operation sets are generated from
//! `spec/v1/artifacts/registry/agent-runtime-scope-registry.json`. Product code
//! consumes the static descriptors and never parses the registry at runtime.
//!
//! The registry closes three scope layers over the same capability sets:
//! the immutable provision ceiling, the accepted key authorization and the
//! requested session scope. Capability selection is decided by exact
//! operation-token equality against the accepted immutable provision actions
//! alone; no lower layer may select or suppress a capability, and recovery
//! never widens an upper-layer ceiling.

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

/// The first layer that omits a mandatory operation of a selected capability.
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

/// Capabilities the accepted immutable provision actions select.
///
/// Registry invariant: selection uses exact operation-token equality against
/// only the accepted immutable provision `requested_scope.actions` array.
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

/// Expand a draft provision ceiling with the mandatory operations of every
/// capability the draft already activates. Authoring completion never adds a
/// capability the draft did not select.
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

/// Assess all three layers. The provision ceiling both selects the capabilities
/// and is itself the first layer checked.
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

/// Assess the immutable provision ceiling on its own, before any key is paired.
pub fn assess_agent_runtime_provision_scope(
    provision_scope: impl IntoIterator<Item = impl AsRef<str>>,
) -> Result<Option<AgentRuntimeScopeDeficiency>, AgentRuntimeScopeError> {
    assess_agent_runtime_scope_layers(collect_scope(provision_scope), Vec::new())
}

/// Assess the provision ceiling and the accepted key authorization it bounds.
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

    const INTERACTIVE_CHAT_MANDATORY: [&str; 3] = [
        "ak.self.events.command.submit.v1",
        "ak.self.committed_event.read.scan.v1",
        "ak.self.committed_event.stream.subscribe.v1",
    ];
    const E2EE_MANDATORY: &str = "ak.self.keys.keypackages.upload.create.v1";

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
        for operation in INTERACTIVE_CHAT_MANDATORY {
            assert!(required.iter().any(|id| id == operation));
        }
        assert!(required.iter().any(|id| id == E2EE_MANDATORY));

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
            // Drop the first mandatory operation: it is not an activation
            // operation of any other capability, so the provision selection is
            // unchanged and only the assessed layer becomes deficient.
            match layer {
                AgentRuntimeScopeLayer::Provision => provision.remove(0),
                AgentRuntimeScopeLayer::KeyAuthorization => key.remove(0),
                AgentRuntimeScopeLayer::Session => session.remove(0),
            };
            let deficiency = assess_agent_runtime_scopes(&provision, &key, &session)
                .unwrap()
                .unwrap();
            assert_eq!(deficiency.layer, layer);
            assert_eq!(deficiency.reason, reason);
            assert_eq!(
                deficiency.recovery,
                agent_runtime_scope_layer_descriptor(layer).recovery
            );
        }
    }

    #[test]
    fn immutable_provision_actions_are_the_only_capability_authority() {
        for activation in INTERACTIVE_CHAT_MANDATORY {
            let selected = selected_agent_runtime_capabilities([activation]).unwrap();
            assert!(selected.contains(&AgentRuntimeCapability::InteractiveChat));
        }
        for activation in [
            "ak.self.keys.keypackages.upload.create.v1",
            "ak.self.keys.keypackages.command.consume.v1",
        ] {
            let selected = selected_agent_runtime_capabilities([activation]).unwrap();
            assert!(selected.contains(&AgentRuntimeCapability::E2ee));
        }
        let selected = selected_agent_runtime_capabilities([
            "ak.self.authz.read.check.v1",
            "ak.self.device_messages.read.list.v1",
            "ak.self.keys.keypackages.command.revoke.v1",
        ])
        .unwrap();
        assert!(selected.is_empty());
    }

    #[test]
    fn authoring_completion_expands_selected_atomic_floors() {
        let completed = complete_agent_runtime_scope([
            "ak.self.committed_event.read.scan.v1",
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
    fn partial_capability_scopes_reach_the_registered_migration_reasons() {
        let interactive_without_submit = [
            "ak.self.committed_event.stream.subscribe.v1",
            "ak.self.committed_event.read.scan.v1",
        ];
        let deficiency = assess_agent_runtime_scopes(
            interactive_without_submit,
            interactive_without_submit,
            interactive_without_submit,
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
            ["ak.self.events.command.submit.v1"]
        );

        for activation in ["ak.self.keys.keypackages.command.consume.v1"] {
            let deficiency = assess_agent_runtime_scopes([activation], [activation], [activation])
                .unwrap()
                .unwrap();
            assert_eq!(deficiency.layer, AgentRuntimeScopeLayer::Provision);
            assert_eq!(deficiency.missing_operations, [E2EE_MANDATORY]);
        }
    }

    #[test]
    fn provision_only_assessment_ignores_lower_layers() {
        assert!(
            assess_agent_runtime_provision_scope(required())
                .unwrap()
                .is_none()
        );
        let mut short = required();
        short.remove(0);
        let deficiency = assess_agent_runtime_provision_scope(&short)
            .unwrap()
            .unwrap();
        assert_eq!(deficiency.layer, AgentRuntimeScopeLayer::Provision);
    }

    #[test]
    fn key_assessment_stops_at_the_key_authorization_layer() {
        let provision = required();
        let mut key = required();
        key.remove(0);
        let deficiency = assess_agent_runtime_key_scopes(&provision, &key)
            .unwrap()
            .unwrap();
        assert_eq!(deficiency.layer, AgentRuntimeScopeLayer::KeyAuthorization);
        assert_eq!(
            deficiency.reason,
            ReasonCode::AgentKeyScopeReauthorizationRequired
        );
    }

    #[test]
    fn lower_layers_cannot_select_a_capability() {
        let provision = ["ak.self.authz.read.check.v1"];
        let lower_layer_activation = ["ak.self.committed_event.stream.subscribe.v1"];
        assert!(
            assess_agent_runtime_scopes(provision, lower_layer_activation, lower_layer_activation,)
                .unwrap()
                .is_none()
        );
    }
}
