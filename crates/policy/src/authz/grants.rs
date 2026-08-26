//! Capability-action registry digest helpers and the capability-relinquish
//! intent builder.
//!
//! The wire shape for capability grants is the core authority type
//! [`arkret_models_collaboration::governance::grant_constraint::CapabilityGrant`]
//! (spec `capability-grant.schema.json`).

use arkret_wire::{DidCoreId, Hash};
use chrono::{DateTime, Utc};
use serde_json::Value;

use super::*;

/// Capability-action registries that remain addressable because accepted
/// Realm authority roots and aggregate grants may still cite their digest.
///
/// These are exact immutable artifacts, not aliases to the current registry:
/// aggregate expansion must retain the coverage that was signed at creation
/// time and must never inherit actions added by a later registry revision.
const RETAINED_CAPABILITY_ACTION_REGISTRIES: &[(&str, &str)] = &[(
    "sha256:85c4e7f01bf0744bdb47a4b340de38b5919287da00a79d80bd7fdbdcb7cfbe45",
    include_str!("snapshots/capability-action-registry-2026-08-26.1.json"),
)];

/// Return the JCS SHA-256 digest of the current embedded capability-action
/// registry.
pub fn current_capability_action_registry_digest() -> Result<Hash> {
    let registry = arkret_schema::embedded_json_artifact(
        "registry/capability-action-registry.json",
    )
    .map_err(|_| {
        WireError::Protocol(
            "capability_registry_basis_unavailable: embedded registry missing".to_owned(),
        )
    })?;
    capability_action_registry_digest(&registry)
}

fn capability_action_registry_digest(registry: &Value) -> Result<Hash> {
    let bytes = arkret_canonical::canonical_json_bytes(registry).map_err(|error| {
        WireError::Protocol(format!(
            "capability_registry_basis_unavailable: registry JCS failed: {error}"
        ))
    })?;
    Hash::new(arkret_canonical::sha256_digest(&bytes)).map_err(|error| {
        WireError::Protocol(format!(
            "capability_registry_basis_unavailable: invalid registry digest: {error}"
        ))
    })
}

/// Resolve the current capability-action registry after verifying its signed
/// digest basis.
pub(crate) fn capability_action_registry_snapshot(basis: &Hash) -> Result<Value> {
    let current = arkret_schema::embedded_json_artifact("registry/capability-action-registry.json")
        .map_err(|_| {
            WireError::Protocol(
                "capability_registry_basis_unavailable: embedded registry missing".to_owned(),
            )
        })?;
    if capability_action_registry_digest(&current)? == *basis {
        return Ok(current);
    }

    for (expected_digest, encoded) in RETAINED_CAPABILITY_ACTION_REGISTRIES {
        if basis.as_str() != *expected_digest {
            continue;
        }
        let retained: Value = serde_json::from_str(encoded).map_err(|error| {
            WireError::Protocol(format!(
                "capability_registry_basis_unavailable: retained registry JSON is invalid: {error}"
            ))
        })?;
        if capability_action_registry_digest(&retained)? != *basis {
            return Err(WireError::Protocol(
                "capability_registry_basis_unavailable: retained registry digest mismatch"
                    .to_owned(),
            ));
        }
        return Ok(retained);
    }

    Err(WireError::Protocol(
        "capability_registry_basis_unavailable: registry digest does not match a current or retained embedded registry"
            .to_owned(),
    ))
}

pub(crate) fn capability_action_descriptor_in<'a>(
    registry: &'a Value,
    action: &str,
) -> Result<&'a Value> {
    registry
        .get("actions")
        .and_then(Value::as_array)
        .and_then(|actions| {
            actions.iter().find(|entry| {
                entry.get("action").and_then(Value::as_str) == Some(action)
            })
        })
        .ok_or_else(|| {
            WireError::Protocol(format!(
                "schema_violation: capability action '{action}' is not registered in the bound snapshot"
            ))
        })
}

/// Validate the registry snapshot binding required by aggregate-admin actions.
/// Any supplied digest must identify the exact embedded snapshot; receivers
/// never fall back to a different/current registry for an unknown basis.
pub fn validate_capability_action_registry_binding(
    actions: &[String],
    digest: Option<&Hash>,
) -> Result<()> {
    let registry = match digest {
        Some(digest) => capability_action_registry_snapshot(digest)?,
        None => arkret_schema::embedded_json_artifact("registry/capability-action-registry.json")
            .map_err(|_| {
            WireError::Protocol(
                "capability_registry_basis_unavailable: embedded registry missing".to_owned(),
            )
        })?,
    };
    let mut requires_binding = false;
    for action in actions {
        let descriptor = capability_action_descriptor_in(&registry, action)?;
        requires_binding |=
            descriptor.get("event_mapping_kind").and_then(Value::as_str) == Some("aggregate_admin");
    }
    if digest.is_some_and(|value| !value.as_str().starts_with("sha256:")) {
        return Err(WireError::Protocol(
            "schema_violation: capability_action_registry_digest must be sha256".to_owned(),
        ));
    }
    if requires_binding && digest.is_none() {
        return Err(WireError::Protocol(
            "capability_registry_basis_unavailable: aggregate_admin grant is missing capability_action_registry_digest"
                .to_owned(),
        ));
    }
    let Some(digest) = digest else {
        return Ok(());
    };
    capability_action_registry_snapshot(digest)?;
    Ok(())
}

/// Build a `ak.capability.relinquish` intent for `subject` under `scope_ref`.
pub fn build_capability_relinquish_intent(
    scope_ref: arkret_wire::ScopeRef,
    subject: DidCoreId,
    created_at: DateTime<Utc>,
    payload: arkret_models_collaboration::events_payloads::CapabilityRelinquishPayload,
) -> Result<arkret_event_draft::EventIntent> {
    arkret_event_draft::TypedEventDraft::<arkret_wire::event_spec::CapabilityRelinquish>::new(
        scope_ref,
        subject.clone(),
        subject,
        payload,
    )
    .map_err(|error| WireError::Protocol(error.to_string()))?
    .into_intent(created_at)
    .map_err(|error| WireError::Protocol(error.to_string()))
}
