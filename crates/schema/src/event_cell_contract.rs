//! Registry-driven validation of reducer-input Event cell contracts.
//!
//! The event-kind registry, not a producer-selected `effects[].cell`, is the
//! authority for a reducer target. This module implements the common v1
//! single-target `cas_register`/`set` path used by Realm bootstrap facets.

use arkret_wire::{CellId, Event, LatticeOpType};
use serde_json::Value;
use thiserror::Error;

/// Envelope context used while validating the registry-declared CBA plane.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum EventCellContractContext {
    /// A post-genesis Event: control writes require `seal_basis`; data writes
    /// require `seal_ref` plus `auth_context`.
    #[default]
    Standard,
    /// A follow-up in the closed ordinary Realm genesis transaction. There is
    /// no accepted Seal yet, so the control write MUST use the spec's
    /// bootstrap exception and carry no CBA basis fields.
    OrdinaryRealmBootstrap,
}

/// Failure while matching an Event against its generated registry contract.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum EventCellContractError {
    #[error("event kind {0} is not a registered reducer input")]
    UnregisteredReducerInput(String),
    #[error("event kind {0} has no single-target cell contract")]
    MissingCellContract(String),
    #[error("event kind {kind} is routed through the wrong CBA plane; expected {expected}")]
    PlaneMismatch { kind: String, expected: String },
    #[error("event kind {kind} requires exactly one effect, got {actual}")]
    EffectCount { kind: String, actual: usize },
    #[error("event kind {kind} has an invalid cell id: {message}")]
    InvalidCell { kind: String, message: String },
    #[error("event kind {kind} targeted {actual}, expected {expected}")]
    CellMismatch {
        kind: String,
        expected: String,
        actual: String,
    },
    #[error("event kind {kind} requires lattice op {expected}, got {actual}")]
    OperationMismatch {
        kind: String,
        expected: String,
        actual: String,
    },
    #[error("event kind {kind} effect value does not match its signed payload")]
    PayloadMismatch { kind: String },
    #[error("event kind {kind} cell subject cannot be derived: {message}")]
    SubjectDerivation { kind: String, message: String },
}

impl EventCellContractError {
    /// Normative reason code for a submit rejection.
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::PlaneMismatch { .. } => "plane_cross_write",
            _ => "effects_payload_mismatch",
        }
    }
}

/// Validate a registry-declared, single-target `cas_register` Event.
///
/// The expected cell family, subject, plane and lattice are read from the
/// generated event-kind descriptor. The set value is derived from the signed
/// payload: payloads carrying a top-level `value` project that value; otherwise
/// the complete payload object is the registered value.
pub fn validate_single_target_set_event_contract(
    event: &Event,
) -> Result<(), EventCellContractError> {
    validate_single_target_set_event_contract_in_context(event, EventCellContractContext::Standard)
}

/// Validate a registry-declared single-target Event in its envelope context.
pub fn validate_single_target_set_event_contract_in_context(
    event: &Event,
    context: EventCellContractContext,
) -> Result<(), EventCellContractError> {
    let kind = event.kind.as_str().to_owned();
    let descriptor = event
        .kind
        .descriptor()
        .filter(|descriptor| descriptor.reducer_input)
        .ok_or_else(|| EventCellContractError::UnregisteredReducerInput(kind.clone()))?;
    let family = descriptor
        .cell_family
        .ok_or_else(|| EventCellContractError::MissingCellContract(kind.clone()))?;
    if descriptor.lattice != Some("cas_register") {
        return Err(EventCellContractError::MissingCellContract(kind));
    }

    validate_plane(event, descriptor.plane, context)?;

    if event.effects.len() != 1 {
        return Err(EventCellContractError::EffectCount {
            kind,
            actual: event.effects.len(),
        });
    }
    let effect = &event.effects[0];
    let cell =
        CellId::from_ref(&effect.cell).map_err(|error| EventCellContractError::InvalidCell {
            kind: kind.clone(),
            message: error.to_string(),
        })?;
    let expected_subject = derive_subject(event, descriptor.cell_subject_rule)?;
    if cell.component() != family || cell.subject() != expected_subject {
        return Err(EventCellContractError::CellMismatch {
            kind: kind.clone(),
            expected: format!("ak:cell:{family}:{expected_subject}"),
            actual: effect.cell.as_str().to_owned(),
        });
    }
    if effect.op.op_type != LatticeOpType::Set
        || effect.op.tag.is_some()
        || effect.op.from.is_some()
        || effect.op.to.is_some()
        || effect.op.reason.is_some()
        || effect.op.issuer_seq.is_some()
    {
        return Err(EventCellContractError::OperationMismatch {
            kind: kind.clone(),
            expected: "set".to_owned(),
            actual: format!("{:?}", effect.op.op_type).to_lowercase(),
        });
    }
    let payload = Value::Object(event.payload.clone().into_iter().collect());
    let expected_value = event.payload.get("value").unwrap_or(&payload);
    if effect.op.value.as_ref() != Some(expected_value) {
        return Err(EventCellContractError::PayloadMismatch { kind });
    }
    Ok(())
}

fn validate_plane(
    event: &Event,
    plane: Option<&str>,
    context: EventCellContractContext,
) -> Result<(), EventCellContractError> {
    let kind = event.kind.as_str().to_owned();
    let matches = match (plane, context) {
        (Some("control"), EventCellContractContext::Standard) => {
            event.seal_basis.is_some() && event.seal_ref.is_none() && event.auth_context.is_none()
        }
        (Some("data"), EventCellContractContext::Standard) => {
            event.seal_basis.is_none() && event.seal_ref.is_some() && event.auth_context.is_some()
        }
        (Some("control"), EventCellContractContext::OrdinaryRealmBootstrap) => {
            event.seal_basis.is_none() && event.seal_ref.is_none() && event.auth_context.is_none()
        }
        _ => false,
    };
    if matches {
        Ok(())
    } else {
        Err(EventCellContractError::PlaneMismatch {
            kind,
            expected: plane.unwrap_or("registered").to_owned(),
        })
    }
}

fn derive_subject(
    event: &Event,
    rule_json: Option<&str>,
) -> Result<String, EventCellContractError> {
    let kind = event.kind.as_str().to_owned();
    let Some(rule_json) = rule_json else {
        return Ok(event.realm_id.as_str().to_owned());
    };
    let rule: Value = serde_json::from_str(rule_json).map_err(|error| {
        EventCellContractError::SubjectDerivation {
            kind: kind.clone(),
            message: error.to_string(),
        }
    })?;
    let rule_type = rule.get("type").and_then(Value::as_str).unwrap_or_default();
    match rule_type {
        "composite" => {
            let fields = rule
                .get("components")
                .and_then(Value::as_array)
                .ok_or_else(|| subject_error(&kind, "composite components are missing"))?;
            derive_composite(event, fields, &kind)
        }
        "tuple" => {
            let components = rule
                .get("components")
                .and_then(Value::as_array)
                .ok_or_else(|| subject_error(&kind, "tuple components are missing"))?;
            let fields = components
                .iter()
                .map(|component| {
                    component
                        .get("field")
                        .cloned()
                        .ok_or_else(|| subject_error(&kind, "tuple component field is missing"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            derive_composite(event, &fields, &kind)
        }
        "coalesce" => {
            let fields = rule
                .get("fields")
                .and_then(Value::as_array)
                .ok_or_else(|| subject_error(&kind, "coalesce fields are missing"))?;
            for field in fields {
                if let Some(value) = field.as_str().and_then(|path| field_value(event, path)) {
                    return scalar_subject(value).map_err(|message| subject_error(&kind, &message));
                }
            }
            Err(subject_error(&kind, "no coalesce field is present"))
        }
        _ => {
            let path = rule
                .get("field")
                .and_then(Value::as_str)
                .ok_or_else(|| subject_error(&kind, "cell subject field is missing"))?;
            let value = field_value(event, path)
                .ok_or_else(|| subject_error(&kind, &format!("{path} is missing")))?;
            scalar_subject(value).map_err(|message| subject_error(&kind, &message))
        }
    }
}

fn derive_composite(
    event: &Event,
    fields: &[Value],
    kind: &str,
) -> Result<String, EventCellContractError> {
    let parts = fields
        .iter()
        .map(|field| {
            let path = field
                .as_str()
                .ok_or_else(|| subject_error(kind, "composite field must be a string"))?;
            let value = field_value(event, path)
                .ok_or_else(|| subject_error(kind, &format!("{path} is missing")))?;
            scalar_subject(value).map_err(|message| subject_error(kind, &message))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let refs = parts.iter().map(String::as_str).collect::<Vec<_>>();
    arkret_wire::cell::composite_subject(&refs)
        .map_err(|error| subject_error(kind, &error.to_string()))
}

fn field_value<'a>(event: &'a Event, path: &str) -> Option<&'a Value> {
    if path == "payload" {
        return None;
    }
    let path = path.strip_prefix("payload.").unwrap_or(path);
    let mut segments = path.split('.');
    let first = segments.next()?;
    let mut current = event.payload.get(first)?;
    for segment in segments {
        current = current.as_object()?.get(segment)?;
    }
    Some(current)
}

fn scalar_subject(value: &Value) -> Result<String, String> {
    match value {
        Value::String(value) => Ok(value.clone()),
        Value::Number(value) => Ok(value.to_string()),
        Value::Bool(value) => Ok(value.to_string()),
        _ => Err("cell subject field must be a scalar".to_owned()),
    }
}

fn subject_error(kind: &str, message: &str) -> EventCellContractError {
    EventCellContractError::SubjectDerivation {
        kind: kind.to_owned(),
        message: message.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arkret_wire::events::kinds::EventKind;
    use serde_json::json;

    fn realm_facet(kind: &str, family: &str, payload: Value, value: Value) -> Event {
        serde_json::from_value(json!({
            "event_id": "ak:event:019f9000-0000-7000-8000-000000000001",
            "kind": kind,
            "realm_id": "ak:realm:019f9000-0000-7000-8000-000000000002",
            "actor_id": "did:webvh:z6mkfixture:alice.example",
            "actor_seq": 3,
            "created_at": "2026-07-20T00:00:00.000Z",
            "hlc": "019f90000000-0000-aabbccdd",
            "prev_refs": [],
            "preconditions": [],
            "effects": [{
                "cell": format!("ak:cell:{family}:ak:realm:019f9000-0000-7000-8000-000000000002"),
                "op": {"kind": "set", "value": value}
            }],
            "seal_basis": {
                "leaves": ["ak:seal:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
                "control_event_set_root": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "state_root": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            },
            "payload": payload,
            "proofs": []
        }))
        .unwrap()
    }

    #[test]
    fn validates_realm_join_rule_from_registry() {
        let event = realm_facet(
            EventKind::REALM_JOIN_RULE,
            "ak.component.realm.join_rule.v1",
            json!({"value": "knock_restricted"}),
            json!("knock_restricted"),
        );
        validate_single_target_set_event_contract(&event).unwrap();
    }

    #[test]
    fn rejects_producer_selected_family_and_payload_value() {
        let mut event = realm_facet(
            EventKind::REALM_DISCOVERY,
            "ak.component.realm.discovery.v1",
            json!({"value": "listed"}),
            json!("listed"),
        );
        event.effects[0].cell = arkret_wire::CellRef::new(
            "ak:cell:ak.component.realm.join_rule.v1:ak:realm:019f9000-0000-7000-8000-000000000002",
        )
        .unwrap();
        let error = validate_single_target_set_event_contract(&event).unwrap_err();
        assert_eq!(error.reason_code(), "effects_payload_mismatch");

        event.effects[0].cell = arkret_wire::CellRef::new(
            "ak:cell:ak.component.realm.discovery.v1:ak:realm:019f9000-0000-7000-8000-000000000002",
        )
        .unwrap();
        event.effects[0].op.value = Some(json!("secret"));
        assert!(matches!(
            validate_single_target_set_event_contract(&event),
            Err(EventCellContractError::PayloadMismatch { .. })
        ));
    }

    #[test]
    fn accepts_only_basis_free_control_facets_in_realm_bootstrap_context() {
        let mut event = realm_facet(
            EventKind::REALM_JOIN_RULE,
            "ak.component.realm.join_rule.v1",
            json!({"value": "invite"}),
            json!("invite"),
        );
        event.seal_basis = None;
        validate_single_target_set_event_contract_in_context(
            &event,
            EventCellContractContext::OrdinaryRealmBootstrap,
        )
        .unwrap();

        event.seal_ref = Some(
            arkret_wire::SealId::new(
                "ak:seal:sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            )
            .unwrap(),
        );
        assert_eq!(
            validate_single_target_set_event_contract_in_context(
                &event,
                EventCellContractContext::OrdinaryRealmBootstrap,
            )
            .unwrap_err()
            .reason_code(),
            "plane_cross_write"
        );
    }
}
