//! Registry-driven validation of reducer-input Event cell contracts.
//!
//! The event-kind registry, not a producer-selected `effects[].cell`, is the
//! authority for reducer targets. This module implements the common v1
//! single-target validation paths and the exact conditional multi-target
//! validation used by invite, call, MLS, and Realm bootstrap contracts.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use arkret_wire::{CellId, Event, LatticeOpType};
use serde_json::Value;
use thiserror::Error;

/// Canonical wire subject segment of a cell family declared with
/// `cell_subject: null` (`conformance/encoding.md` section 4).
///
/// The literal ASCII `null` is used rather than an empty segment because
/// `ak:cell:<family>:` cannot be told apart from a truncated wire id, and
/// truncated ids must be rejected.
pub const NULL_CELL_SUBJECT: &str = "null";

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
    #[error("event kind {kind} has an invalid registered effect set: {message}")]
    EffectSetMismatch { kind: String, message: String },
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

static EMBEDDED_EVENT_KIND_REGISTRY: OnceLock<Result<Value, String>> = OnceLock::new();

fn event_kind_registry() -> Result<&'static Value, EventCellContractError> {
    EMBEDDED_EVENT_KIND_REGISTRY
        .get_or_init(|| {
            crate::embedded_json_artifact("registry/event-kind-registry.json")
                .map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(|message| EventCellContractError::EffectSetMismatch {
            kind: "<registry>".to_owned(),
            message: message.clone(),
        })
}

/// Validate the exact target set of a registry `cell_writes[]` contract.
///
/// This is the common multi-target/conditional path. It derives every active
/// target from the signed Event, evaluates the closed condition grammar, and
/// rejects missing, duplicate, inactive or unregistered effects. Domain
/// reducers remain responsible for value-specific invariants, while the
/// lattice registry validates the detailed op shape.
pub fn validate_registered_cell_writes(event: &Event) -> Result<(), EventCellContractError> {
    let kind = event.kind.as_str().to_owned();
    let registry = event_kind_registry()?;
    let row = registry
        .get("event_kinds")
        .and_then(Value::as_array)
        .and_then(|rows| {
            rows.iter()
                .find(|row| row.get("event_kind").and_then(Value::as_str) == Some(kind.as_str()))
        })
        .ok_or_else(|| EventCellContractError::UnregisteredReducerInput(kind.clone()))?;
    let Some(writes) = row.get("cell_writes").and_then(Value::as_array) else {
        return Ok(());
    };

    let mut expected = BTreeMap::<String, &str>::new();
    for write in writes {
        if !condition_matches(event, write.get("condition"), &kind)? {
            continue;
        }
        let family = write
            .get("cell_family")
            .and_then(Value::as_str)
            .ok_or_else(|| effect_set_error(&kind, "cell write omits cell_family"))?;
        let subject_rule = write.get("cell_subject");
        let subject_json = subject_rule
            .filter(|value| !value.is_null())
            .map(serde_json::to_string)
            .transpose()
            .map_err(|error| effect_set_error(&kind, &error.to_string()))?;
        let subject = derive_subject(event, subject_json.as_deref())?;
        let cell = format!("ak:cell:{family}:{subject}");
        let lattice = write
            .get("lattice")
            .and_then(Value::as_str)
            .ok_or_else(|| effect_set_error(&kind, "cell write omits lattice"))?;
        if expected.insert(cell.clone(), lattice).is_some() {
            return Err(effect_set_error(
                &kind,
                &format!("two active targets derive the same cell {cell}"),
            ));
        }
    }

    let mut actual = BTreeMap::<String, usize>::new();
    for effect in &event.effects {
        *actual.entry(effect.cell.as_str().to_owned()).or_default() += 1;
    }
    if actual.values().any(|count| *count != 1) {
        return Err(effect_set_error(
            &kind,
            "an Event may write each registered target only once",
        ));
    }
    let actual_cells = actual.keys().cloned().collect::<Vec<_>>();
    let expected_cells = expected.keys().cloned().collect::<Vec<_>>();
    if actual_cells != expected_cells {
        return Err(effect_set_error(
            &kind,
            &format!("expected cells {expected_cells:?}, got {actual_cells:?}"),
        ));
    }

    for effect in &event.effects {
        let lattice = expected
            .get(effect.cell.as_str())
            .expect("actual and expected cell sets were compared");
        let valid_kind = match *lattice {
            "cas_register" | "mv_register" => effect.op.op_type == LatticeOpType::Set,
            "fsm" => effect.op.op_type == LatticeOpType::Transition,
            "ordered_log" => effect.op.op_type == LatticeOpType::Append,
            "or_set" => matches!(
                effect.op.op_type,
                LatticeOpType::Add | LatticeOpType::Remove
            ),
            "counter" => matches!(effect.op.op_type, LatticeOpType::Inc | LatticeOpType::Dec),
            _ => false,
        };
        if !valid_kind {
            return Err(EventCellContractError::OperationMismatch {
                kind: kind.clone(),
                expected: (*lattice).to_owned(),
                actual: format!("{:?}", effect.op.op_type).to_lowercase(),
            });
        }
    }
    Ok(())
}

fn condition_matches(
    event: &Event,
    condition: Option<&Value>,
    kind: &str,
) -> Result<bool, EventCellContractError> {
    let Some(condition) = condition else {
        return Ok(true);
    };
    let condition_type = condition
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| effect_set_error(kind, "condition omits type"))?;
    let present = |path: &str| field_value(event, path).is_some_and(|value| !value.is_null());
    match condition_type {
        "field_present" => condition
            .get("field")
            .and_then(Value::as_str)
            .map(present)
            .ok_or_else(|| effect_set_error(kind, "field_present omits field")),
        "field_absent" => condition
            .get("field")
            .and_then(Value::as_str)
            .map(|path| !present(path))
            .ok_or_else(|| effect_set_error(kind, "field_absent omits field")),
        "field_equals" => {
            let path = condition
                .get("field")
                .and_then(Value::as_str)
                .ok_or_else(|| effect_set_error(kind, "field_equals omits field"))?;
            let expected = condition
                .get("const")
                .ok_or_else(|| effect_set_error(kind, "field_equals omits const"))?;
            if !matches!(
                expected,
                Value::String(_) | Value::Number(_) | Value::Bool(_)
            ) {
                return Err(effect_set_error(
                    kind,
                    "field_equals const must be a string, number, or boolean",
                ));
            }
            Ok(field_value(event, path) == Some(expected))
        }
        "any_field_present" => {
            let fields = condition
                .get("fields")
                .and_then(Value::as_array)
                .ok_or_else(|| effect_set_error(kind, "any_field_present omits fields"))?;
            if fields.len() < 2 || fields.iter().any(|field| field.as_str().is_none()) {
                return Err(effect_set_error(
                    kind,
                    "any_field_present requires at least two string fields",
                ));
            }
            Ok(fields.iter().filter_map(Value::as_str).any(present))
        }
        other => Err(effect_set_error(
            kind,
            &format!("unknown condition type {other}"),
        )),
    }
}

fn effect_set_error(kind: &str, message: &str) -> EventCellContractError {
    EventCellContractError::EffectSetMismatch {
        kind: kind.to_owned(),
        message: message.to_owned(),
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

/// Validate a registry-declared, single-target `ordered_log` append Event.
///
/// Closes the delivery-family contract: the cell is re-derived from the
/// registry (never trusted from `effects[].cell`), the op must be an `append`
/// carrying `issuer_seq`, and `op.value` must equal the registry-declared
/// projection recomputed from the signed payload.
pub fn validate_single_target_append_event_contract(
    event: &Event,
    digest_suite: arkret_canonical::DigestSuite,
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
    if descriptor.lattice != Some("ordered_log") {
        return Err(EventCellContractError::MissingCellContract(kind));
    }

    validate_plane(event, descriptor.plane, EventCellContractContext::Standard)?;

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
    if effect.op.op_type != LatticeOpType::Append
        || effect.op.issuer_seq.is_none()
        || effect.op.tag.is_some()
        || effect.op.from.is_some()
        || effect.op.to.is_some()
        || effect.op.reason.is_some()
    {
        return Err(EventCellContractError::OperationMismatch {
            kind: kind.clone(),
            expected: "append".to_owned(),
            actual: format!("{:?}", effect.op.op_type).to_lowercase(),
        });
    }

    // A kind whose registry row declares no projection has no machine-checkable
    // append value yet; accepting an arbitrary producer-chosen value here would
    // be exactly the parallel protocol the contract exists to prevent.
    let rule_json = descriptor
        .value_projection_rule
        .ok_or_else(|| EventCellContractError::MissingCellContract(kind.clone()))?;
    let expected_value = derive_value_projection(event, rule_json, digest_suite)?;
    if effect.op.value.as_ref() != Some(&expected_value) {
        return Err(EventCellContractError::PayloadMismatch { kind });
    }
    Ok(())
}

/// Recompute a registry-declared `op.value` projection from the signed payload.
fn derive_value_projection(
    event: &Event,
    rule_json: &str,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<Value, EventCellContractError> {
    let kind = event.kind.as_str().to_owned();
    let rule: Value = serde_json::from_str(rule_json).map_err(|error| {
        EventCellContractError::SubjectDerivation {
            kind: kind.clone(),
            message: error.to_string(),
        }
    })?;
    if rule.get("type").and_then(Value::as_str) != Some("object") {
        return Err(projection_error(
            &kind,
            "value projection type must be object",
        ));
    }
    let members = rule
        .get("members")
        .and_then(Value::as_array)
        .ok_or_else(|| projection_error(&kind, "value projection members are missing"))?;

    let mut projected = serde_json::Map::new();
    for member in members {
        let name = member
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| projection_error(&kind, "value projection member is unnamed"))?;
        let optional = member
            .get("optional")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        if let Some(literal) = member.get("literal") {
            projected.insert(name.to_owned(), literal.clone());
            continue;
        }
        let resolved = if let Some(path) = member.get("field").and_then(Value::as_str) {
            field_value(event, path).cloned()
        } else if let Some(component) = member.get("select") {
            let path = select_field_path(event, component, &kind)?;
            field_value(event, &path).cloned()
        } else if let Some(digest_of) = member.get("digest_of") {
            member_digest(event, digest_of, &kind, digest_suite)?
        } else {
            return Err(projection_error(
                &kind,
                &format!("member {name} declares no source"),
            ));
        };
        match resolved {
            // Absent optional members are omitted, never written as null.
            None if optional => continue,
            None => {
                return Err(projection_error(
                    &kind,
                    &format!("member {name} is missing"),
                ));
            }
            Some(value) => {
                projected.insert(name.to_owned(), value);
            }
        }
    }
    Ok(Value::Object(projected))
}

/// Compute a `digest_of` member over its declared input encoding.
fn member_digest(
    event: &Event,
    digest_of: &Value,
    kind: &str,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<Option<Value>, EventCellContractError> {
    // The whole-payload input has no field path: it commits to every signed
    // byte, so a projection cannot silently lose a semantically relevant field
    // as the payload evolves (device-lifecycle.md 13.0.1).
    if digest_of.get("input").and_then(Value::as_str) == Some("event_payload_canonical_bytes") {
        let payload = Value::Object(event.payload.clone().into_iter().collect());
        let bytes = arkret_canonical::canonical_json_bytes(&payload)
            .map_err(|error| projection_error(kind, &error.to_string()))?;
        return Ok(Some(Value::String(arkret_canonical::digest(
            digest_suite,
            &bytes,
        ))));
    }
    let path = digest_of
        .get("field")
        .and_then(Value::as_str)
        .ok_or_else(|| projection_error(kind, "digest_of field is missing"))?;
    let Some(source) = field_value(event, path) else {
        return Ok(None);
    };
    let bytes = match digest_of.get("input").and_then(Value::as_str) {
        // Digesting the base64url text instead of the decoded ciphertext is
        // explicitly forbidden by `conformance/encoding.md` §10.
        Some("base64url_decoded_bytes") => {
            let encoded = source
                .as_str()
                .ok_or_else(|| projection_error(kind, &format!("{path} must be a string")))?;
            arkret_canonical::base64url_decode(encoded)
                .map_err(|error| projection_error(kind, &error.to_string()))?
        }
        Some("canonical_json_bytes") => arkret_canonical::canonical_json_bytes(source)
            .map_err(|error| projection_error(kind, &error.to_string()))?,
        other => {
            return Err(projection_error(
                kind,
                &format!(
                    "unsupported digest_of input {}",
                    other.unwrap_or("<missing>")
                ),
            ));
        }
    };
    // device-lifecycle.md 13.0.1: the wire form follows the Realm's active
    // `digest_algorithm`. Hard-coding SHA-256 would make a blake3 Realm's
    // `op.value` — and therefore its state root — diverge from any conformant
    // implementation.
    Ok(Some(Value::String(arkret_canonical::digest(
        digest_suite,
        &bytes,
    ))))
}

fn projection_error(kind: &str, message: &str) -> EventCellContractError {
    EventCellContractError::SubjectDerivation {
        kind: kind.to_owned(),
        message: message.to_owned(),
    }
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
        // `cell_subject: null` is a per-Realm singleton located by the Event
        // envelope `realm_id`. Its canonical wire subject segment is the literal
        // ASCII string `null` (`conformance/encoding.md` section 4). Encoding the
        // Realm id here instead would fork the `state_root` leaf set and leaf
        // order against any implementation that follows the spec.
        return Ok(NULL_CELL_SUBJECT.to_owned());
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
            let components = rule
                .get("components")
                .and_then(Value::as_array)
                .ok_or_else(|| subject_error(&kind, "composite components are missing"))?;
            derive_composite(event, components, &kind)
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
                let Some(path) = field.as_str() else {
                    continue;
                };
                if let Some(value) = field_value(event, path) {
                    return scalar_subject(value).map_err(|message| subject_error(&kind, &message));
                }
                if let Some(value) = envelope_field(event, path) {
                    return Ok(value);
                }
            }
            Err(subject_error(&kind, "no coalesce field is present"))
        }
        _ => {
            let path = rule
                .get("field")
                .and_then(Value::as_str)
                .ok_or_else(|| subject_error(&kind, "cell subject field is missing"))?;
            if let Some(value) = field_value(event, path) {
                return scalar_subject(value).map_err(|message| subject_error(&kind, &message));
            }
            envelope_field(event, path)
                .ok_or_else(|| subject_error(&kind, &format!("{path} is missing")))
        }
    }
}

fn derive_composite(
    event: &Event,
    components: &[Value],
    kind: &str,
) -> Result<String, EventCellContractError> {
    let parts = components
        .iter()
        .map(|component| component_scalar(event, component, kind))
        .collect::<Result<Vec<_>, _>>()?;
    let refs = parts.iter().map(String::as_str).collect::<Vec<_>>();
    arkret_wire::cell::composite_subject(&refs)
        .map_err(|error| subject_error(kind, &error.to_string()))
}

/// Resolve one composite component: either a plain field path or a
/// discriminated `select` (`conformance/encoding.md` §9.5.1).
fn component_scalar(
    event: &Event,
    component: &Value,
    kind: &str,
) -> Result<String, EventCellContractError> {
    if let Some(path) = component.as_str() {
        let value = field_value(event, path)
            .ok_or_else(|| subject_error(kind, &format!("{path} is missing")))?;
        return scalar_subject(value).map_err(|message| subject_error(kind, &message));
    }
    let path = select_field_path(event, component, kind)?;
    let value = field_value(event, &path)
        .ok_or_else(|| subject_error(kind, &format!("{path} is missing")))?;
    scalar_subject(value).map_err(|message| subject_error(kind, &message))
}

/// Evaluate a `select` component and return the selected field path.
///
/// The discriminator is read as the schema-validated raw string and matched
/// byte-for-byte against the closed branch map: no case folding, Unicode
/// normalisation or alias resolution.
///
/// Branch exclusivity comes only from the selected branch's declared
/// `forbidden_fields`. Treating "an unselected branch's field is present" as
/// ambiguity would be wrong in general: branches legitimately share fields —
/// an `effective_scope` with `kind="circle"` is required by schema to carry
/// `realm_id` as well, which is exactly the `realm` branch's value field.
fn select_field_path(
    event: &Event,
    component: &Value,
    kind: &str,
) -> Result<String, EventCellContractError> {
    if component.get("type").and_then(Value::as_str) != Some("select") {
        return Err(subject_error(
            kind,
            "composite component has an unknown type",
        ));
    }
    let selector = component
        .get("selector")
        .and_then(Value::as_str)
        .ok_or_else(|| subject_error(kind, "select component is missing selector"))?;
    let branches = component
        .get("branches")
        .and_then(Value::as_object)
        .ok_or_else(|| subject_error(kind, "select component is missing branches"))?;
    let discriminator = field_value(event, selector)
        .and_then(Value::as_str)
        .ok_or_else(|| subject_error(kind, &format!("selector {selector} is missing")))?;
    let branch = branches.get(discriminator).ok_or_else(|| {
        subject_error(
            kind,
            &format!("selector {selector} has no registered branch"),
        )
    })?;
    let selected = branch
        .get("field")
        .and_then(Value::as_str)
        .ok_or_else(|| subject_error(kind, "selected branch declares no field"))?;
    // Only the fields this branch explicitly forbids make the payload
    // ambiguous. The registry mirrors the wire schema's exclusivity here so
    // derivation still fails closed off the schema-validated path.
    for forbidden in branch
        .get("forbidden_fields")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        if field_value(event, forbidden).is_some() {
            return Err(subject_error(
                kind,
                &format!("forbidden field {forbidden} is present for branch {discriminator}"),
            ));
        }
    }
    Ok(selected.to_owned())
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

/// Resolve a **non-composite** subject path that names an Event Envelope field.
///
/// `event-and-patch.md` section 2.4.2 derives a cell subject from "the Event
/// Envelope and payload", and `ak.invite.accept` relies on that: its
/// `ak.component.member.state.v1` subject is the envelope `actor_id`, the
/// invitee who submitted the acceptance. `encoding.md` section 9.5.1 keeps
/// *composite* components narrower (effect value / payload fields only), so this
/// resolver is deliberately reachable only from the non-composite paths.
///
/// The set is closed: an unlisted bare path stays unresolved and the caller
/// fails the derivation closed rather than guessing.
fn envelope_field(event: &Event, path: &str) -> Option<String> {
    match path {
        "actor_id" => Some(event.actor_id.as_str().to_owned()),
        "event_id" => Some(event.event_id.to_string()),
        "realm_id" => Some(event.realm_id.as_str().to_owned()),
        _ => None,
    }
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
    use arkret_wire::events::kinds::EventKind;
    use serde_json::json;

    use super::*;

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
                "cell": format!("ak:cell:{family}:null"),
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

    /// A member-device realm key share whose effect is built exactly as the
    /// registry declares it.
    fn delivery_share_event() -> Event {
        let payload = json!({
            "share_class": "member_device",
            "recipient_principal_id": "did:webvh:z6mkfixture:bob.example",
            "recipient_device_id": "ak:device:019f9000-0000-7000-8000-000000000003",
            "sender_device_id": "ak:device:019f9000-0000-7000-8000-000000000004",
            "source_authorization_ref": "ak:event:019f9000-0000-7000-8000-000000000005",
            "sender_device_signature": {
                "kid": "did:webvh:z6mkfixture:alice.example#ak:device:019f9000-0000-7000-8000-000000000004",
                "alg": "EdDSA",
                "sig": "AAAA"
            },
            "key_scope": {
                "effective_scope": {
                    "kind": "realm",
                    "realm_id": "ak:realm:019f9000-0000-7000-8000-000000000002"
                },
                "policy_digest": format!("sha256:{}", "aa".repeat(32)),
                "from_epoch": 1,
                "to_epoch": 3
            },
            "ciphertext": "Y2lwaGVy",
            "created_at": "2026-07-26T00:00:00.000Z"
        });
        let mut event: Event = serde_json::from_value(json!({
            "event_id": "ak:event:019f9000-0000-7000-8000-000000000001",
            "kind": EventKind::REALM_KEY_SHARE,
            "realm_id": "ak:realm:019f9000-0000-7000-8000-000000000002",
            "actor_id": "did:webvh:z6mkfixture:alice.example",
            "actor_seq": 7,
            "created_at": "2026-07-26T00:00:00.000Z",
            "hlc": "019f90000000-0000-aabbccdd",
            "prev_refs": [],
            "effects": [],
            "seal_ref": "ak:seal:sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "auth_context": {
                "did": "did:webvh:z6mkfixture:alice.example",
                "key_id": "ak:device:019f9000-0000-7000-8000-000000000004",
                "key_epoch": 1,
                "capability_refs": []
            },
            "payload": payload,
            "proofs": []
        }))
        .unwrap();

        let descriptor = event.kind.descriptor().unwrap();
        let subject = derive_subject(&event, descriptor.cell_subject_rule).unwrap();
        let family = descriptor.cell_family.unwrap();
        let value = derive_value_projection(
            &event,
            descriptor.value_projection_rule.unwrap(),
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        event.effects = vec![
            serde_json::from_value(json!({
                "cell": format!("ak:cell:{family}:{subject}"),
                "op": {"kind": "append", "issuer_seq": 0, "value": value}
            }))
            .unwrap(),
        ];
        event
    }

    #[test]
    fn validates_delivery_append_from_registry() {
        validate_single_target_append_event_contract(
            &delivery_share_event(),
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
    }

    fn invite_create_event(invitee: Option<&str>) -> Event {
        let mut payload = json!({
            "invite_id": "ak:invite:019f9000-0000-7000-8000-000000000010"
        });
        if let Some(invitee) = invitee {
            payload["invitee"] = json!(invitee);
        }
        let mut effects = vec![json!({
            "cell": "ak:cell:ak.component.invite.lifecycle.v1:ak:invite:019f9000-0000-7000-8000-000000000010",
            "op": {"kind": "transition", "from": null, "to": "pending"}
        })];
        if let Some(invitee) = invitee {
            effects.push(json!({
                "cell": format!("ak:cell:ak.component.member.state.v1:{invitee}"),
                "op": {"kind": "transition", "from": "leave", "to": "invite"}
            }));
        }
        serde_json::from_value(json!({
            "event_id": "ak:event:019f9000-0000-7000-8000-000000000011",
            "kind": EventKind::INVITE_CREATE,
            "realm_id": "ak:realm:019f9000-0000-7000-8000-000000000002",
            "actor_id": "did:webvh:z6mkfixture:alice.example",
            "actor_seq": 4,
            "created_at": "2026-07-26T00:00:00.000Z",
            "hlc": "019f90000000-0000-aabbccdd",
            "prev_refs": [],
            "effects": effects,
            "payload": payload,
            "proofs": []
        }))
        .unwrap()
    }

    #[test]
    fn conditional_invite_member_target_is_exact() {
        let directed = invite_create_event(Some("did:webvh:z6mkfixture:bob.example"));
        validate_registered_cell_writes(&directed).unwrap();

        let mut missing_member = directed;
        missing_member.effects.pop();
        assert!(matches!(
            validate_registered_cell_writes(&missing_member),
            Err(EventCellContractError::EffectSetMismatch { .. })
        ));

        let third_party = invite_create_event(None);
        validate_registered_cell_writes(&third_party).unwrap();
    }

    fn call_event(kind: &str, payload: Value, effects: Vec<Value>) -> Event {
        serde_json::from_value(json!({
            "event_id": "ak:event:019f9000-0000-7000-8000-000000000021",
            "kind": kind,
            "realm_id": "ak:realm:019f9000-0000-7000-8000-000000000002",
            "actor_id": "did:webvh:z6mkfixture:alice.example",
            "actor_seq": 5,
            "created_at": "2026-07-26T00:00:00.000Z",
            "hlc": "019f90000000-0000-aabbccdd",
            "prev_refs": [],
            "effects": effects,
            "payload": payload,
            "proofs": []
        }))
        .unwrap()
    }

    #[test]
    fn conditional_call_axis_targets_are_exact() {
        let call_id = "ak:call:019f9000-0000-7000-8000-000000000022";
        let effects = vec![
            json!({
                "cell": format!("ak:cell:ak.component.call.state.v1:{call_id}"),
                "op": {"kind": "transition", "from": "ringing", "to": "active"}
            }),
            json!({
                "cell": format!("ak:cell:ak.component.call.focus.v1:{call_id}"),
                "op": {"kind": "set", "value": {"mode": "sfu", "session_focus": "fra-1"}}
            }),
            json!({
                "cell": format!("ak:cell:ak.component.call.roster.v1:{call_id}"),
                "op": {"kind": "add", "tag": "alice-device", "value": {"actor_id": "did:webvh:z6mkfixture:alice.example"}}
            }),
        ];
        let event = call_event(
            EventKind::CALL_STATE,
            json!({
                "call_id": call_id,
                "state": "active",
                "mode": "sfu",
                "session_focus": "fra-1",
                "participants": [{
                    "actor_id": "did:webvh:z6mkfixture:alice.example",
                    "device_id": "ak:device:019f9000-0000-7000-8000-000000000023"
                }]
            }),
            effects,
        );
        validate_registered_cell_writes(&event).unwrap();

        let mut missing_roster = event.clone();
        missing_roster.effects.pop();
        assert!(matches!(
            validate_registered_cell_writes(&missing_roster),
            Err(EventCellContractError::EffectSetMismatch { .. })
        ));

        let recording_id = "ak:recording:019f9000-0000-7000-8000-000000000024";
        let recording_subject = arkret_wire::composite_subject(&[call_id, recording_id]).unwrap();
        let mut inactive_recording = event;
        inactive_recording.effects.push(
            serde_json::from_value(json!({
                "cell": format!("ak:cell:ak.component.call.recording.v1:{recording_subject}"),
                "op": {"kind": "transition", "from": "recording", "to": "ready"}
            }))
            .unwrap(),
        );
        assert!(matches!(
            validate_registered_cell_writes(&inactive_recording),
            Err(EventCellContractError::EffectSetMismatch { .. })
        ));
    }

    #[test]
    fn capture_kind_selects_exactly_one_capture_family() {
        let call_id = "ak:call:019f9000-0000-7000-8000-000000000031";
        let recording_id = "ak:recording:019f9000-0000-7000-8000-000000000032";
        let subject = arkret_wire::composite_subject(&[call_id, recording_id]).unwrap();
        let recording = call_event(
            EventKind::CALL_RECORDING_START,
            json!({
                "call_id": call_id,
                "recording_id": recording_id,
                "capture_kind": "recording"
            }),
            vec![json!({
                "cell": format!("ak:cell:ak.component.call.recording.v1:{subject}"),
                "op": {"kind": "transition", "from": null, "to": "recording"}
            })],
        );
        validate_registered_cell_writes(&recording).unwrap();

        let transcript = call_event(
            EventKind::CALL_RECORDING_START,
            json!({
                "call_id": call_id,
                "recording_id": recording_id,
                "capture_kind": "transcript"
            }),
            vec![json!({
                "cell": format!("ak:cell:ak.component.call.transcript.v1:{subject}"),
                "op": {"kind": "transition", "from": null, "to": "transcribing"}
            })],
        );
        validate_registered_cell_writes(&transcript).unwrap();

        let mut wrong_family = transcript;
        wrong_family.effects[0].cell =
            arkret_wire::CellRef::new(format!("ak:cell:ak.component.call.recording.v1:{subject}"))
                .unwrap();
        assert!(matches!(
            validate_registered_cell_writes(&wrong_family),
            Err(EventCellContractError::EffectSetMismatch { .. })
        ));
    }

    #[test]
    fn delivery_subject_selects_the_share_class_branch() {
        let event = delivery_share_event();
        let rule = event.kind.descriptor().unwrap().cell_subject_rule;
        let member_subject = derive_subject(&event, rule).unwrap();

        // The RRK branch derives from a different target field, so the same
        // recipient and scope MUST NOT collapse onto one delivery cell.
        let mut rrk = event.clone();
        rrk.payload.remove("recipient_device_id");
        rrk.payload
            .insert("share_class".to_owned(), json!("realm_recovery_key"));
        rrk.payload.insert(
            "recipient_verification_method".to_owned(),
            json!("did:webvh:z6mkfixture:acme.example#realm-history-recovery-1"),
        );
        rrk.payload.insert(
            "recovery_recipient_id".to_owned(),
            // Deliberately spelled like a device id: without `share_class` in
            // the components an RRK share could target a member device's cell.
            json!("ak:device:019f9000-0000-7000-8000-000000000003"),
        );
        let rrk_subject = derive_subject(&rrk, rule).unwrap();
        assert_ne!(member_subject, rrk_subject);
    }

    #[test]
    fn delivery_supports_circle_scope_which_also_carries_realm_id() {
        // `effective_scope.kind="circle"` is required by schema to carry
        // `realm_id` too — the `realm` branch's value field. A blanket
        // "unselected branch field present => ambiguous" rule would reject
        // every legitimate Circle key share.
        let mut event = delivery_share_event();
        event.payload.insert(
            "key_scope".to_owned(),
            json!({
                "effective_scope": {
                    "kind": "circle",
                    "realm_id": "ak:realm:019f9000-0000-7000-8000-000000000002",
                    "circle_id": "ak:circle:019f9000-0000-7000-8000-000000000007"
                },
                "policy_digest": format!("sha256:{}", "aa".repeat(32))
            }),
        );
        let descriptor = event.kind.descriptor().unwrap();
        let subject = derive_subject(&event, descriptor.cell_subject_rule).unwrap();
        let family = descriptor.cell_family.unwrap();
        let value = derive_value_projection(
            &event,
            descriptor.value_projection_rule.unwrap(),
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        assert_eq!(
            value["effective_scope_id"],
            json!("ak:circle:019f9000-0000-7000-8000-000000000007"),
            "circle branch must project the circle id"
        );
        event.effects = vec![
            serde_json::from_value(json!({
                "cell": format!("ak:cell:{family}:{subject}"),
                "op": {"kind": "append", "issuer_seq": 0, "value": value}
            }))
            .unwrap(),
        ];
        validate_single_target_append_event_contract(&event, arkret_canonical::DigestSuite::Sha256)
            .unwrap();

        // And a Realm-scoped share must still land on a different cell.
        assert_ne!(
            subject,
            derive_subject(&delivery_share_event(), descriptor.cell_subject_rule).unwrap()
        );
    }

    #[test]
    fn delivery_subject_rejects_cross_carried_branch_field() {
        let mut event = delivery_share_event();
        event
            .payload
            .insert("recovery_recipient_id".to_owned(), json!("rr-1"));
        let rule = event.kind.descriptor().unwrap().cell_subject_rule;
        let error = derive_subject(&event, rule).unwrap_err();
        assert!(
            format!("{error}").contains("forbidden field payload.recovery_recipient_id"),
            "got {error}"
        );
    }

    #[test]
    fn delivery_subject_rejects_unknown_discriminator() {
        let mut event = delivery_share_event();
        event
            .payload
            .insert("share_class".to_owned(), json!("member-device"));
        let rule = event.kind.descriptor().unwrap().cell_subject_rule;
        let error = derive_subject(&event, rule).unwrap_err();
        assert!(
            format!("{error}").contains("no registered branch"),
            "byte-for-byte branch match only; got {error}"
        );
    }

    #[test]
    fn delivery_append_rejects_producer_chosen_value() {
        let mut event = delivery_share_event();
        let Some(value) = event.effects[0].op.value.as_mut() else {
            panic!("append must carry a value");
        };
        value
            .as_object_mut()
            .unwrap()
            .insert("delivery_outcome".to_owned(), json!("withheld"));
        assert!(matches!(
            validate_single_target_append_event_contract(
                &event,
                arkret_canonical::DigestSuite::Sha256
            ),
            Err(EventCellContractError::PayloadMismatch { .. })
        ));
    }

    #[test]
    fn delivery_append_commits_to_every_signed_field() {
        // Regression: a projection that only committed to the ciphertext let
        // semantically different deliveries collapse into one idempotent
        // duplicate. Each of these differs only in a field that is signed and
        // changes delivery meaning.
        let base = delivery_share_event();
        let rule = base
            .kind
            .descriptor()
            .unwrap()
            .value_projection_rule
            .unwrap();
        let suite = arkret_canonical::DigestSuite::Sha256;
        let baseline = derive_value_projection(&base, rule, suite).unwrap();

        let mutations: [(&str, fn(&mut Event)); 4] = [
            ("expires_at", |event: &mut Event| {
                event
                    .payload
                    .insert("expires_at".to_owned(), json!("2026-08-01T00:00:00.000Z"));
            }),
            ("aad_digest", |event: &mut Event| {
                event.payload.insert(
                    "aad_digest".to_owned(),
                    json!(format!("sha256:{}", "cc".repeat(32))),
                );
            }),
            (
                "key_scope.membership_frontier_digest",
                |event: &mut Event| {
                    event
                        .payload
                        .get_mut("key_scope")
                        .unwrap()
                        .as_object_mut()
                        .unwrap()
                        .insert(
                            "membership_frontier_digest".to_owned(),
                            json!(format!("sha256:{}", "dd".repeat(32))),
                        );
                },
            ),
            ("ciphertext", |event: &mut Event| {
                event
                    .payload
                    .insert("ciphertext".to_owned(), json!("b3RoZXI"));
            }),
        ];
        for (label, mutate) in mutations {
            let mut mutated = base.clone();
            mutate(&mut mutated);
            let value = derive_value_projection(&mutated, rule, suite).unwrap();
            assert_ne!(
                baseline, value,
                "{label} is signed and changes delivery meaning; it must change op.value"
            );
        }
    }

    #[test]
    fn delivery_append_commits_to_the_material_digest() {
        // Two different sealed materials to the same recipient and scope must
        // not project to the same entry, or §9.3.1 would dedupe one away.
        let first = delivery_share_event();
        let mut second = first.clone();
        second
            .payload
            .insert("ciphertext".to_owned(), json!("b3RoZXI"));
        let rule = second.kind.descriptor().unwrap().value_projection_rule;
        let second_value = derive_value_projection(
            &second,
            rule.unwrap(),
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        assert_ne!(first.effects[0].op.value.as_ref().unwrap(), &second_value);

        // The commitment is over the complete canonical signed payload.
        let payload = Value::Object(first.payload.clone().into_iter().collect());
        let expected = arkret_canonical::sha256_digest(
            arkret_canonical::canonical_json_bytes(&payload).unwrap(),
        );
        assert_eq!(
            first.effects[0].op.value.as_ref().unwrap()["payload_digest"],
            json!(expected)
        );
    }

    #[test]
    fn delivery_material_digest_follows_the_realm_digest_suite() {
        // A blake3 Realm must project a blake3 material digest; hard-coding
        // SHA-256 would diverge from every conformant implementation's state.
        let event = delivery_share_event();
        let rule = event
            .kind
            .descriptor()
            .unwrap()
            .value_projection_rule
            .unwrap();
        let blake3 =
            derive_value_projection(&event, rule, arkret_canonical::DigestSuite::Blake3).unwrap();
        let payload = Value::Object(event.payload.clone().into_iter().collect());
        assert_eq!(
            blake3["payload_digest"],
            json!(arkret_canonical::digest(
                arkret_canonical::DigestSuite::Blake3,
                arkret_canonical::canonical_json_bytes(&payload).unwrap()
            ))
        );
        // And the sha256 projection (used to build `event`) must be rejected
        // when the Realm is on blake3.
        assert!(matches!(
            validate_single_target_append_event_contract(
                &event,
                arkret_canonical::DigestSuite::Blake3
            ),
            Err(EventCellContractError::PayloadMismatch { .. })
        ));
    }

    #[test]
    fn delivery_append_omits_absent_optional_members() {
        let mut event = delivery_share_event();
        event
            .payload
            .get_mut("key_scope")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove("to_epoch");
        let rule = event.kind.descriptor().unwrap().value_projection_rule;
        let value =
            derive_value_projection(&event, rule.unwrap(), arkret_canonical::DigestSuite::Sha256)
                .unwrap();
        let object = value.as_object().unwrap();
        assert!(object.contains_key("from_epoch"));
        assert!(
            !object.contains_key("to_epoch"),
            "absent optional members are omitted, never written as null"
        );
    }

    #[test]
    fn delivery_append_rejects_producer_chosen_cell() {
        let mut event = delivery_share_event();
        event.effects[0].cell = arkret_wire::CellRef::new(
            "ak:cell:ak.component.realm_key.delivery.v1:not-the-derived-subject",
        )
        .unwrap();
        assert_eq!(
            validate_single_target_append_event_contract(
                &event,
                arkret_canonical::DigestSuite::Sha256
            )
            .unwrap_err()
            .reason_code(),
            "effects_payload_mismatch"
        );
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
        event.effects[0].cell =
            arkret_wire::CellRef::new("ak:cell:ak.component.realm.join_rule.v1:null").unwrap();
        let error = validate_single_target_set_event_contract(&event).unwrap_err();
        assert_eq!(error.reason_code(), "effects_payload_mismatch");

        event.effects[0].cell =
            arkret_wire::CellRef::new("ak:cell:ak.component.realm.discovery.v1:null").unwrap();
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
